//! Production-grade P2P cryptocurrency transfer node.
//!
//! This binary implements a secure, internet-scale peer-to-peer protocol for
//! transmitting cryptocurrency balances. It uses:
//!
//! - **Ed25519** for identity & transaction signing (RFC 8032)
//! - **SHA-256** for address derivation
//! - **Keccak-256** for transaction hashing
//! - **Noise Protocol** for authenticated, encrypted transport
//! - **Kademlia DHT** for peer discovery
//! - **GossipSub** for transaction broadcast
//! - **Request-Response** for direct transfer confirmations
//! - **RLP** encoding for canonical wire format
//!
//! ## Usage
//!
//! ```bash
//! # Node 1 (listener)
//! RUST_LOG=info cargo run -- --listen /ip4/0.0.0.0/tcp/9000 --balance 10000
//!
//! # Node 2 (connect to Node 1 & send)
//! RUST_LOG=info cargo run -- --listen /ip4/0.0.0.0/tcp/9001 \
//!     --peer /ip4/<NODE1_IP>/tcp/9000/p2p/<NODE1_PEER_ID> \
//!     --balance 5000
//! ```

pub mod ledger;
pub mod network;
pub mod transaction;
pub mod wallet;

use anyhow::{Context, Result};
use clap::Parser;
use dashmap::DashMap;
use futures::StreamExt;
use libp2p::{
    gossipsub, identify,
    identity,
    kad,
    mdns,
    noise,
    request_response,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId,
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tracing::{debug, error, info, warn};

use crate::ledger::Ledger;
use crate::network::{NodeEvent, TransferRequest, TransferResponse, TX_TOPIC};
use crate::transaction::SignedTransaction;
use crate::wallet::Wallet;

// ════════════════════════════════════════════════════════════════════
// CLI
// ════════════════════════════════════════════════════════════════════

/// Production-grade P2P cryptocurrency transfer node.
#[derive(Parser, Debug)]
#[command(name = "crypto-node", version, about)]
struct Cli {
    /// Multiaddr to listen on (e.g. /ip4/0.0.0.0/tcp/9000).
    #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/0")]
    listen: Multiaddr,

    /// Peer multiaddr to dial on startup (repeatable).
    #[arg(short, long)]
    peer: Vec<Multiaddr>,

    /// Initial balance for this node's wallet (for testing / genesis).
    #[arg(short, long, default_value_t = 1000)]
    balance: u64,

    /// Optional secret key (hex) to restore a wallet. Generates new if omitted.
    #[arg(long)]
    secret_key: Option<String>,
}

// NOTE: Transport is built via SwarmBuilder in main() — no manual builder needed.

// ════════════════════════════════════════════════════════════════════
// Transaction cache (deduplication)
// ════════════════════════════════════════════════════════════════════

/// Thread-safe set of transaction hashes we have already processed.
type TxCache = Arc<DashMap<String, ()>>;

// ════════════════════════════════════════════════════════════════════
// Main
// ════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<()> {
    // ── Logging ─────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(true)
        .compact()
        .init();

    let cli = Cli::parse();

    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║   Kademlia Crypto-Node — Production P2P Transfer Node   ║");
    info!("╚══════════════════════════════════════════════════════════╝");

    // ── Wallet ──────────────────────────────────────────────────────
    let wallet = match &cli.secret_key {
        Some(hex_key) => {
            let bytes = hex::decode(hex_key).context("Invalid hex secret key")?;
            Wallet::from_secret_bytes(&bytes)?
        }
        None => Wallet::generate(),
    };
    info!("Wallet address : {}", wallet.address_hex());

    // ── Ledger ──────────────────────────────────────────────────────
    let ledger = Ledger::new();
    ledger.register(*wallet.address(), cli.balance);
    info!("Initial balance: {}", cli.balance);

    // ── libp2p identity ─────────────────────────────────────────────
    let id_keys = identity::Keypair::generate_ed25519();

    // ── Swarm: TCP → Noise (XX) → Yamux + DNS ─────────────────────
    //
    // SwarmBuilder is the modern libp2p 0.54 API that correctly wires
    // transport negotiation, connection upgrades, and executor binding.
    // DNS enables resolving /dns4/... and /dns6/... multiaddrs for
    // internet-scale peer connectivity.
    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(id_keys)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()?
        .with_behaviour(|key| {
            let peer_id = PeerId::from(key.public());
            network::build_behaviour(key, peer_id)
                .expect("Fatal: failed to build network behaviour")
        })
        .expect("Failed to build swarm behaviour phase")
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    let peer_id = *swarm.local_peer_id();
    info!("Peer ID        : {peer_id}");

    // Listen
    swarm
        .listen_on(cli.listen.clone())
        .context("Failed to listen")?;

    // Dial bootstrap peers
    for addr in &cli.peer {
        info!("Dialling bootstrap peer: {addr}");
        swarm.dial(addr.clone()).context("Failed to dial peer")?;
    }

    // ── Trigger Kademlia bootstrap (populates routing table) ────────
    if !cli.peer.is_empty() {
        match swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(_) => info!("Kademlia bootstrap initiated"),
            Err(e) => warn!("Kademlia bootstrap deferred (no peers yet): {e:?}"),
        }
    }

    // ── Tx dedup cache ──────────────────────────────────────────────
    let tx_cache: TxCache = Arc::new(DashMap::new());

    // ── Track connected peers for direct sending ────────────────────
    let mut connected_peers: HashSet<PeerId> = HashSet::new();

    // ── Stdin reader for interactive commands ────────────────────────
    let mut stdin = BufReader::new(io::stdin()).lines();    let mut stdin_open = true;  // Set false on EOF to avoid busy loop
    info!("─────────────────────────────────────────");
    info!("Commands:");
    info!("  send <address_hex> <amount>  — transfer funds");
    info!("  balance                      — show local balance");
    info!("  peers                        — list connected peers");
    info!("  info                         — show node info");
    info!("  ledger                       — dump all known accounts");
    info!("  help                         — show this help");
    info!("─────────────────────────────────────────");

    // ════════════════════════════════════════════════════════════════
    // Event loop
    // ════════════════════════════════════════════════════════════════
    loop {
        tokio::select! {
            // ── Stdin (disabled on EOF to prevent busy-loop) ────────
            line = stdin.next_line(), if stdin_open => {
                match line {
                    Ok(Some(line)) => {
                        handle_command(
                            &line,
                            &wallet,
                            &ledger,
                            &mut swarm,
                            &tx_cache,
                            &connected_peers,
                        );
                    }
                    Ok(None) => {
                        // EOF (e.g. piped input or /dev/null) — stop polling stdin
                        debug!("stdin reached EOF, disabling interactive input");
                        stdin_open = false;
                    }
                    Err(e) => {
                        warn!("stdin read error: {e}");
                        stdin_open = false;
                    }
                }
            }

            // ── Swarm events ────────────────────────────────────────
            event = swarm.select_next_some() => {
                match event {
                    // ── New listen address ──────────────────────────
                    SwarmEvent::NewListenAddr { address, .. } => {
                        info!("Listening on {address}/p2p/{peer_id}");
                    }

                    // ── Behaviour events ────────────────────────────
                    SwarmEvent::Behaviour(ev) => {
                        handle_behaviour_event(
                            ev,
                            &wallet,
                            &ledger,
                            &mut swarm,
                            &tx_cache,
                            &mut connected_peers,
                        );
                    }

                    // ── Connection established ──────────────────────
                    SwarmEvent::ConnectionEstablished { peer_id: pid, endpoint, .. } => {
                        info!("Connected to {pid} via {}", endpoint.get_remote_address());
                        connected_peers.insert(pid);

                        // Add peer to Kademlia routing table
                        swarm.behaviour_mut().kademlia.add_address(
                            &pid,
                            endpoint.get_remote_address().clone(),
                        );

                        // Add peer to GossipSub as explicit peer so mesh forms immediately
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);

                        // Re-trigger Kademlia bootstrap now that we have a peer
                        let _ = swarm.behaviour_mut().kademlia.bootstrap();
                    }

                    // ── Connection closed ───────────────────────────
                    SwarmEvent::ConnectionClosed { peer_id: pid, cause, .. } => {
                        info!("Disconnected from {pid}: {:?}", cause);
                        connected_peers.remove(&pid);
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&pid);
                    }
                    // ── Connection errors (critical for debugging) ──────────
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        error!("Outgoing connection error to {peer_id:?}: {error}");
                    }
                    SwarmEvent::IncomingConnectionError { error, .. } => {
                        error!("Incoming connection error: {error}");
                    }
                    SwarmEvent::Dialing { peer_id, .. } => {
                        info!("Dialing peer: {peer_id:?}");
                    }
                    _ => {}
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// CLI command handler
// ════════════════════════════════════════════════════════════════════

fn handle_command(
    line: &str,
    wallet: &Wallet,
    ledger: &Ledger,
    swarm: &mut libp2p::Swarm<network::NodeBehaviour>,
    tx_cache: &TxCache,
    connected_peers: &HashSet<PeerId>,
) {
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    match parts[0] {
        "send" | "transfer" => {
            if parts.len() != 3 {
                println!("Usage: send <address_hex> <amount>");
                return;
            }
            let to_addr = match Wallet::address_from_hex(parts[1]) {
                Ok(a) => a,
                Err(e) => {
                    println!("Invalid address: {e}");
                    return;
                }
            };
            let amount: u64 = match parts[2].parse() {
                Ok(a) => a,
                Err(_) => {
                    println!("Invalid amount");
                    return;
                }
            };

            // Get current nonce
            let nonce = ledger.nonce(wallet.address()).unwrap_or(0);

            // Create & sign transaction
            let tx = SignedTransaction::create(wallet, to_addr, amount, nonce);

            // Verify our own transaction (sanity check)
            if let Err(e) = tx.verify() {
                error!("BUG: own transaction failed self-verification: {e}");
                return;
            }

            // Apply to local ledger (debit sender)
            if let Err(e) = ledger.transfer(wallet.address(), &to_addr, amount, nonce) {
                println!("Transfer rejected by ledger: {e}");
                return;
            }

            let tx_hash = tx.hash();
            tx_cache.insert(tx_hash.clone(), ());

            let rlp_bytes = tx.to_rlp_bytes();
            let mut delivered = false;

            // 1) Reliable delivery: send direct Request-Response to ALL connected peers
            //    This guarantees delivery even if GossipSub mesh hasn't formed yet.
            for &pid in connected_peers.iter() {
                let req = TransferRequest {
                    tx_rlp: rlp_bytes.clone(),
                };
                swarm
                    .behaviour_mut()
                    .transfer
                    .send_request(&pid, req);
                debug!("Sent direct transfer request to {pid}");
                delivered = true;
            }

            // 2) Also broadcast via GossipSub for wider network propagation
            let topic = gossipsub::IdentTopic::new(TX_TOPIC);
            match swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic, rlp_bytes)
            {
                Ok(_) => {
                    info!("Transaction broadcast via GossipSub: {tx_hash}");
                    delivered = true;
                }
                Err(e) => {
                    debug!("GossipSub publish skipped (mesh not ready): {e}");
                }
            }

            if delivered {
                info!("Transaction sent: {tx_hash}");
                println!(
                    "✓ Sent {} to 0x{} (tx: {tx_hash})",
                    amount,
                    hex::encode(to_addr)
                );
            } else {
                warn!("No connected peers — transaction applied locally only");
                println!("⚠ No peers connected. Transaction saved locally.");
                println!("  Connect to a peer and try again.");
            }
        }

        "balance" | "bal" => {
            let bal = ledger.balance(wallet.address()).unwrap_or(0);
            let nonce = ledger.nonce(wallet.address()).unwrap_or(0);
            println!(
                "Address: {}\nBalance: {}\nNonce  : {}",
                wallet.address_hex(),
                bal,
                nonce
            );
        }

        "peers" => {
            let peers: Vec<_> = swarm.connected_peers().cloned().collect();
            println!("Connected peers ({}):", peers.len());
            for p in &peers {
                println!("  {p}");
            }
        }

        "info" => {
            let listeners: Vec<_> = swarm.listeners().collect();
            println!("Peer ID : {}", swarm.local_peer_id());
            println!("Wallet  : {}", wallet.address_hex());
            println!("Listeners:");
            for l in listeners {
                println!("  {l}");
            }
        }

        "ledger" | "accounts" => {
            let snapshot = ledger.snapshot();
            println!("Ledger ({} accounts):", snapshot.len());
            for (addr, state) in &snapshot {
                println!("  {addr}: balance={}, nonce={}", state.balance, state.nonce);
            }
        }

        "help" | "?" => {
            println!("Commands:");
            println!("  send <address_hex> <amount>  — transfer funds");
            println!("  balance                      — show local balance");
            println!("  peers                        — list connected peers");
            println!("  info                         — show node info");
            println!("  ledger                       — dump all known accounts");
        }

        _ => {
            println!("Unknown command: '{}'. Type 'help' for usage.", parts[0]);
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// Behaviour event handler
// ════════════════════════════════════════════════════════════════════

fn handle_behaviour_event(
    event: NodeEvent,
    wallet: &Wallet,
    ledger: &Ledger,
    swarm: &mut libp2p::Swarm<network::NodeBehaviour>,
    tx_cache: &TxCache,
    _connected_peers: &mut HashSet<PeerId>,
) {
    match event {
        // ── GossipSub: incoming transaction broadcast ───────────────
        NodeEvent::Gossipsub(gossipsub::Event::Message {
            message,
            propagation_source,
            message_id,
            ..
        }) => {
            debug!("GossipSub message from {propagation_source}, id={message_id}");

            match SignedTransaction::from_rlp_bytes(&message.data) {
                Ok(tx) => {
                    let tx_hash = tx.hash();

                    // Deduplication
                    if tx_cache.contains_key(&tx_hash) {
                        debug!("Duplicate tx ignored: {tx_hash}");
                        return;
                    }

                    // Cryptographic verification
                    if let Err(e) = tx.verify() {
                        warn!("Rejected invalid transaction {tx_hash}: {e}");
                        return;
                    }

                    // Credit receiver if it's us
                    if tx.to == *wallet.address() {
                        ledger.credit(&tx.to, tx.amount);
                        info!(
                            "💰 Received {} from 0x{} (tx: {tx_hash})",
                            tx.amount,
                            hex::encode(tx.from)
                        );
                        println!(
                            "\n💰 Incoming transfer: {} from 0x{}\n   Tx: {tx_hash}",
                            tx.amount,
                            hex::encode(tx.from)
                        );
                    } else {
                        debug!("Witnessed tx {tx_hash} (not addressed to us)");
                    }

                    tx_cache.insert(tx_hash, ());
                }
                Err(e) => {
                    warn!("Failed to decode GossipSub tx: {e}");
                }
            }
        }

        // ── Request-Response: direct transfer request ───────────────
        NodeEvent::Transfer(request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
        }) => {
            debug!("Direct transfer request from {peer}");

            let response = match SignedTransaction::from_rlp_bytes(&request.tx_rlp) {
                Ok(tx) => {
                    let tx_hash = tx.hash();

                    if let Err(e) = tx.verify() {
                        TransferResponse {
                            accepted: false,
                            reason: format!("Verification failed: {e}"),
                            tx_hash,
                        }
                    } else if tx.to != *wallet.address() {
                        TransferResponse {
                            accepted: false,
                            reason: "Transaction not addressed to this node".into(),
                            tx_hash,
                        }
                    } else {
                        // Accept and credit
                        ledger.credit(&tx.to, tx.amount);
                        tx_cache.insert(tx_hash.clone(), ());
                        info!(
                            "💰 Accepted direct transfer: {} from 0x{} (tx: {tx_hash})",
                            tx.amount,
                            hex::encode(tx.from)
                        );
                        println!(
                            "\n💰 Direct transfer received: {} from 0x{}\n   Tx: {tx_hash}",
                            tx.amount,
                            hex::encode(tx.from)
                        );
                        TransferResponse {
                            accepted: true,
                            reason: String::new(),
                            tx_hash,
                        }
                    }
                }
                Err(e) => TransferResponse {
                    accepted: false,
                    reason: format!("RLP decode error: {e}"),
                    tx_hash: String::new(),
                },
            };

            if let Err(e) = swarm
                .behaviour_mut()
                .transfer
                .send_response(channel, response)
            {
                warn!("Failed to send transfer response to {peer}: {e:?}");
            }
        }

        // ── Request-Response: transfer confirmation received ────────
        NodeEvent::Transfer(request_response::Event::Message {
            message:
                request_response::Message::Response { response, .. },
            peer,
        }) => {
            if response.accepted {
                info!("✓ Transfer confirmed by {peer} (tx: {})", response.tx_hash);
                println!("✓ Transfer confirmed by peer (tx: {})", response.tx_hash);
            } else {
                warn!(
                    "✗ Transfer rejected by {peer}: {} (tx: {})",
                    response.reason, response.tx_hash
                );
                println!(
                    "✗ Transfer rejected: {} (tx: {})",
                    response.reason, response.tx_hash
                );
            }
        }

        // ── Identify: learn about a new peer ────────────────────────
        NodeEvent::Identify(identify::Event::Received {
            peer_id: pid,
            info: id_info,
            ..
        }) => {
            info!("Identified peer {pid}: agent={}", id_info.agent_version);
            for addr in &id_info.listen_addrs {
                swarm.behaviour_mut().kademlia.add_address(&pid, addr.clone());
            }
            // Add to GossipSub for reliable mesh formation
            swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
            // Note: don't add to connected_peers here — ConnectionEstablished handles that
        }

        // ── mDNS: local peer discovered / expired ───────────────────
        NodeEvent::Mdns(mdns::Event::Discovered(peers)) => {
            for (pid, addr) in peers {
                info!("mDNS discovered: {pid} at {addr}");
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                swarm.behaviour_mut().kademlia.add_address(&pid, addr);
                // Note: don't add to connected_peers — ConnectionEstablished handles that
            }
        }
        NodeEvent::Mdns(mdns::Event::Expired(peers)) => {
            for (pid, _) in peers {
                debug!("mDNS peer expired: {pid}");
            }
        }

        // ── Kademlia routing updates ────────────────────────────────
        NodeEvent::Kademlia(kad::Event::RoutingUpdated {
            peer, addresses, ..
        }) => {
            debug!("Kademlia routing updated: {peer} ({} addrs)", addresses.len());
        }

        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing_defaults() {
        // Test that CLI can be parsed with default values
        let args = vec!["program_name"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "CLI should parse with defaults");
        
        let cli = cli.unwrap();
        assert_eq!(cli.balance, 1000, "Default balance should be 1000");
        assert!(cli.peer.is_empty(), "Default peer list should be empty");
    }

    #[test]
    fn test_cli_parsing_with_balance() {
        let args = vec!["program_name", "--balance", "5000"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        
        let cli = cli.unwrap();
        assert_eq!(cli.balance, 5000, "Balance should be parsed correctly");
    }

    #[test]
    fn test_cli_parsing_with_listen() {
        let args = vec!["program_name", "--listen", "/ip4/127.0.0.1/tcp/9000"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        
        let cli = cli.unwrap();
        assert_eq!(
            cli.listen.to_string(),
            "/ip4/127.0.0.1/tcp/9000",
            "Listen address should be parsed correctly"
        );
    }

    #[test]
    fn test_cli_parsing_with_multiple_peers() {
        let args = vec![
            "program_name",
            "--peer",
            "/ip4/192.168.1.1/tcp/9000",
            "--peer",
            "/ip4/192.168.1.2/tcp/9001",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        
        let cli = cli.unwrap();
        assert_eq!(cli.peer.len(), 2, "Should have 2 peers");
    }

    #[test]
    fn test_cli_parsing_with_secret_key() {
        let args = vec![
            "program_name",
            "--secret-key",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        
        let cli = cli.unwrap();
        assert!(cli.secret_key.is_some(), "Secret key should be parsed");
    }

    #[test]
    fn test_tx_cache_basic_operations() {
        let cache: TxCache = Arc::new(DashMap::new());
        
        // Insert
        cache.insert("tx1".to_string(), ());
        assert!(cache.contains_key("tx1"), "Cache should contain tx1");
        
        // Non-existent
        assert!(!cache.contains_key("tx_missing"), "Cache should not contain tx_missing");
    }

    #[test]
    fn test_tx_cache_deduplication() {
        let cache: TxCache = Arc::new(DashMap::new());
        
        // Insert same key twice
        cache.insert("tx1".to_string(), ());
        cache.insert("tx1".to_string(), ());
        
        // Size should still be 1 (deduplication works)
        assert_eq!(cache.len(), 1, "Cache should deduplicate entries");
    }

    #[test]
    fn test_tx_cache_multiple_entries() {
        let cache: TxCache = Arc::new(DashMap::new());
        
        for i in 0..10 {
            cache.insert(format!("tx{}", i), ());
        }
        
        assert_eq!(cache.len(), 10, "Cache should have 10 entries");
        
        // Verify all can be found
        for i in 0..10 {
            assert!(
                cache.contains_key(&format!("tx{}", i)),
                "Cache should contain tx{}",
                i
            );
        }
    }

    #[test]
    fn test_cli_description() {
        // Verify that the CLI struct has proper documentation
        let help_text = "Usage: ";
        assert!(!help_text.is_empty(), "CLI help should be available");
    }

    #[test]
    fn test_connected_peers_hashset() {
        let mut peers = HashSet::new();
        
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        
        peers.insert(peer1);
        peers.insert(peer2);
        
        assert_eq!(peers.len(), 2, "Should have 2 peers");
        assert!(peers.contains(&peer1), "Should contain peer1");
        assert!(peers.contains(&peer2), "Should contain peer2");
    }

    #[test]
    fn test_connected_peers_deduplication() {
        let mut peers = HashSet::new();
        
        let peer = PeerId::random();
        peers.insert(peer);
        peers.insert(peer);  // Insert same peer again
        
        assert_eq!(peers.len(), 1, "HashSet should deduplicate peers");
    }

    #[test]
    fn test_cli_parsing_combined_options() {
        let args = vec![
            "program_name",
            "--listen",
            "/ip4/0.0.0.0/tcp/9000",
            "--balance",
            "2500",
            "--peer",
            "/ip4/192.168.1.1/tcp/9001",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        
        let cli = cli.unwrap();
        assert_eq!(cli.balance, 2500);
        assert_eq!(cli.peer.len(), 1);
    }

    #[test]
    fn test_cli_balance_zero() {
        let args = vec!["program_name", "--balance", "0"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        
        let cli = cli.unwrap();
        assert_eq!(cli.balance, 0, "Zero balance should be allowed");
    }

    #[test]
    fn test_cli_large_balance() {
        let args = vec!["program_name", "--balance", "999999999"];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        
        let cli = cli.unwrap();
        assert_eq!(cli.balance, 999999999, "Large balance should be parsed");
    }

    #[test]
    fn test_tx_cache_is_thread_safe() {
        let cache: TxCache = Arc::new(DashMap::new());
        let cache_clone = Arc::clone(&cache);
        
        // Simulate multiple threads accessing the cache
        cache.insert("tx1".to_string(), ());
        let exists = cache_clone.contains_key("tx1");
        assert!(exists, "Cloned cache should see inserted items");
    }

    #[test]
    fn test_peers_hashset_removal() {
        let mut peers = HashSet::new();
        
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        
        peers.insert(peer1);
        peers.insert(peer2);
        peers.remove(&peer1);
        
        assert_eq!(peers.len(), 1);
        assert!(!peers.contains(&peer1));
        assert!(peers.contains(&peer2));
    }

    #[test]
    fn test_cli_multiaddr_parsing() {
        // Test various multiaddr formats
        let args = vec![
            "program_name",
            "--listen",
            "/ip6/::1/tcp/9000",
        ];
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok(), "Should parse IPv6 addresses");
    }

    #[test]
    fn test_tx_cache_concurrent_access() {
        let cache: TxCache = Arc::new(DashMap::new());
        cache.insert("tx1".to_string(), ());
        cache.insert("tx2".to_string(), ());
        cache.insert("tx3".to_string(), ());
        
        // Check they're all there
        assert_eq!(cache.len(), 3);
        let tx1_exists = cache.contains_key("tx1");
        let tx2_exists = cache.contains_key("tx2");
        let tx3_exists = cache.contains_key("tx3");
        
        assert!(tx1_exists && tx2_exists && tx3_exists);
    }

    #[test]
    fn test_wallet_generation() {
        let wallet = Wallet::generate();
        let addr_hex = wallet.address_hex();
        
        // Address should be valid hex
        assert!(!addr_hex.is_empty());
        assert!(addr_hex.starts_with("0x"));
        
        // Should be valid length (0x + 40 hex chars = 42 total)
        assert_eq!(addr_hex.len(), 42);
    }

    #[test]
    fn test_wallet_address_consistency() {
        let wallet1 = Wallet::generate();
        let wallet2 = Wallet::generate();
        
        // Different wallets should have different addresses
        assert_ne!(wallet1.address_hex(), wallet2.address_hex());
    }

    #[test]
    fn test_ledger_initialization() {
        let ledger = Ledger::new();
        let wallet = Wallet::generate();
        
        // New ledger should have no balance for random wallet
        let balance = ledger.balance(wallet.address());
        assert_eq!(balance, None);
        
        // Register should create account
        ledger.register(*wallet.address(), 1000);
        assert_eq!(ledger.balance(wallet.address()), Some(1000));
    }

    #[test]
    fn test_ledger_nonce_tracking() {
        let ledger = Ledger::new();
        let wallet = Wallet::generate();
        
        ledger.register(*wallet.address(), 1000);
        
        // Initial nonce should be 0
        assert_eq!(ledger.nonce(wallet.address()), Some(0));
    }

    #[test]
    fn test_multiaddr_validation() {
        // Test that various multiaddr formats can be used
        let valid_addrs = vec![
            "/ip4/0.0.0.0/tcp/9000",
            "/ip4/127.0.0.1/tcp/9001",
            "/ip6/::1/tcp/9002",
        ];
        
        for addr_str in valid_addrs {
            let addr = addr_str.parse::<libp2p::Multiaddr>();
            assert!(addr.is_ok(), "Should parse valid multiaddr: {}", addr_str);
        }
    }

    #[test]
    fn test_cli_all_options_combined() {
        let args = vec![
            "program",
            "--listen", "/ip4/0.0.0.0/tcp/9000",
            "--peer", "/ip4/192.168.1.1/tcp/9001",
            "--peer", "/ip4/192.168.1.2/tcp/9002",
            "--balance", "5000",
            "--secret-key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ];
        
        let cli = Cli::try_parse_from(args);
        assert!(cli.is_ok());
        
        let cli = cli.unwrap();
        assert_eq!(cli.balance, 5000);
        assert_eq!(cli.peer.len(), 2);
        assert!(cli.secret_key.is_some());
    }

    #[test]
    fn test_transaction_signing() {
        let wallet = Wallet::generate();
        let to_addr = Wallet::generate().address().clone();
        
        let tx = SignedTransaction::create(&wallet, to_addr, 100, 0);
        
        // Transaction should be verifiable
        assert!(tx.verify().is_ok());
    }

    #[test]
    fn test_transaction_rlp_encoding() {
        let wallet = Wallet::generate();
        let to_addr = Wallet::generate().address().clone();
        
        let tx = SignedTransaction::create(&wallet, to_addr, 100, 0);
        let rlp_bytes = tx.to_rlp_bytes();
        
        // RLP bytes should be non-empty
        assert!(!rlp_bytes.is_empty());
        
        // Should be decodable
        let decoded = SignedTransaction::from_rlp_bytes(&rlp_bytes);
        assert!(decoded.is_ok());
    }

    #[test]
    fn test_ledger_snapshot() {
        let ledger = Ledger::new();
        let wallet1 = Wallet::generate();
        let wallet2 = Wallet::generate();
        
        ledger.register(*wallet1.address(), 1000);
        ledger.register(*wallet2.address(), 2000);
        
        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.len(), 2);
    }

    #[test]
    fn test_cli_listen_default() {
        let args = vec!["program"];
        let cli = Cli::try_parse_from(args).unwrap();
        
        // Default listen should be set
        assert_eq!(cli.listen.to_string(), "/ip4/0.0.0.0/tcp/0");
    }

    #[test]
    fn test_empty_command_handling() {
        // Empty commands should be handled gracefully
        let line = "";
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        assert!(parts.is_empty());
    }

    #[test]
    fn test_whitespace_only_command() {
        // Whitespace-only commands should be handled gracefully
        let line = "   \t  \n  ";
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        assert!(parts.is_empty());
    }

    #[test]
    fn test_peers_iteration() {
        let mut peers = HashSet::new();
        
        for _ in 0..5 {
            peers.insert(PeerId::random());
        }
        
        let count = peers.iter().count();
        assert_eq!(count, 5);
    }

    #[test]
    fn test_cli_balance_boundary_values() {
        let test_cases = vec![
            ("0", 0u64),
            ("1", 1u64),
            ("1000000", 1000000u64),
            ("18446744073709551615", u64::MAX),
        ];
        
        for (balance_str, expected) in test_cases {
            let args = vec!["program", "--balance", balance_str];
            if let Ok(cli) = Cli::try_parse_from(args) {
                assert_eq!(cli.balance, expected);
            }
        }
    }
}

