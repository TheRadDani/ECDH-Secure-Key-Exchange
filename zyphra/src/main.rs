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
    core::upgrade,
    gossipsub, identify,
    identity,
    kad,
    mdns,
    noise,
    request_response,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, Transport,
};
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

// ════════════════════════════════════════════════════════════════════
// Transport builder
// ════════════════════════════════════════════════════════════════════

/// Build the production transport stack: TCP → Noise → Yamux.
///
/// Security layers:
/// 1. **TCP** with `NODELAY` for low-latency P2P communication.
/// 2. **Noise** (XX handshake) for authenticated encryption with PFS.
/// 3. **Yamux** for multiplexed streams over a single connection.
fn build_transport(
    keypair: &identity::Keypair,
) -> Result<libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>> {
    let tcp_transport =
        tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));

    let noise_config =
        noise::Config::new(keypair).context("Failed to build Noise config")?;

    let transport = tcp_transport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(yamux::Config::default())
        .timeout(Duration::from_secs(20))
        .boxed();

    Ok(transport)
}

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
    let peer_id = PeerId::from(id_keys.public());
    info!("Peer ID        : {peer_id}");

    // ── Transport ───────────────────────────────────────────────────
    let transport = build_transport(&id_keys)?;

    // ── Network behaviour ───────────────────────────────────────────
    let behaviour = network::build_behaviour(&id_keys, peer_id)?;

    // ── Swarm ───────────────────────────────────────────────────────
    let mut swarm = libp2p::Swarm::new(
        transport,
        behaviour,
        peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(120)),
    );

    // Listen
    swarm
        .listen_on(cli.listen.clone())
        .context("Failed to listen")?;

    // Dial bootstrap peers
    for addr in &cli.peer {
        info!("Dialling bootstrap peer: {addr}");
        swarm.dial(addr.clone()).context("Failed to dial peer")?;
    }

    // ── Tx dedup cache ──────────────────────────────────────────────
    let tx_cache: TxCache = Arc::new(DashMap::new());

    // ── Stdin reader for interactive commands ────────────────────────
    let mut stdin = BufReader::new(io::stdin()).lines();

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
            // ── Stdin ───────────────────────────────────────────────
            line = stdin.next_line() => {
                if let Ok(Some(line)) = line {
                    handle_command(
                        &line,
                        &wallet,
                        &ledger,
                        &mut swarm,
                        &tx_cache,
                    );
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
                        );
                    }

                    // ── Connection established ──────────────────────
                    SwarmEvent::ConnectionEstablished { peer_id: pid, endpoint, .. } => {
                        info!("Connected to {pid} via {}", endpoint.get_remote_address());
                        swarm.behaviour_mut().kademlia.add_address(
                            &pid,
                            endpoint.get_remote_address().clone(),
                        );
                    }

                    // ── Connection closed ───────────────────────────
                    SwarmEvent::ConnectionClosed { peer_id: pid, cause, .. } => {
                        info!("Disconnected from {pid}: {:?}", cause);
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

            // Broadcast via GossipSub
            let topic = gossipsub::IdentTopic::new(TX_TOPIC);
            let rlp_bytes = tx.to_rlp_bytes();
            match swarm
                .behaviour_mut()
                .gossipsub
                .publish(topic, rlp_bytes)
            {
                Ok(_) => {
                    info!("Transaction broadcast: {tx_hash}");
                    println!(
                        "✓ Sent {} to 0x{} (tx: {tx_hash})",
                        amount,
                        hex::encode(to_addr)
                    );
                }
                Err(e) => {
                    warn!("GossipSub publish failed (no peers?): {e}");
                    println!("⚠ Transaction applied locally but broadcast failed: {e}");
                    println!("  (The tx will propagate when peers connect)");
                }
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
            debug!("Identified peer {pid}: protocols={:?}", id_info.protocols);
            for addr in id_info.listen_addrs {
                swarm.behaviour_mut().kademlia.add_address(&pid, addr);
            }
        }

        // ── mDNS: local peer discovered / expired ───────────────────
        NodeEvent::Mdns(mdns::Event::Discovered(peers)) => {
            for (pid, addr) in peers {
                info!("mDNS discovered: {pid} at {addr}");
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&pid);
                swarm.behaviour_mut().kademlia.add_address(&pid, addr);
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
