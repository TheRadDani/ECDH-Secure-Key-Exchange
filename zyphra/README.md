# Zyphra

<p align="center">
  <img src="./images/zyphra_logo.svg" alt="Project Logo" style="width:40%;"/>
</p>



## Features

- **🔐 Ed25519 Signatures** – Cryptographically sign and verify transactions (RFC 8032)
- **📍 Address Derivation** – SHA-256 based 20-byte addresses (Ethereum-style)
- **⛓️ Double-Spend Prevention** – Nonce-based replay protection per account
- **🌐 P2P Networking** – Open internet communication via libp2p
- **🔍 Peer Discovery** – Kademlia DHT + mDNS (LAN fallback)
- **📢 Transaction Broadcast** – GossipSub pub/sub for all-peer propagation
- **💬 Direct Transfers** – Request-Response protocol for peer-to-peer confirmations
- **⚙️ Thread-Safe Ledger** – Lock-free DashMap + atomic transfers
- **🔗 RLP Encoding** – Ethereum-standard binary wire format

## Architecture

```
┌─────────────────────────────────────────┐
│         Transaction (RLP encoded)       │
│  [from, to, amount, nonce, timestamp,   │
│   pubkey, Ed25519_signature]            │
└─────────────────────────────────────────┘
                    ↓
        ┌───────────────────────────┐
        │    Wallet (local)         │
        │  - Ed25519 keypair        │
        │  - Address derivation     │
        │  - Sign transactions      │
        └───────────────────────────┘
                    ↓
        ┌───────────────────────────┐
        │    Ledger (local)         │
        │  - Balance tracking       │
        │  - Nonce ordering         │
        │  - Double-spend prevention│
        └───────────────────────────┘
                    ↓
        ┌───────────────────────────────────────┐
        │      P2P Network (libp2p)             │
        │  ┌──────────────────────────────────┐ │
        │  │ Kademlia DHT   - peer routing    │ │
        │  │ GossipSub      - tx broadcast    │ │
        │  │ Request-Response - direct xfers  │ │
        │  │ Identify       - capability info │ │
        │  │ mDNS           - LAN discovery   │ │
        │  └──────────────────────────────────┘ │
        │  Transport: TCP → Noise → Yamux       │
        └───────────────────────────────────────┘
```

## Prerequisites

- **Rust 1.70+** ([Install](https://rustup.rs/))
- **Tokio async runtime**
- **libp2p 0.54** with required features pre-configured

## Building

### Debug Build (faster compile, slower runtime)

```bash
cd kademlia-crypto-node
cargo build
```

### Release Build (optimized binary for production)

```bash
cargo build --release
```

The binary will be at `target/release/kademlia-crypto-node` (or `target/debug/kademlia-crypto-node` for debug).

## Running

### Single Node (Listener)

Start a node with 10,000 initial balance:

```bash
RUST_LOG=info cargo run -- --listen /ip4/0.0.0.0/tcp/9000 --balance 10000
```

Output:

```
╔══════════════════════════════════════════════════════════╗
║   Kademlia Crypto-Node — Production P2P Transfer Node   ║
╚══════════════════════════════════════════════════════════╝
Wallet address : 0xa105a6b88e2f02c313310a4a87ba162e6f62210f
Initial balance: 10000
Peer ID        : 12D3KooWDTL5biqavBCWpfPquVvCr1CU1Mrks7reuW7wwJrvshTK
Listening on /ip4/0.0.0.0/tcp/9000/p2p/12D3KooWDTL5biqavBCWpfPquVvCr1CU1Mrks7reuW7wwJrvshTK
```

### Multi-Node (Sender → Receiver)

**Terminal 1 – Receiver (listening on port 9000):**

```bash
RUST_LOG=info cargo run -- --listen /ip4/127.0.0.1/tcp/9000 --balance 5000
```

Note the receiver's peer ID (e.g., `12D3KooWDTL5biqavBCWpfPquVvCr1CU1Mrks7reuW7wwJrvshTK`) and address (e.g., `0xa105a6b88e2f02c313310a4a87ba162e6f62210f`).

**Terminal 2 – Sender (connects to receiver on port 9001):**

```bash
RUST_LOG=info cargo run -- \
  --listen /ip4/127.0.0.1/tcp/9001 \
  --peer /ip4/127.0.0.1/tcp/9000/p2p/12D3KooWDTL5biqavBCWpfPquVvCr1CU1Mrks7reuW7wwJrvshTK \
  --balance 8000
```

## Interactive Commands

Once a node is running, type commands at the prompt:

| Command                   | Description                        | Example                                               |
| ------------------------- | ---------------------------------- | ----------------------------------------------------- |
| `send <address> <amount>` | Transfer funds to recipient        | `send 0xa105a6b88e2f02c313310a4a87ba162e6f62210f 250` |
| `balance`                 | Show wallet balance & nonce        | `balance`                                             |
| `peers`                   | List all connected peers           | `peers`                                               |
| `info`                    | Show node info (PeerID, listeners) | `info`                                                |
| `ledger`                  | Dump all known accounts            | `ledger`                                              |
| `help`                    | Show command help                  | `help`                                                |

### Transfer Example

**Sender Terminal:**

```
> send 0xa105a6b88e2f02c313310a4a87ba162e6f62210f 250
✓ Sent 250 to 0xa105a6b88e... (tx: 0x1f5c...)
```

**Receiver Terminal:**

```
💰 Incoming transfer: 250 from 0xb8e2f02c...
   Tx: 0x1f5c...
```

## Logging

Control verbosity with `RUST_LOG`:

```bash
# Info level (default)
RUST_LOG=info cargo run -- --balance 1000

# Debug level (protocol details)
RUST_LOG=debug cargo run -- --balance 1000

# Trace level (everything)
RUST_LOG=trace cargo run -- --balance 1000

# Target-specific
RUST_LOG=kademlia_crypto_node=debug,libp2p=info cargo run -- --balance 1000
```

## Wallet Restore

To run a node with a previously-generated private key:

```bash
# Get secret key hex from somewhere (32 bytes)
RUST_LOG=info cargo run -- \
  --listen /ip4/0.0.0.0/tcp/9000 \
  --balance 5000 \
  --secret_key a1b2c3d4...e8f9
```

## Testing

Run all unit tests (18 total):

```bash
cargo test
```

Run tests with output:

```bash
cargo test -- --nocapture
```

Test a specific module:

```bash
cargo test --lib wallet
cargo test --lib ledger
cargo test --lib transaction
```

## Configuration

### Default Values

| Parameter   | Default              | Description                               |
| ----------- | -------------------- | ----------------------------------------- |
| `--listen`  | `/ip4/0.0.0.0/tcp/0` | Bind address and port (0 = any available) |
| `--balance` | 1,000                | Initial account balance (atomic units)    |
| `--peer`    | (empty)              | Bootstrap peer multiaddr (repeatable)     |

### Transport Stack

- **TCP** with `NODELAY` enabled (low-latency P2P)
- **Noise Protocol** (XX handshake, authenticated encryption, PFS)
- **Yamux** (stream multiplexing)
- **Connection timeout**: 20 seconds
- **Idle timeout**: 120 seconds

### Network Protocols

| Protocol             | Purpose                  | Config                                               |
| -------------------- | ------------------------ | ---------------------------------------------------- |
| **Kademlia**         | DHT + peer routing       | Query timeout 60s, record TTL 24h, provider TTL 12h  |
| **GossipSub**        | Transaction broadcast    | Heartbeat 1s, max msg size 64 KiB, strict validation |
| **Request-Response** | Direct transfer confirms | Request timeout 30s                                  |
| **Identify**         | Peer capabilities        | Push listen addr updates every 60s                   |
| **mDNS**             | LAN peer discovery       | Active on loopback + all interfaces                  |

## Performance Notes

- **Ledger**: Lock-free reads (DashMap) with RwLock only for transfers
- **GossipSub**: Message deduplication prevents replay
- **Transaction verification**: Ed25519 (constant-time), Keccak256 hashing
- **Release build optimizations**: LTO, 1 codegen unit, opt-level 3, binary stripped

## Security Considerations

### Implemented

✅ Ed25519 signatures (RFC 8032, side-channel hardened)  
✅ Nonce-based replay protection  
✅ Address-pubkey binding verification  
✅ Noise Protocol authenticated encryption + PFS  
✅ GossipSub message signature validation  
✅ No cryptographic material in logs

### Not Implemented (Future)

⚠️ At-rest encryption for private keys (use OS keyring)  
⚠️ Distributed consensus (current: local ledger per node)  
⚠️ Transaction fees  
⚠️ Merkle tree proofs for light clients

## Code Organization

```
src/
├── main.rs           - Entry point, CLI, event loop, command/event handlers
├── wallet.rs         - Ed25519 keypair, address derivation, signing
├── transaction.rs    - SignedTransaction, RLP encoding, verification
├── ledger.rs         - Balance tracking, double-spend prevention
└── network.rs        - libp2p behaviour (Kademlia, GossipSub, etc.)
```

## Example Workflows

### Scenario 1: Local LAN Transfer

Two nodes on same WiFi, auto-discover via mDNS:

**Node A:**

```bash
RUST_LOG=info cargo run -- --balance 1000
# Gets address: 0xabc123...
# Waits for peers
```

**Node B:**

```bash
RUST_LOG=info cargo run -- --balance 500
# mDNS auto-discovers Node A
# Type: send 0xabc123... 100
```

### Scenario 2: Internet Transfer with Bootstrap

Three nodes across regions:

**Bootstrap (public server):**

```bash
RUST_LOG=info cargo run -- --listen /ip4/your.public.ip/tcp/9000 --balance 0
# Advertise this address to other nodes
```

**Node A (homelab):**

```bash
RUST_LOG=info cargo run -- \
  --listen /ip4/0.0.0.0/tcp/9000 \
  --peer /ip4/your.public.ip/tcp/9000/p2p/BOOTSTRAP_PEER_ID \
  --balance 5000
```

**Node B (cloud):**

```bash
RUST_LOG=info cargo run -- \
  --listen /ip4/0.0.0.0/tcp/9000 \
  --peer /ip4/your.public.ip/tcp/9000/p2p/BOOTSTRAP_PEER_ID \
  --balance 5000
# Both nodes discover each other via DHT
```

## Troubleshooting

### Compilation Issues

**Problem:** `error[E0432]: unresolved import 'libp2p::...'`  
**Solution:** Ensure `Cargo.toml` includes all required libp2p features. Run `cargo update`.

**Problem:** `error: Unknown option '--secret_key'`  
**Solution:** You're using an older version. Run `cargo update`.

### Runtime Issues

**Problem:** `"No known peers"` warning at startup  
**Solution:** Normal for first node. Connect it with `--peer` flag or wait for mDNS discovery.

**Problem:** Node doesn't receive broadcast transactions  
**Solution:** Ensure nodes are connected (`info` → check connected peers). High firewall? Use `--peer` bootstrap.

**Problem:** "Transfer rejected by ledger"  
**Solution:** Check balance (`balance`) and nonce. Nonce must increment sequentially.

## Contributing

This is a reference implementation. Extend it with:

- Persistent storage (RocksDB)
- Transaction pool / mempool prioritization
- BFT consensus protocol
- Light client support
- State channels

## License

This project is provided as-is for educational and research purposes.

## References

- [libp2p Rust](https://github.com/libp2p/rust-libp2p)
- [Ed25519-Dalek](https://docs.rs/ed25519-dalek/)
- [RLP Encoding](https://github.com/paritytech/rlp)
- [Noise Protocol](https://noiseprotocol.org/)
- [Kademlia DHT](https://en.wikipedia.org/wiki/Kademlia)
