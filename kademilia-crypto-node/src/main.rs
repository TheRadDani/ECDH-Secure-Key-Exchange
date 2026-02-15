use anyhow::{Context, Result};
use lilp2p::{
    core::upgrade,
    identity,
    kad::{self, store::MemoryStore, Behaviour as KademliaBehaviour, Config as KademliaConfig},
    noise,
    swarm::{NetworkBehavious, SwarmBuilder, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Transport,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::io::{self, BufRead};
use std::time::Duration;
use tokio::time::sleep;

/// Transaction structure mimicking real cryptocurrency transactions
///
/// In real crypto networks like Ethereum, transactions contain:
/// - Sender and recipient addresses (derived from public keys)
/// - Value being transferred
/// - Signature proving the sender authorized the transaction
/// - Nonce to prevent replay attacks (simplified here)

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Transaction {
    /// Sender's NodeID (in real crypto, this would be their address)
    from: String,

    /// Recipient's NodeID
    to: String,

    /// Amount being transferred
    amount: u64,

    /// Digital signature (placeholder - in production would use ECDSA)
    /// This proves the transaction was created by the owner of the 'from' address
    signature: Vec<u8>,

    /// Nounce to prevent replay attacks
    nonce: Vec<u8>,
}

impl Transaction {
    /// Serialize the transaction to bytes for hashing
    ///
    /// In real blockchains, this creates a canonical representation
    /// that can be hashed to create a unique transaction ID
    fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Seriealization should never fail")
    }

    /// Compute the transaction hash using Keccak256
    /// 
    /// This is exactly how Ethereum computes transaction hashes:
    /// TxHash = Keccak256(RLP(transaction_data))
    /// 
    /// The hash serves as:
    /// 1. A unique identifier for the transaction
    /// 2. The key for storing/retrieving from the DHT
    /// 3. A tamper-evident fingerprint
    fn hash(&self) -> String {
        let bytes = self.to_bytes();
        let hash = Keccak256::digest(&bytes);
        format!("0x{}", hex::encode(hash))
    }
}

fn main() {
    println!("Hello, world!");
}
