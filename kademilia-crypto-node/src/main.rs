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

fn main() {
    println!("Hello, world!");
}
