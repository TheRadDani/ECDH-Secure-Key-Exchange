//! Cryptographic wallet: keypair management & address derivation.
//!
//! Each node owns exactly one [`Wallet`]. The wallet holds an Ed25519 signing
//! keypair and derives a globally-unique **AddressID** from the public key:
//!
//! ```text
//! AddressID = SHA-256(Ed25519_PublicKey)[0..20]   // 20-byte address
//! ```
//!
//! This mirrors Ethereum's approach (Keccak256 → last 20 bytes) but uses
//! SHA-256 for broader compatibility and NIST compliance.
//!
//! # Security Properties
//! - Private key **never** leaves the local process.
//! - AddressID is collision-resistant (birthday bound ≈ 2^80 for 20 bytes).
//! - Signatures are Ed25519 (RFC 8032), deterministic and side-channel hardened.

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;

/// Length of a derived address in bytes (20 bytes = 160 bits, Ethereum-style).
pub const ADDRESS_LEN: usize = 20;

/// A cryptographic wallet that owns an Ed25519 keypair and a derived address.
///
/// The private key is held in memory only; production deployments should
/// encrypt it at rest (e.g. via libsodium sealed boxes or OS keyring).
pub struct Wallet {
    /// Ed25519 signing key (contains both secret + public halves).
    signing_key: SigningKey,
    /// Pre-computed 20-byte address derived from the public key.
    address: [u8; ADDRESS_LEN],
}

impl Wallet {
    /// Create a brand-new wallet with a fresh Ed25519 keypair.
    ///
    /// Uses the OS CSPRNG (`OsRng`) – suitable for production use on all
    /// major platforms (calls `getrandom` / `CryptGenRandom` under the hood).
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let address = Self::derive_address(signing_key.verifying_key());
        Self {
            signing_key,
            address,
        }
    }

    /// Restore a wallet from a raw 32-byte secret key.
    ///
    /// # Errors
    /// Returns an error if `bytes` has wrong length.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() == SECRET_KEY_LENGTH,
            "Secret key must be exactly {} bytes, got {}",
            SECRET_KEY_LENGTH,
            bytes.len()
        );
        let mut buf = [0u8; SECRET_KEY_LENGTH];
        buf.copy_from_slice(bytes);
        let signing_key = SigningKey::from_bytes(&buf);
        let address = Self::derive_address(signing_key.verifying_key());
        Ok(Self {
            signing_key,
            address,
        })
    }

    // ── Accessors ───────────────────────────────────────────────────

    /// The 20-byte AddressID (hex representation uses `address_hex()`).
    #[inline]
    pub fn address(&self) -> &[u8; ADDRESS_LEN] {
        &self.address
    }

    /// Hex-encoded address with `0x` prefix.
    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }

    /// The Ed25519 public (verifying) key.
    #[inline]
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Raw 32-byte public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    // ── Signing ─────────────────────────────────────────────────────

    /// Sign an arbitrary message, returning a 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    // ── Static helpers ──────────────────────────────────────────────

    /// Derive a 20-byte address from an Ed25519 public key.
    ///
    /// ```text
    /// address = SHA-256(public_key_bytes)[12..32]
    /// ```
    ///
    /// We take the **last** 20 bytes (same convention as Ethereum) so
    /// the address space is uniformly distributed.
    pub fn derive_address(pubkey: VerifyingKey) -> [u8; ADDRESS_LEN] {
        let hash = Sha256::digest(pubkey.as_bytes());
        let mut addr = [0u8; ADDRESS_LEN];
        addr.copy_from_slice(&hash[12..32]);
        addr
    }

    /// Verify a signature against a public key and message.
    ///
    /// This is a static helper so any node can verify without owning
    /// the wallet (only needs the sender's public key).
    pub fn verify(pubkey: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<()> {
        pubkey
            .verify(message, signature)
            .context("Ed25519 signature verification failed")
    }

    /// Convert a hex address string (with or without `0x`) to bytes.
    pub fn address_from_hex(s: &str) -> Result<[u8; ADDRESS_LEN]> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).context("Invalid hex address")?;
        anyhow::ensure!(
            bytes.len() == ADDRESS_LEN,
            "Address must be {} bytes, got {}",
            ADDRESS_LEN,
            bytes.len()
        );
        let mut addr = [0u8; ADDRESS_LEN];
        addr.copy_from_slice(&bytes);
        Ok(addr)
    }
}

impl fmt::Display for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Wallet({})", self.address_hex())
    }
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the private key
        f.debug_struct("Wallet")
            .field("address", &self.address_hex())
            .finish()
    }
}

// ────────────────────────────────────────────────────────────────────
// Unit tests
// ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_derivation_is_deterministic() {
        let w = Wallet::generate();
        let addr2 = Wallet::derive_address(w.public_key());
        assert_eq!(w.address(), &addr2);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let w = Wallet::generate();
        let msg = b"transfer 100 to alice";
        let sig = w.sign(msg);
        assert!(Wallet::verify(&w.public_key(), msg, &sig).is_ok());
    }

    #[test]
    fn bad_signature_is_rejected() {
        let w = Wallet::generate();
        let msg = b"transfer 100 to alice";
        let sig = w.sign(msg);
        let other = Wallet::generate();
        assert!(Wallet::verify(&other.public_key(), msg, &sig).is_err());
    }

    #[test]
    fn address_hex_roundtrip() {
        let w = Wallet::generate();
        let hex_addr = w.address_hex();
        let parsed = Wallet::address_from_hex(&hex_addr).unwrap();
        assert_eq!(w.address(), &parsed);
    }

    #[test]
    fn restore_from_secret_bytes() {
        let w1 = Wallet::generate();
        let secret = w1.signing_key.to_bytes();
        let w2 = Wallet::from_secret_bytes(&secret).unwrap();
        assert_eq!(w1.address(), w2.address());
    }
}
