//! Signed transaction: construction, signing, verification, and RLP encoding.
//!
//! A [`SignedTransaction`] wraps the unsigned payload with an Ed25519 signature
//! and the sender's public key. Any node can verify authenticity without
//! contacting the sender.
//!
//! ## Wire format (RLP)
//!
//! ```text
//! RLP([from_addr, to_addr, amount, nonce, timestamp, pubkey, signature])
//! ```
//!
//! The hash is computed over the *unsigned* portion only (fields 0..5),
//! matching Ethereum's approach where the signature is not part of the
//! signed digest.

use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use rlp::{Decodable, Encodable, Rlp, RlpStream};
use sha3::{Digest, Keccak256};
use tracing::debug;

use crate::wallet::{Wallet, ADDRESS_LEN};

/// A fully signed cryptocurrency transfer transaction.
///
/// This is the primary data structure exchanged between peers.
/// It is self-contained: any node can verify it with zero extra state.
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    // ── Unsigned payload ────────────────────────────────────────────
    /// Sender address (20 bytes, hex-encoded with 0x prefix in display).
    pub from: [u8; ADDRESS_LEN],
    /// Recipient address.
    pub to: [u8; ADDRESS_LEN],
    /// Amount in atomic units.
    pub amount: u64,
    /// Monotonic nonce (per-sender, starts at 0).
    pub nonce: u64,
    /// UTC timestamp (milliseconds since epoch) – used for ordering / TTL.
    pub timestamp: u64,

    // ── Signature envelope ──────────────────────────────────────────
    /// Ed25519 public key of the sender (32 bytes).
    pub pubkey: [u8; 32],
    /// Ed25519 signature over the unsigned digest (64 bytes).
    pub signature: [u8; 64],
}

impl SignedTransaction {
    /// Build and sign a new transaction.
    ///
    /// The wallet's private key signs `Keccak256(RLP(from, to, amount, nonce, ts))`.
    pub fn create(wallet: &Wallet, to: [u8; ADDRESS_LEN], amount: u64, nonce: u64) -> Self {
        let from = *wallet.address();
        let timestamp = Utc::now().timestamp_millis() as u64;
        let pubkey = wallet.public_key_bytes();

        // Build the unsigned digest
        let digest = Self::compute_unsigned_digest(&from, &to, amount, nonce, timestamp);

        // Sign the digest
        let sig = wallet.sign(&digest);

        Self {
            from,
            to,
            amount,
            nonce,
            timestamp,
            pubkey,
            signature: sig.to_bytes(),
        }
    }

    // ── Verification ────────────────────────────────────────────────

    /// Verify the transaction's cryptographic integrity.
    ///
    /// Checks:
    /// 1. The public key derives to the claimed `from` address.
    /// 2. The Ed25519 signature is valid over the unsigned digest.
    ///
    /// Does **not** check balance or nonce ordering (that's the ledger's job).
    pub fn verify(&self) -> Result<()> {
        // 1. Reconstruct VerifyingKey
        let vk = VerifyingKey::from_bytes(&self.pubkey)
            .context("Invalid Ed25519 public key in transaction")?;

        // 2. Check pubkey → address binding
        let derived = Wallet::derive_address(vk);
        anyhow::ensure!(
            derived == self.from,
            "Address mismatch: pubkey derives to 0x{}, but tx.from is 0x{}",
            hex::encode(derived),
            hex::encode(self.from),
        );

        // 3. Verify signature over unsigned digest
        let digest = Self::compute_unsigned_digest(
            &self.from,
            &self.to,
            self.amount,
            self.nonce,
            self.timestamp,
        );
        let sig = Signature::from_bytes(&self.signature);
        Wallet::verify(&vk, &digest, &sig)?;

        debug!("Transaction verified: hash={}", self.hash());
        Ok(())
    }

    // ── Hashing ─────────────────────────────────────────────────────

    /// Compute the unsigned digest that is signed / verified.
    ///
    /// `digest = Keccak256(RLP(from, to, amount, nonce, timestamp))`
    fn compute_unsigned_digest(
        from: &[u8; ADDRESS_LEN],
        to: &[u8; ADDRESS_LEN],
        amount: u64,
        nonce: u64,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut s = RlpStream::new_list(5);
        s.append(&from.as_slice());
        s.append(&to.as_slice());
        s.append(&amount);
        s.append(&nonce);
        s.append(&timestamp);
        Keccak256::digest(s.out().as_ref()).to_vec()
    }

    /// Full transaction hash (includes signature) – used as a global tx ID.
    pub fn hash(&self) -> String {
        let bytes = self.to_rlp_bytes();
        format!("0x{}", hex::encode(Keccak256::digest(&bytes)))
    }

    // ── RLP serialization ───────────────────────────────────────────

    /// Encode the full signed transaction to RLP bytes.
    pub fn to_rlp_bytes(&self) -> Vec<u8> {
        rlp::encode(self).to_vec()
    }

    /// Decode a signed transaction from RLP bytes.
    pub fn from_rlp_bytes(data: &[u8]) -> Result<Self> {
        let rlp = Rlp::new(data);
        Self::decode(&rlp).context("Failed to RLP-decode SignedTransaction")
    }
}

// ── RLP trait impls ─────────────────────────────────────────────────

impl Encodable for SignedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(7);
        s.append(&self.from.as_slice());
        s.append(&self.to.as_slice());
        s.append(&self.amount);
        s.append(&self.nonce);
        s.append(&self.timestamp);
        s.append(&self.pubkey.as_slice());
        s.append(&self.signature.as_slice());
    }
}

impl Decodable for SignedTransaction {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, rlp::DecoderError> {
        let from_bytes: Vec<u8> = rlp.val_at(0)?;
        let to_bytes: Vec<u8> = rlp.val_at(1)?;
        let amount: u64 = rlp.val_at(2)?;
        let nonce: u64 = rlp.val_at(3)?;
        let timestamp: u64 = rlp.val_at(4)?;
        let pubkey_bytes: Vec<u8> = rlp.val_at(5)?;
        let sig_bytes: Vec<u8> = rlp.val_at(6)?;

        // Convert Vec<u8> → fixed arrays with length checks
        let from = vec_to_array::<ADDRESS_LEN>(&from_bytes)?;
        let to = vec_to_array::<ADDRESS_LEN>(&to_bytes)?;
        let pubkey = vec_to_array::<32>(&pubkey_bytes)?;
        let signature = vec_to_array::<64>(&sig_bytes)?;

        Ok(Self {
            from,
            to,
            amount,
            nonce,
            timestamp,
            pubkey,
            signature,
        })
    }
}

/// Helper: convert `Vec<u8>` to `[u8; N]` with a proper RLP error.
fn vec_to_array<const N: usize>(v: &[u8]) -> std::result::Result<[u8; N], rlp::DecoderError> {
    v.try_into()
        .map_err(|_| rlp::DecoderError::Custom("wrong byte length"))
}

// ── Display ─────────────────────────────────────────────────────────

impl std::fmt::Display for SignedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Tx {{ 0x{}→0x{} amt={} nonce={} hash={} }}",
            hex::encode(self.from),
            hex::encode(self.to),
            self.amount,
            self.nonce,
            self.hash(),
        )
    }
}

// ────────────────────────────────────────────────────────────────────
// Unit tests
// ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;

    #[test]
    fn create_sign_verify() {
        let sender = Wallet::generate();
        let receiver = Wallet::generate();

        let tx = SignedTransaction::create(&sender, *receiver.address(), 500, 0);
        assert!(tx.verify().is_ok(), "Valid transaction must verify");
    }

    #[test]
    fn tampered_amount_fails_verify() {
        let sender = Wallet::generate();
        let receiver = Wallet::generate();

        let mut tx = SignedTransaction::create(&sender, *receiver.address(), 500, 0);
        tx.amount = 9999; // tamper
        assert!(tx.verify().is_err(), "Tampered tx must fail verification");
    }

    #[test]
    fn wrong_pubkey_fails_verify() {
        let sender = Wallet::generate();
        let receiver = Wallet::generate();
        let imposter = Wallet::generate();

        let mut tx = SignedTransaction::create(&sender, *receiver.address(), 500, 0);
        tx.pubkey = imposter.public_key_bytes(); // swap pubkey
        assert!(tx.verify().is_err(), "Wrong pubkey must fail");
    }

    #[test]
    fn rlp_roundtrip() {
        let sender = Wallet::generate();
        let receiver = Wallet::generate();

        let tx = SignedTransaction::create(&sender, *receiver.address(), 42, 7);
        let encoded = tx.to_rlp_bytes();
        let decoded = SignedTransaction::from_rlp_bytes(&encoded).unwrap();

        assert_eq!(tx.from, decoded.from);
        assert_eq!(tx.to, decoded.to);
        assert_eq!(tx.amount, decoded.amount);
        assert_eq!(tx.nonce, decoded.nonce);
        assert_eq!(tx.signature, decoded.signature);
        assert_eq!(tx.hash(), decoded.hash());
    }

    #[test]
    fn decoded_tx_still_verifies() {
        let sender = Wallet::generate();
        let receiver = Wallet::generate();

        let tx = SignedTransaction::create(&sender, *receiver.address(), 100, 0);
        let bytes = tx.to_rlp_bytes();
        let decoded = SignedTransaction::from_rlp_bytes(&bytes).unwrap();
        assert!(decoded.verify().is_ok());
    }
}
