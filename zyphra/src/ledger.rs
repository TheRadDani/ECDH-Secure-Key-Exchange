//! Local ledger: balance tracking and double-spend prevention.
//!
//! Every node maintains an in-memory ledger that maps `AddressID → balance`.
//! The ledger enforces:
//! 1. **Sufficient funds** – a send is rejected if balance < amount.
//! 2. **Nonce ordering** – each address has a monotonically increasing nonce;
//!    replayed or out-of-order transactions are rejected.
//! 3. **Atomic updates** – credit/debit happen under a single write lock so
//!    the ledger is always consistent.
//!
//! This is a **local consensus** model: each node trusts its own view. A full
//! blockchain would add distributed consensus on top.

use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

use crate::wallet::ADDRESS_LEN;

/// Errors specific to ledger operations.
#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    #[error("Address not found: 0x{}", hex::encode(.0))]
    AddressNotFound([u8; ADDRESS_LEN]),

    #[error("Self-transfer is not allowed")]
    SelfTransfer,

    #[error("Zero-value transfer is not allowed")]
    ZeroValue,
}

/// Per-account state held in the ledger.
#[derive(Debug, Clone)]
pub struct AccountState {
    /// Current balance in atomic units.
    pub balance: u64,
    /// Next expected nonce (starts at 0, increments on each outgoing tx).
    pub nonce: u64,
}

impl AccountState {
    fn new(initial_balance: u64) -> Self {
        Self {
            balance: initial_balance,
            nonce: 0,
        }
    }
}

/// Thread-safe local ledger.
///
/// Uses `DashMap` (lock-free concurrent hashmap) for high-throughput
/// reads and `RwLock` only for the atomic debit+credit pair.
#[derive(Clone)]
pub struct Ledger {
    /// Map from 20-byte address → account state.
    accounts: Arc<DashMap<[u8; ADDRESS_LEN], AccountState>>,
    /// Write lock used to make debit+credit atomic.
    transfer_lock: Arc<RwLock<()>>,
}

impl Ledger {
    /// Create a new empty ledger.
    pub fn new() -> Self {
        Self {
            accounts: Arc::new(DashMap::new()),
            transfer_lock: Arc::new(RwLock::new(())),
        }
    }

    /// Register an account with an initial balance (e.g. faucet / genesis).
    ///
    /// If the account already exists this is a no-op and returns false.
    pub fn register(&self, address: [u8; ADDRESS_LEN], initial_balance: u64) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.accounts.entry(address) {
            Entry::Vacant(e) => {
                info!(
                    "Registered account 0x{} with balance {}",
                    hex::encode(address),
                    initial_balance
                );
                e.insert(AccountState::new(initial_balance));
                true
            }
            Entry::Occupied(_) => {
                debug!("Account 0x{} already registered", hex::encode(address));
                false
            }
        }
    }

    /// Get the current balance for an address.
    pub fn balance(&self, address: &[u8; ADDRESS_LEN]) -> Option<u64> {
        self.accounts.get(address).map(|a| a.balance)
    }

    /// Get the next expected nonce for an address.
    pub fn nonce(&self, address: &[u8; ADDRESS_LEN]) -> Option<u64> {
        self.accounts.get(address).map(|a| a.nonce)
    }

    /// Execute a transfer: debit `from`, credit `to`, bump nonce atomically.
    ///
    /// # Validation performed
    /// 1. Neither address is zero-length or equal (no self-transfers).
    /// 2. `amount > 0`.
    /// 3. Sender has sufficient balance.
    /// 4. `nonce` matches the sender's expected nonce (replay protection).
    ///
    /// # Errors
    /// Returns [`LedgerError`] on any validation failure.
    pub fn transfer(
        &self,
        from: &[u8; ADDRESS_LEN],
        to: &[u8; ADDRESS_LEN],
        amount: u64,
        nonce: u64,
    ) -> Result<(), LedgerError> {
        // ── Pre-checks (no lock needed) ────────────────────────────
        if from == to {
            return Err(LedgerError::SelfTransfer);
        }
        if amount == 0 {
            return Err(LedgerError::ZeroValue);
        }

        // ── Atomic transfer under write lock ───────────────────────
        let _guard = self.transfer_lock.write();

        // Validate sender
        let mut sender = self
            .accounts
            .get_mut(from)
            .ok_or(LedgerError::AddressNotFound(*from))?;

        if sender.nonce != nonce {
            return Err(LedgerError::InvalidNonce {
                expected: sender.nonce,
                got: nonce,
            });
        }
        if sender.balance < amount {
            return Err(LedgerError::InsufficientBalance {
                have: sender.balance,
                need: amount,
            });
        }

        // Debit sender
        sender.balance -= amount;
        sender.nonce += 1;
        drop(sender); // release DashMap ref before accessing `to`

        // Credit receiver (auto-create account if needed)
        self.accounts
            .entry(*to)
            .and_modify(|a| a.balance += amount)
            .or_insert_with(|| {
                info!(
                    "Auto-created account 0x{} via incoming transfer",
                    hex::encode(to)
                );
                AccountState {
                    balance: amount,
                    nonce: 0,
                }
            });

        debug!(
            "Transfer executed: 0x{} → 0x{} amount={}",
            hex::encode(from),
            hex::encode(to),
            amount
        );

        Ok(())
    }

    /// Credit an account directly (used for receiving confirmed transfers).
    ///
    /// Auto-registers the account if it doesn't exist.
    pub fn credit(&self, address: &[u8; ADDRESS_LEN], amount: u64) {
        self.accounts
            .entry(*address)
            .and_modify(|a| a.balance += amount)
            .or_insert_with(|| AccountState::new(amount));
    }

    /// Snapshot of all accounts (for debugging / status display).
    pub fn snapshot(&self) -> HashMap<String, AccountState> {
        self.accounts
            .iter()
            .map(|entry| {
                let addr = format!("0x{}", hex::encode(entry.key()));
                (addr, entry.value().clone())
            })
            .collect()
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

// ────────────────────────────────────────────────────────────────────
// Unit tests
// ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> [u8; ADDRESS_LEN] {
        let mut a = [0u8; ADDRESS_LEN];
        a[0] = b;
        a
    }

    #[test]
    fn register_and_balance() {
        let ledger = Ledger::new();
        ledger.register(addr(1), 1000);
        assert_eq!(ledger.balance(&addr(1)), Some(1000));
        assert_eq!(ledger.nonce(&addr(1)), Some(0));
    }

    #[test]
    fn basic_transfer() {
        let ledger = Ledger::new();
        ledger.register(addr(1), 1000);
        ledger.register(addr(2), 500);
        ledger.transfer(&addr(1), &addr(2), 300, 0).unwrap();
        assert_eq!(ledger.balance(&addr(1)), Some(700));
        assert_eq!(ledger.balance(&addr(2)), Some(800));
        assert_eq!(ledger.nonce(&addr(1)), Some(1));
    }

    #[test]
    fn insufficient_balance() {
        let ledger = Ledger::new();
        ledger.register(addr(1), 100);
        ledger.register(addr(2), 0);
        let err = ledger.transfer(&addr(1), &addr(2), 200, 0).unwrap_err();
        assert!(matches!(err, LedgerError::InsufficientBalance { .. }));
    }

    #[test]
    fn replay_attack_rejected() {
        let ledger = Ledger::new();
        ledger.register(addr(1), 1000);
        ledger.register(addr(2), 0);
        ledger.transfer(&addr(1), &addr(2), 100, 0).unwrap();
        // Replay same nonce → rejected
        let err = ledger.transfer(&addr(1), &addr(2), 100, 0).unwrap_err();
        assert!(matches!(err, LedgerError::InvalidNonce { .. }));
    }

    #[test]
    fn nonce_must_match() {
        let ledger = Ledger::new();
        ledger.register(addr(1), 1000);
        ledger.register(addr(2), 0);
        // Skip nonce 0, try nonce 1 → rejected
        let err = ledger.transfer(&addr(1), &addr(2), 100, 1).unwrap_err();
        assert!(matches!(err, LedgerError::InvalidNonce { .. }));
    }

    #[test]
    fn self_transfer_rejected() {
        let ledger = Ledger::new();
        ledger.register(addr(1), 1000);
        let err = ledger.transfer(&addr(1), &addr(1), 100, 0).unwrap_err();
        assert!(matches!(err, LedgerError::SelfTransfer));
    }

    #[test]
    fn zero_value_rejected() {
        let ledger = Ledger::new();
        ledger.register(addr(1), 1000);
        ledger.register(addr(2), 0);
        let err = ledger.transfer(&addr(1), &addr(2), 0, 0).unwrap_err();
        assert!(matches!(err, LedgerError::ZeroValue));
    }

    #[test]
    fn credit_auto_creates_account() {
        let ledger = Ledger::new();
        ledger.credit(&addr(9), 500);
        assert_eq!(ledger.balance(&addr(9)), Some(500));
    }
}
