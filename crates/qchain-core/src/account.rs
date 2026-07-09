use borsh::{BorshDeserialize, BorshSerialize};
use qchain_crypto::{AlgorithmId, Pubkey, COMBO_HYBRID_ED25519_ML_DSA_65};
use serde::{Deserialize, Serialize};

/// Base unit of the native token. Ticker and name are placeholders
/// ("QCH") - not a branding decision, just needs a symbol to write code
/// against; trivial to rename project-wide later.
pub const UNITS_PER_QCH: u64 = 1_000_000_000;

/// Placeholder economic constants - explicit starting points, not modeled
/// figures. See `ARCHITECTURE.md` §5 ("Fuera de alcance en fase 1": real
/// economic calibration) and the `project-lessons-learned` skill.
pub const DUST_THRESHOLD_UNITS: u64 = 10_000;
pub const BASE_FEE_PER_BYTE_UNITS: u64 = 2;
pub const PRIORITY_FEE_MIN_UNITS: u64 = 0;

/// Account leaf, matching the state tree schema in `ARCHITECTURE.md` §3.
/// `storage_root` is deferred (see module docs in `qchain-storage`) -
/// contract storage is a flat byte blob in phase 1, not a nested Merkle
/// tree per account yet.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
    /// Which registered signing policy controls this account - see
    /// `qchain_crypto::registry` for the distinction between individual
    /// scheme ids and combo ids. Every phase-1 account is
    /// `COMBO_HYBRID_ED25519_ML_DSA_65`.
    pub algorithm_id: AlgorithmId,
    /// The program allowed to mutate this account's `data`. Plain wallets
    /// are owned by the System Program.
    pub owner: Pubkey,
    /// 0 for plain wallets; the WASM module hash for a contract account.
    pub code_hash: [u8; 32],
    pub data: Vec<u8>,
}

impl Account {
    pub fn new_wallet(owner: Pubkey) -> Self {
        Account {
            balance: 0,
            nonce: 0,
            algorithm_id: COMBO_HYBRID_ED25519_ML_DSA_65,
            owner,
            code_hash: [0u8; 32],
            data: Vec::new(),
        }
    }
}
