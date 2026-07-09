use supersol_crypto::Pubkey;
use serde::{Deserialize, Serialize};

/// Smallest indivisible unit of SuperSol, named "photon" - analogous to
/// Solana's "lamport". 1 SSOL = 1_000_000_000 photon.
pub const UNITS_PER_SSOL: u64 = 1_000_000_000;

/// Flat fee charged per transaction, paid to the block leader that processed
/// it. Deliberately far below Solana's typical ~5000 lamport (0.000005 SOL)
/// fee per signature - about 10x lower here, which this MVP can afford
/// because a single-leader devnet has no fee market or congestion pricing
/// yet (see the roadmap for how fees evolve once multiple validators
/// compete for block space).
pub const BASE_FEE_UNITS: u64 = 500; // 0.0000005 SSOL per transaction

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Account {
    /// Balance in base units ("photon").
    pub balance: u64,
    /// The program allowed to mutate this account's `data`. Plain wallets are
    /// owned by the System Program.
    pub owner: Pubkey,
    pub data: Vec<u8>,
    pub executable: bool,
}

impl Account {
    pub fn new_wallet(owner: Pubkey) -> Self {
        Account {
            balance: 0,
            owner,
            data: Vec::new(),
            executable: false,
        }
    }
}
