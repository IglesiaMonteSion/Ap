use supersol_crypto::Pubkey;
use serde::{Deserialize, Serialize};

/// Smallest indivisible unit of SuperSol, named "photon" - analogous to
/// Solana's "lamport". 1 SSOL = 1_000_000_000 photon.
pub const UNITS_PER_SSOL: u64 = 1_000_000_000;

/// Flat fee charged per transaction. Deliberately far below Solana's typical
/// ~5000 lamport (0.000005 SOL) fee per signature - about 10x lower here,
/// which this MVP can afford because a single-leader devnet has no fee
/// market or congestion pricing yet (see the roadmap for how fees evolve
/// once multiple validators compete for block space). The fee is burned
/// (destroyed, not paid to anyone) - see `Ledger::apply_transaction` and
/// `Ledger.total_burned`.
pub const BASE_FEE_UNITS: u64 = 500; // 0.0000005 SSOL per transaction

/// Total, permanently fixed supply: 700,000,000 SSOL, no more and no less.
/// The entire amount is minted exactly once, at genesis, split between the
/// treasury account (`Pubkey::treasury()`, disbursable via the devnet
/// faucet) and the staking rewards reserve (`Pubkey::staking_rewards_pool()`)
/// - see `Ledger::genesis_mint`. Nothing in the codebase can create new units
/// after that: `requestAirdrop` only *moves* units out of the treasury
/// (`Ledger::disburse_from_treasury`), and staking rewards only move units
/// out of the reserve (`Ledger::distribute_staking_rewards`) - neither ever
/// prints new ones. Burned fees permanently remove units from this total,
/// which is fine (and expected to be mildly deflationary over time): the cap
/// is a ceiling on what will ever exist, not a promise that the amount in
/// existence never shrinks.
pub const TOTAL_SUPPLY_SSOL: u64 = 700_000_000;
pub const TOTAL_SUPPLY_UNITS: u64 = TOTAL_SUPPLY_SSOL * UNITS_PER_SSOL;

/// 10% of the total supply, set aside at genesis to fund staking rewards
/// (see `Ledger::distribute_staking_rewards`) instead of paying them out of
/// thin-air inflation. This is a placeholder tokenomics parameter - real
/// emission-rate calibration (targeting some annualized staking yield) is a
/// deliberate governance decision to make before any production launch, not
/// something to trust a default for.
pub const STAKING_RESERVE_SSOL: u64 = 70_000_000;
pub const STAKING_RESERVE_UNITS: u64 = STAKING_RESERVE_SSOL * UNITS_PER_SSOL;

/// What's left for the faucet-disbursable treasury after carving out the
/// staking reserve. `TREASURY_ALLOCATION_UNITS + STAKING_RESERVE_UNITS ==
/// TOTAL_SUPPLY_UNITS`, always.
pub const TREASURY_ALLOCATION_UNITS: u64 = TOTAL_SUPPLY_UNITS - STAKING_RESERVE_UNITS;

/// Any wallet balance left over after a transaction that's above zero but
/// below this is swept away entirely and burned, rather than lingering
/// forever as an unspendable-in-practice residue. This is modeled on the
/// real annoyance of sending "everything" out of a Solana account and having
/// a few cents of un-sendable, rent-exempt-minimum dust stuck behind - here
/// that residue is simply destroyed instead of stranded, which is also
/// mildly deflationary (see `Ledger::apply_transaction`).
pub const DUST_THRESHOLD_UNITS: u64 = 10_000; // 0.00001 SSOL

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
