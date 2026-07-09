use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use supersol_crypto::Pubkey;

/// Id of the built-in Stake Program. Defined here (rather than in
/// `supersol-runtime`, where its instruction-handling logic lives) because
/// the ledger's epoch reward distribution needs to recognize stake accounts
/// directly - that's protocol-level bookkeeping across *all* accounts, not
/// something expressible through the per-instruction `ProgramProcessor`
/// trait, which only ever sees the handful of accounts one instruction
/// names.
pub const STAKE_PROGRAM_ID: Pubkey = Pubkey::new([3u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub enum StakeStatus {
    /// Earning rewards each epoch, delegated to `validator`.
    Active,
    /// No longer earning rewards; its balance may now be withdrawn.
    Deactivated,
}

/// Stored (borsh-encoded) in a stake account's `data`. The account's
/// `balance` field doubles as the staked amount - no separate ledger for it.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct StakeState {
    /// The wallet allowed to deactivate/withdraw this stake.
    pub authority: Pubkey,
    /// Which validator this stake backs. Only one validator exists in this
    /// MVP, but the field is here so multi-validator delegation (phase 2)
    /// doesn't require a data format migration.
    pub validator: Pubkey,
    pub status: StakeStatus,
}
