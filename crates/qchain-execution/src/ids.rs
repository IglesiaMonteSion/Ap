//! Well-known, unkeyed protocol program/account addresses - sentinel
//! pubkeys the same way `Pubkey::system_program_id()` ([0u8;32]) already
//! is. Nobody holds a private key for any of these; only the matching
//! native program is ever allowed to mutate the accounts it owns.

use qchain_crypto::Pubkey;

pub const STAKING_PROGRAM_ID: Pubkey = Pubkey::new([1u8; 32]);
/// Singleton account (owned by `STAKING_PROGRAM_ID`) whose `data` is a
/// borsh-encoded `u64` running total of currently-delegated stake -
/// updated on every `Delegate`/`Undelegate` so governance quorum checks
/// never need to scan every stake account in existence.
pub const STAKING_STATS_ID: Pubkey = Pubkey::new([2u8; 32]);

pub const GOVERNANCE_PROGRAM_ID: Pubkey = Pubkey::new([3u8; 32]);
/// Singleton account (owned by `GOVERNANCE_PROGRAM_ID`) whose `data` is a
/// borsh-encoded `Vec<qchain_crypto::RegistryEntry>` - the on-chain
/// algorithm registry a passed `Registry`-tier proposal mutates.
pub const REGISTRY_ACCOUNT_ID: Pubkey = Pubkey::new([4u8; 32]);
/// Singleton account (owned by `GOVERNANCE_PROGRAM_ID`) whose `data` is a
/// borsh-encoded `crate::params::EconomicParams` - the on-chain economic
/// parameters a passed `Low`-tier proposal mutates, and what `Ledger`
/// reads fee/dust/gas pricing from at execution time.
pub const PARAMS_ACCOUNT_ID: Pubkey = Pubkey::new([5u8; 32]);
/// Singleton account (owned by `STAKING_PROGRAM_ID`) whose `data` is a
/// borsh-encoded `crate::staking::RewardPoolData` and whose `balance` is
/// the real QCH held for delegators to claim - see `staking.rs`'s module
/// docs for the reward-per-share accrual mechanism this backs.
pub const STAKING_REWARDS_POOL_ID: Pubkey = Pubkey::new([6u8; 32]);

/// Owner of every account created by `SystemInstruction::DeployProgram`
/// (see `native.rs`) - a deployed contract's bytecode lives in that
/// account's `data` (borsh-encoded `native::WasmProgramData`), the same
/// way any other program-owned account works, so it persists through
/// `SledStore` like everything else instead of living only in the
/// in-memory `Ledger::programs` registry the three built-in native
/// programs use. `Ledger::apply_transaction`'s instruction dispatch falls
/// back to reading this owner + deserializing this data whenever
/// `ix.program_id` isn't one of the fixed native ids.
pub const LOADER_PROGRAM_ID: Pubkey = Pubkey::new([7u8; 32]);

/// Well-known singleton holding the dynamic-fee bookkeeping (`FeeState`: the
/// current fee epoch/round and the bytes committed in it so far). Kept in its
/// OWN account rather than folded into `EconomicParams` so existing persisted
/// `PARAMS` accounts (from a network deployed before dynamic fees) still
/// deserialize unchanged - this account is simply absent there and created,
/// deterministically, on the first transaction after the upgrade. The dynamic
/// `base_fee_per_byte` itself stays in `EconomicParams`; only the accumulator
/// lives here. See `Ledger::advance_dynamic_fee`.
pub const FEE_STATE_ACCOUNT_ID: Pubkey = Pubkey::new([8u8; 32]);
