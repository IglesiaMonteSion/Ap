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
