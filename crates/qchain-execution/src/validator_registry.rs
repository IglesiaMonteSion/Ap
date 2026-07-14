//! On-chain validator registry (design: `ARCHITECTURE.md` §1/§6 - dynamic,
//! permissionless validator membership, phase 3). This is the foundation
//! that lets a newcomer become a validator by *staking and registering
//! on-chain* instead of a coordinator hand-editing a genesis file and every
//! operator re-deploying: the newcomer locks self-stake (the existing,
//! already-tested `StakeAccountData` where `owner == validator`) and
//! publishes, in `VALIDATOR_REGISTRY_ACCOUNT_ID`, the three things a peer
//! needs to actually consense with them: their consensus key bundle (to
//! verify their votes/certificates), their P2P network address (so other
//! nodes can dial them - real peer discovery), and the self-stake backing
//! them (Sybil resistance + slashable skin-in-the-game).
//!
//! **Inert on its own (this increment).** Nothing reads this registry for
//! consensus yet - `qchain-consensus::ValidatorSet` still loads its members
//! from the node's static config. This increment only builds and secures
//! the on-chain directory + the `RegisterValidator`/`UnregisterValidator`
//! instructions that populate it, plus the `GET /validator_registry`
//! query. The active-set-by-stake selection, epoch snapshotting, and the
//! wiring that makes `qchain-consensus` read its membership from here are
//! the following increments (see the phase-3 roadmap). Building it in this
//! order keeps each step live-verifiable: the registry can be populated and
//! inspected on a real testnet before anything depends on it for safety.
//!
//! Sybil resistance is the whole point of gating registration on real
//! self-stake: registering costs a genuine, bonded, slashable
//! `MIN_VALIDATOR_STAKE`, so spinning up a thousand fake validator
//! identities costs a thousand real stakes - the same economic barrier
//! every proof-of-stake chain relies on, reusing this project's existing
//! self-stake + equivocation-slashing machinery rather than inventing a new
//! one.

use crate::error::ExecError;
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_crypto::{Pubkey, PublicKeyBundle};

/// The minimum self-stake an identity must have bonded (in a
/// `StakeAccountData` where `owner == validator ==` the registrant) to
/// register as a validator. A real, slashable economic barrier to Sybil
/// identities - see module docs. Placeholder magnitude, tunable by
/// governance later (the same way `EconomicParams` fields are): 10,000,000
/// units matches the self-stake amounts this project's own live tests and
/// slashing scenarios already use for a validator's position.
pub const MIN_VALIDATOR_STAKE: u64 = 10_000_000;

/// Hard cap on how many validators the registry will hold, so a flood of
/// cheap registrations can't grow the on-chain account (and every node's
/// in-memory copy of it) without bound - the same kind of explicit bound
/// this project puts on every other unbounded-growth surface. Generous
/// relative to any realistic validator count for this chain's target
/// (10-20, per the closed deployment decisions), while still a real
/// ceiling.
pub const MAX_REGISTERED_VALIDATORS: usize = 1_000;

/// Hard cap on a registered P2P address string (`"ip:port"`), so a
/// registrant can't bloat the registry account with a megabyte "address."
/// Comfortably fits an IPv6 literal with a port and then some.
pub const MAX_VALIDATOR_ADDRESS_LEN: usize = 128;

/// One validator's entry in the on-chain registry: everything a peer needs
/// to consense with them. `stake` is a snapshot of the registrant's
/// self-stake at (re-)registration time - later increments that actually
/// select an active set by stake will define exactly how/when this is
/// refreshed; for this inert increment it is simply recorded.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct RegisteredValidator {
    /// The validator's address (== `pubkey_bundle.to_address()`, verified at
    /// registration). This is the identity that stakes, votes, and can be
    /// slashed.
    pub validator: Pubkey,
    /// The consensus key bundle other nodes verify this validator's
    /// votes/certificates against.
    pub pubkey_bundle: PublicKeyBundle,
    /// The P2P network address (`"ip:port"`) other nodes dial to reach this
    /// validator - real peer discovery, replacing the hand-edited peer list.
    pub address: String,
    /// Self-stake backing this validator at registration time (>=
    /// `MIN_VALIDATOR_STAKE`).
    pub stake: u64,
}

/// The registry account's (`VALIDATOR_REGISTRY_ACCOUNT_ID`) borsh-encoded
/// `data`: the full directory of registered validators.
#[derive(Clone, Default, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct ValidatorRegistryData {
    pub validators: Vec<RegisteredValidator>,
}

impl ValidatorRegistryData {
    pub fn try_read(data: &[u8]) -> Result<Self, ExecError> {
        Self::try_from_slice(data).map_err(|e| ExecError::ProgramError(format!("corrupt validator registry: {e}")))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ExecError> {
        borsh::to_vec(self).map_err(|e| ExecError::ProgramError(e.to_string()))
    }

    /// Index of the entry for `validator`, if present.
    pub fn position_of(&self, validator: &Pubkey) -> Option<usize> {
        self.validators.iter().position(|v| &v.validator == validator)
    }
}

/// The genesis `data` for the empty validator registry singleton - seeded
/// once by the node at startup (see `main.rs`), the same way the staking
/// stats, algorithm registry, and economic params singletons are. Starts
/// empty; validators register into it live.
pub fn genesis_validator_registry_account_data() -> Vec<u8> {
    borsh::to_vec(&ValidatorRegistryData::default()).expect("empty validator registry always serializes")
}
