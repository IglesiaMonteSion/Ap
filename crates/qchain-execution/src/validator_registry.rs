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

// ---- active-set selection + epochs (phase 3.2) ----
//
// The registry above is the full *directory* of everyone who has registered.
// The ACTIVE set - who actually participates in consensus - is a bounded,
// stake-ranked subset of it, re-selected once per epoch. This part is still
// inert: it's a pure, deterministic function over the registry plus the
// epoch math, tested in isolation. Phase 3.3 is what feeds the selected set
// into `qchain-consensus::ValidatorSet` and freezes it for the epoch's
// duration; nothing here reads or writes consensus state yet.

/// Rounds per epoch - the granularity at which the active validator set is
/// (re-)selected from the on-chain registry. Consensus membership is meant
/// to be frozen for the duration of an epoch (phase 3.3) so honest nodes
/// never disagree about who is in the set mid-epoch. Placeholder magnitude,
/// governance-tunable later: 1024 matches `DAG_RETENTION_ROUNDS` (see the
/// node's DAG-pruning notes), so an epoch is ~one retention window - long
/// enough that re-selection churn is rare, short enough that a newly
/// registered validator waits at most ~one epoch to be considered.
pub const EPOCH_ROUNDS: u64 = 1024;

/// Hard cap on how many validators are ACTIVE (participating in consensus)
/// at once, independent of how many have registered. The registry can hold
/// up to `MAX_REGISTERED_VALIDATORS`; only the top `MAX_ACTIVE_VALIDATORS`
/// by stake actually consense. Generous relative to this chain's 10-20
/// target while still bounding quorum-certificate size, which grows with the
/// active count (see the measured certificate-size scaling in the project
/// notes - the reason signature aggregation matters before growing much
/// past this range).
pub const MAX_ACTIVE_VALIDATORS: usize = 100;

/// Which epoch a given consensus round falls in.
pub fn epoch_of(round: u64) -> u64 {
    round / EPOCH_ROUNDS
}

/// Deterministically select the active validator set from the registry: the
/// top `max_active` by stake, keeping only entries that still meet
/// `MIN_VALIDATOR_STAKE`. **Determinism is a safety requirement, not a nicety**:
/// every honest node must select the byte-identical set from the identical
/// on-chain registry, or phase 3.3 (consensus reading this) would fork the
/// moment two nodes disagreed on membership. Ties in stake are broken by
/// validator address ascending (a total order over distinct addresses), so
/// the output is a pure function of the registry *contents* - independent of
/// registration order or the underlying `Vec`'s order. The min-stake filter
/// is a defensive re-check: every registered entry satisfied it at
/// registration, but `stake` is a snapshot, so re-applying it here keeps
/// selection correct even if a future increment lets a registered validator's
/// recorded stake drop.
pub fn select_active_set(registry: &ValidatorRegistryData, max_active: usize) -> Vec<RegisteredValidator> {
    let mut eligible: Vec<RegisteredValidator> = registry.validators.iter().filter(|v| v.stake >= MIN_VALIDATOR_STAKE).cloned().collect();
    // Highest stake first; ties broken by address ascending for a total,
    // node-independent order.
    eligible.sort_by(|a, b| b.stake.cmp(&a.stake).then_with(|| a.validator.cmp(&b.validator)));
    eligible.truncate(max_active);
    eligible
}

/// A snapshot of the active validator set chosen for a specific epoch - the
/// unit phase 3.3 will freeze and feed to consensus. Borsh-encoded so a
/// later increment can persist it on-chain (a per-epoch snapshot account)
/// without a format change here.
#[derive(Clone, Default, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct ActiveValidatorSet {
    pub epoch: u64,
    pub validators: Vec<RegisteredValidator>,
}

/// The active set for `epoch`, selected from the current registry contents.
/// Pure and deterministic (see `select_active_set`). The `epoch` argument is
/// carried through verbatim so a caller can label "who is active in epoch N"
/// without the selection itself depending on the epoch number - selection is
/// purely stake-ranked. (Epoch-dependent rotation beyond stake ranking, if
/// ever wanted, would layer on top of this.)
pub fn active_set_for_epoch(registry: &ValidatorRegistryData, epoch: u64, max_active: usize) -> ActiveValidatorSet {
    ActiveValidatorSet { epoch, validators: select_active_set(registry, max_active) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_crypto::KeyComponent;

    /// A registered entry with a given address byte and stake. The
    /// `pubkey_bundle` is a throwaway placeholder - selection only ranks by
    /// `stake`/`validator`, never touches the bundle.
    fn entry(addr_byte: u8, stake: u64) -> RegisteredValidator {
        RegisteredValidator {
            validator: Pubkey::new([addr_byte; 32]),
            pubkey_bundle: PublicKeyBundle { components: vec![KeyComponent { scheme: qchain_crypto::AlgorithmId(1), bytes: vec![addr_byte] }] },
            address: format!("10.0.0.{addr_byte}:9000"),
            stake,
        }
    }

    #[test]
    fn epoch_of_partitions_rounds_into_fixed_windows() {
        assert_eq!(epoch_of(0), 0);
        assert_eq!(epoch_of(EPOCH_ROUNDS - 1), 0);
        assert_eq!(epoch_of(EPOCH_ROUNDS), 1);
        assert_eq!(epoch_of(EPOCH_ROUNDS * 3 + 5), 3);
    }

    #[test]
    fn select_active_set_ranks_by_stake_descending() {
        let registry = ValidatorRegistryData { validators: vec![entry(1, MIN_VALIDATOR_STAKE), entry(2, MIN_VALIDATOR_STAKE * 5), entry(3, MIN_VALIDATOR_STAKE * 2)] };
        let active = select_active_set(&registry, 10);
        let stakes: Vec<u64> = active.iter().map(|v| v.stake).collect();
        assert_eq!(stakes, vec![MIN_VALIDATOR_STAKE * 5, MIN_VALIDATOR_STAKE * 2, MIN_VALIDATOR_STAKE]);
    }

    #[test]
    fn select_active_set_is_deterministic_regardless_of_input_order() {
        let a = entry(9, MIN_VALIDATOR_STAKE * 3);
        let b = entry(1, MIN_VALIDATOR_STAKE * 3); // same stake as a - tie
        let c = entry(5, MIN_VALIDATOR_STAKE * 7);
        let forward = select_active_set(&ValidatorRegistryData { validators: vec![a.clone(), b.clone(), c.clone()] }, 10);
        let reversed = select_active_set(&ValidatorRegistryData { validators: vec![c, b, a] }, 10);
        assert_eq!(forward, reversed, "selection must not depend on the Vec order");
        // Highest stake first, then the tie broken by address ascending
        // (byte 1 before byte 9).
        let order: Vec<u8> = forward.iter().map(|v| v.validator.to_bytes()[0]).collect();
        assert_eq!(order, vec![5, 1, 9]);
    }

    #[test]
    fn select_active_set_enforces_the_cap() {
        let registry = ValidatorRegistryData { validators: (1..=10).map(|i| entry(i, MIN_VALIDATOR_STAKE * i as u64)).collect() };
        let active = select_active_set(&registry, 3);
        assert_eq!(active.len(), 3, "only the top `max_active` are selected");
        // The three largest stakes (i = 10, 9, 8).
        let stakes: Vec<u64> = active.iter().map(|v| v.stake).collect();
        assert_eq!(stakes, vec![MIN_VALIDATOR_STAKE * 10, MIN_VALIDATOR_STAKE * 9, MIN_VALIDATOR_STAKE * 8]);
    }

    #[test]
    fn select_active_set_filters_below_minimum_stake() {
        // A registry that somehow contains a below-minimum entry (a future
        // increment could let recorded stake drop) must exclude it.
        let registry = ValidatorRegistryData { validators: vec![entry(1, MIN_VALIDATOR_STAKE), entry(2, MIN_VALIDATOR_STAKE - 1)] };
        let active = select_active_set(&registry, 10);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].validator, Pubkey::new([1u8; 32]));
    }

    #[test]
    fn active_set_for_epoch_carries_the_epoch_and_selects() {
        let registry = ValidatorRegistryData { validators: vec![entry(1, MIN_VALIDATOR_STAKE * 2), entry(2, MIN_VALIDATOR_STAKE)] };
        let set = active_set_for_epoch(&registry, 7, MAX_ACTIVE_VALIDATORS);
        assert_eq!(set.epoch, 7);
        assert_eq!(set.validators.len(), 2);
        assert_eq!(set.validators[0].stake, MIN_VALIDATOR_STAKE * 2);
    }

    #[test]
    fn active_validator_set_borsh_round_trips() {
        let set = active_set_for_epoch(&ValidatorRegistryData { validators: vec![entry(1, MIN_VALIDATOR_STAKE)] }, 3, MAX_ACTIVE_VALIDATORS);
        let bytes = borsh::to_vec(&set).unwrap();
        let back = ActiveValidatorSet::try_from_slice(&bytes).unwrap();
        assert_eq!(set, back);
    }
}
