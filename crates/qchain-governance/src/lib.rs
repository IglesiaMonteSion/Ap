//! On-chain governance: pure data types and tally logic (design:
//! `ARCHITECTURE.md` §6, `blockchain-security-audit` #7). Deliberately
//! dependency-free of any I/O, storage, or execution concerns - the same
//! "deterministic core, I/O pushed to the edges" split used by
//! `qchain-consensus` (see the `blockchain-core-rust` skill). The native
//! program that actually mutates on-chain accounts using these types lives
//! in `qchain-execution` (`governance.rs`); this crate only decides *what
//! a valid vote outcome is*, given numbers, not *how state gets read or
//! written*.
//!
//! Two risk tiers are implemented, per `ARCHITECTURE.md` §6: `Registry`
//! (algorithm activate/deprecate/retire - supermajority + mandatory
//! time-lock) and `Low` (economic parameters - base fee, dust threshold,
//! gas price - simple majority, no time-lock). The on-chain accounts a
//! `Low`-tier action actually mutates live in `qchain-execution`
//! (`EconomicParams`), not here - same "this crate only decides what a
//! valid vote outcome is" split as `Registry`-tier actions mutating the
//! algorithm registry.

use qchain_core::Round;
use qchain_crypto::{AlgorithmId, Pubkey, RegistryEntry};
use serde::{Deserialize, Serialize};

pub type ProposalId = u64;

#[derive(Clone, Copy, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Debug, PartialEq, Eq)]
pub enum RiskTier {
    /// Reserved for genuinely low-risk, non-monetary future parameters:
    /// simple majority, low participation floor, no time-lock. Nothing
    /// routes here today — every economic/monetary action was promoted to
    /// the `Economic` tier (governance-hardening task #213), which the
    /// audit requires to demand a supermajority + a real review time-lock
    /// rather than an instant simple-majority flip.
    Low,
    /// Monetary/economic parameters (base fee, dust threshold, gas price,
    /// staking commission, emission APR): **supermajority + a mandatory
    /// review time-lock** and a raised participation floor. Money supply and
    /// fee policy must never change instantly on a thin simple majority
    /// (task #213 — "los cambios de emisión, gas, fees, dust y comisiones no
    /// deberían ejecutarse inmediatamente con poca participación").
    Economic,
    /// Algorithm registry changes: supermajority + mandatory time-lock
    /// review window (`ARCHITECTURE.md` §6, `blockchain-security-audit`
    /// #7 - never instant activation or instant invalidation).
    Registry,
}

/// The rules a proposal of a given risk tier must satisfy to pass.
/// Constants below are explicit starting points, not modeled figures -
/// same pattern as the economic placeholders in `qchain_core::account`
/// (`DUST_THRESHOLD_UNITS` etc.) - adjustable by a future governance
/// action over governance's own parameters, not hand-picked as final.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuorumRule {
    /// Minimum fraction (basis points, 10_000 = 100%) of total staked
    /// supply that must have voted (yes+no+abstain) for the vote to be
    /// valid at all - a turnout floor, independent of the approval
    /// threshold below.
    pub min_participation_bps: u32,
    /// Minimum fraction of *decided* votes (yes / (yes+no), abstains
    /// excluded from the denominator) that must be `Yes` to pass.
    pub approval_threshold_bps: u32,
    /// How many DAG rounds a proposal stays open for voting after
    /// creation.
    pub voting_period_rounds: u64,
    /// Mandatory delay, in DAG rounds, between a proposal passing and it
    /// becoming executable - the "public review window" `ARCHITECTURE.md`
    /// §6 and `blockchain-security-audit` #7 require before a registry
    /// change takes effect.
    pub timelock_rounds: u64,
}

pub fn quorum_rule(tier: RiskTier) -> QuorumRule {
    match tier {
        // Reserved tier (nothing routes here today). Simple majority
        // (5_001, not 5_000 — a 50/50 tie must not pass), a low turnout
        // floor and no time-lock — the profile a genuinely low-risk,
        // non-monetary parameter would use. Kept for API/future stability.
        RiskTier::Low => QuorumRule { min_participation_bps: 1_000, approval_threshold_bps: 5_001, voting_period_rounds: 100, timelock_rounds: 0 },
        // Monetary/economic changes (task #213). A supermajority (2/3), a
        // raised 30% turnout floor, and a real post-passage review
        // time-lock (120 rounds) so a fee/gas/dust/commission/emission
        // change can never take effect instantly on thin participation —
        // there is always a review window during which the emergency
        // multisig can pause it (see `qchain-execution`'s EmergencyState).
        RiskTier::Economic => {
            QuorumRule { min_participation_bps: 3_000, approval_threshold_bps: 6_667, voting_period_rounds: 150, timelock_rounds: 120 }
        }
        // 2/3 supermajority per ARCHITECTURE.md §6 ("Cambios al registro
        // de algoritmos ... supermayoría (2/3) + ventana de revisión con
        // time-lock obligatorio"). Turnout floor raised to 25% (task #213).
        RiskTier::Registry => {
            QuorumRule { min_participation_bps: 2_500, approval_threshold_bps: 6_667, voting_period_rounds: 200, timelock_rounds: 100 }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Debug, PartialEq, Eq)]
pub enum ProposalAction {
    /// Adds a new entry to the algorithm registry, `Active` from
    /// execution. Fails at execution time if the id already exists.
    ActivateAlgorithm(RegistryEntry),
    /// Moves an existing `Active` entry to `Deprecated`, starting its
    /// migration grace period - never an instant cutoff.
    DeprecateAlgorithm { id: AlgorithmId, retirement_round: Round },
    /// Moves a `Deprecated` entry to `Retired`. Fails at execution time
    /// if `retirement_round` hasn't been reached yet.
    RetireAlgorithm { id: AlgorithmId },
    /// New value for the byte-scaled base fee (`ARCHITECTURE.md` §5).
    SetBaseFeePerByte(u64),
    /// New value for the dust-sweep threshold (`ARCHITECTURE.md` §5).
    SetDustThreshold(u64),
    /// New value for the WASM gas price (fuel-to-unit conversion).
    SetGasPricePerFuel(u64),
    /// New validator commission (basis points, out of 10,000) on the
    /// staking-reward share of `base_fee` (`ARCHITECTURE.md` §5's staking
    /// rewards paragraph).
    SetStakingCommissionBps(u16),
    /// New QCH emission rate (annual, basis points out of 10,000) minted into
    /// the staking reward pool per round (`ARCHITECTURE.md` §5's emission
    /// paragraph). Tunes the sustainable staking APR on top of fees.
    SetEmissionApr(u16),
}

impl ProposalAction {
    pub fn risk_tier(&self) -> RiskTier {
        match self {
            ProposalAction::ActivateAlgorithm(_) | ProposalAction::DeprecateAlgorithm { .. } | ProposalAction::RetireAlgorithm { .. } => {
                RiskTier::Registry
            }
            ProposalAction::SetBaseFeePerByte(_)
            | ProposalAction::SetDustThreshold(_)
            | ProposalAction::SetGasPricePerFuel(_)
            | ProposalAction::SetStakingCommissionBps(_)
            | ProposalAction::SetEmissionApr(_) => RiskTier::Economic,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Debug, PartialEq, Eq)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

#[derive(Clone, Copy, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Debug, PartialEq, Eq)]
pub enum ProposalStatus {
    Voting,
    Passed,
    Rejected,
    Executed,
}

#[derive(Clone, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize, Debug)]
pub struct Proposal {
    pub id: ProposalId,
    pub proposer: Pubkey,
    pub action: ProposalAction,
    pub created_round: Round,
    pub voting_ends_round: Round,
    /// The total bonded supply captured at proposal CREATION (task #213),
    /// read from the canonical staking-stats singleton by `CreateProposal`.
    /// This — not the live value at finalize time — is the quorum
    /// denominator, so a validator can't shrink `total_staked` after a
    /// proposal opens to lower the participation bar and pass a change with
    /// far less than real support ("tomar snapshot del poder de voto al
    /// crear la propuesta"). Standard snapshot-governance discipline
    /// (Compound/OZ Governor). Frozen for the whole life of the proposal.
    pub snapshot_total_staked: u64,
    pub yes_stake: u64,
    pub no_stake: u64,
    pub abstain_stake: u64,
    /// Stake accounts that have already voted on this proposal - checked
    /// on every `Vote` to prevent the same bonded position from being
    /// counted twice (a staker's *pubkey* isn't unique enough to key this
    /// on, since one staker can hold several stake accounts).
    pub voted_stake_accounts: Vec<Pubkey>,
    pub status: ProposalStatus,
    pub passed_round: Option<Round>,
}

impl Proposal {
    pub fn new(id: ProposalId, proposer: Pubkey, action: ProposalAction, created_round: Round, snapshot_total_staked: u64) -> Self {
        let rule = quorum_rule(action.risk_tier());
        Proposal {
            id,
            proposer,
            voting_ends_round: created_round + rule.voting_period_rounds,
            action,
            created_round,
            snapshot_total_staked,
            yes_stake: 0,
            no_stake: 0,
            abstain_stake: 0,
            voted_stake_accounts: Vec::new(),
            status: ProposalStatus::Voting,
            passed_round: None,
        }
    }

    /// Records one stake account's vote. Returns `false` (no-op) if that
    /// stake account already voted on this proposal. Per-voter ELIGIBILITY —
    /// that the position was bonded at or before `created_round` (the per-voter
    /// creation-time snapshot, roadmap #6) — is enforced by the execution-layer
    /// `Vote` handler (`qchain-execution::governance`) BEFORE it calls this,
    /// since only the ledger knows a position's creation round; this pure crate
    /// just tallies the `weight` it's handed.
    pub fn record_vote(&mut self, stake_account: Pubkey, choice: VoteChoice, weight: u64) -> bool {
        if self.voted_stake_accounts.contains(&stake_account) {
            return false;
        }
        // saturating_add for overflow-safety discipline (release runs with
        // overflow-checks=true, so a plain `+` that overflows panics
        // deterministically on every node = a network halt). Unreachable at
        // realistic supply (yes_stake <= total_staked << u64::MAX), but the
        // v4.0.0 emission model grows supply over time, so this no longer rests
        // on a static invariant. `Proposal::evaluate` already uses saturating/u128
        // math; this makes record_vote consistent. Byte-identical for all
        // reachable values.
        match choice {
            VoteChoice::Yes => self.yes_stake = self.yes_stake.saturating_add(weight),
            VoteChoice::No => self.no_stake = self.no_stake.saturating_add(weight),
            VoteChoice::Abstain => self.abstain_stake = self.abstain_stake.saturating_add(weight),
        }
        self.voted_stake_accounts.push(stake_account);
        true
    }

    /// Decides pass/fail against the CREATION-time `snapshot_total_staked`
    /// (task #213), per this proposal's risk tier's `QuorumRule`. Using the
    /// frozen snapshot as the denominator — rather than the live value at
    /// finalize — means post-creation manipulation of `total_staked` can't
    /// move the participation bar. Pure function of the proposal — no side
    /// effects; callers (the `qchain-execution` native program) apply the
    /// resulting status transition.
    pub fn evaluate(&self) -> ProposalStatus {
        let rule = quorum_rule(self.action.risk_tier());
        let total_staked = self.snapshot_total_staked;
        // Clamp participating to the frozen denominator so a voter who bonded
        // AFTER the snapshot (live vote weight can exceed the snapshot supply)
        // can never push participation past 100% — the frozen snapshot is the
        // authority for the turnout bar. The main gaming vector (shrinking the
        // denominator to pass on thin support) is closed by the snapshot; a
        // flash-staker still can't LOWER the bar, and their capital is locked
        // through the whole window by the vote-lock + min-bonding rules.
        let participating = self.yes_stake.saturating_add(self.no_stake).saturating_add(self.abstain_stake).min(total_staked);

        if total_staked == 0 {
            return ProposalStatus::Rejected;
        }
        let participation_bps = (participating as u128 * 10_000 / total_staked as u128) as u32;
        if participation_bps < rule.min_participation_bps {
            return ProposalStatus::Rejected;
        }

        let decided = self.yes_stake.saturating_add(self.no_stake);
        if decided == 0 {
            return ProposalStatus::Rejected;
        }
        let approval_bps = (self.yes_stake as u128 * 10_000 / decided as u128) as u32;
        if approval_bps >= rule.approval_threshold_bps {
            ProposalStatus::Passed
        } else {
            ProposalStatus::Rejected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_action() -> ProposalAction {
        ProposalAction::DeprecateAlgorithm { id: AlgorithmId(2), retirement_round: 1_000 }
    }

    fn economic_action() -> ProposalAction {
        ProposalAction::SetBaseFeePerByte(5)
    }

    #[test]
    fn below_participation_floor_is_rejected_even_with_unanimous_yes() {
        // snapshot_total_staked = 100_000; 100 yes = 0.1% turnout, far under
        // the Registry floor, even though every vote cast was Yes.
        let mut p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0, 100_000);
        p.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 100);
        assert_eq!(p.evaluate(), ProposalStatus::Rejected);
    }

    #[test]
    fn supermajority_threshold_is_enforced_not_simple_majority() {
        let mut p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0, 100);
        // 60% yes, 40% no, full participation - fails the 2/3 (66.67%)
        // supermajority bar for a Registry-tier proposal even though it
        // would pass a simple-majority rule.
        p.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 60);
        p.record_vote(Pubkey::new([2u8; 32]), VoteChoice::No, 40);
        assert_eq!(p.evaluate(), ProposalStatus::Rejected);
    }

    #[test]
    fn meeting_both_participation_and_supermajority_passes() {
        let mut p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0, 100);
        p.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 70);
        p.record_vote(Pubkey::new([2u8; 32]), VoteChoice::No, 30);
        assert_eq!(p.evaluate(), ProposalStatus::Passed);
    }

    #[test]
    fn abstain_votes_count_toward_participation_but_not_approval() {
        let mut p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0, 100);
        p.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 20);
        p.record_vote(Pubkey::new([2u8; 32]), VoteChoice::Abstain, 60);
        // Participation = 80/100 (way past the floor), but of *decided*
        // votes (yes+no = 20), 100% are Yes - still passes on approval,
        // proving abstains don't drag down the approval ratio.
        assert_eq!(p.evaluate(), ProposalStatus::Passed);
    }

    #[test]
    fn the_same_stake_account_cannot_vote_twice() {
        let mut p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0, 100);
        let stake_account = Pubkey::new([1u8; 32]);
        assert!(p.record_vote(stake_account, VoteChoice::Yes, 50));
        assert!(!p.record_vote(stake_account, VoteChoice::No, 50), "a second vote from the same stake account must be rejected");
        assert_eq!(p.yes_stake, 50);
        assert_eq!(p.no_stake, 0);
    }

    #[test]
    fn zero_total_staked_never_passes() {
        let p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0, 0);
        assert_eq!(p.evaluate(), ProposalStatus::Rejected, "an empty staking pool (snapshot 0) must never be able to pass a proposal");
    }

    #[test]
    fn a_snapshot_denominator_cannot_be_shrunk_after_creation_to_lower_the_bar() {
        // The proposal snapshots a large bonded supply at creation. Even if
        // total_staked later collapses, the frozen snapshot is the quorum
        // denominator, so 100 yes out of a 100_000 snapshot stays below the
        // floor — a shrink-the-denominator attack can't pass it (task #213).
        let mut p = Proposal::new(1, Pubkey::system_program_id(), economic_action(), 0, 100_000);
        p.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 100);
        assert_eq!(p.evaluate(), ProposalStatus::Rejected);
    }

    #[test]
    fn participation_is_clamped_to_the_snapshot_denominator() {
        // A voter who bonded after the snapshot votes with live weight far
        // exceeding the snapshot supply; participation clamps to 100%, it
        // never overflows the ratio.
        let mut p = Proposal::new(1, Pubkey::system_program_id(), economic_action(), 0, 100);
        p.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 10_000);
        assert_eq!(p.evaluate(), ProposalStatus::Passed, "clamped to the snapshot, a lone huge Yes is 100% participation and 100% approval");
    }

    #[test]
    fn voting_period_and_timelock_are_derived_from_risk_tier() {
        let p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 500, 0);
        let rule = quorum_rule(RiskTier::Registry);
        assert_eq!(p.voting_ends_round, 500 + rule.voting_period_rounds);
    }

    #[test]
    fn economic_tier_requires_a_supermajority_and_a_real_timelock() {
        // 51/49 (a bare simple majority) must NOT pass an economic change —
        // monetary policy now demands a 2/3 supermajority (task #213).
        let mut simple = Proposal::new(1, Pubkey::system_program_id(), economic_action(), 0, 100);
        simple.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 51);
        simple.record_vote(Pubkey::new([2u8; 32]), VoteChoice::No, 49);
        assert_eq!(simple.evaluate(), ProposalStatus::Rejected, "a bare simple majority must not pass a monetary change");

        // 70/30 clears the 2/3 bar.
        let mut super_maj = Proposal::new(2, Pubkey::system_program_id(), economic_action(), 0, 100);
        super_maj.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 70);
        super_maj.record_vote(Pubkey::new([2u8; 32]), VoteChoice::No, 30);
        assert_eq!(super_maj.evaluate(), ProposalStatus::Passed);

        // And an economic change now carries a real, mandatory review window.
        assert!(quorum_rule(RiskTier::Economic).timelock_rounds > 0, "monetary changes must have a real review time-lock");
    }

    #[test]
    fn economic_and_registry_tiers_have_raised_floors_over_the_reserved_low_tier() {
        let low = quorum_rule(RiskTier::Low);
        let economic = quorum_rule(RiskTier::Economic);
        let registry = quorum_rule(RiskTier::Registry);
        assert!(economic.min_participation_bps > low.min_participation_bps, "economic floor raised");
        assert!(registry.min_participation_bps > low.min_participation_bps, "registry floor raised");
        assert_eq!(economic.approval_threshold_bps, 6_667, "economic needs a 2/3 supermajority");
        assert!(economic.timelock_rounds > 0 && registry.timelock_rounds > 0);
    }

    #[test]
    fn set_base_fee_action_is_economic_tier() {
        assert_eq!(economic_action().risk_tier(), RiskTier::Economic);
        assert_eq!(ProposalAction::SetEmissionApr(1).risk_tier(), RiskTier::Economic);
        assert_eq!(sample_action().risk_tier(), RiskTier::Registry);
    }
}

#[cfg(test)]
mod fuzz_proptests {
    //! Property tests del borde de decodificación de gobernanza (roadmap #14,
    //! superficie "gobernanza"). Una `Proposal` y su `ProposalAction` se decodifican
    //! de la `data` de una cuenta on-chain (Borsh) — bytes que en última instancia
    //! provienen de una tx de un usuario. Deserializar bytes ARBITRARIOS nunca debe
    //! panicar/colgar ni al re-serializar.
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic_governance(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            if let Ok(p) = borsh::from_slice::<Proposal>(&bytes) { let _ = borsh::to_vec(&p); }
            let _ = borsh::from_slice::<ProposalAction>(&bytes);
            let _ = borsh::from_slice::<VoteChoice>(&bytes);
            let _ = borsh::from_slice::<RiskTier>(&bytes);
        }
    }
}
