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
    /// Economic parameters (fee curve constants, gas pricing table):
    /// simple majority of participating stake, no mandatory time-lock -
    /// `ARCHITECTURE.md` §6 doesn't require one for this tier, unlike
    /// `Registry`.
    Low,
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
        // Strict simple majority (5_001, not 5_000 - a 50/50 tie must not
        // pass) of participating stake, per ARCHITECTURE.md §6 ("bajo
        // riesgo ... mayoría simple del stake participante"). Lower
        // participation floor and no time-lock, reflecting that this
        // tier is deliberately meant to be easier to move than a
        // registry change. All values are placeholders pending real
        // testnet operating data, same as the Registry tier below.
        RiskTier::Low => QuorumRule { min_participation_bps: 1_000, approval_threshold_bps: 5_001, voting_period_rounds: 100, timelock_rounds: 0 },
        // 2/3 supermajority per ARCHITECTURE.md §6 ("Cambios al registro
        // de algoritmos ... supermayoría (2/3) + ventana de revisión con
        // time-lock obligatorio"). Participation floor and round counts
        // are placeholders pending real testnet operating data.
        RiskTier::Registry => {
            QuorumRule { min_participation_bps: 2_000, approval_threshold_bps: 6_667, voting_period_rounds: 200, timelock_rounds: 100 }
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
}

impl ProposalAction {
    pub fn risk_tier(&self) -> RiskTier {
        match self {
            ProposalAction::ActivateAlgorithm(_) | ProposalAction::DeprecateAlgorithm { .. } | ProposalAction::RetireAlgorithm { .. } => {
                RiskTier::Registry
            }
            ProposalAction::SetBaseFeePerByte(_) | ProposalAction::SetDustThreshold(_) | ProposalAction::SetGasPricePerFuel(_) => RiskTier::Low,
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
    pub fn new(id: ProposalId, proposer: Pubkey, action: ProposalAction, created_round: Round) -> Self {
        let rule = quorum_rule(action.risk_tier());
        Proposal {
            id,
            proposer,
            voting_ends_round: created_round + rule.voting_period_rounds,
            action,
            created_round,
            yes_stake: 0,
            no_stake: 0,
            abstain_stake: 0,
            voted_stake_accounts: Vec::new(),
            status: ProposalStatus::Voting,
            passed_round: None,
        }
    }

    /// Records one stake account's vote. Returns `false` (no-op) if that
    /// stake account already voted on this proposal.
    pub fn record_vote(&mut self, stake_account: Pubkey, choice: VoteChoice, weight: u64) -> bool {
        if self.voted_stake_accounts.contains(&stake_account) {
            return false;
        }
        match choice {
            VoteChoice::Yes => self.yes_stake += weight,
            VoteChoice::No => self.no_stake += weight,
            VoteChoice::Abstain => self.abstain_stake += weight,
        }
        self.voted_stake_accounts.push(stake_account);
        true
    }

    /// Decides pass/fail against `total_staked` (the bonded supply at
    /// finalization time), per this proposal's risk tier's `QuorumRule`.
    /// Pure function of the vote tallies - no side effects, callers
    /// (the `qchain-execution` native program) apply the resulting
    /// status transition.
    pub fn evaluate(&self, total_staked: u64) -> ProposalStatus {
        let rule = quorum_rule(self.action.risk_tier());
        let participating = self.yes_stake.saturating_add(self.no_stake).saturating_add(self.abstain_stake);

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

    fn low_risk_action() -> ProposalAction {
        ProposalAction::SetBaseFeePerByte(5)
    }

    #[test]
    fn below_participation_floor_is_rejected_even_with_unanimous_yes() {
        let mut p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0);
        p.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 100);
        // 100 out of a 100_000 total supply is 0.1% - far under the 20%
        // participation floor for the Registry tier, even though every
        // vote cast was Yes.
        assert_eq!(p.evaluate(100_000), ProposalStatus::Rejected);
    }

    #[test]
    fn supermajority_threshold_is_enforced_not_simple_majority() {
        let mut p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0);
        // 60% yes, 40% no, full participation - fails the 2/3 (66.67%)
        // supermajority bar for a Registry-tier proposal even though it
        // would pass a simple-majority rule.
        p.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 60);
        p.record_vote(Pubkey::new([2u8; 32]), VoteChoice::No, 40);
        assert_eq!(p.evaluate(100), ProposalStatus::Rejected);
    }

    #[test]
    fn meeting_both_participation_and_supermajority_passes() {
        let mut p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0);
        p.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 70);
        p.record_vote(Pubkey::new([2u8; 32]), VoteChoice::No, 30);
        assert_eq!(p.evaluate(100), ProposalStatus::Passed);
    }

    #[test]
    fn abstain_votes_count_toward_participation_but_not_approval() {
        let mut p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0);
        p.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 20);
        p.record_vote(Pubkey::new([2u8; 32]), VoteChoice::Abstain, 60);
        // Participation = 80/100 (way past the floor), but of *decided*
        // votes (yes+no = 20), 100% are Yes - still passes on approval,
        // proving abstains don't drag down the approval ratio.
        assert_eq!(p.evaluate(100), ProposalStatus::Passed);
    }

    #[test]
    fn the_same_stake_account_cannot_vote_twice() {
        let mut p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0);
        let stake_account = Pubkey::new([1u8; 32]);
        assert!(p.record_vote(stake_account, VoteChoice::Yes, 50));
        assert!(!p.record_vote(stake_account, VoteChoice::No, 50), "a second vote from the same stake account must be rejected");
        assert_eq!(p.yes_stake, 50);
        assert_eq!(p.no_stake, 0);
    }

    #[test]
    fn zero_total_staked_never_passes() {
        let p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 0);
        assert_eq!(p.evaluate(0), ProposalStatus::Rejected, "an empty staking pool must never be able to pass a proposal");
    }

    #[test]
    fn voting_period_and_timelock_are_derived_from_risk_tier() {
        let p = Proposal::new(1, Pubkey::system_program_id(), sample_action(), 500);
        let rule = quorum_rule(RiskTier::Registry);
        assert_eq!(p.voting_ends_round, 500 + rule.voting_period_rounds);
    }

    #[test]
    fn low_tier_passes_on_a_strict_simple_majority_not_a_tie() {
        let mut tied = Proposal::new(1, Pubkey::system_program_id(), low_risk_action(), 0);
        tied.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 50);
        tied.record_vote(Pubkey::new([2u8; 32]), VoteChoice::No, 50);
        assert_eq!(tied.evaluate(100), ProposalStatus::Rejected, "a 50/50 tie must not pass a simple-majority vote");

        let mut clear = Proposal::new(2, Pubkey::system_program_id(), low_risk_action(), 0);
        clear.record_vote(Pubkey::new([1u8; 32]), VoteChoice::Yes, 51);
        clear.record_vote(Pubkey::new([2u8; 32]), VoteChoice::No, 49);
        assert_eq!(clear.evaluate(100), ProposalStatus::Passed);
    }

    #[test]
    fn low_tier_has_a_lower_participation_floor_and_no_timelock_than_registry() {
        let low_rule = quorum_rule(RiskTier::Low);
        let registry_rule = quorum_rule(RiskTier::Registry);
        assert!(low_rule.min_participation_bps < registry_rule.min_participation_bps);
        assert_eq!(low_rule.timelock_rounds, 0, "ARCHITECTURE.md §6 doesn't require a time-lock for low-risk parameters");
        assert!(registry_rule.timelock_rounds > 0);
    }

    #[test]
    fn set_base_fee_action_is_low_risk_tier() {
        assert_eq!(low_risk_action().risk_tier(), RiskTier::Low);
        assert_eq!(sample_action().risk_tier(), RiskTier::Registry);
    }
}
