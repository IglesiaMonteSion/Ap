//! Automated on-chain governance execution (design: `ARCHITECTURE.md` §6,
//! `blockchain-security-audit` #7). Phase 1 had binding on-chain voting but
//! a manual/multisig execution step; this program closes that gap for the
//! one action type the phase-2 roadmap names explicitly - algorithm
//! registry activate/deprecate/retire - end to end and permissionlessly:
//! anyone can call `Finalize` once voting ends and `Execute` once the
//! post-passage timelock has elapsed, no privileged actor required.
//!
//! Voting power comes from `staking.rs`'s stake accounts (see that
//! module's docs for why: real delegated stake, not the small hardcoded
//! consensus validator set). A stake account's *current* `amount` is read
//! at vote time from the account the voter declares in the instruction -
//! consistent with this project's access-list execution model
//! (`ARCHITECTURE.md` §4): there is no hidden scan over every stake
//! account in existence, a voter always names their own.

use crate::error::ExecError;
use crate::ids::GOVERNANCE_PROGRAM_ID;
use crate::native::NativeProgram;
use crate::staking::StakeAccountData;
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{Account, Instruction, Round};
use qchain_crypto::{AlgorithmStatus, Pubkey, RegistryEntry};
use qchain_governance::{quorum_rule, Proposal, ProposalAction, ProposalId, ProposalStatus, VoteChoice};
use std::collections::HashMap;

/// Emergency governance state, stored in `EMERGENCY_ACCOUNT_ID`. A set of
/// guardian keys with an M-of-N threshold can flip `paused`, which blocks
/// governance `Execute` for ALL proposals — an emergency brake on any pending
/// or rushed change while the guardians investigate. **It only ever flips a
/// boolean and gates execution; it never reads or writes a balance, so it is
/// structurally incapable of confiscating or moving funds** (task #213's
/// "pausa de emergencia ... sin permitir confiscación de fondos"). Approvals
/// accumulate across separate guardian transactions in committed order, so the
/// threshold is reached deterministically and identically on every node.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct EmergencyState {
    pub guardians: Vec<Pubkey>,
    pub threshold: u8,
    pub paused: bool,
    /// Distinct guardians who have approved pausing since the last state flip.
    pub pause_approvals: Vec<Pubkey>,
    /// Distinct guardians who have approved unpausing since the last flip.
    pub unpause_approvals: Vec<Pubkey>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub enum GovernanceInstruction {
    /// accounts[0] = proposer wallet (must equal the transaction payer),
    /// accounts[1] = a fresh pubkey for the new proposal account,
    /// accounts[2] = the canonical staking-stats singleton (read-only) —
    /// the bonded supply here is SNAPSHOTTED into the proposal as the frozen
    /// quorum denominator (task #213).
    CreateProposal { id: ProposalId, action: ProposalAction },
    /// accounts[0] = proposal account, accounts[1] = the voter's stake
    /// account (its stored `owner` must equal the transaction payer).
    Vote { choice: VoteChoice },
    /// accounts[0] = proposal account, accounts[1] = the staking-stats
    /// singleton (pinned; the quorum denominator now comes from the
    /// proposal's creation-time snapshot, so its live value is unused).
    /// Permissionless once the voting period has ended.
    Finalize,
    /// accounts[0] = proposal account, accounts[1] = the target singleton
    /// (algorithm registry / economic params), accounts[2] = the emergency
    /// singleton (`EMERGENCY_ACCOUNT_ID`, pinned so the pause can't be
    /// bypassed by omitting it). Permissionless once the post-passage
    /// timelock has elapsed AND governance is not under an emergency pause.
    Execute,
    /// accounts[0] = the emergency singleton. The transaction payer must be a
    /// configured guardian. Records one guardian's approval to PAUSE; once
    /// `threshold` distinct guardians have approved, `paused` becomes true.
    /// Appended (discriminant 4) so the wallet's Vote/Finalize/Execute
    /// encodings (0..3) stay byte-identical.
    EmergencyPause,
    /// accounts[0] = the emergency singleton. Mirror of `EmergencyPause`:
    /// records a guardian's approval to UNPAUSE; once `threshold` distinct
    /// guardians approve, `paused` becomes false. Discriminant 5.
    EmergencyUnpause,
}

fn borsh_err(e: impl std::fmt::Display) -> ExecError {
    ExecError::ProgramError(e.to_string())
}

fn read_proposal(accounts: &HashMap<Pubkey, Account>, pk: &Pubkey) -> Result<Proposal, ExecError> {
    let account = accounts.get(pk).ok_or(ExecError::AccountNotFound(*pk))?;
    Proposal::try_from_slice(&account.data).map_err(borsh_err)
}

fn write_proposal(accounts: &mut HashMap<Pubkey, Account>, pk: &Pubkey, proposal: &Proposal) -> Result<(), ExecError> {
    accounts.get_mut(pk).ok_or(ExecError::AccountNotFound(*pk))?.data = borsh::to_vec(proposal).map_err(borsh_err)?;
    Ok(())
}

pub struct GovernanceProgram;

impl NativeProgram for GovernanceProgram {
    fn process(&self, accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey, current_round: Round) -> Result<(), ExecError> {
        let instr = GovernanceInstruction::try_from_slice(&instruction.data).map_err(borsh_err)?;
        match instr {
            GovernanceInstruction::CreateProposal { id, action } => {
                let proposer =
                    *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("CreateProposal requires accounts[0]".into()))?;
                let proposal_pk =
                    *instruction.accounts.get(1).ok_or_else(|| ExecError::ProgramError("CreateProposal requires accounts[1]".into()))?;
                // accounts[2] = the canonical staking-stats singleton. The bonded
                // supply here is SNAPSHOTTED into the proposal as the frozen quorum
                // denominator (task #213), so a later shrink of total_staked can't
                // lower the participation bar. Pinned to the canonical id for the
                // same reason Finalize/Execute pin theirs — a caller must not be
                // able to name a look-alike account with a tiny total.
                let stats_pk =
                    *instruction.accounts.get(2).ok_or_else(|| ExecError::ProgramError("CreateProposal requires accounts[2] = the staking-stats singleton (voting-power snapshot)".into()))?;
                if stats_pk != crate::ids::STAKING_STATS_ID {
                    return Err(ExecError::ProgramError("CreateProposal accounts[2] must be the canonical staking-stats account".into()));
                }
                if proposer != *payer {
                    return Err(ExecError::Unauthorized("CreateProposal's proposer account must be the transaction payer".into()));
                }
                if accounts.contains_key(&proposal_pk) {
                    return Err(ExecError::ProgramError("proposal account already exists".into()));
                }
                let snapshot_total_staked = u64::try_from_slice(&accounts.get(&stats_pk).ok_or(ExecError::AccountNotFound(stats_pk))?.data).map_err(borsh_err)?;
                let proposal = Proposal::new(id, proposer, action, current_round, snapshot_total_staked);
                let mut account = Account::new_wallet(GOVERNANCE_PROGRAM_ID);
                account.data = borsh::to_vec(&proposal).map_err(borsh_err)?;
                accounts.insert(proposal_pk, account);
            }

            GovernanceInstruction::Vote { choice } => {
                let proposal_pk = *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("Vote requires accounts[0]".into()))?;
                let stake_pk = *instruction.accounts.get(1).ok_or_else(|| ExecError::ProgramError("Vote requires accounts[1]".into()))?;

                let stake_account = accounts.get(&stake_pk).ok_or(ExecError::AccountNotFound(stake_pk))?;
                // Defense in depth: the vote weight is derived from bytes in
                // this account's `data`, so it must be a genuine staking-program
                // account, not an arbitrary account whose `data` an attacker
                // packed to forge a large `amount`. No current instruction lets
                // a caller write arbitrary bytes with their own pubkey as the
                // StakeAccountData layout, but pinning the owner here makes a
                // future arbitrary-data primitive unable to silently enable
                // vote-weight forgery.
                if stake_account.owner != crate::ids::STAKING_PROGRAM_ID {
                    return Err(ExecError::Unauthorized("Vote's stake account must be owned by the staking program".into()));
                }
                let mut stake_data = StakeAccountData::try_from_slice(&stake_account.data).map_err(borsh_err)?;
                if stake_data.owner != *payer {
                    return Err(ExecError::Unauthorized("Vote's stake account must be owned by the transaction payer".into()));
                }
                if stake_data.amount == 0 {
                    return Err(ExecError::ProgramError("stake account has no active (undelegated) stake to vote with".into()));
                }

                let mut proposal = read_proposal(accounts, &proposal_pk)?;
                if proposal.status != ProposalStatus::Voting {
                    return Err(ExecError::ProgramError("proposal is not open for voting".into()));
                }
                if current_round >= proposal.voting_ends_round {
                    return Err(ExecError::ProgramError("voting period has ended - call Finalize instead".into()));
                }
                if !proposal.record_vote(stake_pk, choice, stake_data.amount) {
                    return Err(ExecError::ProgramError("this stake account already voted on this proposal".into()));
                }
                write_proposal(accounts, &proposal_pk, &proposal)?;

                // Real, live-confirmed governance attack this closes (see
                // `StakeAccountData::locked_until_round`'s doc comment):
                // the vote weight just recorded above is permanent, so the
                // stake behind it must stay locked at least until this
                // proposal is decided - `max` because one position can
                // vote on several proposals with overlapping periods.
                // Locked through the ENTIRE window the vote has effect: the
                // voting period PLUS the post-passage time-lock (Registry tier),
                // so a Yes-voter can't reclaim their capital the instant voting
                // ends and sit out the review window with zero exposure while
                // their recorded vote still drives execution. Low tier has a
                // zero time-lock, so this is unchanged there.
                let lock_until = proposal.voting_ends_round.saturating_add(quorum_rule(proposal.action.risk_tier()).timelock_rounds);
                stake_data.locked_until_round = stake_data.locked_until_round.max(lock_until);
                accounts.get_mut(&stake_pk).unwrap().data = borsh::to_vec(&stake_data).map_err(borsh_err)?;
            }

            GovernanceInstruction::Finalize => {
                let proposal_pk = *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("Finalize requires accounts[0]".into()))?;
                let stats_pk = *instruction.accounts.get(1).ok_or_else(|| ExecError::ProgramError("Finalize requires accounts[1]".into()))?;

                // The stats singleton is still PINNED here (CLI/wallet unchanged),
                // but the quorum denominator now comes from the proposal's
                // creation-time snapshot (task #213), not this account's live
                // value — so a validator can't shrink `total_staked` after a
                // proposal opens to lower the bar. The pin keeps the account shape
                // canonical for callers; its current value is intentionally unused.
                if stats_pk != crate::ids::STAKING_STATS_ID {
                    return Err(ExecError::ProgramError(
                        "Finalize accounts[1] must be the canonical staking-stats account".into(),
                    ));
                }

                let mut proposal = read_proposal(accounts, &proposal_pk)?;
                if proposal.status != ProposalStatus::Voting {
                    return Err(ExecError::ProgramError("proposal has already been finalized".into()));
                }
                if current_round < proposal.voting_ends_round {
                    return Err(ExecError::ProgramError("voting period has not ended yet".into()));
                }

                let outcome = proposal.evaluate();
                proposal.status = outcome;
                if outcome == ProposalStatus::Passed {
                    proposal.passed_round = Some(current_round);
                }
                write_proposal(accounts, &proposal_pk, &proposal)?;
            }

            GovernanceInstruction::Execute => {
                let proposal_pk = *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("Execute requires accounts[0]".into()))?;
                // The account this action actually mutates - the
                // algorithm registry for a Registry-tier action, the
                // economic-params singleton for a Low-tier one. The
                // caller (a CLI/client) is expected to have read the
                // proposal first and pass the matching target; this
                // program just applies whichever variant `proposal.action`
                // turns out to be against whatever it's handed.
                let target_pk = *instruction.accounts.get(1).ok_or_else(|| ExecError::ProgramError("Execute requires accounts[1]".into()))?;
                // accounts[2] MUST be the emergency singleton (task #213). Pinning
                // it means a caller can't bypass an active pause by simply omitting
                // the account: Execute refuses to run without it declared. The read
                // itself is TOLERANT — on a network whose genesis predates this
                // feature the account is absent (or undecodable), which is treated
                // as "no guardians, not paused", so a legacy chain's governance
                // keeps working unchanged. On a guarded network the account exists
                // and a `paused` state blocks every Execute until the guardians
                // unpause. The pause only gates execution here — it never reads or
                // writes any balance, so it cannot move or confiscate funds.
                let emergency_pk = *instruction.accounts.get(2).ok_or_else(|| ExecError::ProgramError("Execute requires accounts[2] = the emergency governance singleton".into()))?;
                if emergency_pk != crate::ids::EMERGENCY_ACCOUNT_ID {
                    return Err(ExecError::ProgramError("Execute accounts[2] must be the canonical emergency governance account".into()));
                }
                // FAIL-LOUD (#217): absent EMERGENCY account = legacy network without
                // guardians (pause inert, tolerated). But PRESENT-but-undecodable must
                // NOT be silently ignored — that would disable the pause gate on a
                // corrupt singleton and let a rushed Execute through. Refuse to run.
                if let Some(acc) = accounts.get(&crate::ids::EMERGENCY_ACCOUNT_ID) {
                    let state = EmergencyState::try_from_slice(&acc.data).unwrap_or_else(|e| {
                        panic!("EMERGENCY_ACCOUNT is present but does not decode as EmergencyState ({e}); refusing to run on corrupt emergency-governance state")
                    });
                    if state.paused {
                        return Err(ExecError::ProgramError(
                            "governance is under an emergency pause — Execute is blocked until the guardian multisig unpauses".into(),
                        ));
                    }
                }

                let mut proposal = read_proposal(accounts, &proposal_pk)?;
                if proposal.status != ProposalStatus::Passed {
                    return Err(ExecError::ProgramError("proposal has not passed - nothing to execute".into()));
                }
                let rule = quorum_rule(proposal.action.risk_tier());
                let passed_round = proposal.passed_round.ok_or_else(|| ExecError::ProgramError("passed proposal is missing passed_round".into()))?;
                if current_round < passed_round + rule.timelock_rounds {
                    return Err(ExecError::ProgramError("the mandatory review time-lock has not elapsed yet".into()));
                }

                // Pin the mutated account to the canonical singleton for the
                // action's tier. Without this, a caller could name a
                // different account they control and have `Execute` overwrite
                // it with registry/params bytes, or (with a look-alike data
                // layout) desync what the rest of the ledger reads as the
                // real registry/params. The legitimate CLI always passes
                // `REGISTRY_ACCOUNT_ID` (Registry tier) or `PARAMS_ACCOUNT_ID`
                // (Low tier) as accounts[1].
                match &proposal.action {
                    ProposalAction::ActivateAlgorithm(_) | ProposalAction::DeprecateAlgorithm { .. } | ProposalAction::RetireAlgorithm { .. } => {
                        if target_pk != crate::ids::REGISTRY_ACCOUNT_ID {
                            return Err(ExecError::ProgramError(
                                "Execute accounts[1] must be the canonical registry account for a registry action".into(),
                            ));
                        }
                        let target_account = accounts.get(&target_pk).ok_or(ExecError::AccountNotFound(target_pk))?;
                        let mut registry: Vec<RegistryEntry> = Vec::try_from_slice(&target_account.data).map_err(borsh_err)?;
                        apply_registry_action(&mut registry, &proposal.action, current_round)?;
                        accounts.get_mut(&target_pk).unwrap().data = borsh::to_vec(&registry).map_err(borsh_err)?;
                    }
                    ProposalAction::SetBaseFeePerByte(_)
                    | ProposalAction::SetDustThreshold(_)
                    | ProposalAction::SetGasPricePerFuel(_)
                    | ProposalAction::SetStakingCommissionBps(_)
                    | ProposalAction::SetEmissionApr(_) => {
                        if target_pk != crate::ids::PARAMS_ACCOUNT_ID {
                            return Err(ExecError::ProgramError(
                                "Execute accounts[1] must be the canonical economic-params account for a Low-tier action".into(),
                            ));
                        }
                        let target_account = accounts.get(&target_pk).ok_or(ExecError::AccountNotFound(target_pk))?;
                        let mut params = crate::params::EconomicParams::read_or_legacy(&target_account.data)
                            .ok_or_else(|| ExecError::ProgramError("economic-params account is unreadable".into()))?;
                        apply_economic_action(&mut params, &proposal.action)?;
                        accounts.get_mut(&target_pk).unwrap().data = borsh::to_vec(&params).map_err(borsh_err)?;
                    }
                }

                proposal.status = ProposalStatus::Executed;
                write_proposal(accounts, &proposal_pk, &proposal)?;
            }

            GovernanceInstruction::EmergencyPause => apply_emergency_approval(accounts, instruction, payer, true)?,
            GovernanceInstruction::EmergencyUnpause => apply_emergency_approval(accounts, instruction, payer, false)?,
        }
        Ok(())
    }
}

/// One guardian's approval to pause (`want_paused = true`) or unpause
/// (`false`). accounts[0] must be the emergency singleton. The payer must be a
/// configured guardian; approvals accumulate (deduplicated) across separate
/// transactions until `threshold` distinct guardians agree, at which point
/// `paused` flips and both approval lists are cleared to start the next round
/// clean. This handler ONLY mutates the emergency flag/approval lists — it
/// never touches a balance, so it is structurally unable to move funds.
fn apply_emergency_approval(
    accounts: &mut HashMap<Pubkey, Account>,
    instruction: &Instruction,
    payer: &Pubkey,
    want_paused: bool,
) -> Result<(), ExecError> {
    let em_pk = *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("Emergency instruction requires accounts[0] = the emergency singleton".into()))?;
    if em_pk != crate::ids::EMERGENCY_ACCOUNT_ID {
        return Err(ExecError::ProgramError("Emergency accounts[0] must be the canonical emergency governance account".into()));
    }
    let account = accounts.get(&em_pk).ok_or(ExecError::AccountNotFound(em_pk))?;
    let mut state = EmergencyState::try_from_slice(&account.data).map_err(borsh_err)?;

    if state.guardians.is_empty() || state.threshold == 0 {
        return Err(ExecError::ProgramError("no emergency guardians are configured on this network".into()));
    }
    if !state.guardians.contains(payer) {
        return Err(ExecError::Unauthorized("only a configured guardian can approve an emergency pause/unpause".into()));
    }
    if state.paused == want_paused {
        return Err(ExecError::ProgramError(if want_paused { "governance is already paused" } else { "governance is not paused" }.into()));
    }

    // A new pause round supersedes any stale unpause approvals and vice versa.
    if want_paused {
        state.unpause_approvals.clear();
        if !state.pause_approvals.contains(payer) {
            state.pause_approvals.push(*payer);
        }
        if state.pause_approvals.len() as u32 >= state.threshold as u32 {
            state.paused = true;
            state.pause_approvals.clear();
        }
    } else {
        state.pause_approvals.clear();
        if !state.unpause_approvals.contains(payer) {
            state.unpause_approvals.push(*payer);
        }
        if state.unpause_approvals.len() as u32 >= state.threshold as u32 {
            state.paused = false;
            state.unpause_approvals.clear();
        }
    }

    accounts.get_mut(&em_pk).unwrap().data = borsh::to_vec(&state).map_err(borsh_err)?;
    Ok(())
}

fn apply_registry_action(registry: &mut Vec<RegistryEntry>, action: &ProposalAction, current_round: Round) -> Result<(), ExecError> {
    match action {
        ProposalAction::ActivateAlgorithm(entry) => {
            if registry.iter().any(|e| e.id == entry.id) {
                return Err(ExecError::ProgramError("algorithm id is already registered".into()));
            }
            registry.push(entry.clone());
        }
        ProposalAction::DeprecateAlgorithm { id, retirement_round } => {
            let entry = registry.iter_mut().find(|e| e.id == *id).ok_or_else(|| ExecError::ProgramError("unknown algorithm id".into()))?;
            if entry.status != AlgorithmStatus::Active {
                return Err(ExecError::ProgramError("only an Active entry can be deprecated".into()));
            }
            entry.status = AlgorithmStatus::Deprecated { retirement_epoch: *retirement_round };
        }
        ProposalAction::RetireAlgorithm { id } => {
            let entry = registry.iter_mut().find(|e| e.id == *id).ok_or_else(|| ExecError::ProgramError("unknown algorithm id".into()))?;
            match entry.status {
                AlgorithmStatus::Deprecated { retirement_epoch } if current_round >= retirement_epoch => {
                    entry.status = AlgorithmStatus::Retired;
                }
                AlgorithmStatus::Deprecated { .. } => {
                    return Err(ExecError::ProgramError("retirement round has not been reached yet".into()));
                }
                _ => return Err(ExecError::ProgramError("only a Deprecated entry can be retired".into())),
            }
        }
        ProposalAction::SetBaseFeePerByte(_)
        | ProposalAction::SetDustThreshold(_)
        | ProposalAction::SetGasPricePerFuel(_)
        | ProposalAction::SetStakingCommissionBps(_)
        | ProposalAction::SetEmissionApr(_) => {
            unreachable!("Execute only calls apply_registry_action for Registry-tier actions")
        }
    }
    Ok(())
}

/// Safety ceiling for the governance-settable `dust_threshold`. 1,000× the
/// ~1,000,000-unit fee anchor - generous headroom for any legitimate
/// recalibration, while far below any real account balance, so a passed
/// proposal can never set it high enough to sweep-and-burn ordinary accounts
/// (the catastrophe an unbounded `dust_threshold` allowed - see
/// `apply_economic_action`).
const MAX_DUST_THRESHOLD: u64 = 1_000_000_000;

/// Per-proposal change limit (task #213): a single passed proposal may move a
/// multiplicative economic parameter (base fee, dust threshold, gas price) by
/// at most this factor up or down. Combined with the Economic tier's mandatory
/// review time-lock, this makes a hostile-but-passing proposal unable to swing
/// a parameter to an extreme in one shot — any large move must proceed in
/// several proposals, each with its own supermajority + review window.
const MAX_ECON_CHANGE_FACTOR: u64 = 2;
/// Absolute step allowances so a parameter sitting at a tiny value can still
/// move by a sensible amount (a strict 2× of `1` would only reach `2`). A
/// change is accepted if it is within the multiplicative factor OR within the
/// absolute step — whichever is more permissive.
const BASE_FEE_ABS_STEP: u64 = crate::params::FEE_MIN_BASE_FEE_PER_BYTE;
const DUST_ABS_STEP: u64 = 100_000;
const GAS_ABS_STEP: u64 = 10;
/// Additive per-proposal caps for the basis-point parameters.
const COMMISSION_STEP_BPS: u16 = 2_000;
const EMISSION_STEP_BPS: u16 = 500;

/// True if `new` is within `factor`× (up or down) of `current`, OR within
/// `abs_step` of it (the small-value escape hatch). All math in u128 so it
/// never overflows or divides by zero.
fn within_change_limit(current: u64, new: u64, factor: u64, abs_step: u64) -> bool {
    let (cur, nw, f) = (current as u128, new as u128, factor as u128);
    if nw <= cur.saturating_mul(f) && nw.saturating_mul(f) >= cur {
        return true;
    }
    new.abs_diff(current) <= abs_step
}

/// Only ever called with a `Low`-tier action (the `Execute` match arm routes
/// accordingly) - the other variants are unreachable here. Enforces sanity
/// bounds on each economic parameter: a passed `Low`-tier proposal executes
/// with zero time-lock, so an out-of-range value (e.g. `dust_threshold =
/// u64::MAX`, `base_fee = 0`, `gas_price = 0`) would take effect immediately
/// with no window to react - these bounds keep governance from bricking the
/// chain even with a transient majority.
fn apply_economic_action(params: &mut crate::params::EconomicParams, action: &ProposalAction) -> Result<(), ExecError> {
    match action {
        // Floor: below the anti-spam minimum the dynamic fee mechanism already
        // clamps to (`FEE_MIN_BASE_FEE_PER_BYTE`), so a governance-set value
        // under it is both pointless (the next round would raise it back) and
        // dangerous (a `0` would make transactions free - spam DoS).
        ProposalAction::SetBaseFeePerByte(v) => {
            if *v < crate::params::FEE_MIN_BASE_FEE_PER_BYTE {
                return Err(ExecError::ProgramError(format!(
                    "base_fee_per_byte {v} is below the anti-spam floor {}",
                    crate::params::FEE_MIN_BASE_FEE_PER_BYTE
                )));
            }
            // Ceiling: without it a passed `Low`-tier proposal setting the fee to
            // `u64::MAX` bricks the chain PERMANENTLY - every tx (including the
            // governance tx needed to lower it back) would exceed any balance, and
            // the dynamic-fee decay only runs inside `apply_transaction`, so no tx
            // could ever apply to self-heal. `MAX_BASE_FEE_PER_BYTE` keeps it
            // recoverable while leaving huge headroom for legitimate repeg.
            if *v > crate::params::MAX_BASE_FEE_PER_BYTE {
                return Err(ExecError::ProgramError(format!(
                    "base_fee_per_byte {v} exceeds the safety cap {} - a higher value would brick the chain with no recovery path",
                    crate::params::MAX_BASE_FEE_PER_BYTE
                )));
            }
            if !within_change_limit(params.base_fee_per_byte, *v, MAX_ECON_CHANGE_FACTOR, BASE_FEE_ABS_STEP) {
                return Err(ExecError::ProgramError(format!(
                    "base_fee_per_byte {v} moves more than {MAX_ECON_CHANGE_FACTOR}× (or {BASE_FEE_ABS_STEP}) from the current {} in one proposal - split a large change across several proposals",
                    params.base_fee_per_byte
                )));
            }
            params.base_fee_per_byte = *v;
        }
        // Hard cap: `dust_threshold` is the balance BELOW which a system-owned
        // account is zeroed-and-burned when it participates in any transaction.
        // With no ceiling a single passed `Low`-tier proposal could set it to
        // `u64::MAX` and irreversibly burn EVERY ordinary account the next time
        // it transacts (even as a mere transfer recipient) - total supply
        // destruction. The cap keeps the value in genuine "dust" territory
        // (generous headroom over the ~1M anchor for recalibration) while making
        // that catastrophe impossible.
        ProposalAction::SetDustThreshold(v) => {
            if *v > MAX_DUST_THRESHOLD {
                return Err(ExecError::ProgramError(format!(
                    "dust_threshold {v} exceeds the safety cap {MAX_DUST_THRESHOLD} - a higher value would sweep-and-burn ordinary balances"
                )));
            }
            if !within_change_limit(params.dust_threshold, *v, MAX_ECON_CHANGE_FACTOR, DUST_ABS_STEP) {
                return Err(ExecError::ProgramError(format!(
                    "dust_threshold {v} moves more than {MAX_ECON_CHANGE_FACTOR}× (or {DUST_ABS_STEP}) from the current {} in one proposal",
                    params.dust_threshold
                )));
            }
            params.dust_threshold = *v;
        }
        // A `0` gas price makes WASM compute free, defeating the gas-metering
        // DoS protections (trap billing, memory limiter, fuel limit).
        ProposalAction::SetGasPricePerFuel(v) => {
            if *v == 0 {
                return Err(ExecError::ProgramError("gas_price_per_fuel cannot be zero - would make WASM compute free (DoS)".into()));
            }
            // Ceiling, symmetric with `base_fee`: an unbounded gas price makes
            // every WASM-consuming tx unaffordable (smaller blast radius than the
            // base fee - transfers/governance carry no fuel - but capped for a
            // fully airtight economic-parameter surface).
            if *v > crate::params::MAX_GAS_PRICE_PER_FUEL {
                return Err(ExecError::ProgramError(format!(
                    "gas_price_per_fuel {v} exceeds the safety cap {}",
                    crate::params::MAX_GAS_PRICE_PER_FUEL
                )));
            }
            if !within_change_limit(params.gas_price_per_fuel, *v, MAX_ECON_CHANGE_FACTOR, GAS_ABS_STEP) {
                return Err(ExecError::ProgramError(format!(
                    "gas_price_per_fuel {v} moves more than {MAX_ECON_CHANGE_FACTOR}× (or {GAS_ABS_STEP}) from the current {} in one proposal",
                    params.gas_price_per_fuel
                )));
            }
            params.gas_price_per_fuel = *v;
        }
        ProposalAction::SetStakingCommissionBps(v) => {
            if *v > 10_000 {
                return Err(ExecError::ProgramError("staking commission cannot exceed 10,000 bps (100%)".into()));
            }
            if v.abs_diff(params.staking_commission_bps) > COMMISSION_STEP_BPS {
                return Err(ExecError::ProgramError(format!(
                    "staking commission {v} bps moves more than {COMMISSION_STEP_BPS} bps from the current {} in one proposal",
                    params.staking_commission_bps
                )));
            }
            params.staking_commission_bps = *v;
        }
        // Cap: emission is real new supply minted every round; an unbounded APR
        // (e.g. u16::MAX ≈ 655%) executed with zero time-lock would inflate the
        // token catastrophically before anyone could react. The cap keeps it in
        // a plausible monetary-policy band.
        ProposalAction::SetEmissionApr(v) => {
            if *v > crate::params::MAX_EMISSION_APR_BPS {
                return Err(ExecError::ProgramError(format!(
                    "emission APR {v} bps exceeds the safety cap {} bps",
                    crate::params::MAX_EMISSION_APR_BPS
                )));
            }
            if v.abs_diff(params.emission_apr_bps) > EMISSION_STEP_BPS {
                return Err(ExecError::ProgramError(format!(
                    "emission APR {v} bps moves more than {EMISSION_STEP_BPS} bps from the current {} in one proposal",
                    params.emission_apr_bps
                )));
            }
            params.emission_apr_bps = *v;
        }
        ProposalAction::ActivateAlgorithm(_) | ProposalAction::DeprecateAlgorithm { .. } | ProposalAction::RetireAlgorithm { .. } => {
            unreachable!("Execute only calls apply_economic_action for Low-tier actions")
        }
    }
    Ok(())
}

/// Builds the genesis algorithm-registry account contents - callers (node
/// startup) write this into `REGISTRY_ACCOUNT_ID` once, at genesis.
pub fn genesis_registry_account_data() -> Vec<u8> {
    borsh::to_vec(&qchain_crypto::registry::genesis_registry()).expect("genesis registry always serializes")
}

/// Builds the genesis economic-params account contents - callers (node
/// startup) write this into `PARAMS_ACCOUNT_ID` once, at genesis.
pub fn genesis_params_account_data() -> Vec<u8> {
    borsh::to_vec(&crate::params::EconomicParams::default()).expect("default economic params always serialize")
}

/// Builds the genesis emergency-governance account contents (task #213) —
/// callers (node startup) write this into `EMERGENCY_ACCOUNT_ID` once, at
/// genesis. `threshold` is clamped to `1..=guardians.len()` so a
/// mis-configured genesis can never require more approvals than there are
/// guardians (which would make the pause un-triggerable). An empty guardian
/// set leaves the feature inert (no one can pause), which is the safe default.
pub fn genesis_emergency_account_data(guardians: Vec<Pubkey>, threshold: u8) -> Vec<u8> {
    let threshold = if guardians.is_empty() { 0 } else { threshold.clamp(1, guardians.len().min(u8::MAX as usize) as u8) };
    let state = EmergencyState { guardians, threshold, paused: false, pause_approvals: Vec::new(), unpause_approvals: Vec::new() };
    borsh::to_vec(&state).expect("emergency state always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{PARAMS_ACCOUNT_ID, REGISTRY_ACCOUNT_ID, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID};
    use crate::staking::StakingProgram;
    use qchain_crypto::{ALGORITHM_ED25519, ALGORITHM_ML_DSA_65};

    const PROPOSAL_PK: Pubkey = Pubkey::new([30u8; 32]);
    const STAKE_PK: Pubkey = Pubkey::new([31u8; 32]);
    const OTHER_STAKE_PK: Pubkey = Pubkey::new([32u8; 32]);

    #[test]
    fn governance_instruction_encoding_is_stable() {
        // The WASM wallet (crates/qchain-wasm) hand-rolls these encodings to
        // avoid depending on this crate (which pulls wasmtime, no wasm target).
        // If GovernanceInstruction/VoteChoice ever change, this guard fails so
        // the wallet's sign_vote/finalize/execute are updated in lock-step.
        assert_eq!(borsh::to_vec(&GovernanceInstruction::Vote { choice: VoteChoice::Yes }).unwrap(), vec![1u8, 0], "wasm Vote(Yes) encoding out of sync");
        assert_eq!(borsh::to_vec(&GovernanceInstruction::Vote { choice: VoteChoice::No }).unwrap(), vec![1u8, 1], "wasm Vote(No) encoding out of sync");
        assert_eq!(borsh::to_vec(&GovernanceInstruction::Vote { choice: VoteChoice::Abstain }).unwrap(), vec![1u8, 2], "wasm Vote(Abstain) encoding out of sync");
        assert_eq!(borsh::to_vec(&GovernanceInstruction::Finalize).unwrap(), vec![2u8], "wasm Finalize encoding out of sync");
        assert_eq!(borsh::to_vec(&GovernanceInstruction::Execute).unwrap(), vec![3u8], "wasm Execute encoding out of sync");
    }

    fn wallet(balance: u64) -> Account {
        Account { balance, ..Account::new_wallet(Pubkey::system_program_id()) }
    }

    fn stake_account(owner: Pubkey, amount: u64) -> Account {
        let data =
            StakeAccountData { owner, validator: Pubkey::new([99u8; 32]), amount, reward_debt: 0, locked_until_round: 0, bonding_until_round: 0, unbonding_requested_at_round: None };
        Account { balance: amount, data: borsh::to_vec(&data).unwrap(), ..Account::new_wallet(crate::ids::STAKING_PROGRAM_ID) }
    }

    fn registry_account() -> Account {
        Account { data: genesis_registry_account_data(), ..Account::new_wallet(GOVERNANCE_PROGRAM_ID) }
    }

    fn stats_account(total: u64) -> Account {
        Account { data: borsh::to_vec(&total).unwrap(), ..Account::new_wallet(crate::ids::STAKING_PROGRAM_ID) }
    }

    fn pool_account() -> Account {
        Account { data: borsh::to_vec(&crate::staking::RewardPoolData::default()).unwrap(), ..Account::new_wallet(crate::ids::STAKING_PROGRAM_ID) }
    }

    fn params_account() -> Account {
        Account { data: genesis_params_account_data(), ..Account::new_wallet(GOVERNANCE_PROGRAM_ID) }
    }

    fn new_slh_dsa_entry() -> RegistryEntry {
        // Real, measured sizes for SPHINCS+-SHA2-256s-simple (see
        // `qchain_crypto::slh_dsa`'s own size test) - not a placeholder.
        qchain_crypto::slh_dsa_registry_entry(0)
    }

    fn create_proposal(accounts: &mut HashMap<Pubkey, Account>, proposer: Pubkey, action: ProposalAction, round: Round) {
        let ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![proposer, PROPOSAL_PK, STAKING_STATS_ID],
            data: borsh::to_vec(&GovernanceInstruction::CreateProposal { id: 1, action }).unwrap(),
        };
        GovernanceProgram.process(accounts, &ix, &proposer, round).unwrap();
    }

    fn vote(accounts: &mut HashMap<Pubkey, Account>, voter: Pubkey, stake_pk: Pubkey, choice: VoteChoice, round: Round) -> Result<(), ExecError> {
        let ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![PROPOSAL_PK, stake_pk],
            data: borsh::to_vec(&GovernanceInstruction::Vote { choice }).unwrap(),
        };
        GovernanceProgram.process(accounts, &ix, &voter, round)
    }

    fn finalize(accounts: &mut HashMap<Pubkey, Account>, caller: Pubkey, round: Round) -> Result<(), ExecError> {
        let ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![PROPOSAL_PK, STAKING_STATS_ID],
            data: borsh::to_vec(&GovernanceInstruction::Finalize).unwrap(),
        };
        GovernanceProgram.process(accounts, &ix, &caller, round)
    }

    fn execute(accounts: &mut HashMap<Pubkey, Account>, caller: Pubkey, round: Round) -> Result<(), ExecError> {
        let ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![PROPOSAL_PK, REGISTRY_ACCOUNT_ID, crate::ids::EMERGENCY_ACCOUNT_ID],
            data: borsh::to_vec(&GovernanceInstruction::Execute).unwrap(),
        };
        GovernanceProgram.process(accounts, &ix, &caller, round)
    }

    #[test]
    fn full_registry_activation_lifecycle_passes_and_executes() {
        let proposer = Pubkey::new([1u8; 32]);
        let voter_a = Pubkey::new([2u8; 32]);
        let voter_b = Pubkey::new([3u8; 32]);
        let mut accounts = HashMap::from([
            (proposer, wallet(0)),
            (STAKE_PK, stake_account(voter_a, 700)),
            (OTHER_STAKE_PK, stake_account(voter_b, 300)),
            (STAKING_STATS_ID, stats_account(1_000)),
            (REGISTRY_ACCOUNT_ID, registry_account()),
        ]);

        create_proposal(&mut accounts, proposer, ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()), 0);
        vote(&mut accounts, voter_a, STAKE_PK, VoteChoice::Yes, 5).unwrap();
        vote(&mut accounts, voter_b, OTHER_STAKE_PK, VoteChoice::No, 5).unwrap();

        let rule = quorum_rule(qchain_governance::RiskTier::Registry);
        finalize(&mut accounts, Pubkey::new([9u8; 32]), rule.voting_period_rounds).unwrap();
        let proposal = read_proposal(&accounts, &PROPOSAL_PK).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Passed, "70% yes clears the 2/3 supermajority bar");

        // Too early - the review time-lock hasn't elapsed.
        assert!(execute(&mut accounts, Pubkey::new([9u8; 32]), rule.voting_period_rounds + 1).is_err());

        execute(&mut accounts, Pubkey::new([9u8; 32]), rule.voting_period_rounds + rule.timelock_rounds).unwrap();

        let registry: Vec<RegistryEntry> = Vec::try_from_slice(&accounts[&REGISTRY_ACCOUNT_ID].data).unwrap();
        assert!(registry.iter().any(|e| e.id == qchain_crypto::ALGORITHM_SLH_DSA && e.status == AlgorithmStatus::Active));
        let proposal = read_proposal(&accounts, &PROPOSAL_PK).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Executed);
    }

    #[test]
    fn a_rejected_proposal_never_touches_the_registry() {
        let proposer = Pubkey::new([1u8; 32]);
        let voter_a = Pubkey::new([2u8; 32]);
        let mut accounts = HashMap::from([
            (proposer, wallet(0)),
            (STAKE_PK, stake_account(voter_a, 100)),
            (STAKING_STATS_ID, stats_account(1_000)),
            (REGISTRY_ACCOUNT_ID, registry_account()),
        ]);
        let original_registry = accounts[&REGISTRY_ACCOUNT_ID].data.clone();

        create_proposal(&mut accounts, proposer, ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()), 0);
        // Only 100/1000 = 10% participates - below the 20% floor.
        vote(&mut accounts, voter_a, STAKE_PK, VoteChoice::Yes, 5).unwrap();

        let rule = quorum_rule(qchain_governance::RiskTier::Registry);
        finalize(&mut accounts, Pubkey::new([9u8; 32]), rule.voting_period_rounds).unwrap();
        let proposal = read_proposal(&accounts, &PROPOSAL_PK).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected);

        assert!(execute(&mut accounts, Pubkey::new([9u8; 32]), rule.voting_period_rounds + rule.timelock_rounds).is_err());
        assert_eq!(accounts[&REGISTRY_ACCOUNT_ID].data, original_registry, "a rejected proposal must never mutate the registry");
    }

    #[test]
    fn deprecate_then_retire_respects_the_grace_period() {
        let proposer = Pubkey::new([1u8; 32]);
        let voter = Pubkey::new([2u8; 32]);
        let mut accounts = HashMap::from([
            (proposer, wallet(0)),
            (STAKE_PK, stake_account(voter, 1_000)),
            (STAKING_STATS_ID, stats_account(1_000)),
            (REGISTRY_ACCOUNT_ID, registry_account()),
        ]);
        let rule = quorum_rule(qchain_governance::RiskTier::Registry);
        let full_cycle = rule.voting_period_rounds + rule.timelock_rounds;

        // The retire proposal can only be *created* once the deprecate
        // proposal has executed (round `full_cycle`), and then needs a
        // second full vote+timelock cycle of its own before it's
        // execute-eligible - so its earliest possible execute round is
        // `2 * full_cycle`. Set the algorithm's retirement grace period to
        // land comfortably after that, so there's a real window where the
        // retire proposal's *governance* timelock has elapsed but the
        // entry's *migration grace period* has not.
        let retirement_round = 2 * full_cycle + 50;

        create_proposal(&mut accounts, proposer, ProposalAction::DeprecateAlgorithm { id: ALGORITHM_ED25519, retirement_round }, 0);
        vote(&mut accounts, voter, STAKE_PK, VoteChoice::Yes, 5).unwrap();
        finalize(&mut accounts, proposer, rule.voting_period_rounds).unwrap();
        execute(&mut accounts, proposer, full_cycle).unwrap();

        let registry: Vec<RegistryEntry> = Vec::try_from_slice(&accounts[&REGISTRY_ACCOUNT_ID].data).unwrap();
        let entry = registry.iter().find(|e| e.id == ALGORITHM_ED25519).unwrap();
        assert_eq!(entry.status, AlgorithmStatus::Deprecated { retirement_epoch: retirement_round });
        assert!(registry.iter().any(|e| e.id == ALGORITHM_ML_DSA_65 && e.status == AlgorithmStatus::Active), "unrelated entries must be untouched");

        // A second proposal retires it, created right after the deprecate
        // proposal executed.
        let retire_proposal_pk = Pubkey::new([40u8; 32]);
        let retire_ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![proposer, retire_proposal_pk, STAKING_STATS_ID],
            data: borsh::to_vec(&GovernanceInstruction::CreateProposal { id: 2, action: ProposalAction::RetireAlgorithm { id: ALGORITHM_ED25519 } }).unwrap(),
        };
        GovernanceProgram.process(&mut accounts, &retire_ix, &proposer, full_cycle).unwrap();

        let vote_ix =
            Instruction { program_id: GOVERNANCE_PROGRAM_ID, accounts: vec![retire_proposal_pk, STAKE_PK], data: borsh::to_vec(&GovernanceInstruction::Vote { choice: VoteChoice::Yes }).unwrap() };
        GovernanceProgram.process(&mut accounts, &vote_ix, &voter, full_cycle + 1).unwrap();

        let finalize_ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![retire_proposal_pk, STAKING_STATS_ID],
            data: borsh::to_vec(&GovernanceInstruction::Finalize).unwrap(),
        };
        let retire_finalize_round = full_cycle + rule.voting_period_rounds;
        GovernanceProgram.process(&mut accounts, &finalize_ix, &proposer, retire_finalize_round).unwrap();

        let execute_ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![retire_proposal_pk, REGISTRY_ACCOUNT_ID, crate::ids::EMERGENCY_ACCOUNT_ID],
            data: borsh::to_vec(&GovernanceInstruction::Execute).unwrap(),
        };
        // The retire proposal's own governance timelock has elapsed here,
        // but `retirement_round` (the entry's migration grace period)
        // hasn't - this must still be rejected.
        let retire_execute_ready_round = retire_finalize_round + rule.timelock_rounds;
        assert!(retire_execute_ready_round < retirement_round, "test setup assumption: still before the grace period ends");
        let result = GovernanceProgram.process(&mut accounts, &execute_ix, &proposer, retire_execute_ready_round);
        assert!(result.is_err(), "retiring before the grace period elapses must be rejected");

        GovernanceProgram.process(&mut accounts, &execute_ix, &proposer, retirement_round).unwrap();
        let registry: Vec<RegistryEntry> = Vec::try_from_slice(&accounts[&REGISTRY_ACCOUNT_ID].data).unwrap();
        assert_eq!(registry.iter().find(|e| e.id == ALGORITHM_ED25519).unwrap().status, AlgorithmStatus::Retired);
    }

    #[test]
    fn voting_after_the_period_ends_is_rejected() {
        let proposer = Pubkey::new([1u8; 32]);
        let voter = Pubkey::new([2u8; 32]);
        let mut accounts = HashMap::from([
            (proposer, wallet(0)),
            (STAKE_PK, stake_account(voter, 1_000)),
            (STAKING_STATS_ID, stats_account(1_000)),
            (REGISTRY_ACCOUNT_ID, registry_account()),
        ]);
        create_proposal(&mut accounts, proposer, ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()), 0);
        let rule = quorum_rule(qchain_governance::RiskTier::Registry);
        assert!(vote(&mut accounts, voter, STAKE_PK, VoteChoice::Yes, rule.voting_period_rounds).is_err());
    }

    #[test]
    fn a_stake_account_owned_by_someone_else_cannot_vote() {
        let proposer = Pubkey::new([1u8; 32]);
        let real_owner = Pubkey::new([2u8; 32]);
        let attacker = Pubkey::new([9u8; 32]);
        let mut accounts = HashMap::from([
            (proposer, wallet(0)),
            (STAKE_PK, stake_account(real_owner, 1_000)),
            (STAKING_STATS_ID, stats_account(1_000)),
            (REGISTRY_ACCOUNT_ID, registry_account()),
        ]);
        create_proposal(&mut accounts, proposer, ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()), 0);
        let result = vote(&mut accounts, attacker, STAKE_PK, VoteChoice::Yes, 1);
        assert!(matches!(result, Err(ExecError::Unauthorized(_))));
    }

    /// End-to-end sanity check that `StakingProgram` and `GovernanceProgram`
    /// actually compose: delegate real stake through the staking program,
    /// then vote with the resulting stake account, exactly as a live node
    /// would process two instructions in the same transaction.
    #[test]
    fn delegated_stake_from_the_staking_program_can_vote() {
        let staker = Pubkey::new([1u8; 32]);
        let mut accounts = HashMap::from([
            (staker, wallet(10_000)),
            (STAKING_STATS_ID, stats_account(0)),
            (REGISTRY_ACCOUNT_ID, registry_account()),
            (STAKING_REWARDS_POOL_ID, pool_account()),
        ]);

        let delegate_ix = Instruction {
            program_id: crate::ids::STAKING_PROGRAM_ID,
            accounts: vec![staker, STAKE_PK, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&crate::staking::StakingInstruction::Delegate { validator: Pubkey::new([50u8; 32]), amount: 5_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();

        create_proposal(&mut accounts, staker, ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()), 0);
        vote(&mut accounts, staker, STAKE_PK, VoteChoice::Yes, 1).unwrap();

        let proposal = read_proposal(&accounts, &PROPOSAL_PK).unwrap();
        assert_eq!(proposal.yes_stake, 5_000, "voting power must come from the real delegated amount");
    }

    /// The exact real, live-confirmed attack this closes (see
    /// `StakeAccountData::locked_until_round`'s doc comment): delegate,
    /// vote, then try to reclaim the same stake before the vote is
    /// decided - the Beanstalk/BonkDAO pattern of voting power decoupled
    /// from sustained economic commitment. Composes both real programs
    /// exactly as a live node would, not a synthetic single-program shape.
    #[test]
    fn undelegating_immediately_after_voting_is_rejected_until_the_proposal_is_decided() {
        let staker = Pubkey::new([1u8; 32]);
        let mut accounts = HashMap::from([
            (staker, wallet(10_000)),
            (STAKING_STATS_ID, stats_account(0)),
            (REGISTRY_ACCOUNT_ID, registry_account()),
            (STAKING_REWARDS_POOL_ID, pool_account()),
        ]);

        let delegate_ix = Instruction {
            program_id: crate::ids::STAKING_PROGRAM_ID,
            accounts: vec![staker, STAKE_PK, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&crate::staking::StakingInstruction::Delegate { validator: Pubkey::new([50u8; 32]), amount: 5_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();

        create_proposal(&mut accounts, staker, ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()), 0);
        vote(&mut accounts, staker, STAKE_PK, VoteChoice::Yes, 1).unwrap();

        let rule = quorum_rule(qchain_governance::RiskTier::Registry);
        let undelegate_ix = Instruction {
            program_id: crate::ids::STAKING_PROGRAM_ID,
            accounts: vec![STAKE_PK, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&crate::staking::StakingInstruction::Undelegate).unwrap(),
        };
        let too_early = StakingProgram.process(&mut accounts, &undelegate_ix, &staker, rule.voting_period_rounds - 1);
        assert!(too_early.is_err(), "reclaiming the stake before the vote it cast is decided must be rejected");
        assert_eq!(accounts[&STAKE_PK].balance, 5_000, "the position must remain fully intact while locked");

        // The lock now extends through the ENTIRE Registry window: voting period
        // PLUS the post-passage time-lock. Undelegating the instant the voting
        // period ends must still be rejected - a Yes-voter can't sit out the
        // review window with zero economic exposure while their vote drives
        // execution (audit finding C).
        let still_locked = StakingProgram.process(&mut accounts, &undelegate_ix, &staker, rule.voting_period_rounds);
        assert!(still_locked.is_err(), "a Registry-tier voter stays locked through the time-lock window, not just the voting period");
        assert_eq!(accounts[&STAKE_PK].balance, 5_000, "still fully intact during the time-lock");

        StakingProgram.process(&mut accounts, &undelegate_ix, &staker, rule.voting_period_rounds + rule.timelock_rounds).unwrap();
        assert_eq!(accounts[&STAKE_PK].balance, 0, "once voting period + time-lock have genuinely elapsed, the same position can undelegate normally");
    }

    /// A monetary change now runs on the `Economic` tier (task #213): it needs
    /// a 2/3 supermajority AND must wait out a mandatory review time-lock
    /// before `Execute` — a bare simple majority no longer flips the fee
    /// instantly. Also proves the per-proposal step limit lets a small,
    /// legitimate recalibration through (a big jump is rejected — see
    /// `a_single_proposal_cannot_move_a_parameter_past_the_step_limit`).
    #[test]
    fn economic_parameter_change_needs_supermajority_and_waits_out_the_timelock() {
        let proposer = Pubkey::new([1u8; 32]);
        let voter_a = Pubkey::new([2u8; 32]);
        let voter_b = Pubkey::new([3u8; 32]);
        let mut accounts = HashMap::from([
            (proposer, wallet(0)),
            (STAKE_PK, stake_account(voter_a, 700)),
            (OTHER_STAKE_PK, stake_account(voter_b, 300)),
            (STAKING_STATS_ID, stats_account(1_000)),
            (PARAMS_ACCOUNT_ID, params_account()),
        ]);

        // A small in-step recalibration from the default (180): well within the
        // 2× / abs-step per-proposal limit.
        let new_fee = crate::params::FEE_MIN_BASE_FEE_PER_BYTE + 20;
        create_proposal(&mut accounts, proposer, ProposalAction::SetBaseFeePerByte(new_fee), 0);
        vote(&mut accounts, voter_a, STAKE_PK, VoteChoice::Yes, 1).unwrap();
        vote(&mut accounts, voter_b, OTHER_STAKE_PK, VoteChoice::No, 1).unwrap();

        let rule = quorum_rule(qchain_governance::RiskTier::Economic);
        assert!(rule.timelock_rounds > 0, "a monetary change must carry a real review time-lock");
        let finalize_round = rule.voting_period_rounds;
        finalize(&mut accounts, proposer, finalize_round).unwrap();
        let proposal = read_proposal(&accounts, &PROPOSAL_PK).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Passed, "70% yes clears the 2/3 supermajority");

        let execute_ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![PROPOSAL_PK, PARAMS_ACCOUNT_ID, crate::ids::EMERGENCY_ACCOUNT_ID],
            data: borsh::to_vec(&GovernanceInstruction::Execute).unwrap(),
        };
        // Too early: the review time-lock has NOT elapsed — a monetary change
        // can no longer execute the instant it's finalized.
        assert!(GovernanceProgram.process(&mut accounts, &execute_ix, &proposer, finalize_round).is_err(), "an economic change must wait out its review time-lock");

        GovernanceProgram.process(&mut accounts, &execute_ix, &proposer, finalize_round + rule.timelock_rounds).unwrap();

        let params = crate::params::EconomicParams::try_from_slice(&accounts[&PARAMS_ACCOUNT_ID].data).unwrap();
        assert_eq!(params.base_fee_per_byte, new_fee);
        assert_eq!(params.dust_threshold, crate::params::EconomicParams::default().dust_threshold, "unrelated params must be untouched");
        assert_eq!(read_proposal(&accounts, &PROPOSAL_PK).unwrap().status, ProposalStatus::Executed);
    }

    /// The emergency guardian multisig (task #213): a threshold of guardians
    /// can PAUSE governance, which blocks `Execute` for a passed proposal,
    /// and can UNPAUSE to let it through — all without ever touching a balance.
    #[test]
    fn emergency_multisig_pauses_execution_and_can_never_touch_funds() {
        let proposer = Pubkey::new([1u8; 32]);
        let voter = Pubkey::new([2u8; 32]);
        let g1 = Pubkey::new([71u8; 32]);
        let g2 = Pubkey::new([72u8; 32]);
        let g3 = Pubkey::new([73u8; 32]);
        let outsider = Pubkey::new([99u8; 32]);
        let emergency = Account {
            data: genesis_emergency_account_data(vec![g1, g2, g3], 2),
            ..Account::new_wallet(GOVERNANCE_PROGRAM_ID)
        };
        let mut accounts = HashMap::from([
            (proposer, wallet(0)),
            (STAKE_PK, stake_account(voter, 1_000)),
            (STAKING_STATS_ID, stats_account(1_000)),
            (PARAMS_ACCOUNT_ID, params_account()),
            (crate::ids::EMERGENCY_ACCOUNT_ID, emergency),
        ]);

        let new_fee = crate::params::FEE_MIN_BASE_FEE_PER_BYTE + 10;
        create_proposal(&mut accounts, proposer, ProposalAction::SetBaseFeePerByte(new_fee), 0);
        vote(&mut accounts, voter, STAKE_PK, VoteChoice::Yes, 1).unwrap();
        let rule = quorum_rule(qchain_governance::RiskTier::Economic);
        finalize(&mut accounts, proposer, rule.voting_period_rounds).unwrap();
        let ready_round = rule.voting_period_rounds + rule.timelock_rounds;

        let pause = || Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![crate::ids::EMERGENCY_ACCOUNT_ID],
            data: borsh::to_vec(&GovernanceInstruction::EmergencyPause).unwrap(),
        };
        let unpause = || Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![crate::ids::EMERGENCY_ACCOUNT_ID],
            data: borsh::to_vec(&GovernanceInstruction::EmergencyUnpause).unwrap(),
        };
        let exec = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![PROPOSAL_PK, PARAMS_ACCOUNT_ID, crate::ids::EMERGENCY_ACCOUNT_ID],
            data: borsh::to_vec(&GovernanceInstruction::Execute).unwrap(),
        };

        // An outsider cannot pause.
        assert!(GovernanceProgram.process(&mut accounts, &pause(), &outsider, 1).is_err());
        // One guardian is below the threshold of 2 → not paused yet.
        GovernanceProgram.process(&mut accounts, &pause(), &g1, 1).unwrap();
        // A second DISTINCT guardian reaches the threshold → paused.
        GovernanceProgram.process(&mut accounts, &pause(), &g2, 2).unwrap();
        let em: EmergencyState = borsh::from_slice(&accounts[&crate::ids::EMERGENCY_ACCOUNT_ID].data).unwrap();
        assert!(em.paused, "two of three guardians reached the pause threshold");

        // Now Execute is blocked even though the proposal passed and the
        // timelock elapsed.
        assert!(GovernanceProgram.process(&mut accounts, &exec, &proposer, ready_round).is_err(), "a paused chain must block Execute");
        assert_eq!(
            crate::params::EconomicParams::try_from_slice(&accounts[&PARAMS_ACCOUNT_ID].data).unwrap().base_fee_per_byte,
            crate::params::EconomicParams::default().base_fee_per_byte,
            "the paused change must NOT have taken effect"
        );

        // Two guardians unpause → Execute proceeds.
        GovernanceProgram.process(&mut accounts, &unpause(), &g1, ready_round).unwrap();
        GovernanceProgram.process(&mut accounts, &unpause(), &g3, ready_round).unwrap();
        GovernanceProgram.process(&mut accounts, &exec, &proposer, ready_round).unwrap();
        assert_eq!(crate::params::EconomicParams::try_from_slice(&accounts[&PARAMS_ACCOUNT_ID].data).unwrap().base_fee_per_byte, new_fee);

        // The guardians never held or moved any balance: the emergency account
        // balance stayed zero throughout (it only ever carried the flag).
        assert_eq!(accounts[&crate::ids::EMERGENCY_ACCOUNT_ID].balance, 0, "the pause mechanism must never touch funds");
    }

    #[test]
    fn a_single_proposal_cannot_move_a_parameter_past_the_step_limit() {
        use crate::params::EconomicParams;
        let mut p = EconomicParams::default(); // base_fee default = 180
                                               // Doubling (180 -> 360) is within the 2× per-proposal factor.
        assert!(apply_economic_action(&mut p, &ProposalAction::SetBaseFeePerByte(360)).is_ok());
        assert_eq!(p.base_fee_per_byte, 360);
        // Tripling in one shot (360 -> 1080) exceeds both the 2× factor and the
        // absolute step — rejected. A big move must span several proposals.
        assert!(apply_economic_action(&mut p, &ProposalAction::SetBaseFeePerByte(1080)).is_err());
        assert_eq!(p.base_fee_per_byte, 360, "a rejected step must not mutate the parameter");
        // Emission APR: default 1200 bps. A move within the additive cap (500)
        // is fine; a larger jump is rejected.
        assert!(apply_economic_action(&mut p, &ProposalAction::SetEmissionApr(1_600)).is_ok());
        assert!(apply_economic_action(&mut p, &ProposalAction::SetEmissionApr(2_200)).is_err());
        assert_eq!(p.emission_apr_bps, 1_600);
    }

    #[test]
    fn economic_parameter_bounds_reject_catastrophic_values() {
        use crate::params::EconomicParams;
        let mut p = EconomicParams::default();
        // dust_threshold = u64::MAX would burn every account on touch - rejected.
        assert!(apply_economic_action(&mut p, &ProposalAction::SetDustThreshold(u64::MAX)).is_err());
        // base_fee below the anti-spam floor (e.g. 0 = free spam) - rejected.
        assert!(apply_economic_action(&mut p, &ProposalAction::SetBaseFeePerByte(0)).is_err());
        // gas_price 0 = free WASM compute - rejected.
        assert!(apply_economic_action(&mut p, &ProposalAction::SetGasPricePerFuel(0)).is_err());
        // The state must be untouched after every rejection.
        assert_eq!(p.dust_threshold, EconomicParams::default().dust_threshold);
        assert_eq!(p.base_fee_per_byte, EconomicParams::default().base_fee_per_byte);
        // An emission APR above the safety cap is rejected (unbounded inflation).
        assert!(apply_economic_action(&mut p, &ProposalAction::SetEmissionApr(u16::MAX)).is_err());
        assert_eq!(p.emission_apr_bps, EconomicParams::default().emission_apr_bps);
        // base_fee ABOVE the ceiling is rejected — the permanent-brick vector
        // (a value that makes every tx, including the recovery tx, unaffordable).
        assert!(apply_economic_action(&mut p, &ProposalAction::SetBaseFeePerByte(u64::MAX)).is_err());
        assert_eq!(p.base_fee_per_byte, EconomicParams::default().base_fee_per_byte);
        // gas_price ABOVE the ceiling is rejected too (symmetric bound).
        assert!(apply_economic_action(&mut p, &ProposalAction::SetGasPricePerFuel(u64::MAX)).is_err());
        // Legitimate SMALL in-step recalibrations still apply (a big single jump
        // is separately rejected by the per-proposal step limit — see
        // `a_single_proposal_cannot_move_a_parameter_past_the_step_limit`). `p`
        // is still at defaults here (all prior calls were rejections that never
        // mutated), so a 2× / within-cap move is in-step and applies.
        let d = EconomicParams::default();
        assert!(apply_economic_action(&mut p, &ProposalAction::SetBaseFeePerByte(d.base_fee_per_byte * 2)).is_ok());
        assert!(apply_economic_action(&mut p, &ProposalAction::SetGasPricePerFuel(2)).is_ok());
        assert!(apply_economic_action(&mut p, &ProposalAction::SetDustThreshold(d.dust_threshold * 2)).is_ok());
        assert!(apply_economic_action(&mut p, &ProposalAction::SetEmissionApr(d.emission_apr_bps + 400)).is_ok());
        assert_eq!(p.base_fee_per_byte, d.base_fee_per_byte * 2);
        assert_eq!(p.gas_price_per_fuel, 2);
        assert_eq!(p.dust_threshold, d.dust_threshold * 2);
        assert_eq!(p.emission_apr_bps, d.emission_apr_bps + 400);
    }

    #[test]
    fn an_economic_tie_fails_the_supermajority() {
        let proposer = Pubkey::new([1u8; 32]);
        let voter_a = Pubkey::new([2u8; 32]);
        let voter_b = Pubkey::new([3u8; 32]);
        let mut accounts = HashMap::from([
            (proposer, wallet(0)),
            (STAKE_PK, stake_account(voter_a, 500)),
            (OTHER_STAKE_PK, stake_account(voter_b, 500)),
            (STAKING_STATS_ID, stats_account(1_000)),
            (PARAMS_ACCOUNT_ID, params_account()),
        ]);
        create_proposal(&mut accounts, proposer, ProposalAction::SetDustThreshold(1), 0);
        vote(&mut accounts, voter_a, STAKE_PK, VoteChoice::Yes, 1).unwrap();
        vote(&mut accounts, voter_b, OTHER_STAKE_PK, VoteChoice::No, 1).unwrap();

        let rule = quorum_rule(qchain_governance::RiskTier::Economic);
        finalize(&mut accounts, proposer, rule.voting_period_rounds).unwrap();
        let proposal = read_proposal(&accounts, &PROPOSAL_PK).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected, "a 500/500 tie is nowhere near the 2/3 supermajority a monetary change needs");
    }
}
