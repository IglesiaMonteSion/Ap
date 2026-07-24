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
use qchain_governance::{
    quorum_rule, Proposal, ProposalAction, ProposalId, ProposalStatus, VoteChoice,
};
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
    CreateProposal {
        id: ProposalId,
        action: ProposalAction,
    },
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
    /// PRUNE a terminal proposal (roadmap #16). accounts[0] = the proposal
    /// account, accounts[1] = the proposal's proposer wallet (for a deposit
    /// refund), accounts[2] = the canonical `BURN_ADDRESS` (for a deposit
    /// forfeit). Permissionless: anyone can call it once the proposal is
    /// `Rejected`/`Executed` AND `PROPOSAL_RETENTION_ROUNDS` have elapsed past
    /// its voting-end. It settles the anti-spam deposit (refund if the proposal
    /// reached the participation floor, burn otherwise) and clears the proposal
    /// account's data — reclaiming the unbounded `voted_stake_accounts` blob so
    /// terminal proposals don't accumulate in state forever. Appended
    /// (discriminant 6) so the wallet's Vote/Finalize/Execute encodings (1/2/3)
    /// stay byte-identical.
    CloseProposal,
}

fn borsh_err(e: impl std::fmt::Display) -> ExecError {
    ExecError::ProgramError(e.to_string())
}

/// Domain separator for the canonical governance-proposal address. Bumping this
/// would change every future proposal address; keep it stable.
pub(crate) const PROPOSAL_ADDRESS_DOMAIN: &[u8] = b"qchain-governance-proposal-v1";

/// The canonical address of a governance proposal, derived deterministically
/// from `(proposer, id)`. `CreateProposal` REQUIRES the new proposal account to
/// live here (an attacker can't squat a chosen address, and the address is
/// auditable/reproducible off-chain). The CLI derives the same value via
/// `qchain_execution::governance::derive_proposal_address`. SHA3-256,
/// domain-separated (same construction as `wasm::derive_pda`).
pub fn derive_proposal_address(proposer: &Pubkey, id: ProposalId) -> Pubkey {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PROPOSAL_ADDRESS_DOMAIN);
    h.update(proposer.to_bytes());
    h.update(id.to_le_bytes());
    Pubkey::new(h.finalize().into())
}

/// Read a governance proposal account, ENFORCING that it is genuinely a proposal
/// account before trusting its bytes (audit v8.6.13 #1 / LESSONS-LEDGER EC-01).
///
/// Without the owner check, ANY account whose `data` merely decodes as a
/// `Proposal` was accepted — and a signer can write arbitrary bytes into their
/// OWN (system-owned) account via the WASM `host_set_data` boundary
/// (`ledger.rs`), so an attacker could forge a `Passed` proposal in their own
/// wallet account and have `Execute` apply it WITHOUT any vote. Requiring
/// `owner == GOVERNANCE_PROGRAM_ID` closes this: a proposal account is only ever
/// created governance-owned by `CreateProposal` (with a fresh `Voting`
/// proposal), and a WASM contract can NEVER set an account's owner to the
/// governance program (only to its own `program_id`, via a verified PDA claim).
/// Byte-identical for every legitimately-created proposal (all are
/// governance-owned). The canonical-address check is enforced at CREATE time
/// (new proposals), not here, so proposals created before this change — at
/// arbitrary addresses — still read.
fn read_proposal(accounts: &HashMap<Pubkey, Account>, pk: &Pubkey) -> Result<Proposal, ExecError> {
    let account = accounts.get(pk).ok_or(ExecError::AccountNotFound(*pk))?;
    if account.owner != GOVERNANCE_PROGRAM_ID {
        return Err(ExecError::Unauthorized(
            "proposal account must be owned by the governance program (a forged proposal in a non-governance account is rejected)".into(),
        ));
    }
    // `read_or_legacy` so a proposal account created before the anti-spam deposit
    // field existed (roadmap #16) still decodes — as a zero-deposit proposal.
    Proposal::read_or_legacy(&account.data)
        .ok_or_else(|| ExecError::ProgramError("proposal account does not decode".into()))
}

fn write_proposal(
    accounts: &mut HashMap<Pubkey, Account>,
    pk: &Pubkey,
    proposal: &Proposal,
) -> Result<(), ExecError> {
    accounts
        .get_mut(pk)
        .ok_or(ExecError::AccountNotFound(*pk))?
        .data = borsh::to_vec(proposal).map_err(borsh_err)?;
    Ok(())
}

pub struct GovernanceProgram;

impl NativeProgram for GovernanceProgram {
    fn process(
        &self,
        accounts: &mut HashMap<Pubkey, Account>,
        instruction: &Instruction,
        payer: &Pubkey,
        current_round: Round,
    ) -> Result<(), ExecError> {
        let instr = GovernanceInstruction::try_from_slice(&instruction.data).map_err(borsh_err)?;
        match instr {
            GovernanceInstruction::CreateProposal { id, action } => {
                let proposer = *instruction.accounts.first().ok_or_else(|| {
                    ExecError::ProgramError("CreateProposal requires accounts[0]".into())
                })?;
                let proposal_pk = *instruction.accounts.get(1).ok_or_else(|| {
                    ExecError::ProgramError("CreateProposal requires accounts[1]".into())
                })?;
                // accounts[2] = the canonical staking-stats singleton. The bonded
                // supply here is SNAPSHOTTED into the proposal as the frozen quorum
                // denominator (task #213), so a later shrink of total_staked can't
                // lower the participation bar. Pinned to the canonical id for the
                // same reason Finalize/Execute pin theirs — a caller must not be
                // able to name a look-alike account with a tiny total.
                let stats_pk =
                    *instruction.accounts.get(2).ok_or_else(|| ExecError::ProgramError("CreateProposal requires accounts[2] = the staking-stats singleton (voting-power snapshot)".into()))?;
                if stats_pk != crate::ids::STAKING_STATS_ID {
                    return Err(ExecError::ProgramError(
                        "CreateProposal accounts[2] must be the canonical staking-stats account"
                            .into(),
                    ));
                }
                // accounts[3] = the canonical economic-params singleton (read-only),
                // so the anti-spam deposit (roadmap #16) is read from the SAME
                // authoritative source the ledger uses. Pinned like the others. When
                // `governance_proposal_deposit == 0` (the default) this is a no-op —
                // nothing is charged — so a network without the deposit configured
                // behaves byte-identically; only the account-list of CreateProposal
                // grew (an operator/CLI action, not a wallet one — the wallet never
                // creates proposals), so node + CLI upgrade together.
                let params_pk = *instruction.accounts.get(3).ok_or_else(|| {
                    ExecError::ProgramError(
                        "CreateProposal requires accounts[3] = the canonical economic-params account (anti-spam deposit source)".into(),
                    )
                })?;
                if params_pk != crate::ids::PARAMS_ACCOUNT_ID {
                    return Err(ExecError::ProgramError(
                        "CreateProposal accounts[3] must be the canonical economic-params account".into(),
                    ));
                }
                if proposer != *payer {
                    return Err(ExecError::Unauthorized(
                        "CreateProposal's proposer account must be the transaction payer".into(),
                    ));
                }
                // The proposal account MUST live at its canonical address
                // (audit v8.6.13 #1 / EC-01): `derive_proposal_address(proposer, id)`.
                // This makes the address deterministic + auditable and prevents an
                // attacker from squatting an arbitrary address; combined with the
                // owner check in `read_proposal`, forgery is closed by construction.
                let canonical = derive_proposal_address(&proposer, id);
                if proposal_pk != canonical {
                    return Err(ExecError::ProgramError(
                        "CreateProposal accounts[1] must be the canonical proposal address derive_proposal_address(proposer, id)".into(),
                    ));
                }
                if accounts.contains_key(&proposal_pk) {
                    return Err(ExecError::ProgramError(
                        "proposal account already exists".into(),
                    ));
                }
                let snapshot_total_staked = u64::try_from_slice(
                    &accounts
                        .get(&stats_pk)
                        .ok_or(ExecError::AccountNotFound(stats_pk))?
                        .data,
                )
                .map_err(borsh_err)?;
                // The anti-spam deposit (0 = off). `read_or_legacy` tolerates a
                // pre-#16 params blob (deposit defaults to 0).
                let deposit = crate::params::EconomicParams::read_or_legacy(
                    &accounts
                        .get(&params_pk)
                        .ok_or(ExecError::AccountNotFound(params_pk))?
                        .data,
                )
                .ok_or_else(|| ExecError::ProgramError("economic-params account is unreadable".into()))?
                .governance_proposal_deposit;

                // Charge the deposit from the proposer (== payer, already in the
                // working set with the tx fee debited) and HOLD it in the proposal
                // account's balance. Checked arithmetic (#218): reject the whole
                // transition on underflow rather than wrap.
                if deposit > 0 {
                    let proposer_acct = accounts
                        .get_mut(&proposer)
                        .ok_or(ExecError::AccountNotFound(proposer))?;
                    if proposer_acct.balance < deposit {
                        return Err(ExecError::ProgramError(format!(
                            "insufficient balance for the governance proposal deposit: need {deposit}, have {}",
                            proposer_acct.balance
                        )));
                    }
                    proposer_acct.balance = crate::arith::sub_u64(proposer_acct.balance, deposit)?;
                }
                let proposal =
                    Proposal::new(id, proposer, action, current_round, snapshot_total_staked, deposit);
                let mut account = Account::new_wallet(GOVERNANCE_PROGRAM_ID);
                account.balance = deposit;
                account.data = borsh::to_vec(&proposal).map_err(borsh_err)?;
                accounts.insert(proposal_pk, account);
            }

            GovernanceInstruction::Vote { choice } => {
                let proposal_pk = *instruction
                    .accounts
                    .first()
                    .ok_or_else(|| ExecError::ProgramError("Vote requires accounts[0]".into()))?;
                let stake_pk = *instruction
                    .accounts
                    .get(1)
                    .ok_or_else(|| ExecError::ProgramError("Vote requires accounts[1]".into()))?;

                let stake_account = accounts
                    .get(&stake_pk)
                    .ok_or(ExecError::AccountNotFound(stake_pk))?;
                // Defense in depth: the vote weight is derived from bytes in
                // this account's `data`, so it must be a genuine staking-program
                // account, not an arbitrary account whose `data` an attacker
                // packed to forge a large `amount`. No current instruction lets
                // a caller write arbitrary bytes with their own pubkey as the
                // StakeAccountData layout, but pinning the owner here makes a
                // future arbitrary-data primitive unable to silently enable
                // vote-weight forgery.
                if stake_account.owner != crate::ids::STAKING_PROGRAM_ID {
                    return Err(ExecError::Unauthorized(
                        "Vote's stake account must be owned by the staking program".into(),
                    ));
                }
                let mut stake_data =
                    StakeAccountData::read_or_legacy(&stake_account.data).map_err(borsh_err)?;
                if stake_data.owner != *payer {
                    return Err(ExecError::Unauthorized(
                        "Vote's stake account must be owned by the transaction payer".into(),
                    ));
                }
                if stake_data.amount == 0 {
                    return Err(ExecError::ProgramError(
                        "stake account has no active (undelegated) stake to vote with".into(),
                    ));
                }

                let mut proposal = read_proposal(accounts, &proposal_pk)?;
                if proposal.status != ProposalStatus::Voting {
                    return Err(ExecError::ProgramError(
                        "proposal is not open for voting".into(),
                    ));
                }
                if current_round >= proposal.voting_ends_round {
                    return Err(ExecError::ProgramError(
                        "voting period has ended - call Finalize instead".into(),
                    ));
                }
                // Per-voter creation-time snapshot (roadmap #6). The position
                // must have existed at or before the proposal was created; stake
                // delegated AFTER a proposal opened cannot vote on it. This is
                // sound in the access-list model because a v6 stake account's
                // `amount` is immutable after `Delegate` (only ever zeroed by
                // Undelegate/slash, never increased), so a position that predates
                // the proposal held exactly this `amount` at snapshot time — the
                // live weight IS the historical weight. It closes the residual the
                // aggregate `snapshot_total_staked` (task #213) left open: a
                // flash-staker could still swing a SPECIFIC proposal with capital
                // acquired after it opened, even though they couldn't lower the
                // participation bar. A legacy (pre-#6) position decodes with
                // `created_round = 0` (predates everything), so an existing
                // delegator's rights are unchanged.
                if stake_data.created_round > proposal.created_round {
                    return Err(ExecError::ProgramError(
                        "this stake position was opened after the proposal was created — stake delegated after a proposal opens cannot vote on it (per-voter creation-time snapshot)".into(),
                    ));
                }
                // Formal bound on the proposal's voter blob (task #18): a vote
                // beyond `MAX_PROPOSAL_VOTES` distinct voters is rejected so the
                // on-chain `voted_stake_accounts` Vec can't grow without bound.
                // Generous ceiling — unreachable at realistic turnout, so a
                // network below it is byte-identical; only a blob-inflation
                // attack (a whale splitting into that many tiny stake accounts)
                // ever hits it.
                if proposal.at_vote_capacity() {
                    return Err(ExecError::ProgramError(
                        "this proposal has reached the maximum number of voters".into(),
                    ));
                }
                if !proposal.record_vote(stake_pk, choice, stake_data.amount) {
                    return Err(ExecError::ProgramError(
                        "this stake account already voted on this proposal".into(),
                    ));
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
                let lock_until = proposal
                    .voting_ends_round
                    .saturating_add(quorum_rule(proposal.action.risk_tier()).timelock_rounds);
                stake_data.locked_until_round = stake_data.locked_until_round.max(lock_until);
                accounts.get_mut(&stake_pk).unwrap().data =
                    borsh::to_vec(&stake_data).map_err(borsh_err)?;
            }

            GovernanceInstruction::Finalize => {
                let proposal_pk = *instruction.accounts.first().ok_or_else(|| {
                    ExecError::ProgramError("Finalize requires accounts[0]".into())
                })?;
                let stats_pk = *instruction.accounts.get(1).ok_or_else(|| {
                    ExecError::ProgramError("Finalize requires accounts[1]".into())
                })?;

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
                    return Err(ExecError::ProgramError(
                        "proposal has already been finalized".into(),
                    ));
                }
                if current_round < proposal.voting_ends_round {
                    return Err(ExecError::ProgramError(
                        "voting period has not ended yet".into(),
                    ));
                }

                let outcome = proposal.evaluate();
                proposal.status = outcome;
                if outcome == ProposalStatus::Passed {
                    proposal.passed_round = Some(current_round);
                }
                write_proposal(accounts, &proposal_pk, &proposal)?;
            }

            GovernanceInstruction::Execute => {
                let proposal_pk = *instruction.accounts.first().ok_or_else(|| {
                    ExecError::ProgramError("Execute requires accounts[0]".into())
                })?;
                // The account this action actually mutates - the
                // algorithm registry for a Registry-tier action, the
                // economic-params singleton for a Low-tier one. The
                // caller (a CLI/client) is expected to have read the
                // proposal first and pass the matching target; this
                // program just applies whichever variant `proposal.action`
                // turns out to be against whatever it's handed.
                let target_pk = *instruction.accounts.get(1).ok_or_else(|| {
                    ExecError::ProgramError("Execute requires accounts[1]".into())
                })?;
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
                let emergency_pk = *instruction.accounts.get(2).ok_or_else(|| {
                    ExecError::ProgramError(
                        "Execute requires accounts[2] = the emergency governance singleton".into(),
                    )
                })?;
                if emergency_pk != crate::ids::EMERGENCY_ACCOUNT_ID {
                    return Err(ExecError::ProgramError(
                        "Execute accounts[2] must be the canonical emergency governance account"
                            .into(),
                    ));
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
                    return Err(ExecError::ProgramError(
                        "proposal has not passed - nothing to execute".into(),
                    ));
                }
                let rule = quorum_rule(proposal.action.risk_tier());
                let passed_round = proposal.passed_round.ok_or_else(|| {
                    ExecError::ProgramError("passed proposal is missing passed_round".into())
                })?;
                // Checked arithmetic (EC-05): `passed_round + timelock` could
                // otherwise panic-halt the network in release (overflow-checks).
                // `saturating_add` fails CLOSED — if it saturated, the timelock is
                // treated as never-elapsed and Execute stays blocked.
                if current_round < passed_round.saturating_add(rule.timelock_rounds) {
                    return Err(ExecError::ProgramError(
                        "the mandatory review time-lock has not elapsed yet".into(),
                    ));
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
                    ProposalAction::ActivateAlgorithm(_)
                    | ProposalAction::DeprecateAlgorithm { .. }
                    | ProposalAction::RetireAlgorithm { .. } => {
                        if target_pk != crate::ids::REGISTRY_ACCOUNT_ID {
                            return Err(ExecError::ProgramError(
                                "Execute accounts[1] must be the canonical registry account for a registry action".into(),
                            ));
                        }
                        let target_account = accounts
                            .get(&target_pk)
                            .ok_or(ExecError::AccountNotFound(target_pk))?;
                        let mut registry: Vec<RegistryEntry> =
                            Vec::try_from_slice(&target_account.data).map_err(borsh_err)?;
                        apply_registry_action(&mut registry, &proposal.action, current_round)?;
                        accounts.get_mut(&target_pk).unwrap().data =
                            borsh::to_vec(&registry).map_err(borsh_err)?;
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
                        let target_account = accounts
                            .get(&target_pk)
                            .ok_or(ExecError::AccountNotFound(target_pk))?;
                        let mut params =
                            crate::params::EconomicParams::read_or_legacy(&target_account.data)
                                .ok_or_else(|| {
                                    ExecError::ProgramError(
                                        "economic-params account is unreadable".into(),
                                    )
                                })?;
                        apply_economic_action(&mut params, &proposal.action)?;
                        accounts.get_mut(&target_pk).unwrap().data =
                            borsh::to_vec(&params).map_err(borsh_err)?;
                    }
                }

                proposal.status = ProposalStatus::Executed;
                write_proposal(accounts, &proposal_pk, &proposal)?;
            }

            GovernanceInstruction::EmergencyPause => {
                apply_emergency_approval(accounts, instruction, payer, true)?
            }
            GovernanceInstruction::EmergencyUnpause => {
                apply_emergency_approval(accounts, instruction, payer, false)?
            }
            GovernanceInstruction::CloseProposal => {
                apply_close_proposal(accounts, instruction, current_round)?
            }
        }
        Ok(())
    }
}

/// Minimum rounds a terminal proposal is retained (measured from its
/// `voting_ends_round`) before `CloseProposal` may prune it (roadmap #16).
/// Generous — comfortably larger than any tier's voting period + execution
/// time-lock (~200 + ~120 rounds max) — so a proposal is never pruned while it
/// still has a pending effect: only `Rejected`/`Executed` proposals are
/// closeable, and an `Executed` one already ran, so its execution window (which
/// opened at `passed_round + timelock`, long before `voting_ends + retention`)
/// is long past. At the ~500 ms reference round interval this is ~42 minutes.
const PROPOSAL_RETENTION_ROUNDS: Round = 5_000;

/// Prune a terminal proposal and settle its anti-spam deposit (roadmap #16).
/// accounts[0] = proposal, accounts[1] = the proposer (deposit refund target),
/// accounts[2] = `BURN_ADDRESS` (deposit forfeit sink). Permissionless: anyone
/// can janitor a stale terminal proposal to reclaim its state.
///
/// The proposal must be `Rejected` or `Executed` (never `Voting`, and never a
/// `Passed`-but-not-yet-`Executed` proposal — that still has a pending effect,
/// so it's left until it's executed) AND at least `PROPOSAL_RETENTION_ROUNDS`
/// past its voting end. The proposal account's balance holds the deposit; it is
/// REFUNDED to the proposer if the proposal reached the participation floor (a
/// genuine, engaged proposal) and BURNED otherwise (spam nobody voted on). Any
/// balance beyond the recorded deposit (e.g. an unsolicited transfer to the
/// proposal address) is burned defensively. Finally the proposal account's data
/// is cleared — reclaiming the unbounded `voted_stake_accounts` blob so terminal
/// proposals don't accumulate in state forever.
fn apply_close_proposal(
    accounts: &mut HashMap<Pubkey, Account>,
    instruction: &Instruction,
    current_round: Round,
) -> Result<(), ExecError> {
    let proposal_pk = *instruction
        .accounts
        .first()
        .ok_or_else(|| ExecError::ProgramError("CloseProposal requires accounts[0] = the proposal".into()))?;
    let refund_pk = *instruction
        .accounts
        .get(1)
        .ok_or_else(|| ExecError::ProgramError("CloseProposal requires accounts[1] = the proposer (refund target)".into()))?;
    let burn_pk = *instruction
        .accounts
        .get(2)
        .ok_or_else(|| ExecError::ProgramError("CloseProposal requires accounts[2] = the canonical burn address".into()))?;
    if burn_pk != crate::ids::BURN_ADDRESS {
        return Err(ExecError::ProgramError(
            "CloseProposal accounts[2] must be the canonical burn address".into(),
        ));
    }

    let proposal = read_proposal(accounts, &proposal_pk)?;

    // Only prune a settled, terminal proposal — never one still open, and never
    // a Passed-awaiting-execution one (it still has a pending effect).
    match proposal.status {
        ProposalStatus::Rejected | ProposalStatus::Executed => {}
        ProposalStatus::Voting => {
            return Err(ExecError::ProgramError("proposal is still open for voting — cannot close it".into()));
        }
        ProposalStatus::Passed => {
            return Err(ExecError::ProgramError(
                "proposal passed but has not been executed yet — execute it before closing".into(),
            ));
        }
    }
    let closeable_at = proposal.voting_ends_round.saturating_add(PROPOSAL_RETENTION_ROUNDS);
    if current_round < closeable_at {
        return Err(ExecError::ProgramError(format!(
            "proposal is within its retention window — closeable at round {closeable_at}, current round is {current_round}"
        )));
    }
    // accounts[1] must genuinely be this proposal's proposer, so a caller can't
    // redirect a refund to an account they control.
    if refund_pk != proposal.proposer {
        return Err(ExecError::ProgramError(
            "CloseProposal accounts[1] must be the proposal's own proposer".into(),
        ));
    }

    // The proposal account holds the deposit in its balance. Split it: refund the
    // recorded deposit to the proposer IF the proposal reached the participation
    // floor; burn everything else. Conservation holds — the whole balance is
    // routed (refund + burn == balance), nothing is destroyed off-book.
    let held = accounts
        .get(&proposal_pk)
        .ok_or(ExecError::AccountNotFound(proposal_pk))?
        .balance;
    let refund = if proposal.deposit > 0 && proposal.reached_participation_floor() {
        proposal.deposit.min(held)
    } else {
        0
    };
    let burn = crate::arith::sub_u64(held, refund)?;

    if refund > 0 {
        // Credit the proposer. If their account no longer exists in the working
        // set (they emptied their wallet), create a fresh one to receive it.
        let proposer_acct = accounts
            .entry(refund_pk)
            .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()));
        proposer_acct.balance = crate::arith::add_u64(proposer_acct.balance, refund)?;
    }
    if burn > 0 {
        let burn_acct = accounts
            .entry(burn_pk)
            .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()));
        burn_acct.balance = crate::arith::add_u64(burn_acct.balance, burn)?;
    }

    // Prune: clear the proposal account's balance (routed out above) and its data
    // (the unbounded voted-accounts blob). The leaf itself remains (a native
    // program can't delete an account through the working-set commit), but the
    // growth term — the Borsh Proposal payload — is reclaimed. A subsequent
    // CloseProposal on the emptied account fails to decode the proposal (empty
    // data), so it can't be double-settled.
    let proposal_acct = accounts
        .get_mut(&proposal_pk)
        .ok_or(ExecError::AccountNotFound(proposal_pk))?;
    proposal_acct.balance = 0;
    proposal_acct.data = Vec::new();
    Ok(())
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
    let em_pk = *instruction.accounts.first().ok_or_else(|| {
        ExecError::ProgramError(
            "Emergency instruction requires accounts[0] = the emergency singleton".into(),
        )
    })?;
    if em_pk != crate::ids::EMERGENCY_ACCOUNT_ID {
        return Err(ExecError::ProgramError(
            "Emergency accounts[0] must be the canonical emergency governance account".into(),
        ));
    }
    let account = accounts
        .get(&em_pk)
        .ok_or(ExecError::AccountNotFound(em_pk))?;
    let mut state = EmergencyState::try_from_slice(&account.data).map_err(borsh_err)?;

    if state.guardians.is_empty() || state.threshold == 0 {
        return Err(ExecError::ProgramError(
            "no emergency guardians are configured on this network".into(),
        ));
    }
    if !state.guardians.contains(payer) {
        return Err(ExecError::Unauthorized(
            "only a configured guardian can approve an emergency pause/unpause".into(),
        ));
    }
    if state.paused == want_paused {
        return Err(ExecError::ProgramError(
            if want_paused {
                "governance is already paused"
            } else {
                "governance is not paused"
            }
            .into(),
        ));
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

fn apply_registry_action(
    registry: &mut Vec<RegistryEntry>,
    action: &ProposalAction,
    current_round: Round,
) -> Result<(), ExecError> {
    match action {
        ProposalAction::ActivateAlgorithm(entry) => {
            if registry.iter().any(|e| e.id == entry.id) {
                return Err(ExecError::ProgramError(
                    "algorithm id is already registered".into(),
                ));
            }
            registry.push(entry.clone());
        }
        ProposalAction::DeprecateAlgorithm {
            id,
            retirement_round,
        } => {
            let entry = registry
                .iter_mut()
                .find(|e| e.id == *id)
                .ok_or_else(|| ExecError::ProgramError("unknown algorithm id".into()))?;
            if entry.status != AlgorithmStatus::Active {
                return Err(ExecError::ProgramError(
                    "only an Active entry can be deprecated".into(),
                ));
            }
            entry.status = AlgorithmStatus::Deprecated {
                retirement_epoch: *retirement_round,
            };
        }
        ProposalAction::RetireAlgorithm { id } => {
            let entry = registry
                .iter_mut()
                .find(|e| e.id == *id)
                .ok_or_else(|| ExecError::ProgramError("unknown algorithm id".into()))?;
            match entry.status {
                AlgorithmStatus::Deprecated { retirement_epoch }
                    if current_round >= retirement_epoch =>
                {
                    entry.status = AlgorithmStatus::Retired;
                }
                AlgorithmStatus::Deprecated { .. } => {
                    return Err(ExecError::ProgramError(
                        "retirement round has not been reached yet".into(),
                    ));
                }
                _ => {
                    return Err(ExecError::ProgramError(
                        "only a Deprecated entry can be retired".into(),
                    ))
                }
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
fn apply_economic_action(
    params: &mut crate::params::EconomicParams,
    action: &ProposalAction,
) -> Result<(), ExecError> {
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
            if !within_change_limit(
                params.base_fee_per_byte,
                *v,
                MAX_ECON_CHANGE_FACTOR,
                BASE_FEE_ABS_STEP,
            ) {
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
            if !within_change_limit(
                params.dust_threshold,
                *v,
                MAX_ECON_CHANGE_FACTOR,
                DUST_ABS_STEP,
            ) {
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
                return Err(ExecError::ProgramError(
                    "gas_price_per_fuel cannot be zero - would make WASM compute free (DoS)".into(),
                ));
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
            if !within_change_limit(
                params.gas_price_per_fuel,
                *v,
                MAX_ECON_CHANGE_FACTOR,
                GAS_ABS_STEP,
            ) {
                return Err(ExecError::ProgramError(format!(
                    "gas_price_per_fuel {v} moves more than {MAX_ECON_CHANGE_FACTOR}× (or {GAS_ABS_STEP}) from the current {} in one proposal",
                    params.gas_price_per_fuel
                )));
            }
            params.gas_price_per_fuel = *v;
        }
        ProposalAction::SetStakingCommissionBps(v) => {
            if *v > 10_000 {
                return Err(ExecError::ProgramError(
                    "staking commission cannot exceed 10,000 bps (100%)".into(),
                ));
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
        ProposalAction::ActivateAlgorithm(_)
        | ProposalAction::DeprecateAlgorithm { .. }
        | ProposalAction::RetireAlgorithm { .. } => {
            unreachable!("Execute only calls apply_economic_action for Low-tier actions")
        }
    }
    Ok(())
}

/// Builds the genesis algorithm-registry account contents - callers (node
/// startup) write this into `REGISTRY_ACCOUNT_ID` once, at genesis.
pub fn genesis_registry_account_data() -> Vec<u8> {
    borsh::to_vec(&qchain_crypto::registry::genesis_registry())
        .expect("genesis registry always serializes")
}

/// Builds the genesis economic-params account contents - callers (node
/// startup) write this into `PARAMS_ACCOUNT_ID` once, at genesis.
pub fn genesis_params_account_data() -> Vec<u8> {
    borsh::to_vec(&crate::params::EconomicParams::default())
        .expect("default economic params always serialize")
}

/// Builds the genesis emergency-governance account contents (task #213) —
/// callers (node startup) write this into `EMERGENCY_ACCOUNT_ID` once, at
/// genesis. `threshold` is clamped to `1..=guardians.len()` so a
/// mis-configured genesis can never require more approvals than there are
/// guardians (which would make the pause un-triggerable). An empty guardian
/// set leaves the feature inert (no one can pause), which is the safe default.
pub fn genesis_emergency_account_data(guardians: Vec<Pubkey>, threshold: u8) -> Vec<u8> {
    let threshold = if guardians.is_empty() {
        0
    } else {
        threshold.clamp(1, guardians.len().min(u8::MAX as usize) as u8)
    };
    let state = EmergencyState {
        guardians,
        threshold,
        paused: false,
        pause_approvals: Vec::new(),
        unpause_approvals: Vec::new(),
    };
    borsh::to_vec(&state).expect("emergency state always serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{
        PARAMS_ACCOUNT_ID, REGISTRY_ACCOUNT_ID, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID,
    };
    use crate::staking::StakingProgram;
    use qchain_crypto::{ALGORITHM_ED25519, ALGORITHM_ML_DSA_65};

    // The primary test proposal's canonical address: proposer [1;32], id 1
    // (audit v8.6.13 #1 — CreateProposal now requires the canonical address).
    fn proposal_pk() -> Pubkey {
        derive_proposal_address(&Pubkey::new([1u8; 32]), 1)
    }
    const STAKE_PK: Pubkey = Pubkey::new([31u8; 32]);
    const OTHER_STAKE_PK: Pubkey = Pubkey::new([32u8; 32]);

    #[test]
    fn governance_instruction_encoding_is_stable() {
        // The WASM wallet (crates/qchain-wasm) hand-rolls these encodings to
        // avoid depending on this crate (which pulls wasmtime, no wasm target).
        // If GovernanceInstruction/VoteChoice ever change, this guard fails so
        // the wallet's sign_vote/finalize/execute are updated in lock-step.
        assert_eq!(
            borsh::to_vec(&GovernanceInstruction::Vote {
                choice: VoteChoice::Yes
            })
            .unwrap(),
            vec![1u8, 0],
            "wasm Vote(Yes) encoding out of sync"
        );
        assert_eq!(
            borsh::to_vec(&GovernanceInstruction::Vote {
                choice: VoteChoice::No
            })
            .unwrap(),
            vec![1u8, 1],
            "wasm Vote(No) encoding out of sync"
        );
        assert_eq!(
            borsh::to_vec(&GovernanceInstruction::Vote {
                choice: VoteChoice::Abstain
            })
            .unwrap(),
            vec![1u8, 2],
            "wasm Vote(Abstain) encoding out of sync"
        );
        assert_eq!(
            borsh::to_vec(&GovernanceInstruction::Finalize).unwrap(),
            vec![2u8],
            "wasm Finalize encoding out of sync"
        );
        assert_eq!(
            borsh::to_vec(&GovernanceInstruction::Execute).unwrap(),
            vec![3u8],
            "wasm Execute encoding out of sync"
        );
        // CloseProposal (roadmap #16) is APPENDED at discriminant 6, so it does
        // not shift the wallet's Vote/Finalize/Execute encodings (1/2/3) above.
        assert_eq!(
            borsh::to_vec(&GovernanceInstruction::CloseProposal).unwrap(),
            vec![6u8],
            "CloseProposal must stay discriminant 6 (appended, no shift)"
        );
    }

    #[test]
    fn a_forged_passed_proposal_in_a_non_governance_account_cannot_be_executed() {
        // EXPLOIT TEST — audit v8.6.13 #1 / LESSONS-LEDGER EC-01. Reproduces the
        // exact forgery: an attacker uses the WASM `host_set_data` boundary
        // (ledger.rs) to write forged `Passed` proposal bytes into their OWN
        // (system-owned) account, then calls `Execute` naming it. The owner check
        // in `read_proposal` must REJECT it — WITHOUT the check, `Execute` applies
        // the action with NO vote (governance forged). Fails without the fix.
        let attacker = Pubkey::new([7u8; 32]);
        let mut forged = Proposal::new(
            1,
            attacker,
            ProposalAction::SetBaseFeePerByte(999),
            0,
            1_000_000,
            0,
        );
        forged.status = ProposalStatus::Passed;
        forged.passed_round = Some(1);
        // System-owned wallet with forged data — what host_set_data lets a signer
        // write to their own account.
        let forged_account = Account {
            data: borsh::to_vec(&forged).unwrap(),
            ..Account::new_wallet(Pubkey::system_program_id())
        };
        let attacker_addr = Pubkey::new([8u8; 32]);
        let mut accounts = HashMap::from([
            (attacker_addr, forged_account),
            (PARAMS_ACCOUNT_ID, params_account()),
        ]);
        let params_before = accounts[&PARAMS_ACCOUNT_ID].data.clone();

        let execute_ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![
                attacker_addr,
                PARAMS_ACCOUNT_ID,
                crate::ids::EMERGENCY_ACCOUNT_ID,
            ],
            data: borsh::to_vec(&GovernanceInstruction::Execute).unwrap(),
        };
        let result = GovernanceProgram.process(&mut accounts, &execute_ix, &attacker, 100);
        assert!(
            matches!(result, Err(ExecError::Unauthorized(_))),
            "a forged proposal in a non-governance account must be rejected, got {result:?}"
        );
        assert_eq!(
            accounts[&PARAMS_ACCOUNT_ID].data, params_before,
            "a forged Execute must not mutate the real params singleton"
        );
    }

    #[test]
    fn create_proposal_requires_the_canonical_address() {
        // Audit v8.6.13 #1 / EC-01. A proposal must live at
        // derive_proposal_address(proposer, id); an arbitrary address is rejected.
        let proposer = Pubkey::new([1u8; 32]);
        let mut accounts = HashMap::from([
            (proposer, wallet(0)),
            (STAKING_STATS_ID, stats_account(1_000)),
            (PARAMS_ACCOUNT_ID, params_account()),
        ]);
        let wrong = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![
                proposer,
                Pubkey::new([44u8; 32]),
                STAKING_STATS_ID,
                PARAMS_ACCOUNT_ID,
            ],
            data: borsh::to_vec(&GovernanceInstruction::CreateProposal {
                id: 1,
                action: ProposalAction::SetBaseFeePerByte(500),
            })
            .unwrap(),
        };
        assert!(
            GovernanceProgram
                .process(&mut accounts, &wrong, &proposer, 1)
                .is_err(),
            "a non-canonical proposal address must be rejected"
        );
        let ok = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![
                proposer,
                derive_proposal_address(&proposer, 1),
                STAKING_STATS_ID,
                PARAMS_ACCOUNT_ID,
            ],
            data: borsh::to_vec(&GovernanceInstruction::CreateProposal {
                id: 1,
                action: ProposalAction::SetBaseFeePerByte(500),
            })
            .unwrap(),
        };
        GovernanceProgram
            .process(&mut accounts, &ok, &proposer, 1)
            .expect("the canonical address is accepted");
    }

    fn wallet(balance: u64) -> Account {
        Account {
            balance,
            ..Account::new_wallet(Pubkey::system_program_id())
        }
    }

    fn stake_account(owner: Pubkey, amount: u64) -> Account {
        let data = StakeAccountData {
            owner,
            validator: Pubkey::new([99u8; 32]),
            amount,
            reward_debt: 0,
            locked_until_round: 0,
            bonding_until_round: 0,
            unbonding_requested_at_round: None,
            created_round: 0,
        };
        Account {
            balance: amount,
            data: borsh::to_vec(&data).unwrap(),
            ..Account::new_wallet(crate::ids::STAKING_PROGRAM_ID)
        }
    }

    fn registry_account() -> Account {
        Account {
            data: genesis_registry_account_data(),
            ..Account::new_wallet(GOVERNANCE_PROGRAM_ID)
        }
    }

    fn stats_account(total: u64) -> Account {
        Account {
            data: borsh::to_vec(&total).unwrap(),
            ..Account::new_wallet(crate::ids::STAKING_PROGRAM_ID)
        }
    }

    fn pool_account() -> Account {
        Account {
            data: borsh::to_vec(&crate::staking::RewardPoolData::default()).unwrap(),
            ..Account::new_wallet(crate::ids::STAKING_PROGRAM_ID)
        }
    }

    fn params_account() -> Account {
        Account {
            data: genesis_params_account_data(),
            ..Account::new_wallet(GOVERNANCE_PROGRAM_ID)
        }
    }

    fn new_slh_dsa_entry() -> RegistryEntry {
        // Real, measured sizes for SPHINCS+-SHA2-256s-simple (see
        // `qchain_crypto::slh_dsa`'s own size test) - not a placeholder.
        qchain_crypto::slh_dsa_registry_entry(0)
    }

    fn create_proposal(
        accounts: &mut HashMap<Pubkey, Account>,
        proposer: Pubkey,
        action: ProposalAction,
        round: Round,
    ) {
        // CreateProposal now reads the anti-spam deposit from PARAMS (roadmap
        // #16). Seed a default params account (deposit = 0) if the test didn't,
        // so every existing test stays byte-identical (no deposit charged).
        accounts.entry(PARAMS_ACCOUNT_ID).or_insert_with(params_account);
        // The proposal lives at its canonical address for the ACTUAL proposer
        // (audit v8.6.13 #1). For the common [1;32] proposer this equals
        // proposal_pk().
        let ppk = derive_proposal_address(&proposer, 1);
        let ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![proposer, ppk, STAKING_STATS_ID, PARAMS_ACCOUNT_ID],
            data: borsh::to_vec(&GovernanceInstruction::CreateProposal { id: 1, action }).unwrap(),
        };
        GovernanceProgram
            .process(accounts, &ix, &proposer, round)
            .unwrap();
    }

    fn vote(
        accounts: &mut HashMap<Pubkey, Account>,
        voter: Pubkey,
        stake_pk: Pubkey,
        choice: VoteChoice,
        round: Round,
    ) -> Result<(), ExecError> {
        let ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![proposal_pk(), stake_pk],
            data: borsh::to_vec(&GovernanceInstruction::Vote { choice }).unwrap(),
        };
        GovernanceProgram.process(accounts, &ix, &voter, round)
    }

    fn finalize(
        accounts: &mut HashMap<Pubkey, Account>,
        caller: Pubkey,
        round: Round,
    ) -> Result<(), ExecError> {
        let ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![proposal_pk(), STAKING_STATS_ID],
            data: borsh::to_vec(&GovernanceInstruction::Finalize).unwrap(),
        };
        GovernanceProgram.process(accounts, &ix, &caller, round)
    }

    fn execute(
        accounts: &mut HashMap<Pubkey, Account>,
        caller: Pubkey,
        round: Round,
    ) -> Result<(), ExecError> {
        let ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![
                proposal_pk(),
                REGISTRY_ACCOUNT_ID,
                crate::ids::EMERGENCY_ACCOUNT_ID,
            ],
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

        create_proposal(
            &mut accounts,
            proposer,
            ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()),
            0,
        );
        vote(&mut accounts, voter_a, STAKE_PK, VoteChoice::Yes, 5).unwrap();
        vote(&mut accounts, voter_b, OTHER_STAKE_PK, VoteChoice::No, 5).unwrap();

        let rule = quorum_rule(qchain_governance::RiskTier::Registry);
        finalize(
            &mut accounts,
            Pubkey::new([9u8; 32]),
            rule.voting_period_rounds,
        )
        .unwrap();
        let proposal = read_proposal(&accounts, &proposal_pk()).unwrap();
        assert_eq!(
            proposal.status,
            ProposalStatus::Passed,
            "70% yes clears the 2/3 supermajority bar"
        );

        // Too early - the review time-lock hasn't elapsed.
        assert!(execute(
            &mut accounts,
            Pubkey::new([9u8; 32]),
            rule.voting_period_rounds + 1
        )
        .is_err());

        execute(
            &mut accounts,
            Pubkey::new([9u8; 32]),
            rule.voting_period_rounds + rule.timelock_rounds,
        )
        .unwrap();

        let registry: Vec<RegistryEntry> =
            Vec::try_from_slice(&accounts[&REGISTRY_ACCOUNT_ID].data).unwrap();
        assert!(registry.iter().any(
            |e| e.id == qchain_crypto::ALGORITHM_SLH_DSA && e.status == AlgorithmStatus::Active
        ));
        let proposal = read_proposal(&accounts, &proposal_pk()).unwrap();
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

        create_proposal(
            &mut accounts,
            proposer,
            ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()),
            0,
        );
        // Only 100/1000 = 10% participates - below the 20% floor.
        vote(&mut accounts, voter_a, STAKE_PK, VoteChoice::Yes, 5).unwrap();

        let rule = quorum_rule(qchain_governance::RiskTier::Registry);
        finalize(
            &mut accounts,
            Pubkey::new([9u8; 32]),
            rule.voting_period_rounds,
        )
        .unwrap();
        let proposal = read_proposal(&accounts, &proposal_pk()).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Rejected);

        assert!(execute(
            &mut accounts,
            Pubkey::new([9u8; 32]),
            rule.voting_period_rounds + rule.timelock_rounds
        )
        .is_err());
        assert_eq!(
            accounts[&REGISTRY_ACCOUNT_ID].data, original_registry,
            "a rejected proposal must never mutate the registry"
        );
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

        create_proposal(
            &mut accounts,
            proposer,
            ProposalAction::DeprecateAlgorithm {
                id: ALGORITHM_ED25519,
                retirement_round,
            },
            0,
        );
        vote(&mut accounts, voter, STAKE_PK, VoteChoice::Yes, 5).unwrap();
        finalize(&mut accounts, proposer, rule.voting_period_rounds).unwrap();
        execute(&mut accounts, proposer, full_cycle).unwrap();

        let registry: Vec<RegistryEntry> =
            Vec::try_from_slice(&accounts[&REGISTRY_ACCOUNT_ID].data).unwrap();
        let entry = registry.iter().find(|e| e.id == ALGORITHM_ED25519).unwrap();
        assert_eq!(
            entry.status,
            AlgorithmStatus::Deprecated {
                retirement_epoch: retirement_round
            }
        );
        assert!(
            registry
                .iter()
                .any(|e| e.id == ALGORITHM_ML_DSA_65 && e.status == AlgorithmStatus::Active),
            "unrelated entries must be untouched"
        );

        // A second proposal retires it, created right after the deprecate
        // proposal executed.
        let retire_proposal_pk = derive_proposal_address(&proposer, 2);
        let retire_ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![proposer, retire_proposal_pk, STAKING_STATS_ID, PARAMS_ACCOUNT_ID],
            data: borsh::to_vec(&GovernanceInstruction::CreateProposal {
                id: 2,
                action: ProposalAction::RetireAlgorithm {
                    id: ALGORITHM_ED25519,
                },
            })
            .unwrap(),
        };
        GovernanceProgram
            .process(&mut accounts, &retire_ix, &proposer, full_cycle)
            .unwrap();

        let vote_ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![retire_proposal_pk, STAKE_PK],
            data: borsh::to_vec(&GovernanceInstruction::Vote {
                choice: VoteChoice::Yes,
            })
            .unwrap(),
        };
        GovernanceProgram
            .process(&mut accounts, &vote_ix, &voter, full_cycle + 1)
            .unwrap();

        let finalize_ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![retire_proposal_pk, STAKING_STATS_ID],
            data: borsh::to_vec(&GovernanceInstruction::Finalize).unwrap(),
        };
        let retire_finalize_round = full_cycle + rule.voting_period_rounds;
        GovernanceProgram
            .process(
                &mut accounts,
                &finalize_ix,
                &proposer,
                retire_finalize_round,
            )
            .unwrap();

        let execute_ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![
                retire_proposal_pk,
                REGISTRY_ACCOUNT_ID,
                crate::ids::EMERGENCY_ACCOUNT_ID,
            ],
            data: borsh::to_vec(&GovernanceInstruction::Execute).unwrap(),
        };
        // The retire proposal's own governance timelock has elapsed here,
        // but `retirement_round` (the entry's migration grace period)
        // hasn't - this must still be rejected.
        let retire_execute_ready_round = retire_finalize_round + rule.timelock_rounds;
        assert!(
            retire_execute_ready_round < retirement_round,
            "test setup assumption: still before the grace period ends"
        );
        let result = GovernanceProgram.process(
            &mut accounts,
            &execute_ix,
            &proposer,
            retire_execute_ready_round,
        );
        assert!(
            result.is_err(),
            "retiring before the grace period elapses must be rejected"
        );

        GovernanceProgram
            .process(&mut accounts, &execute_ix, &proposer, retirement_round)
            .unwrap();
        let registry: Vec<RegistryEntry> =
            Vec::try_from_slice(&accounts[&REGISTRY_ACCOUNT_ID].data).unwrap();
        assert_eq!(
            registry
                .iter()
                .find(|e| e.id == ALGORITHM_ED25519)
                .unwrap()
                .status,
            AlgorithmStatus::Retired
        );
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
        create_proposal(
            &mut accounts,
            proposer,
            ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()),
            0,
        );
        let rule = quorum_rule(qchain_governance::RiskTier::Registry);
        assert!(vote(
            &mut accounts,
            voter,
            STAKE_PK,
            VoteChoice::Yes,
            rule.voting_period_rounds
        )
        .is_err());
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
        create_proposal(
            &mut accounts,
            proposer,
            ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()),
            0,
        );
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
            data: borsh::to_vec(&crate::staking::StakingInstruction::Delegate {
                validator: Pubkey::new([50u8; 32]),
                amount: 5_000,
            })
            .unwrap(),
        };
        StakingProgram
            .process(&mut accounts, &delegate_ix, &staker, 0)
            .unwrap();

        create_proposal(
            &mut accounts,
            staker,
            ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()),
            0,
        );
        vote(&mut accounts, staker, STAKE_PK, VoteChoice::Yes, 1).unwrap();

        let proposal = read_proposal(&accounts, &proposal_pk()).unwrap();
        assert_eq!(
            proposal.yes_stake, 5_000,
            "voting power must come from the real delegated amount"
        );
    }

    /// Roadmap #6 — the per-voter creation-time snapshot. Composes both real
    /// programs exactly as a live node would: a position DELEGATED AFTER the
    /// proposal opened cannot vote on it (the flash-stake-to-swing-a-specific-
    /// vote residual the aggregate `snapshot_total_staked` left open), while a
    /// position that predates the proposal votes with its full weight.
    #[test]
    fn stake_delegated_after_the_proposal_opened_cannot_vote_but_an_earlier_position_can() {
        // Non-reserved pubkeys (low bytes collide with the singleton ids like
        // STAKING_STATS_ID=[2;32]).
        let early = Pubkey::new([61u8; 32]);
        let latecomer = Pubkey::new([62u8; 32]);
        let early_stake = Pubkey::new([63u8; 32]);
        let late_stake = Pubkey::new([64u8; 32]);
        let mut accounts = HashMap::from([
            (early, wallet(10_000)),
            (latecomer, wallet(10_000)),
            (STAKING_STATS_ID, stats_account(0)),
            (REGISTRY_ACCOUNT_ID, registry_account()),
            (STAKING_REWARDS_POOL_ID, pool_account()),
        ]);
        let validator = Pubkey::new([50u8; 32]);
        let delegate = |accounts: &mut HashMap<Pubkey, Account>,
                        staker: Pubkey,
                        stake_pk: Pubkey,
                        amount: u64,
                        round: Round| {
            let ix = Instruction {
                program_id: crate::ids::STAKING_PROGRAM_ID,
                accounts: vec![staker, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
                data: borsh::to_vec(&crate::staking::StakingInstruction::Delegate {
                    validator,
                    amount,
                })
                .unwrap(),
            };
            StakingProgram
                .process(accounts, &ix, &staker, round)
                .unwrap();
        };

        // `early` delegated at round 5 — BEFORE the proposal opens at round 10.
        delegate(&mut accounts, early, early_stake, 6_000, 5);

        // Proposal created at round 10 (its per-voter snapshot boundary). The
        // proposer is the standard [1;32] so the proposal lives at proposal_pk()
        // (the vote/finalize helpers target that canonical address); who proposes
        // is incidental to this test (it checks per-voter creation-round eligibility).
        create_proposal(
            &mut accounts,
            Pubkey::new([1u8; 32]),
            ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()),
            10,
        );

        // `latecomer` delegates at round 15 — AFTER the proposal opened — and
        // tries to vote it down. Rejected: its stake wasn't part of the
        // creation-time picture, so it can't vote on THIS proposal.
        delegate(&mut accounts, latecomer, late_stake, 9_000, 15);
        let late = vote(&mut accounts, latecomer, late_stake, VoteChoice::No, 16);
        assert!(
            matches!(late, Err(ExecError::ProgramError(ref m)) if m.contains("after the proposal was created")),
            "stake delegated after the proposal opened must not be able to vote on it, got {late:?}",
        );

        // The earlier position votes normally (created_round 5 <= 10).
        vote(&mut accounts, early, early_stake, VoteChoice::Yes, 16).unwrap();
        let proposal = read_proposal(&accounts, &proposal_pk()).unwrap();
        assert_eq!(
            proposal.yes_stake, 6_000,
            "a position that predates the proposal votes with its full weight"
        );
        assert_eq!(proposal.no_stake, 0, "the flash-staked No never counted");
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
            data: borsh::to_vec(&crate::staking::StakingInstruction::Delegate {
                validator: Pubkey::new([50u8; 32]),
                amount: 5_000,
            })
            .unwrap(),
        };
        StakingProgram
            .process(&mut accounts, &delegate_ix, &staker, 0)
            .unwrap();

        create_proposal(
            &mut accounts,
            staker,
            ProposalAction::ActivateAlgorithm(new_slh_dsa_entry()),
            0,
        );
        vote(&mut accounts, staker, STAKE_PK, VoteChoice::Yes, 1).unwrap();

        let rule = quorum_rule(qchain_governance::RiskTier::Registry);
        let undelegate_ix = Instruction {
            program_id: crate::ids::STAKING_PROGRAM_ID,
            accounts: vec![STAKE_PK, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&crate::staking::StakingInstruction::Undelegate).unwrap(),
        };
        let too_early = StakingProgram.process(
            &mut accounts,
            &undelegate_ix,
            &staker,
            rule.voting_period_rounds - 1,
        );
        assert!(
            too_early.is_err(),
            "reclaiming the stake before the vote it cast is decided must be rejected"
        );
        assert_eq!(
            accounts[&STAKE_PK].balance, 5_000,
            "the position must remain fully intact while locked"
        );

        // The lock now extends through the ENTIRE Registry window: voting period
        // PLUS the post-passage time-lock. Undelegating the instant the voting
        // period ends must still be rejected - a Yes-voter can't sit out the
        // review window with zero economic exposure while their vote drives
        // execution (audit finding C).
        let still_locked = StakingProgram.process(
            &mut accounts,
            &undelegate_ix,
            &staker,
            rule.voting_period_rounds,
        );
        assert!(still_locked.is_err(), "a Registry-tier voter stays locked through the time-lock window, not just the voting period");
        assert_eq!(
            accounts[&STAKE_PK].balance, 5_000,
            "still fully intact during the time-lock"
        );

        StakingProgram
            .process(
                &mut accounts,
                &undelegate_ix,
                &staker,
                rule.voting_period_rounds + rule.timelock_rounds,
            )
            .unwrap();
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
        create_proposal(
            &mut accounts,
            proposer,
            ProposalAction::SetBaseFeePerByte(new_fee),
            0,
        );
        vote(&mut accounts, voter_a, STAKE_PK, VoteChoice::Yes, 1).unwrap();
        vote(&mut accounts, voter_b, OTHER_STAKE_PK, VoteChoice::No, 1).unwrap();

        let rule = quorum_rule(qchain_governance::RiskTier::Economic);
        assert!(
            rule.timelock_rounds > 0,
            "a monetary change must carry a real review time-lock"
        );
        let finalize_round = rule.voting_period_rounds;
        finalize(&mut accounts, proposer, finalize_round).unwrap();
        let proposal = read_proposal(&accounts, &proposal_pk()).unwrap();
        assert_eq!(
            proposal.status,
            ProposalStatus::Passed,
            "70% yes clears the 2/3 supermajority"
        );

        let execute_ix = Instruction {
            program_id: GOVERNANCE_PROGRAM_ID,
            accounts: vec![
                proposal_pk(),
                PARAMS_ACCOUNT_ID,
                crate::ids::EMERGENCY_ACCOUNT_ID,
            ],
            data: borsh::to_vec(&GovernanceInstruction::Execute).unwrap(),
        };
        // Too early: the review time-lock has NOT elapsed — a monetary change
        // can no longer execute the instant it's finalized.
        assert!(
            GovernanceProgram
                .process(&mut accounts, &execute_ix, &proposer, finalize_round)
                .is_err(),
            "an economic change must wait out its review time-lock"
        );

        GovernanceProgram
            .process(
                &mut accounts,
                &execute_ix,
                &proposer,
                finalize_round + rule.timelock_rounds,
            )
            .unwrap();

        let params =
            crate::params::EconomicParams::try_from_slice(&accounts[&PARAMS_ACCOUNT_ID].data)
                .unwrap();
        assert_eq!(params.base_fee_per_byte, new_fee);
        assert_eq!(
            params.dust_threshold,
            crate::params::EconomicParams::default().dust_threshold,
            "unrelated params must be untouched"
        );
        assert_eq!(
            read_proposal(&accounts, &proposal_pk()).unwrap().status,
            ProposalStatus::Executed
        );
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
        create_proposal(
            &mut accounts,
            proposer,
            ProposalAction::SetBaseFeePerByte(new_fee),
            0,
        );
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
            accounts: vec![
                proposal_pk(),
                PARAMS_ACCOUNT_ID,
                crate::ids::EMERGENCY_ACCOUNT_ID,
            ],
            data: borsh::to_vec(&GovernanceInstruction::Execute).unwrap(),
        };

        // An outsider cannot pause.
        assert!(GovernanceProgram
            .process(&mut accounts, &pause(), &outsider, 1)
            .is_err());
        // One guardian is below the threshold of 2 → not paused yet.
        GovernanceProgram
            .process(&mut accounts, &pause(), &g1, 1)
            .unwrap();
        // A second DISTINCT guardian reaches the threshold → paused.
        GovernanceProgram
            .process(&mut accounts, &pause(), &g2, 2)
            .unwrap();
        let em: EmergencyState =
            borsh::from_slice(&accounts[&crate::ids::EMERGENCY_ACCOUNT_ID].data).unwrap();
        assert!(
            em.paused,
            "two of three guardians reached the pause threshold"
        );

        // Now Execute is blocked even though the proposal passed and the
        // timelock elapsed.
        assert!(
            GovernanceProgram
                .process(&mut accounts, &exec, &proposer, ready_round)
                .is_err(),
            "a paused chain must block Execute"
        );
        assert_eq!(
            crate::params::EconomicParams::try_from_slice(&accounts[&PARAMS_ACCOUNT_ID].data)
                .unwrap()
                .base_fee_per_byte,
            crate::params::EconomicParams::default().base_fee_per_byte,
            "the paused change must NOT have taken effect"
        );

        // Two guardians unpause → Execute proceeds.
        GovernanceProgram
            .process(&mut accounts, &unpause(), &g1, ready_round)
            .unwrap();
        GovernanceProgram
            .process(&mut accounts, &unpause(), &g3, ready_round)
            .unwrap();
        GovernanceProgram
            .process(&mut accounts, &exec, &proposer, ready_round)
            .unwrap();
        assert_eq!(
            crate::params::EconomicParams::try_from_slice(&accounts[&PARAMS_ACCOUNT_ID].data)
                .unwrap()
                .base_fee_per_byte,
            new_fee
        );

        // The guardians never held or moved any balance: the emergency account
        // balance stayed zero throughout (it only ever carried the flag).
        assert_eq!(
            accounts[&crate::ids::EMERGENCY_ACCOUNT_ID].balance,
            0,
            "the pause mechanism must never touch funds"
        );
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
        assert_eq!(
            p.base_fee_per_byte, 360,
            "a rejected step must not mutate the parameter"
        );
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
        assert!(
            apply_economic_action(&mut p, &ProposalAction::SetDustThreshold(u64::MAX)).is_err()
        );
        // base_fee below the anti-spam floor (e.g. 0 = free spam) - rejected.
        assert!(apply_economic_action(&mut p, &ProposalAction::SetBaseFeePerByte(0)).is_err());
        // gas_price 0 = free WASM compute - rejected.
        assert!(apply_economic_action(&mut p, &ProposalAction::SetGasPricePerFuel(0)).is_err());
        // The state must be untouched after every rejection.
        assert_eq!(p.dust_threshold, EconomicParams::default().dust_threshold);
        assert_eq!(
            p.base_fee_per_byte,
            EconomicParams::default().base_fee_per_byte
        );
        // An emission APR above the safety cap is rejected (unbounded inflation).
        assert!(apply_economic_action(&mut p, &ProposalAction::SetEmissionApr(u16::MAX)).is_err());
        assert_eq!(
            p.emission_apr_bps,
            EconomicParams::default().emission_apr_bps
        );
        // base_fee ABOVE the ceiling is rejected — the permanent-brick vector
        // (a value that makes every tx, including the recovery tx, unaffordable).
        assert!(
            apply_economic_action(&mut p, &ProposalAction::SetBaseFeePerByte(u64::MAX)).is_err()
        );
        assert_eq!(
            p.base_fee_per_byte,
            EconomicParams::default().base_fee_per_byte
        );
        // gas_price ABOVE the ceiling is rejected too (symmetric bound).
        assert!(
            apply_economic_action(&mut p, &ProposalAction::SetGasPricePerFuel(u64::MAX)).is_err()
        );
        // Legitimate SMALL in-step recalibrations still apply (a big single jump
        // is separately rejected by the per-proposal step limit — see
        // `a_single_proposal_cannot_move_a_parameter_past_the_step_limit`). `p`
        // is still at defaults here (all prior calls were rejections that never
        // mutated), so a 2× / within-cap move is in-step and applies.
        let d = EconomicParams::default();
        assert!(apply_economic_action(
            &mut p,
            &ProposalAction::SetBaseFeePerByte(d.base_fee_per_byte * 2)
        )
        .is_ok());
        assert!(apply_economic_action(&mut p, &ProposalAction::SetGasPricePerFuel(2)).is_ok());
        assert!(apply_economic_action(
            &mut p,
            &ProposalAction::SetDustThreshold(d.dust_threshold * 2)
        )
        .is_ok());
        assert!(apply_economic_action(
            &mut p,
            &ProposalAction::SetEmissionApr(d.emission_apr_bps + 400)
        )
        .is_ok());
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
        create_proposal(
            &mut accounts,
            proposer,
            ProposalAction::SetDustThreshold(1),
            0,
        );
        vote(&mut accounts, voter_a, STAKE_PK, VoteChoice::Yes, 1).unwrap();
        vote(&mut accounts, voter_b, OTHER_STAKE_PK, VoteChoice::No, 1).unwrap();

        let rule = quorum_rule(qchain_governance::RiskTier::Economic);
        finalize(&mut accounts, proposer, rule.voting_period_rounds).unwrap();
        let proposal = read_proposal(&accounts, &proposal_pk()).unwrap();
        assert_eq!(
            proposal.status,
            ProposalStatus::Rejected,
            "a 500/500 tie is nowhere near the 2/3 supermajority a monetary change needs"
        );
    }

    /// Roadmap #16 end to end: an anti-spam deposit is charged at creation and
    /// held in the proposal account; `CloseProposal` prunes a terminal proposal
    /// and settles the deposit — REFUNDED to the proposer if the proposal reached
    /// the participation floor (a genuine proposal), BURNED to the canonical burn
    /// address otherwise (spam nobody engaged with); the guards (retention window,
    /// still-voting, wrong burn address) reject; and supply is conserved.
    #[test]
    fn governance_deposit_is_charged_then_refunded_or_burned_and_close_prunes() {
        let proposer = Pubkey::new([1u8; 32]);
        let voter = Pubkey::new([2u8; 32]);
        // Canonical proposal addresses (audit v8.6.13 #1) — ids 1/2/3 below.
        let p_genuine = derive_proposal_address(&proposer, 1);
        let p_spam = derive_proposal_address(&proposer, 2);
        let deposit = 5_000_000u64;
        let start_balance = 100_000_000u64;

        // A params account whose `governance_proposal_deposit` is set > 0.
        let params = crate::params::EconomicParams { governance_proposal_deposit: deposit, ..Default::default() };
        let params_acct = Account {
            data: borsh::to_vec(&params).unwrap(),
            ..Account::new_wallet(GOVERNANCE_PROGRAM_ID)
        };
        let mut accounts = HashMap::from([
            (proposer, wallet(start_balance)),
            (STAKE_PK, stake_account(voter, 1_000)),
            (STAKING_STATS_ID, stats_account(1_000)),
            (PARAMS_ACCOUNT_ID, params_acct),
        ]);

        let create = |accounts: &mut HashMap<Pubkey, Account>, ppk: Pubkey, id: u64| {
            let ix = Instruction {
                program_id: GOVERNANCE_PROGRAM_ID,
                accounts: vec![proposer, ppk, STAKING_STATS_ID, PARAMS_ACCOUNT_ID],
                data: borsh::to_vec(&GovernanceInstruction::CreateProposal { id, action: ProposalAction::SetDustThreshold(1_000_000) }).unwrap(),
            };
            GovernanceProgram.process(accounts, &ix, &proposer, 0).unwrap();
        };
        let vote_no = |accounts: &mut HashMap<Pubkey, Account>, ppk: Pubkey| {
            let ix = Instruction {
                program_id: GOVERNANCE_PROGRAM_ID,
                accounts: vec![ppk, STAKE_PK],
                data: borsh::to_vec(&GovernanceInstruction::Vote { choice: VoteChoice::No }).unwrap(),
            };
            GovernanceProgram.process(accounts, &ix, &voter, 1).unwrap();
        };
        let finalize_at = |accounts: &mut HashMap<Pubkey, Account>, ppk: Pubkey, round: Round| {
            let ix = Instruction {
                program_id: GOVERNANCE_PROGRAM_ID,
                accounts: vec![ppk, STAKING_STATS_ID],
                data: borsh::to_vec(&GovernanceInstruction::Finalize).unwrap(),
            };
            GovernanceProgram.process(accounts, &ix, &proposer, round).unwrap();
        };
        let close = |accounts: &mut HashMap<Pubkey, Account>, ppk: Pubkey, refund_to: Pubkey, burn: Pubkey, round: Round| -> Result<(), ExecError> {
            let ix = Instruction {
                program_id: GOVERNANCE_PROGRAM_ID,
                accounts: vec![ppk, refund_to, burn],
                data: borsh::to_vec(&GovernanceInstruction::CloseProposal).unwrap(),
            };
            GovernanceProgram.process(accounts, &ix, &proposer, round)
        };

        // --- Charge: two proposals, each debits `deposit`, holding it in-account.
        create(&mut accounts, p_genuine, 1);
        create(&mut accounts, p_spam, 2);
        assert_eq!(accounts[&proposer].balance, start_balance - 2 * deposit, "each proposal debits the deposit");
        assert_eq!(accounts[&p_genuine].balance, deposit, "the deposit is held in the proposal account");
        assert_eq!(accounts[&p_spam].balance, deposit);
        assert_eq!(read_proposal(&accounts, &p_genuine).unwrap().deposit, deposit, "the deposit is recorded on the proposal");

        // --- Genuine: reaches the floor (full turnout) but is voted down → Rejected.
        vote_no(&mut accounts, p_genuine);
        let rule = quorum_rule(qchain_governance::RiskTier::Economic);
        finalize_at(&mut accounts, p_genuine, rule.voting_period_rounds);
        finalize_at(&mut accounts, p_spam, rule.voting_period_rounds); // no votes → Rejected below floor
        let g = read_proposal(&accounts, &p_genuine).unwrap();
        assert_eq!(g.status, ProposalStatus::Rejected);
        assert!(g.reached_participation_floor(), "full turnout → deposit will refund");
        let s = read_proposal(&accounts, &p_spam).unwrap();
        assert_eq!(s.status, ProposalStatus::Rejected);
        assert!(!s.reached_participation_floor(), "no turnout → deposit will burn");

        let voting_ends = rule.voting_period_rounds;
        let closeable = voting_ends + 5_000; // PROPOSAL_RETENTION_ROUNDS

        // --- Guards.
        assert!(close(&mut accounts, p_genuine, proposer, crate::ids::BURN_ADDRESS, voting_ends + 10).is_err(), "within the retention window → rejected");
        assert!(close(&mut accounts, p_genuine, proposer, Pubkey::new([7u8; 32]), closeable).is_err(), "a non-canonical burn address → rejected");
        // A still-Voting proposal cannot be closed (create a throwaway one).
        let p_open = derive_proposal_address(&proposer, 3);
        create(&mut accounts, p_open, 3);
        assert!(close(&mut accounts, p_open, proposer, crate::ids::BURN_ADDRESS, closeable).is_err(), "a still-open proposal cannot be closed");

        // --- Settle: genuine refunds, spam burns; both proposals are pruned.
        let before_refund = accounts[&proposer].balance;
        close(&mut accounts, p_genuine, proposer, crate::ids::BURN_ADDRESS, closeable).unwrap();
        assert_eq!(accounts[&proposer].balance, before_refund + deposit, "a genuine proposal refunds its deposit");
        assert_eq!(accounts[&p_genuine].balance, 0, "the pruned proposal holds nothing");
        assert!(accounts[&p_genuine].data.is_empty(), "the pruned proposal's data (the vote blob) is cleared");

        close(&mut accounts, p_spam, proposer, crate::ids::BURN_ADDRESS, closeable).unwrap();
        assert_eq!(accounts[&crate::ids::BURN_ADDRESS].balance, deposit, "a spam proposal's deposit is burned");
        assert!(accounts[&p_spam].data.is_empty());

        // A second close of an already-pruned proposal fails (empty data won't decode).
        assert!(close(&mut accounts, p_spam, proposer, crate::ids::BURN_ADDRESS, closeable).is_err(), "cannot double-settle a pruned proposal");

        // --- Conservation: every atom is accounted for (the p_open deposit is
        // still held in its account, un-refunded, since it was never closed).
        let total: u64 = accounts.values().map(|a| a.balance).sum();
        assert_eq!(total, start_balance + 1_000, "supply conserved (start balance + the 1_000-atom stake account)");
    }
}
