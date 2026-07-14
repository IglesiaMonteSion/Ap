//! Delegated staking (design: `ARCHITECTURE.md` §5 - "Delegated staking
//! desde fase 1... cualquier holder puede delegar a un validador"). This
//! was declared in scope for phase 1 but never actually built then (see
//! `project-lessons-learned`); it's implemented now because phase 2's
//! governance needs a *real* stake-weighted voting base, not the small
//! hardcoded validator set `qchain-consensus` uses for BFT quorum - that
//! set is a fixed, config-loaded list of ~10-20 validators, deliberately
//! separate from "how many QCH does an arbitrary holder have bonded,"
//! which is what governance §6 actually means by "votación ponderada por
//! stake."
//!
//! Each `Delegate` call opens a brand-new stake account (no top-up/reuse
//! of an existing position, mirroring how `CreateAccount` already works
//! elsewhere in this codebase) - a staker can hold several. `Undelegate`
//! closes a position once its minimum bonding period has elapsed (see
//! `StakeAccountData::bonding_until_round` - added after a live-confirmed
//! reward-sniping attack showed instant, zero-cost delegate/undelegate
//! round-trips capturing a real, disproportionate share of the reward
//! pool; this is a real minimum lock-up, not the full economic
//! calibration - a properly tuned unbonding schedule tied to a real
//! emission model is still out of scope per `ARCHITECTURE.md` §5's
//! "fuera de alcance en fase 1: calibración fina de la tasa de
//! emisión/staking"). A closed stake account is zeroed rather than
//! deleted, since this execution model has no account-deletion primitive
//! yet (see `Ledger`'s working-set commit loop) - a documented phase-2
//! limitation, not an oversight.
//!
//! `ReportEquivocation` slashes a proven-Byzantine validator's *own*
//! self-stake (a `StakeAccountData` where `owner == validator ==` the
//! accused address) - real, found-during-a-security-review scope: this
//! project's BFT quorum weight (`qchain-consensus::ValidatorSet`) is a
//! static, config-loaded list, entirely disconnected from this delegated
//! staking module (see `StakeAccountData::validator`'s own doc comment).
//! Slashing here is therefore a real economic penalty - the validator
//! permanently loses bonded QCH and any pending reward - not an ejection
//! from the active validator set, which would need that quorum-weighting
//! disconnect closed first (a much larger change, not this one). Burns
//! the *entire* self-staked position, not a partial percentage: no
//! `slash_bps`-style tunable exists yet (unlike `staking_commission_bps`),
//! a deliberate placeholder simplicity choice given this is the first
//! slashing mechanism this project has ever had. Delegators are never
//! touched - only a position where `owner == validator` (the validator's
//! own money, not money entrusted to them) can be slashed, so nobody
//! else's stake is put at risk by another party's misbehavior.

use crate::error::ExecError;
use crate::ids::STAKING_PROGRAM_ID;
use crate::native::NativeProgram;
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{Account, EquivocationEvidence, Instruction, Round};
use qchain_crypto::Pubkey;
use std::collections::HashMap;

/// Fixed-point scale for `RewardPoolData::acc_reward_per_share` (a
/// Synthetix/MasterChef-style reward-per-share accumulator) - large enough
/// that dividing a realistic per-transaction fee share by realistic total
/// stake doesn't truncate to zero. See module docs below for the full
/// mechanism this backs.
pub const PRECISION: u128 = 1_000_000_000_000;

/// The shared delegator reward pool's on-chain data
/// (`STAKING_REWARDS_POOL_ID` - see `ids.rs`), whose account `balance` is
/// the real QCH available for delegators to claim. `acc_reward_per_share`
/// is the running total (fixed-point, scaled by `PRECISION`) of reward
/// units earned per unit of stake since genesis - the standard
/// reward-per-share accrual pattern: crediting a delegator's *share* of
/// newly-earned fees only requires reading this one number, never
/// iterating every delegator (this execution model has no
/// scan-all-accounts primitive - see module docs above).
#[derive(Clone, Copy, Default, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct RewardPoolData {
    pub acc_reward_per_share: u128,
}

#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct StakeAccountData {
    /// The withdraw authority - only this pubkey (checked against the
    /// transaction payer) can `Undelegate`, and this is who casts votes
    /// with this position's weight in governance.
    pub owner: Pubkey,
    /// Informational only in this increment: doesn't yet feed
    /// `qchain-consensus`'s BFT quorum weighting, which still reads
    /// validator stake from the node's static config (see module docs).
    pub validator: Pubkey,
    /// 0 once undelegated - the account is a zeroed tombstone, not
    /// deleted (see module docs).
    pub amount: u64,
    /// `amount * acc_reward_per_share / PRECISION` as of the last time
    /// this position's reward was settled (delegate, claim, or
    /// undelegate) - the standard "debt" ledger that makes per-position
    /// reward correct without needing to remember every historical
    /// accrual: `pending = amount * current_acc / PRECISION - reward_debt`.
    pub reward_debt: u128,
    /// A real, live-confirmed governance attack this closes (see
    /// `project-lessons-learned`): before this field existed, `Vote`
    /// snapshotted this position's `amount` into the proposal's permanent
    /// tally, but nothing stopped `Undelegate` from reclaiming that same
    /// stake an instant later - a voter's recorded weight stayed locked
    /// into the outcome forever, with zero real economic exposure for
    /// more than one transaction. Confirmed live: delegate, vote yes,
    /// undelegate immediately, and a `Low`-tier proposal (no time-lock)
    /// still passed and executed with the "attacker" holding zero stake
    /// by the time it was decided - the same decoupling-of-voting-power-
    /// from-commitment pattern behind the real Beanstalk ($182M, 2022)
    /// and BonkDAO ($20M, 2026) governance drains. `Vote` sets this to
    /// `max(current value, the proposal's voting_ends_round)`;
    /// `Undelegate` refuses while `current_round < locked_until_round`.
    /// 0 for a position that has never voted - never blocks an ordinary
    /// delegator who stays out of governance.
    pub locked_until_round: u64,
    /// A real, live-confirmed reward-sniping vulnerability this closes
    /// (see `project-lessons-learned`): before this field existed, a
    /// position could `Delegate` a large amount right before real fee
    /// activity credited the shared reward pool, capture a share of that
    /// accrual proportional to its (temporarily huge) stake, and
    /// `Undelegate` an instant later - zero real economic exposure,
    /// zero opportunity cost, zero risk. Confirmed live: a "sniper"
    /// delegating 50,000,000 for the duration of one burst of real fee
    /// transactions captured ~99.8% of the reward generated during that
    /// window, while a genuine long-term delegator present the entire
    /// time (before, during, and after) with 1,000,000 real stake
    /// captured only ~0.2% - a real, quantified transfer of value from
    /// sustained network security to an instant round-trip. Set by
    /// `Delegate` to `current_round + MINIMUM_BONDING_ROUNDS`; `Undelegate`
    /// refuses while `current_round < bonding_until_round`. Doesn't change
    /// the reward-per-share math itself (still simple, still correct for
    /// genuinely long-term positions) - it removes the "free, zero-
    /// duration" property that made sniping profitable at no real cost,
    /// same principle as `locked_until_round` above but applied
    /// unconditionally to every position, not just ones that voted.
    pub bonding_until_round: u64,
    /// A real, live-confirmed slash-evasion vulnerability this closes (see
    /// `project-lessons-learned`): before this field existed, `Undelegate`
    /// paid out a self-stake position's full principal in one instant
    /// transaction, with no delay at all - a validator who equivocated
    /// could simply submit their own `Undelegate` in the same breath as
    /// the conflicting vertices, and if that transaction executed before
    /// anyone else's `ReportEquivocation` (a real race - detecting,
    /// signing, and submitting a report transaction takes at least one
    /// real round of latency, while the equivocator's own `Undelegate` can
    /// be prepared in advance and fired the instant they misbehave), the
    /// stake account was already zeroed by the time the slash tried to
    /// burn it - `ReportEquivocation` rejects with "nothing to slash",
    /// and the validator walks away with their full principal despite
    /// being cryptographically proven Byzantine. Confirmed live: an
    /// equivocating validator's `Undelegate` and a third party's
    /// `ReportEquivocation` submitted immediately afterward - the
    /// `Undelegate` won the race, the report failed with exactly that
    /// error, and the validator's wallet balance came back to its
    /// pre-delegation level. `None` until a self-stake position's first
    /// `Undelegate` call, which starts the clock instead of paying out
    /// immediately (see `SELF_STAKE_UNBONDING_ROUNDS`) - a second
    /// `Undelegate` call after that many rounds have passed completes the
    /// withdrawal. Only ever set on self-stake positions (`owner ==
    /// validator`); an ordinary delegator's `Undelegate` is completely
    /// unaffected and stays instant, since slashing never touches
    /// delegator stake in the first place.
    pub unbonding_requested_at_round: Option<u64>,
}

/// How long a self-stake position's principal stays slashable after
/// `Undelegate` is first requested, before a second `Undelegate` call can
/// actually withdraw it - see `StakeAccountData::unbonding_requested_at_
/// round`'s doc comment for the real slash-evasion race this closes. Same
/// magnitude already established elsewhere in this module for "long
/// enough that a same-instant round-trip can't work."
pub const SELF_STAKE_UNBONDING_ROUNDS: u64 = 100;

/// A real economic cost for reward-sniping (see
/// `StakeAccountData::bonding_until_round`'s doc comment): capital
/// delegated is genuinely tied up for this many rounds before it can be
/// reclaimed, regardless of when it was delegated. Chosen to match this
/// codebase's own already-established magnitude for "long enough that an
/// instant round-trip can't work" - `qchain_governance::RiskTier::Low`'s
/// `voting_period_rounds` is the same 100, a number this project already
/// treats as a real, if modest, commitment window elsewhere.
pub const MINIMUM_BONDING_ROUNDS: u64 = 100;

#[derive(BorshSerialize, BorshDeserialize)]
pub enum StakingInstruction {
    /// accounts[0] = staker wallet (funding source; must equal the
    /// transaction payer), accounts[1] = a fresh pubkey for the new stake
    /// account, accounts[2] = the staking-stats singleton
    /// (`STAKING_STATS_ID`), accounts[3] = the reward pool singleton
    /// (`STAKING_REWARDS_POOL_ID`) - read (not paid from) to fix this new
    /// position's starting `reward_debt` so it doesn't retroactively earn
    /// a share of rewards accrued before it existed.
    Delegate { validator: Pubkey, amount: u64 },
    /// accounts[0] = the stake account to close (its stored `owner` must
    /// equal the transaction payer), accounts[1] = the staking-stats
    /// singleton, accounts[2] = the reward pool singleton. Returned funds
    /// (principal + any pending reward, paid out automatically as a UX
    /// nicety - see module docs) go to the payer's own wallet.
    Undelegate,
    /// accounts[0] = the stake account to claim against (its stored
    /// `owner` must equal the transaction payer), accounts[1] = the
    /// reward pool singleton. Pays any pending reward to the payer's
    /// wallet and resets `reward_debt`; the position itself is untouched.
    ClaimReward,
    /// accounts[0] = the self-stake account to slash - its stored `owner`
    /// *and* `validator` must both equal the accused validator's address
    /// (a genuine self-delegation; a delegator's position is never
    /// touched by someone else's misbehavior). Permissionless: anyone
    /// holding valid `evidence` can call this, not just the accused
    /// validator's peers - see `EquivocationEvidence`'s doc comment for
    /// what makes it independently verifiable. See module docs below for
    /// why this burns the whole position rather than a partial fraction.
    ReportEquivocation { evidence: Box<EquivocationEvidence> },
}

fn read_stats(account: &Account) -> Result<u64, ExecError> {
    u64::try_from_slice(&account.data).map_err(|e| ExecError::ProgramError(format!("corrupt staking stats: {e}")))
}

fn read_pool(account: &Account) -> Result<RewardPoolData, ExecError> {
    RewardPoolData::try_from_slice(&account.data).map_err(|e| ExecError::ProgramError(format!("corrupt reward pool: {e}")))
}

/// The reward this position has earned but not yet been paid, given its
/// `amount`/`reward_debt` and the pool's current `acc_reward_per_share`.
/// Public so the node's `/stake/:address` RPC can report live pending reward.
pub fn pending_reward(amount: u64, reward_debt: u128, acc_reward_per_share: u128) -> u64 {
    let accrued = (amount as u128).saturating_mul(acc_reward_per_share) / PRECISION;
    accrued.saturating_sub(reward_debt).min(u64::MAX as u128) as u64
}

/// The `reward_debt` to record for a position holding `amount` right after
/// its reward has just been settled (paid or freshly opened) against the
/// pool's current `acc_reward_per_share` - i.e. "zero pending, starting
/// from here."
fn settled_reward_debt(amount: u64, acc_reward_per_share: u128) -> u128 {
    (amount as u128).saturating_mul(acc_reward_per_share) / PRECISION
}

/// Increases the shared reward pool's `acc_reward_per_share` by `pool_share`
/// newly-earned units, spread proportionally over `total_staked`. Called
/// from `Ledger`'s fee-crediting path (`ledger.rs`) with the
/// post-commission remainder of `base_fee`'s validator share - kept here
/// (not duplicated in `ledger.rs`) since it's the same accumulator math
/// `Delegate`/`Undelegate`/`ClaimReward` already depend on. Returns
/// `false` (and leaves the pool untouched) when `total_staked == 0`,
/// since dividing by zero total stake would otherwise silently burn the
/// fee share - the caller is expected to credit the validator directly
/// with the full amount in that case, preserving pre-staking-reward
/// behavior when there are no delegators yet to share with.
pub fn accrue_reward_pool(accounts: &mut HashMap<Pubkey, Account>, pool_pk: Pubkey, stats_pk: Pubkey, pool_share: u64) -> Result<bool, ExecError> {
    if pool_share == 0 {
        return Ok(true);
    }
    let total_staked = match accounts.get(&stats_pk) {
        Some(stats) => read_stats(stats)?,
        None => 0,
    };
    if total_staked == 0 {
        return Ok(false);
    }
    let pool_account = accounts
        .entry(pool_pk)
        .or_insert_with(|| Account { data: borsh::to_vec(&RewardPoolData::default()).unwrap(), ..Account::new_wallet(STAKING_PROGRAM_ID) });
    let mut pool = read_pool(pool_account)?;
    pool.acc_reward_per_share = pool.acc_reward_per_share.saturating_add((pool_share as u128).saturating_mul(PRECISION) / total_staked as u128);
    pool_account.data = borsh::to_vec(&pool).map_err(|e| ExecError::ProgramError(e.to_string()))?;
    pool_account.balance = pool_account.balance.saturating_add(pool_share);
    Ok(true)
}

pub struct StakingProgram;

impl NativeProgram for StakingProgram {
    fn process(&self, accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey, current_round: Round) -> Result<(), ExecError> {
        let instr = StakingInstruction::try_from_slice(&instruction.data)
            .map_err(|e| ExecError::ProgramError(format!("bad instruction data: {e}")))?;
        match instr {
            StakingInstruction::Delegate { validator, amount } => {
                let staker = *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("Delegate requires accounts[0]".into()))?;
                let stake_pk = *instruction.accounts.get(1).ok_or_else(|| ExecError::ProgramError("Delegate requires accounts[1]".into()))?;
                let stats_pk = *instruction.accounts.get(2).ok_or_else(|| ExecError::ProgramError("Delegate requires accounts[2]".into()))?;
                let pool_pk = *instruction.accounts.get(3).ok_or_else(|| ExecError::ProgramError("Delegate requires accounts[3]".into()))?;

                if staker != *payer {
                    return Err(ExecError::Unauthorized("Delegate's funding account must be the transaction payer".into()));
                }
                if accounts.contains_key(&stake_pk) {
                    return Err(ExecError::ProgramError("stake account already exists - Delegate always opens a fresh position".into()));
                }

                let staker_balance = accounts.get(&staker).ok_or(ExecError::AccountNotFound(staker))?.balance;
                if staker_balance < amount {
                    return Err(ExecError::InsufficientFunds);
                }
                accounts.get_mut(&staker).unwrap().balance -= amount;

                let pool_acc = match accounts.get(&pool_pk) {
                    Some(pool) => read_pool(pool)?.acc_reward_per_share,
                    None => 0,
                };
                let mut stake_account = Account::new_wallet(STAKING_PROGRAM_ID);
                stake_account.balance = amount;
                stake_account.data = borsh::to_vec(&StakeAccountData {
                    owner: staker,
                    validator,
                    amount,
                    reward_debt: settled_reward_debt(amount, pool_acc),
                    locked_until_round: 0,
                    bonding_until_round: current_round + MINIMUM_BONDING_ROUNDS,
                    unbonding_requested_at_round: None,
                })
                .map_err(|e| ExecError::ProgramError(e.to_string()))?;
                accounts.insert(stake_pk, stake_account);

                let stats = accounts
                    .entry(stats_pk)
                    .or_insert_with(|| Account { data: borsh::to_vec(&0u64).unwrap(), ..Account::new_wallet(STAKING_PROGRAM_ID) });
                let total = read_stats(stats)?.saturating_add(amount);
                stats.data = borsh::to_vec(&total).map_err(|e| ExecError::ProgramError(e.to_string()))?;
            }
            StakingInstruction::Undelegate => {
                let stake_pk = *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("Undelegate requires accounts[0]".into()))?;
                let stats_pk = *instruction.accounts.get(1).ok_or_else(|| ExecError::ProgramError("Undelegate requires accounts[1]".into()))?;
                let pool_pk = *instruction.accounts.get(2).ok_or_else(|| ExecError::ProgramError("Undelegate requires accounts[2]".into()))?;

                let stake_account = accounts.get(&stake_pk).ok_or(ExecError::AccountNotFound(stake_pk))?;
                let mut data = StakeAccountData::try_from_slice(&stake_account.data)
                    .map_err(|e| ExecError::ProgramError(format!("corrupt stake account: {e}")))?;
                if data.owner != *payer {
                    return Err(ExecError::Unauthorized("Undelegate must be signed by the stake account's owner".into()));
                }
                // Real, live-confirmed governance attack this closes - see
                // `StakeAccountData::locked_until_round`'s doc comment for
                // the full reproduction (vote, undelegate immediately, a
                // no-time-lock proposal still passes with the voter
                // holding zero stake by decision time).
                if current_round < data.locked_until_round {
                    return Err(ExecError::ProgramError(format!(
                        "this position voted on a proposal still deciding until round {} - cannot undelegate until then",
                        data.locked_until_round
                    )));
                }
                // Real, live-confirmed reward-sniping vulnerability this
                // closes - see `StakeAccountData::bonding_until_round`'s
                // doc comment for the full reproduction and measured
                // severity (~99.8% of a reward event captured by a
                // seconds-long position).
                if current_round < data.bonding_until_round {
                    return Err(ExecError::ProgramError(format!(
                        "this position is still in its minimum bonding period until round {} - cannot undelegate until then",
                        data.bonding_until_round
                    )));
                }
                // A real, live-confirmed slash-evasion race this closes -
                // see `StakeAccountData::unbonding_requested_at_round`'s
                // doc comment for the full reproduction. Only a genuine
                // self-stake position (the only kind `ReportEquivocation`
                // ever touches) goes through this two-step exit; an
                // ordinary delegator's `Undelegate` stays instant, exactly
                // as before.
                if data.owner == data.validator {
                    match data.unbonding_requested_at_round {
                        None => {
                            data.unbonding_requested_at_round = Some(current_round);
                            let stake_account = accounts.get_mut(&stake_pk).unwrap();
                            stake_account.data = borsh::to_vec(&data).map_err(|e| ExecError::ProgramError(e.to_string()))?;
                            return Ok(());
                        }
                        Some(requested_round) if current_round < requested_round + SELF_STAKE_UNBONDING_ROUNDS => {
                            return Err(ExecError::ProgramError(format!(
                                "this self-stake position is still unbonding until round {} - cannot withdraw until then",
                                requested_round + SELF_STAKE_UNBONDING_ROUNDS
                            )));
                        }
                        Some(_) => {}
                    }
                }
                let amount = data.amount;

                let pool_acc = match accounts.get(&pool_pk) {
                    Some(pool) => read_pool(pool)?.acc_reward_per_share,
                    None => 0,
                };
                let reward = pending_reward(data.amount, data.reward_debt, pool_acc);

                data.amount = 0;
                data.reward_debt = 0;
                let stake_account = accounts.get_mut(&stake_pk).unwrap();
                stake_account.balance = 0;
                stake_account.data = borsh::to_vec(&data).map_err(|e| ExecError::ProgramError(e.to_string()))?;

                if reward > 0 {
                    let pool_account = accounts.get_mut(&pool_pk).ok_or(ExecError::AccountNotFound(pool_pk))?;
                    pool_account.balance = pool_account.balance.saturating_sub(reward);
                }
                accounts.entry(*payer).or_insert_with(|| Account::new_wallet(Pubkey::system_program_id())).balance += amount + reward;

                let stats = accounts.get_mut(&stats_pk).ok_or(ExecError::AccountNotFound(stats_pk))?;
                let total = read_stats(stats)?.saturating_sub(amount);
                stats.data = borsh::to_vec(&total).map_err(|e| ExecError::ProgramError(e.to_string()))?;
            }
            StakingInstruction::ClaimReward => {
                let stake_pk = *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("ClaimReward requires accounts[0]".into()))?;
                let pool_pk = *instruction.accounts.get(1).ok_or_else(|| ExecError::ProgramError("ClaimReward requires accounts[1]".into()))?;

                let stake_account = accounts.get(&stake_pk).ok_or(ExecError::AccountNotFound(stake_pk))?;
                let mut data = StakeAccountData::try_from_slice(&stake_account.data)
                    .map_err(|e| ExecError::ProgramError(format!("corrupt stake account: {e}")))?;
                if data.owner != *payer {
                    return Err(ExecError::Unauthorized("ClaimReward must be signed by the stake account's owner".into()));
                }

                let pool_acc = read_pool(accounts.get(&pool_pk).ok_or(ExecError::AccountNotFound(pool_pk))?)?.acc_reward_per_share;
                let reward = pending_reward(data.amount, data.reward_debt, pool_acc);

                data.reward_debt = settled_reward_debt(data.amount, pool_acc);
                let stake_account = accounts.get_mut(&stake_pk).unwrap();
                stake_account.data = borsh::to_vec(&data).map_err(|e| ExecError::ProgramError(e.to_string()))?;

                if reward > 0 {
                    let pool_account = accounts.get_mut(&pool_pk).unwrap();
                    pool_account.balance = pool_account.balance.saturating_sub(reward);
                    accounts.entry(*payer).or_insert_with(|| Account::new_wallet(Pubkey::system_program_id())).balance += reward;
                }
            }
            StakingInstruction::ReportEquivocation { evidence } => {
                let stake_pk =
                    *instruction.accounts.first().ok_or_else(|| ExecError::ProgramError("ReportEquivocation requires accounts[0]".into()))?;
                // Optional accounts[1] = the staking-stats singleton. The CLI
                // always passes it (see `report-equivocation`), so in practice
                // it is always present and the global `total_staked` counter
                // is kept correct; it's tolerated-absent only so a caller that
                // omits it degrades to a no-op on the counter rather than a
                // hard rejection (the slash itself still applies either way).
                let stats_pk = instruction.accounts.get(1).copied();

                if evidence.vertex_a.round != evidence.vertex_b.round || evidence.vertex_a.author != evidence.vertex_b.author {
                    return Err(ExecError::ProgramError("evidence must reference the same (round, author)".into()));
                }
                let author = evidence.vertex_a.author;
                if evidence.vertex_a.digest() == evidence.vertex_b.digest() {
                    return Err(ExecError::ProgramError("evidence vertices are identical - not a conflict".into()));
                }
                // The bundle must genuinely be the accused validator's own
                // - otherwise anyone could submit two arbitrary signed
                // vertices under a bundle they control and frame someone
                // else's address.
                if evidence.author_bundle.to_address() != author {
                    return Err(ExecError::ProgramError("author_bundle does not match the accused validator's address".into()));
                }
                // What actually makes this evidence, not merely an
                // accusation: both signatures must independently verify
                // under the accused's own registered bundle, each over its
                // own vertex's digest.
                if !qchain_crypto::verify(&evidence.author_bundle, &evidence.vertex_a.digest(), &evidence.signature_a) {
                    return Err(ExecError::ProgramError("evidence signature_a does not verify".into()));
                }
                if !qchain_crypto::verify(&evidence.author_bundle, &evidence.vertex_b.digest(), &evidence.signature_b) {
                    return Err(ExecError::ProgramError("evidence signature_b does not verify".into()));
                }

                let stake_account = accounts.get(&stake_pk).ok_or(ExecError::AccountNotFound(stake_pk))?;
                let mut data = StakeAccountData::try_from_slice(&stake_account.data)
                    .map_err(|e| ExecError::ProgramError(format!("corrupt stake account: {e}")))?;
                if data.owner != author || data.validator != author {
                    return Err(ExecError::Unauthorized(
                        "the named stake account is not the accused validator's own self-stake - delegators can't be slashed for a validator's misbehavior".into(),
                    ));
                }
                if data.amount == 0 {
                    return Err(ExecError::ProgramError("nothing to slash - this self-stake position is already empty".into()));
                }

                // Burn the whole position - see module docs for why this
                // is a full slash, not a partial percentage. No one is
                // credited the slashed amount (not the reporter, not other
                // validators): it simply leaves circulating supply, same
                // as the existing burn-half-of-fees pattern elsewhere in
                // this codebase.
                let slashed = data.amount;
                data.amount = 0;
                data.reward_debt = 0;
                let stake_account = accounts.get_mut(&stake_pk).unwrap();
                stake_account.balance = 0;
                stake_account.data = borsh::to_vec(&data).map_err(|e| ExecError::ProgramError(e.to_string()))?;

                // Decrement the global `total_staked` counter by the slashed
                // amount - the same bookkeeping `Undelegate` does when a
                // position leaves. Without this the counter stays inflated
                // forever after any slash, permanently under-crediting honest
                // delegators' reward-per-share (which divides by
                // `total_staked`) and understating governance participation
                // (which measures turnout against it). `saturating_sub`
                // guards against any pre-existing desync rather than
                // underflowing.
                if let Some(stats_pk) = stats_pk {
                    let stats = accounts.get_mut(&stats_pk).ok_or(ExecError::AccountNotFound(stats_pk))?;
                    let total = read_stats(stats)?.saturating_sub(slashed);
                    stats.data = borsh::to_vec(&total).map_err(|e| ExecError::ProgramError(e.to_string()))?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{STAKING_REWARDS_POOL_ID, STAKING_STATS_ID};

    #[test]
    fn stake_instruction_encoding_is_stable() {
        // The WASM wallet (crates/qchain-wasm) hand-rolls these encodings to
        // avoid depending on this crate (which pulls wasmtime, no wasm target).
        // If the enum ever changes, this guard fails so the wallet is updated.
        let validator = Pubkey::new([7u8; 32]);
        let amount = 0x0102_0304_0506_0708u64;
        let mut expected = vec![0u8];
        expected.extend_from_slice(&validator.to_bytes());
        expected.extend_from_slice(&amount.to_le_bytes());
        assert_eq!(borsh::to_vec(&StakingInstruction::Delegate { validator, amount }).unwrap(), expected, "wasm Delegate encoding out of sync");
        assert_eq!(borsh::to_vec(&StakingInstruction::Undelegate).unwrap(), vec![1u8], "wasm Undelegate encoding out of sync");
        assert_eq!(borsh::to_vec(&StakingInstruction::ClaimReward).unwrap(), vec![2u8], "wasm ClaimReward encoding out of sync");
    }

    fn wallet_with(balance: u64) -> Account {
        Account { balance, ..Account::new_wallet(Pubkey::system_program_id()) }
    }

    fn stats_account() -> Account {
        Account { data: borsh::to_vec(&0u64).unwrap(), ..Account::new_wallet(STAKING_PROGRAM_ID) }
    }

    fn pool_account() -> Account {
        Account { data: borsh::to_vec(&RewardPoolData::default()).unwrap(), ..Account::new_wallet(STAKING_PROGRAM_ID) }
    }

    #[test]
    fn delegate_moves_funds_into_a_new_stake_account_and_updates_stats() {
        let staker = Pubkey::new([22u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let validator = Pubkey::new([21u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account()), (STAKING_REWARDS_POOL_ID, pool_account())]);

        let ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator, amount: 4_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &ix, &staker, 0).unwrap();

        assert_eq!(accounts[&staker].balance, 6_000);
        assert_eq!(accounts[&stake_pk].balance, 4_000);
        let data = StakeAccountData::try_from_slice(&accounts[&stake_pk].data).unwrap();
        assert_eq!(
            data,
            StakeAccountData { owner: staker, validator, amount: 4_000, reward_debt: 0, locked_until_round: 0, bonding_until_round: MINIMUM_BONDING_ROUNDS, unbonding_requested_at_round: None }
        );
        assert_eq!(read_stats(&accounts[&STAKING_STATS_ID]).unwrap(), 4_000);
    }

    #[test]
    fn delegating_someone_elses_wallet_is_rejected() {
        let staker = Pubkey::new([22u8; 32]);
        let attacker = Pubkey::new([23u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account()), (STAKING_REWARDS_POOL_ID, pool_account())]);

        let ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator: Pubkey::new([21u8; 32]), amount: 1_000 }).unwrap(),
        };
        let result = StakingProgram.process(&mut accounts, &ix, &attacker, 0);
        assert!(matches!(result, Err(ExecError::Unauthorized(_))));
    }

    #[test]
    fn undelegate_returns_funds_and_zeroes_the_position() {
        let staker = Pubkey::new([22u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let validator = Pubkey::new([21u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account()), (STAKING_REWARDS_POOL_ID, pool_account())]);
        let delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator, amount: 4_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();

        let undelegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Undelegate).unwrap(),
        };
        StakingProgram.process(&mut accounts, &undelegate_ix, &staker, MINIMUM_BONDING_ROUNDS).unwrap();

        assert_eq!(accounts[&staker].balance, 10_000, "funds must return in full once the minimum bonding period has elapsed");
        assert_eq!(accounts[&stake_pk].balance, 0);
        assert_eq!(read_stats(&accounts[&STAKING_STATS_ID]).unwrap(), 0);
    }

    /// The real, live-confirmed governance attack this closes (see
    /// `StakeAccountData::locked_until_round`'s doc comment): a position
    /// that voted must not be undelegated before the proposal it voted on
    /// is decided. `locked_until_round` here stands in for what
    /// `governance.rs`'s `Vote` handler would have set - this test targets
    /// `Undelegate`'s enforcement in isolation.
    #[test]
    fn undelegate_is_rejected_while_a_vote_still_has_it_locked() {
        let staker = Pubkey::new([22u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let validator = Pubkey::new([21u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account()), (STAKING_REWARDS_POOL_ID, pool_account())]);
        let delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator, amount: 4_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();

        // Simulate what a real `Vote` would do: lock this position until
        // round 266.
        let mut data = StakeAccountData::try_from_slice(&accounts[&stake_pk].data).unwrap();
        data.locked_until_round = 266;
        accounts.get_mut(&stake_pk).unwrap().data = borsh::to_vec(&data).unwrap();

        let undelegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Undelegate).unwrap(),
        };
        let result = StakingProgram.process(&mut accounts, &undelegate_ix, &staker, 200);
        assert!(result.is_err(), "undelegating before the locking proposal is decided must be rejected");
        assert_eq!(accounts[&stake_pk].balance, 4_000, "the position must remain intact, not partially unwound");

        // Once the voting period has actually ended, the same position
        // can undelegate normally.
        StakingProgram.process(&mut accounts, &undelegate_ix, &staker, 266).unwrap();
        assert_eq!(accounts[&stake_pk].balance, 0);
        assert_eq!(accounts[&staker].balance, 10_000, "funds return in full once the lock has genuinely expired");
    }

    /// The real, live-confirmed reward-sniping vulnerability this closes
    /// (see `StakeAccountData::bonding_until_round`'s doc comment): a
    /// same-round, zero-duration delegate/undelegate round-trip - the exact
    /// shape of the live attack - must be rejected.
    #[test]
    fn undelegate_is_rejected_during_its_minimum_bonding_period() {
        let staker = Pubkey::new([24u8; 32]);
        let stake_pk = Pubkey::new([25u8; 32]);
        let validator = Pubkey::new([26u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account()), (STAKING_REWARDS_POOL_ID, pool_account())]);
        let delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator, amount: 4_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();

        let undelegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Undelegate).unwrap(),
        };

        // The exact reward-sniping window this closes: a same-round,
        // zero-duration delegate/undelegate round-trip must be rejected.
        let result = StakingProgram.process(&mut accounts, &undelegate_ix, &staker, 0);
        assert!(result.is_err(), "undelegating in the same round as delegating must be rejected");
        assert_eq!(result.unwrap_err().to_string(), "program error: this position is still in its minimum bonding period until round 100 - cannot undelegate until then");
        assert_eq!(accounts[&stake_pk].balance, 4_000, "the position must remain intact, not partially unwound");

        // Still locked one round before the bonding period elapses.
        let result = StakingProgram.process(&mut accounts, &undelegate_ix, &staker, MINIMUM_BONDING_ROUNDS - 1);
        assert!(result.is_err(), "undelegating before the minimum bonding period has elapsed must be rejected");
        assert_eq!(accounts[&stake_pk].balance, 4_000);

        // Once the minimum bonding period has genuinely elapsed, the same
        // position can undelegate normally.
        StakingProgram.process(&mut accounts, &undelegate_ix, &staker, MINIMUM_BONDING_ROUNDS).unwrap();
        assert_eq!(accounts[&stake_pk].balance, 0);
        assert_eq!(accounts[&staker].balance, 10_000, "funds return in full once the bonding period has genuinely elapsed");
    }

    #[test]
    fn undelegate_by_a_non_owner_is_rejected() {
        let staker = Pubkey::new([22u8; 32]);
        let attacker = Pubkey::new([23u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let mut accounts =
            HashMap::from([(staker, wallet_with(10_000)), (attacker, wallet_with(0)), (STAKING_STATS_ID, stats_account()), (STAKING_REWARDS_POOL_ID, pool_account())]);
        let delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator: Pubkey::new([21u8; 32]), amount: 4_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();

        let undelegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Undelegate).unwrap(),
        };
        let result = StakingProgram.process(&mut accounts, &undelegate_ix, &attacker, 0);
        assert!(matches!(result, Err(ExecError::Unauthorized(_))));
        assert_eq!(accounts[&stake_pk].balance, 4_000, "an unauthorized undelegate must not touch the position");
    }

    #[test]
    fn accrue_reward_pool_falls_back_when_nothing_is_delegated() {
        let mut accounts = HashMap::from([(STAKING_STATS_ID, stats_account())]);
        let credited = accrue_reward_pool(&mut accounts, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, 500).unwrap();
        assert!(!credited, "with zero total stake the caller must fall back to crediting the validator directly");
        assert!(!accounts.contains_key(&STAKING_REWARDS_POOL_ID), "pool must be untouched when the accrual is skipped");
    }

    #[test]
    fn accrue_reward_pool_increases_acc_reward_per_share_proportionally() {
        let staker = Pubkey::new([22u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account()), (STAKING_REWARDS_POOL_ID, pool_account())]);
        let delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator: Pubkey::new([21u8; 32]), amount: 1_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();

        let credited = accrue_reward_pool(&mut accounts, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, 100).unwrap();
        assert!(credited);
        assert_eq!(accounts[&STAKING_REWARDS_POOL_ID].balance, 100);

        let claim_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::ClaimReward).unwrap(),
        };
        StakingProgram.process(&mut accounts, &claim_ix, &staker, 0).unwrap();
        assert_eq!(accounts[&staker].balance, 9_000 + 100, "the sole delegator earns the entire pool_share");
        assert_eq!(accounts[&STAKING_REWARDS_POOL_ID].balance, 0);
    }

    #[test]
    fn claim_reward_pays_the_pending_amount_and_resets_debt() {
        let staker = Pubkey::new([22u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account()), (STAKING_REWARDS_POOL_ID, pool_account())]);
        let delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator: Pubkey::new([21u8; 32]), amount: 1_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();
        accrue_reward_pool(&mut accounts, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, 100).unwrap();

        let claim_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::ClaimReward).unwrap(),
        };
        StakingProgram.process(&mut accounts, &claim_ix, &staker, 0).unwrap();
        assert_eq!(accounts[&staker].balance, 9_100);

        // A second, immediate claim with no new accrual must pay nothing more.
        StakingProgram.process(&mut accounts, &claim_ix, &staker, 0).unwrap();
        assert_eq!(accounts[&staker].balance, 9_100, "reward_debt must have been settled so a repeat claim pays zero");
        let data = StakeAccountData::try_from_slice(&accounts[&stake_pk].data).unwrap();
        assert_eq!(data.amount, 1_000, "claiming must not touch the principal");
    }

    #[test]
    fn claim_reward_by_a_non_owner_is_rejected() {
        let staker = Pubkey::new([22u8; 32]);
        let attacker = Pubkey::new([23u8; 32]);
        let stake_pk = Pubkey::new([20u8; 32]);
        let mut accounts = HashMap::from([(staker, wallet_with(10_000)), (STAKING_STATS_ID, stats_account()), (STAKING_REWARDS_POOL_ID, pool_account())]);
        let delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![staker, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator: Pubkey::new([21u8; 32]), amount: 1_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &delegate_ix, &staker, 0).unwrap();
        accrue_reward_pool(&mut accounts, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, 100).unwrap();

        let claim_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::ClaimReward).unwrap(),
        };
        let result = StakingProgram.process(&mut accounts, &claim_ix, &attacker, 0);
        assert!(matches!(result, Err(ExecError::Unauthorized(_))));
        assert_eq!(accounts[&STAKING_REWARDS_POOL_ID].balance, 100, "an unauthorized claim must not touch the pool");
    }

    #[test]
    fn a_delegator_joining_after_accrual_does_not_earn_the_earlier_share() {
        let early = Pubkey::new([22u8; 32]);
        let early_stake_pk = Pubkey::new([20u8; 32]);
        let late = Pubkey::new([24u8; 32]);
        let late_stake_pk = Pubkey::new([25u8; 32]);
        let mut accounts = HashMap::from([
            (early, wallet_with(10_000)),
            (late, wallet_with(10_000)),
            (STAKING_STATS_ID, stats_account()),
            (STAKING_REWARDS_POOL_ID, pool_account()),
        ]);

        let early_delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![early, early_stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator: Pubkey::new([21u8; 32]), amount: 1_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &early_delegate_ix, &early, 0).unwrap();

        accrue_reward_pool(&mut accounts, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, 100).unwrap();

        let late_delegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![late, late_stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Delegate { validator: Pubkey::new([21u8; 32]), amount: 1_000 }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &late_delegate_ix, &late, 0).unwrap();

        let claim_late_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![late_stake_pk, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::ClaimReward).unwrap(),
        };
        StakingProgram.process(&mut accounts, &claim_late_ix, &late, 0).unwrap();
        assert_eq!(accounts[&late].balance, 9_000, "a delegator who joined after the accrual must earn nothing from it");

        let claim_early_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![early_stake_pk, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::ClaimReward).unwrap(),
        };
        StakingProgram.process(&mut accounts, &claim_early_ix, &early, 0).unwrap();
        assert_eq!(accounts[&early].balance, 9_000 + 100, "the pre-existing delegator must earn the entire prior accrual alone");
    }

    /// Builds two genuinely conflicting, validly author-signed vertices for
    /// the same (round, author) - the real shape `qchain-node::engine`
    /// constructs from two conflicting live `VertexProposal`s.
    fn conflicting_evidence(author_kp: &qchain_crypto::Keypair, round: qchain_core::Round) -> EquivocationEvidence {
        let vertex_a = qchain_core::Vertex { round, author: author_kp.pubkey(), batch_digests: vec![(0, [1u8; 32])], parents: vec![] };
        let vertex_b = qchain_core::Vertex { round, author: author_kp.pubkey(), batch_digests: vec![(0, [2u8; 32])], parents: vec![] };
        let signature_a = author_kp.sign(&vertex_a.digest()[..]).unwrap();
        let signature_b = author_kp.sign(&vertex_b.digest()[..]).unwrap();
        EquivocationEvidence { vertex_a, signature_a, vertex_b, signature_b, author_bundle: author_kp.public_key_bundle() }
    }

    #[test]
    fn report_equivocation_slashes_the_validators_own_self_stake() {
        let validator_kp = qchain_crypto::Keypair::generate().unwrap();
        let validator = validator_kp.pubkey();
        let stake_pk = Pubkey::new([30u8; 32]);
        let reporter = Pubkey::new([31u8; 32]);
        let mut accounts = HashMap::from([(
            stake_pk,
            Account {
                data: borsh::to_vec(&StakeAccountData { owner: validator, validator, amount: 5_000_000, reward_debt: 0, locked_until_round: 0, bonding_until_round: 0, unbonding_requested_at_round: None }).unwrap(),
                balance: 5_000_000,
                ..Account::new_wallet(STAKING_PROGRAM_ID)
            },
        )]);

        let evidence = conflicting_evidence(&validator_kp, 7);
        let ix = Instruction { program_id: STAKING_PROGRAM_ID, accounts: vec![stake_pk], data: borsh::to_vec(&StakingInstruction::ReportEquivocation { evidence: Box::new(evidence) }).unwrap() };
        // Permissionless: signed/paid by an unrelated reporter, not the
        // accused validator and not the stake account's owner via any
        // special relationship - the evidence alone is what authorizes this.
        StakingProgram.process(&mut accounts, &ix, &reporter, 0).unwrap();

        assert_eq!(accounts[&stake_pk].balance, 0, "the whole self-staked position must be burned");
        let data = StakeAccountData::try_from_slice(&accounts[&stake_pk].data).unwrap();
        assert_eq!(data.amount, 0);
        assert_eq!(data.reward_debt, 0);
    }

    /// A slash must also decrement the global `total_staked` counter by the
    /// burned amount, exactly like a normal `Undelegate` does - otherwise the
    /// counter stays permanently inflated, under-crediting honest delegators'
    /// reward-per-share and understating governance turnout forever after any
    /// slash. Verifies the counter drops by exactly the slashed amount when
    /// the stats account is passed as accounts[1].
    #[test]
    fn report_equivocation_also_decrements_the_global_total_staked_counter() {
        let validator_kp = qchain_crypto::Keypair::generate().unwrap();
        let validator = validator_kp.pubkey();
        let stake_pk = Pubkey::new([32u8; 32]);
        let reporter = Pubkey::new([33u8; 32]);
        // Stats starts at 8,000,000 (the accused's 5,000,000 self-stake plus
        // an unrelated 3,000,000 that must survive the slash untouched).
        let mut accounts = HashMap::from([
            (
                stake_pk,
                Account {
                    data: borsh::to_vec(&StakeAccountData { owner: validator, validator, amount: 5_000_000, reward_debt: 0, locked_until_round: 0, bonding_until_round: 0, unbonding_requested_at_round: None }).unwrap(),
                    balance: 5_000_000,
                    ..Account::new_wallet(STAKING_PROGRAM_ID)
                },
            ),
            (STAKING_STATS_ID, Account { data: borsh::to_vec(&8_000_000u64).unwrap(), ..Account::new_wallet(STAKING_PROGRAM_ID) }),
        ]);

        let evidence = conflicting_evidence(&validator_kp, 9);
        let ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_STATS_ID],
            data: borsh::to_vec(&StakingInstruction::ReportEquivocation { evidence: Box::new(evidence) }).unwrap(),
        };
        StakingProgram.process(&mut accounts, &ix, &reporter, 0).unwrap();

        assert_eq!(accounts[&stake_pk].balance, 0, "the self-stake is burned");
        let total: u64 = borsh::BorshDeserialize::try_from_slice(&accounts[&STAKING_STATS_ID].data).unwrap();
        assert_eq!(total, 3_000_000, "total_staked must drop by exactly the slashed 5,000,000, leaving the unrelated 3,000,000");
    }

    /// The exact real, live-confirmed slash-evasion race this closes (see
    /// `StakeAccountData::unbonding_requested_at_round`'s doc comment): an
    /// equivocating validator's own `Undelegate`, submitted the instant
    /// they misbehave, must not be able to empty their self-stake before
    /// `ReportEquivocation` can burn it - live-confirmed to actually
    /// succeed and evade the slash entirely before this fix. The first
    /// `Undelegate` call only starts the clock (funds stay in place,
    /// still slashable); a second call before the unbonding window
    /// elapses is rejected; `ReportEquivocation` still finds and burns
    /// the position while it's merely "unbonding," not yet withdrawn.
    #[test]
    fn a_self_stake_undelegate_starts_an_unbonding_window_instead_of_paying_out_immediately_and_stays_slashable_during_it() {
        let validator_kp = qchain_crypto::Keypair::generate().unwrap();
        let validator = validator_kp.pubkey();
        let stake_pk = Pubkey::new([40u8; 32]);
        let mut accounts = HashMap::from([
            (
                stake_pk,
                Account {
                    data: borsh::to_vec(&StakeAccountData {
                        owner: validator,
                        validator,
                        amount: 5_000_000,
                        reward_debt: 0,
                        locked_until_round: 0,
                        bonding_until_round: 0,
                        unbonding_requested_at_round: None,
                    })
                    .unwrap(),
                    balance: 5_000_000,
                    ..Account::new_wallet(STAKING_PROGRAM_ID)
                },
            ),
            (STAKING_STATS_ID, stats_account()),
            (STAKING_REWARDS_POOL_ID, pool_account()),
        ]);
        let undelegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Undelegate).unwrap(),
        };

        // First call: starts unbonding, funds stay exactly where they are.
        StakingProgram.process(&mut accounts, &undelegate_ix, &validator, 0).unwrap();
        assert_eq!(accounts[&stake_pk].balance, 5_000_000, "the self-stake must not be paid out on the first Undelegate call");
        let data = StakeAccountData::try_from_slice(&accounts[&stake_pk].data).unwrap();
        assert_eq!(data.amount, 5_000_000, "the position's recorded amount must be untouched while merely unbonding");
        assert_eq!(data.unbonding_requested_at_round, Some(0));

        // Exactly the real attack: ReportEquivocation must still find and
        // burn the position while it's mid-unbonding, not yet withdrawn.
        let reporter = Pubkey::new([41u8; 32]);
        let evidence = conflicting_evidence(&validator_kp, 7);
        let report_ix =
            Instruction { program_id: STAKING_PROGRAM_ID, accounts: vec![stake_pk], data: borsh::to_vec(&StakingInstruction::ReportEquivocation { evidence: Box::new(evidence) }).unwrap() };
        StakingProgram.process(&mut accounts, &report_ix, &reporter, 1).unwrap();
        assert_eq!(accounts[&stake_pk].balance, 0, "the slash must still burn the position even though it was mid-unbonding, not yet withdrawn");
    }

    #[test]
    fn a_second_undelegate_before_the_unbonding_window_elapses_is_rejected_but_succeeds_after() {
        let validator_kp = qchain_crypto::Keypair::generate().unwrap();
        let validator = validator_kp.pubkey();
        let stake_pk = Pubkey::new([42u8; 32]);
        let mut accounts = HashMap::from([
            (
                stake_pk,
                Account {
                    data: borsh::to_vec(&StakeAccountData {
                        owner: validator,
                        validator,
                        amount: 5_000_000,
                        reward_debt: 0,
                        locked_until_round: 0,
                        bonding_until_round: 0,
                        unbonding_requested_at_round: None,
                    })
                    .unwrap(),
                    balance: 5_000_000,
                    ..Account::new_wallet(STAKING_PROGRAM_ID)
                },
            ),
            (STAKING_STATS_ID, stats_account()),
            (STAKING_REWARDS_POOL_ID, pool_account()),
        ]);
        let undelegate_ix = Instruction {
            program_id: STAKING_PROGRAM_ID,
            accounts: vec![stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
            data: borsh::to_vec(&StakingInstruction::Undelegate).unwrap(),
        };
        StakingProgram.process(&mut accounts, &undelegate_ix, &validator, 0).unwrap();

        let result = StakingProgram.process(&mut accounts, &undelegate_ix, &validator, SELF_STAKE_UNBONDING_ROUNDS - 1);
        assert!(result.is_err(), "withdrawing before the unbonding window elapses must be rejected");
        assert_eq!(accounts[&stake_pk].balance, 5_000_000, "the position must remain intact, not partially unwound");

        StakingProgram.process(&mut accounts, &undelegate_ix, &validator, SELF_STAKE_UNBONDING_ROUNDS).unwrap();
        assert_eq!(accounts[&stake_pk].balance, 0);
        assert_eq!(accounts[&validator].balance, 5_000_000, "principal returns in full once the unbonding window has genuinely elapsed");
    }

    #[test]
    fn report_equivocation_rejects_a_delegators_position_not_the_validators_own_self_stake() {
        let validator_kp = qchain_crypto::Keypair::generate().unwrap();
        let validator = validator_kp.pubkey();
        let delegator = Pubkey::new([32u8; 32]);
        let stake_pk = Pubkey::new([33u8; 32]);
        let reporter = Pubkey::new([34u8; 32]);
        // A real delegator's position: owner is the delegator, not the
        // validator - must never be touched by the validator's own
        // misbehavior.
        let mut accounts = HashMap::from([(
            stake_pk,
            Account {
                data: borsh::to_vec(&StakeAccountData { owner: delegator, validator, amount: 5_000_000, reward_debt: 0, locked_until_round: 0, bonding_until_round: 0, unbonding_requested_at_round: None }).unwrap(),
                balance: 5_000_000,
                ..Account::new_wallet(STAKING_PROGRAM_ID)
            },
        )]);

        let evidence = conflicting_evidence(&validator_kp, 7);
        let ix = Instruction { program_id: STAKING_PROGRAM_ID, accounts: vec![stake_pk], data: borsh::to_vec(&StakingInstruction::ReportEquivocation { evidence: Box::new(evidence) }).unwrap() };
        let result = StakingProgram.process(&mut accounts, &ix, &reporter, 0);

        assert!(matches!(result, Err(ExecError::Unauthorized(_))));
        assert_eq!(accounts[&stake_pk].balance, 5_000_000, "a delegator's funds must be untouched by someone else's equivocation");
    }

    #[test]
    fn report_equivocation_rejects_a_tampered_signature() {
        let validator_kp = qchain_crypto::Keypair::generate().unwrap();
        let validator = validator_kp.pubkey();
        let stake_pk = Pubkey::new([35u8; 32]);
        let reporter = Pubkey::new([36u8; 32]);
        let mut accounts = HashMap::from([(
            stake_pk,
            Account {
                data: borsh::to_vec(&StakeAccountData { owner: validator, validator, amount: 5_000_000, reward_debt: 0, locked_until_round: 0, bonding_until_round: 0, unbonding_requested_at_round: None }).unwrap(),
                balance: 5_000_000,
                ..Account::new_wallet(STAKING_PROGRAM_ID)
            },
        )]);

        let mut evidence = conflicting_evidence(&validator_kp, 7);
        evidence.signature_b.components[0].bytes[0] ^= 0xFF;
        let ix = Instruction { program_id: STAKING_PROGRAM_ID, accounts: vec![stake_pk], data: borsh::to_vec(&StakingInstruction::ReportEquivocation { evidence: Box::new(evidence) }).unwrap() };
        let result = StakingProgram.process(&mut accounts, &ix, &reporter, 0);

        assert!(matches!(result, Err(ExecError::ProgramError(_))));
        assert_eq!(accounts[&stake_pk].balance, 5_000_000, "a forged/tampered signature must never slash anything");
    }

    #[test]
    fn report_equivocation_rejects_identical_vertices_as_not_a_real_conflict() {
        let validator_kp = qchain_crypto::Keypair::generate().unwrap();
        let validator = validator_kp.pubkey();
        let stake_pk = Pubkey::new([37u8; 32]);
        let reporter = Pubkey::new([38u8; 32]);
        let mut accounts = HashMap::from([(
            stake_pk,
            Account {
                data: borsh::to_vec(&StakeAccountData { owner: validator, validator, amount: 5_000_000, reward_debt: 0, locked_until_round: 0, bonding_until_round: 0, unbonding_requested_at_round: None }).unwrap(),
                balance: 5_000_000,
                ..Account::new_wallet(STAKING_PROGRAM_ID)
            },
        )]);

        let mut evidence = conflicting_evidence(&validator_kp, 7);
        evidence.vertex_b = evidence.vertex_a.clone();
        evidence.signature_b = evidence.signature_a.clone();
        let ix = Instruction { program_id: STAKING_PROGRAM_ID, accounts: vec![stake_pk], data: borsh::to_vec(&StakingInstruction::ReportEquivocation { evidence: Box::new(evidence) }).unwrap() };
        let result = StakingProgram.process(&mut accounts, &ix, &reporter, 0);

        assert!(matches!(result, Err(ExecError::ProgramError(_))));
        assert_eq!(accounts[&stake_pk].balance, 5_000_000, "the exact same vertex twice is not equivocation");
    }

    #[test]
    fn report_equivocation_rejects_mismatched_rounds() {
        let validator_kp = qchain_crypto::Keypair::generate().unwrap();
        let validator = validator_kp.pubkey();
        let stake_pk = Pubkey::new([39u8; 32]);
        let reporter = Pubkey::new([40u8; 32]);
        let mut accounts = HashMap::from([(
            stake_pk,
            Account {
                data: borsh::to_vec(&StakeAccountData { owner: validator, validator, amount: 5_000_000, reward_debt: 0, locked_until_round: 0, bonding_until_round: 0, unbonding_requested_at_round: None }).unwrap(),
                balance: 5_000_000,
                ..Account::new_wallet(STAKING_PROGRAM_ID)
            },
        )]);

        let vertex_a = qchain_core::Vertex { round: 7, author: validator, batch_digests: vec![(0, [1u8; 32])], parents: vec![] };
        let vertex_b = qchain_core::Vertex { round: 8, author: validator, batch_digests: vec![(0, [2u8; 32])], parents: vec![] };
        let signature_a = validator_kp.sign(&vertex_a.digest()[..]).unwrap();
        let signature_b = validator_kp.sign(&vertex_b.digest()[..]).unwrap();
        let evidence = EquivocationEvidence { vertex_a, signature_a, vertex_b, signature_b, author_bundle: validator_kp.public_key_bundle() };
        let ix = Instruction { program_id: STAKING_PROGRAM_ID, accounts: vec![stake_pk], data: borsh::to_vec(&StakingInstruction::ReportEquivocation { evidence: Box::new(evidence) }).unwrap() };
        let result = StakingProgram.process(&mut accounts, &ix, &reporter, 0);

        assert!(matches!(result, Err(ExecError::ProgramError(_))));
        assert_eq!(accounts[&stake_pk].balance, 5_000_000, "two different validators' or rounds' vertices prove nothing about either one equivocating");
    }
}
