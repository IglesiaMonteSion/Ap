//! v7 treasury — a genesis-locked reserve of QCH controlled by a REAL M-of-N
//! MULTISIG with a timelock, per-operation and per-window limits, and a fully
//! on-chain (auditable) operation log. **v7 only** (a v6 network never seeds or
//! dispatches this, so it is byte-identical). Execution-layer native program,
//! same pattern as `StakingV7Program`/`ValidatorV7Program` — it does NOT touch
//! consensus.
//!
//! ## Why it exists — and why MULTISIG (task #222)
//! A clean v7 genesis has zero spendable supply (the only minted QCH is each
//! founder's 500 QCH bond, locked collateral). The operator mints the initial
//! circulating supply into a TREASURY account at genesis, LOCKED: the account is
//! owned by `TREASURY_V7_PROGRAM_ID`, so no ordinary signed transfer can move it.
//! Releasing funds is gated so that **no single key can move administrative funds
//! or change who controls them**:
//! - **M-of-N multisig** — `threshold` distinct signers of the configured set must
//!   approve an operation (e.g. 3 of 5). A hybrid Ed25519+ML-DSA key is still ONE
//!   authority if one person holds it; the multisig is the real separation.
//! - **Timelock** — after the threshold is reached, a mandatory delay
//!   (`timelock_rounds`) elapses before the operation can execute, so a rushed or
//!   coerced release has a public review window.
//! - **Limits** — a per-operation cap (`max_per_release`) and a rolling-window cap
//!   (`max_per_window` over `window_rounds`) bound how much can ever leave.
//! - **Auditable events** — every proposal, approval, and execution lives in the
//!   treasury account's on-chain state (in the Merkle root, i.e. committed by
//!   consensus), readable by anyone (`GET /treasury`). This is a stronger audit
//!   trail than a log line: the full history of who proposed/approved what, and
//!   how much has been released this window, is deterministic on-chain state.
//! - **Signers in genesis, not constants** — the signer set is configured at
//!   genesis (`treasury_signers`), never a hidden compile-time constant.
//! - **Cold keys / HSM** — the signers are just pubkeys; the operator holds each
//!   private key OFFLINE (air-gapped CLI: `keygen` + sign a propose/approve tx on
//!   the cold box, broadcast from another). Same posture as the consensus
//!   remote-signer.
//! - **Recovery / signer substitution** — `SetSigners` (itself multisig+timelock
//!   gated) replaces the signer set + threshold, so a lost or compromised key is
//!   rotated out by the remaining signers without touching funds.
//!
//! Emission/hard-cap is orthogonal (the treasury MOVES QCH on release, never
//! mints — supply is conserved).
//!
//! ## Operation lifecycle (deterministic on every node → no fork)
//! `Propose{op}` (a signer) → `Approve{op_id}` (each other signer, deduplicated)
//! → once the op-kind's required number of distinct signers approve, the timelock
//! clock starts → `Execute{op_id}` (permissionless, once the timelock elapses AND
//! the limits allow it) applies the effect and removes the op. A signer may
//! `Cancel{op_id}` a pending op. Operation kinds:
//! - `Release { amount, destination }` — move `amount` from the treasury to
//!   `destination` (bounded by the per-op + per-window limits).
//! - `SetSigners { signers, threshold, policy_threshold, signers_threshold }` —
//!   rotate the signer set AND set the whole threshold hierarchy (recovery).
//! - `SetPolicy { timelock_rounds, max_per_release, max_per_window, window_rounds,
//!   op_expiry_rounds }` — change the timelock/limits/op-expiry.
//!
//! ## Threshold HIERARCHY + op EXPIRATION (roadmap #17)
//! Not every operation is equally sensitive, so each op KIND requires its own
//! (increasingly strict) approval threshold — `liberar (Release) <= política
//! (SetPolicy) <= firmantes (SetSigners)`:
//! - **liberar** — a `Release` needs `threshold` approvals (the lowest bar;
//!   routine releases are already bounded by the per-op/per-window limits).
//! - **política** — a `SetPolicy` (timelock/limits/expiry) needs `policy_threshold`
//!   approvals. It can NOT touch the signer set or the tier thresholds.
//! - **firmantes** — a `SetSigners` (who controls the treasury, and the tier
//!   thresholds themselves) needs `signers_threshold` approvals (the highest bar).
//!
//! Privilege can't escalate: a política-tier quorum can never weaken who controls
//! the treasury (only `SetSigners`, firmantes-tier, changes signers/thresholds).
//! The required threshold is re-checked at EXECUTE time against current state, so
//! a mid-flight `SetSigners`/`SetPolicy` that raises a bar retroactively holds a
//! stale op back until it re-reaches the new bar.
//!
//! **Op expiration** — a pending op that isn't executed within `op_expiry_rounds`
//! of being proposed is pruned (non-executable). Prevents a coerced/forgotten
//! approved op from lingering executable forever; `0` = no expiry (the default).
//!
//! A pre-#17 treasury migrates (`read_or_legacy`) with all tiers equal to
//! `threshold` and `op_expiry_rounds = 0` → byte-identical behavior.
//!
//! ## Backward compatibility (brick-safe)
//! A network deployed before this change stored a legacy `{authority: Pubkey}`
//! (exactly 32 bytes). `read_state` decodes that as a **1-of-1 multisig** (the old
//! single authority, timelock 0, no limits), so a live single-authority treasury
//! keeps working after a binary-only update — it can then upgrade itself to a real
//! M-of-N via a `SetSigners` op, no relaunch needed. Genuinely corrupt data (not
//! the new layout and not a 32-byte legacy blob) still fails loud (#217).

use crate::error::ExecError;
use crate::ids::TREASURY_ACCOUNT_ID;
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{Account, Instruction, Round};
use qchain_crypto::Pubkey;
use std::collections::HashMap;

/// Max signers in the multisig (bounds the on-chain set + approval scans).
pub const MAX_TREASURY_SIGNERS: usize = 16;
/// Max simultaneously-pending operations (bounds account growth; a full queue
/// rejects new proposals until some are executed or cancelled).
pub const MAX_TREASURY_PENDING: usize = 16;

/// An operation the multisig can authorize.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub enum TreasuryOp {
    /// Unlock+send `amount` from the treasury to `destination`. **liberar** tier —
    /// gated by the base `threshold` (the lowest bar), since routine releases are
    /// already bounded by the per-op + per-window limits.
    Release { amount: u64, destination: Pubkey },
    /// Rotate the signer set + the whole threshold hierarchy (recovery /
    /// substitution). Moves no funds. **firmantes** tier — gated by
    /// `signers_threshold` (the highest bar), since it re-defines who controls the
    /// treasury AND the tier thresholds. Carries the new `threshold` (release/
    /// liberar), `policy_threshold` (política) and `signers_threshold` (firmantes);
    /// validated `1 <= threshold <= policy_threshold <= signers_threshold <= len`.
    SetSigners { signers: Vec<Pubkey>, threshold: u8, policy_threshold: u8, signers_threshold: u8 },
    /// Change the timelock + limits + op-expiry. Moves no funds. **política** tier —
    /// gated by `policy_threshold` (the middle bar). It can NOT change the tier
    /// thresholds or the signer set (that's `SetSigners`, firmantes tier), so a
    /// política-tier quorum can never weaken who controls the treasury.
    SetPolicy { timelock_rounds: u64, max_per_release: u64, max_per_window: u64, window_rounds: u64, op_expiry_rounds: u64 },
}

/// A proposed operation accumulating approvals, plus its timelock anchor.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct PendingOp {
    pub id: u64,
    pub op: TreasuryOp,
    /// Round the operation was proposed (audit).
    pub proposed_round: u64,
    /// Distinct signers who have approved (the proposer counts as the first).
    pub approvals: Vec<Pubkey>,
    /// Round at which the threshold was first reached (0 = not yet). The timelock
    /// runs from HERE, so the review window is after the multisig decides.
    pub threshold_reached_round: u64,
}

impl PendingOp {
    pub fn ready_round(&self, timelock_rounds: u64) -> Option<u64> {
        if self.threshold_reached_round == 0 {
            None
        } else {
            Some(self.threshold_reached_round.saturating_add(timelock_rounds))
        }
    }
}

/// The treasury singleton's `data` (`TREASURY_ACCOUNT_ID.data`). The locked QCH
/// lives in that account's `balance`; only an approved+timelocked multisig
/// operation may move it.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct TreasuryState {
    /// The M-of-N signer set (cold keys). Configured at genesis.
    pub signers: Vec<Pubkey>,
    /// M: distinct signers required to authorize an operation.
    pub threshold: u8,
    /// Mandatory delay (in rounds) after the threshold is reached before an
    /// operation may execute.
    pub timelock_rounds: u64,
    /// Max atoms a single `Release` may move (0 = no per-operation cap).
    pub max_per_release: u64,
    /// Max atoms that may be released within a rolling `window_rounds` window
    /// (0 = no per-window cap).
    pub max_per_window: u64,
    /// Length of the rolling release-accounting window in rounds (0 = disabled).
    pub window_rounds: u64,
    /// Start round of the current accounting window.
    pub window_start_round: u64,
    /// Atoms released so far in the current window.
    pub released_in_window: u64,
    /// Next operation id to assign (monotonic).
    pub next_op_id: u64,
    /// Operations awaiting approvals / timelock.
    pub pending: Vec<PendingOp>,
    // --- roadmap #17: threshold hierarchy + op expiration (appended fields) ---
    /// Approvals required to execute a `SetPolicy` op (política tier). `>= threshold`
    /// (the release/liberar tier). A pre-#17 treasury migrates with this equal to
    /// `threshold` (byte-identical behavior — all tiers the same).
    pub policy_threshold: u8,
    /// Approvals required to execute a `SetSigners` op (firmantes tier — rotating
    /// who controls the treasury, the most sensitive op). `>= policy_threshold`.
    /// Migrates equal to `threshold`.
    pub signers_threshold: u8,
    /// A pending operation EXPIRES (is pruned, becomes non-executable) once
    /// `op_expiry_rounds` have elapsed since it was proposed. `0` = no expiry (the
    /// pre-#17 default). Prevents a coerced/forgotten approved op from lingering
    /// executable forever; a stale op must be re-proposed under the current policy.
    pub op_expiry_rounds: u64,
}

impl TreasuryState {
    /// A single-signer treasury (used by the legacy-decode fallback and simple
    /// setups): 1-of-1, no timelock, no limits, all tiers = 1, no expiry.
    pub fn single(authority: Pubkey) -> Self {
        TreasuryState {
            signers: vec![authority],
            threshold: 1,
            timelock_rounds: 0,
            max_per_release: 0,
            max_per_window: 0,
            window_rounds: 0,
            window_start_round: 0,
            released_in_window: 0,
            next_op_id: 0,
            pending: Vec::new(),
            policy_threshold: 1,
            signers_threshold: 1,
            op_expiry_rounds: 0,
        }
    }

    fn is_signer(&self, pk: &Pubkey) -> bool {
        self.signers.contains(pk)
    }

    /// The approval threshold an op of this KIND requires (roadmap #17), enforcing
    /// the hierarchy `liberar (Release) <= política (SetPolicy) <= firmantes
    /// (SetSigners)`. The `.max` chain is defense-in-depth: even a mis-stored tier
    /// below its predecessor is clamped up, so the ordering can never be violated
    /// at runtime (config-time validation via `validate_thresholds` is the primary
    /// guard). For a pre-#17 treasury every tier equals `threshold`, so this returns
    /// `threshold` for every op — byte-identical to the single-threshold behavior.
    pub fn required_threshold(&self, op: &TreasuryOp) -> u8 {
        match op {
            TreasuryOp::Release { .. } => self.threshold,
            TreasuryOp::SetPolicy { .. } => self.policy_threshold.max(self.threshold),
            TreasuryOp::SetSigners { .. } => self.signers_threshold.max(self.policy_threshold).max(self.threshold),
        }
    }
}

/// The pre-#17 `TreasuryState` layout (every field EXCEPT the three appended
/// #17 fields), used only by `read_or_legacy` to decode a treasury account
/// written before the threshold hierarchy / op-expiry existed. Private; must
/// mirror `TreasuryState` up to (not including) `policy_threshold`.
#[derive(BorshDeserialize, BorshSerialize)]
struct TreasuryStateV0 {
    signers: Vec<Pubkey>,
    threshold: u8,
    timelock_rounds: u64,
    max_per_release: u64,
    max_per_window: u64,
    window_rounds: u64,
    window_start_round: u64,
    released_in_window: u64,
    next_op_id: u64,
    pending: Vec<PendingOp>,
}

impl TreasuryState {
    /// Decode a `TreasuryState`, migrating a pre-#17 record (without the tier
    /// thresholds / op-expiry) by defaulting `policy_threshold = signers_threshold
    /// = threshold` (all tiers equal → byte-identical behavior) and `op_expiry_rounds
    /// = 0` (no expiry). Try the new layout first; a pre-#17 blob is shorter (the 3
    /// appended fields missing) → borsh hits EOF → falls through to `TreasuryStateV0`.
    /// A new blob has trailing bytes the V0 struct can't consume (borsh rejects
    /// trailing), so the two never cross-decode.
    fn read_or_legacy(data: &[u8]) -> Option<Self> {
        if let Ok(s) = borsh::from_slice::<TreasuryState>(data) {
            return Some(s);
        }
        let v0 = borsh::from_slice::<TreasuryStateV0>(data).ok()?;
        Some(TreasuryState {
            signers: v0.signers,
            threshold: v0.threshold,
            timelock_rounds: v0.timelock_rounds,
            max_per_release: v0.max_per_release,
            max_per_window: v0.max_per_window,
            window_rounds: v0.window_rounds,
            window_start_round: v0.window_start_round,
            released_in_window: v0.released_in_window,
            next_op_id: v0.next_op_id,
            pending: v0.pending,
            policy_threshold: v0.threshold,
            signers_threshold: v0.threshold,
            op_expiry_rounds: 0,
        })
    }
}

/// Validate a signer set + threshold: 1..=MAX signers, no duplicates, and
/// `1 <= threshold <= signers.len()`. Used at genesis and on `SetSigners`.
pub fn validate_signer_set(signers: &[Pubkey], threshold: u8) -> Result<(), ExecError> {
    if signers.is_empty() || signers.len() > MAX_TREASURY_SIGNERS {
        return Err(ExecError::ProgramError(format!("treasury needs 1..={MAX_TREASURY_SIGNERS} signers, got {}", signers.len())));
    }
    if threshold == 0 || threshold as usize > signers.len() {
        return Err(ExecError::ProgramError(format!("treasury threshold {threshold} must be 1..={}", signers.len())));
    }
    let mut seen = std::collections::HashSet::new();
    for s in signers {
        if !seen.insert(*s) {
            return Err(ExecError::ProgramError("treasury signer set has a duplicate".into()));
        }
    }
    Ok(())
}

/// The wire instruction. The wallet/CLI hand-encode this, so the discriminants
/// are guarded by `treasury_instruction_encoding_is_stable`.
#[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub enum TreasuryV7Instruction {
    /// Propose an operation. accounts=[signer, treasury]. The proposer must be a
    /// signer; the proposal counts as their approval.
    Propose { op: TreasuryOp },
    /// Approve a pending operation. accounts=[signer, treasury].
    Approve { op_id: u64 },
    /// Execute an approved+timelocked operation. Permissionless (anyone pays the
    /// tx fee). accounts=[executor, treasury] (+ [destination] for a Release).
    Execute { op_id: u64 },
    /// Cancel a pending operation. accounts=[signer, treasury].
    Cancel { op_id: u64 },
}

pub struct TreasuryV7Program;

fn read_state(accounts: &HashMap<Pubkey, Account>) -> Option<TreasuryState> {
    // FAIL-LOUD (#217) with a BRICK-SAFE legacy fallback (task #222): absent = no
    // treasury on this network (None). PRESENT decodes as the multisig state; if
    // that fails but the blob is EXACTLY the 32-byte legacy `{authority}`, lift it
    // to a 1-of-1 multisig (so a live single-authority treasury keeps working after
    // a binary update, then upgrades itself via SetSigners). Anything else is real
    // corruption of the account that guards locked funds → refuse to run.
    accounts.get(&TREASURY_ACCOUNT_ID).map(|a| {
        // `read_or_legacy` handles both the current layout and the pre-#17 layout
        // (without the tier thresholds / op-expiry, migrated with all tiers equal).
        if let Some(s) = TreasuryState::read_or_legacy(&a.data) {
            return s;
        }
        if a.data.len() == 32 {
            if let Ok(authority) = Pubkey::try_from_slice(&a.data) {
                return TreasuryState::single(authority);
            }
        }
        panic!("TREASURY_ACCOUNT is present but does not decode as TreasuryState or a legacy authority; refusing to run on corrupt treasury state")
    })
}

/// Validate the threshold hierarchy against the signer set (roadmap #17):
/// `1 <= threshold <= policy_threshold <= signers_threshold <= signers.len()`.
/// Used at genesis and whenever `SetSigners` changes the set/tiers.
pub fn validate_thresholds(state: &TreasuryState) -> Result<(), ExecError> {
    let n = state.signers.len();
    if state.threshold == 0
        || (state.threshold as usize) > n
        || state.policy_threshold < state.threshold
        || state.signers_threshold < state.policy_threshold
        || (state.signers_threshold as usize) > n
    {
        return Err(ExecError::ProgramError(format!(
            "invalid treasury threshold hierarchy: need 1 <= threshold({}) <= policy({}) <= signers({}) <= {n}",
            state.threshold, state.policy_threshold, state.signers_threshold
        )));
    }
    Ok(())
}

/// Prune any pending op that has expired (roadmap #17): if `op_expiry_rounds > 0`
/// and more than that many rounds have elapsed since an op was proposed, it is
/// removed and can never be executed. Deterministic (same committed round on every
/// node). No-op when expiry is disabled (`0`) → byte-identical for a pre-#17
/// treasury. `saturating_add` keeps the round math overflow-safe (#218).
fn prune_expired(state: &mut TreasuryState, current_round: Round) {
    if state.op_expiry_rounds == 0 {
        return;
    }
    let expiry = state.op_expiry_rounds;
    state
        .pending
        .retain(|p| current_round <= p.proposed_round.saturating_add(expiry));
}

fn write_state(accounts: &mut HashMap<Pubkey, Account>, state: &TreasuryState) -> Result<(), ExecError> {
    let acct = accounts.get_mut(&TREASURY_ACCOUNT_ID).ok_or(ExecError::AccountNotFound(TREASURY_ACCOUNT_ID))?;
    acct.data = borsh::to_vec(state).map_err(|e| ExecError::ProgramError(e.to_string()))?;
    Ok(())
}

impl TreasuryV7Program {
    /// Apply a treasury instruction to the working set at `current_round`.
    pub fn execute(
        accounts: &mut HashMap<Pubkey, Account>,
        instruction: &Instruction,
        payer: &Pubkey,
        current_round: Round,
    ) -> Result<(), ExecError> {
        let instr = TreasuryV7Instruction::try_from_slice(&instruction.data)
            .map_err(|e| ExecError::ProgramError(format!("bad treasury instruction: {e}")))?;
        match instr {
            TreasuryV7Instruction::Propose { op } => Self::propose(accounts, instruction, payer, current_round, op),
            TreasuryV7Instruction::Approve { op_id } => Self::approve(accounts, instruction, payer, current_round, op_id),
            TreasuryV7Instruction::Execute { op_id } => Self::execute_op(accounts, instruction, payer, current_round, op_id),
            TreasuryV7Instruction::Cancel { op_id } => Self::cancel(accounts, instruction, payer, current_round, op_id),
        }
    }

    /// Shared preamble: accounts[0] is the acting account (must be the payer =
    /// the authenticated signer), accounts[1] must be the canonical treasury.
    /// Returns the loaded state with any EXPIRED pending ops already pruned
    /// (roadmap #17) — so a caller always sees, and persists, a queue free of
    /// stale ops (which also frees slots against `MAX_TREASURY_PENDING`).
    fn preamble(accounts: &HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, current_round: Round) -> Result<TreasuryState, ExecError> {
        let acct0 = *ix.accounts.first().ok_or_else(|| ExecError::ProgramError("treasury ix requires accounts[0]".into()))?;
        let treasury_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("treasury ix requires accounts[1] (treasury)".into()))?;
        if treasury_pk != TREASURY_ACCOUNT_ID {
            return Err(ExecError::Unauthorized("treasury ix must name the canonical treasury account".into()));
        }
        // The payer is the only authenticated signer, so requiring accounts[0] ==
        // payer ties the action to a real signature.
        if acct0 != *payer {
            return Err(ExecError::Unauthorized("treasury ix accounts[0] must be the transaction payer".into()));
        }
        let mut state = read_state(accounts).ok_or_else(|| ExecError::ProgramError("treasury account is not initialized".into()))?;
        prune_expired(&mut state, current_round);
        Ok(state)
    }

    fn require_signer(state: &TreasuryState, payer: &Pubkey) -> Result<(), ExecError> {
        if !state.is_signer(payer) {
            return Err(ExecError::Unauthorized("only a configured treasury signer may propose/approve/cancel".into()));
        }
        Ok(())
    }

    fn validate_op(op: &TreasuryOp) -> Result<(), ExecError> {
        match op {
            TreasuryOp::Release { amount, destination } => {
                if *amount == 0 {
                    return Err(ExecError::ProgramError("cannot release zero".into()));
                }
                if *destination == TREASURY_ACCOUNT_ID {
                    return Err(ExecError::ProgramError("cannot release the treasury to itself".into()));
                }
                Ok(())
            }
            TreasuryOp::SetSigners { signers, threshold, policy_threshold, signers_threshold } => {
                validate_signer_set(signers, *threshold)?;
                // Validate the full hierarchy against the NEW set at propose time so
                // a bad rotation is rejected early: 1 <= threshold <= policy <= signers <= len.
                let probe = TreasuryState {
                    signers: signers.clone(),
                    threshold: *threshold,
                    policy_threshold: *policy_threshold,
                    signers_threshold: *signers_threshold,
                    ..TreasuryState::single(signers[0])
                };
                validate_thresholds(&probe)
            }
            TreasuryOp::SetPolicy { op_expiry_rounds, timelock_rounds, .. } => {
                // An op-expiry shorter than the timelock would make a legitimate op
                // expire before it could ever execute — reject that footgun.
                if *op_expiry_rounds > 0 && *op_expiry_rounds <= *timelock_rounds {
                    return Err(ExecError::ProgramError(format!(
                        "op_expiry_rounds {op_expiry_rounds} must exceed timelock_rounds {timelock_rounds} (else an op expires before it can execute)"
                    )));
                }
                Ok(())
            }
        }
    }

    fn propose(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, current_round: Round, op: TreasuryOp) -> Result<(), ExecError> {
        let mut state = Self::preamble(accounts, ix, payer, current_round)?;
        Self::require_signer(&state, payer)?;
        Self::validate_op(&op)?;
        if state.pending.len() >= MAX_TREASURY_PENDING {
            return Err(ExecError::ProgramError(format!("treasury has {MAX_TREASURY_PENDING} pending operations; execute or cancel one first")));
        }
        let id = state.next_op_id;
        state.next_op_id = state.next_op_id.saturating_add(1);
        // The proposer's proposal counts as their approval. If this op-kind's tier
        // threshold is 1 (roadmap #17), the timelock clock starts now.
        let threshold_reached_round = if state.required_threshold(&op) <= 1 { current_round } else { 0 };
        state.pending.push(PendingOp { id, op, proposed_round: current_round, approvals: vec![*payer], threshold_reached_round });
        write_state(accounts, &state)
    }

    fn approve(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, current_round: Round, op_id: u64) -> Result<(), ExecError> {
        let mut state = Self::preamble(accounts, ix, payer, current_round)?;
        Self::require_signer(&state, payer)?;
        let idx = state.pending.iter().position(|p| p.id == op_id).ok_or_else(|| ExecError::ProgramError(format!("no pending treasury op {op_id}")))?;
        // The tier threshold this op-kind requires (roadmap #17), computed before the
        // mutable borrow below.
        let req = state.required_threshold(&state.pending[idx].op);
        let op = &mut state.pending[idx];
        if op.approvals.contains(payer) {
            return Err(ExecError::ProgramError("this signer already approved this operation".into()));
        }
        op.approvals.push(*payer);
        // Once the op-kind's tier threshold is first reached, start the timelock clock.
        if op.threshold_reached_round == 0 && op.approvals.len() as u32 >= req as u32 {
            op.threshold_reached_round = current_round;
        }
        write_state(accounts, &state)
    }

    fn cancel(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, current_round: Round, op_id: u64) -> Result<(), ExecError> {
        let mut state = Self::preamble(accounts, ix, payer, current_round)?;
        Self::require_signer(&state, payer)?;
        let before = state.pending.len();
        state.pending.retain(|p| p.id != op_id);
        if state.pending.len() == before {
            return Err(ExecError::ProgramError(format!("no pending treasury op {op_id}")));
        }
        write_state(accounts, &state)
    }

    fn execute_op(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, _payer: &Pubkey, current_round: Round, op_id: u64) -> Result<(), ExecError> {
        // Execute is PERMISSIONLESS: anyone may push an already-authorized op over
        // the line (they pay the tx fee). Still require accounts[1] == treasury.
        let treasury_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("Execute requires accounts[1] (treasury)".into()))?;
        if treasury_pk != TREASURY_ACCOUNT_ID {
            return Err(ExecError::Unauthorized("Execute must name the canonical treasury account".into()));
        }
        let mut state = read_state(accounts).ok_or_else(|| ExecError::ProgramError("treasury account is not initialized".into()))?;
        // Prune EXPIRED ops first (roadmap #17): an op past its expiry can never be
        // executed — it's removed here and the lookup below then reports "no op".
        prune_expired(&mut state, current_round);
        let pos = state.pending.iter().position(|p| p.id == op_id).ok_or_else(|| ExecError::ProgramError(format!("no pending treasury op {op_id}")))?;
        // Re-check the op-kind's tier threshold against CURRENT state (roadmap #17):
        // a mid-flight SetSigners/SetPolicy that raised this op's bar holds it back
        // until it re-reaches the new bar, even if `threshold_reached_round` was
        // stamped under the old (lower) bar.
        let req = state.required_threshold(&state.pending[pos].op);
        if (state.pending[pos].approvals.len() as u32) < req as u32 {
            return Err(ExecError::Unauthorized(format!(
                "treasury op {op_id} has {} approvals but its tier now requires {req}",
                state.pending[pos].approvals.len()
            )));
        }
        // Threshold + timelock gate.
        let ready = state.pending[pos]
            .ready_round(state.timelock_rounds)
            .ok_or_else(|| ExecError::Unauthorized(format!("treasury op {op_id} has not reached the {req} approval threshold")))?;
        if current_round < ready {
            return Err(ExecError::Unauthorized(format!("treasury op {op_id} is timelocked until round {ready} (now {current_round})")));
        }
        // Take the op out; on any failure below we return WITHOUT having written
        // state, so nothing changes (the tx is discarded).
        let op = state.pending[pos].op.clone();
        match op {
            TreasuryOp::Release { amount, destination } => {
                Self::apply_release(accounts, ix, &mut state, current_round, amount, destination)?;
            }
            TreasuryOp::SetSigners { signers, threshold, policy_threshold, signers_threshold } => {
                state.signers = signers;
                state.threshold = threshold;
                state.policy_threshold = policy_threshold;
                state.signers_threshold = signers_threshold;
                // Re-validate the whole hierarchy against the new set (defense in
                // depth — validate_op already checked at propose time).
                validate_thresholds(&state)?;
                // A signer/threshold change invalidates prior approvals (they came
                // from the old set/tiers), so drop every OTHER pending op.
                state.pending.retain(|p| p.id == op_id);
            }
            TreasuryOp::SetPolicy { timelock_rounds, max_per_release, max_per_window, window_rounds, op_expiry_rounds } => {
                state.timelock_rounds = timelock_rounds;
                state.max_per_release = max_per_release;
                state.max_per_window = max_per_window;
                state.window_rounds = window_rounds;
                state.op_expiry_rounds = op_expiry_rounds;
            }
        }
        // Remove the executed op (SetSigners already retained only this one; remove it too).
        state.pending.retain(|p| p.id != op_id);
        write_state(accounts, &state)
    }

    /// Apply a Release: enforce the per-op + rolling-window limits, then move the
    /// funds (never mint). `state` is mutated (window accounting); the caller
    /// persists it. On any error nothing is written.
    fn apply_release(
        accounts: &mut HashMap<Pubkey, Account>,
        ix: &Instruction,
        state: &mut TreasuryState,
        current_round: Round,
        amount: u64,
        destination: Pubkey,
    ) -> Result<(), ExecError> {
        // The destination must be named in accounts so the ledger persists it, and
        // it must match the destination the multisig approved.
        let dest_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("Execute of a Release requires accounts[2] (destination)".into()))?;
        if dest_pk != destination {
            return Err(ExecError::Unauthorized("Execute destination does not match the approved operation".into()));
        }
        // Per-operation cap.
        if state.max_per_release > 0 && amount > state.max_per_release {
            return Err(ExecError::Unauthorized(format!("release {amount} exceeds the per-operation cap {}", state.max_per_release)));
        }
        // Rolling-window cap: roll the window forward if it has elapsed, then check.
        if state.window_rounds > 0 {
            if current_round >= state.window_start_round.saturating_add(state.window_rounds) {
                state.window_start_round = current_round;
                state.released_in_window = 0;
            }
            if state.max_per_window > 0 {
                let after = state.released_in_window.saturating_add(amount);
                if after > state.max_per_window {
                    return Err(ExecError::Unauthorized(format!(
                        "release {amount} would exceed the per-window cap {} ({} already released this window)",
                        state.max_per_window, state.released_in_window
                    )));
                }
                state.released_in_window = after;
            } else {
                state.released_in_window = state.released_in_window.saturating_add(amount);
            }
        }
        // Move (never mint): debit the treasury, credit the destination.
        let treasury_balance = accounts.get(&TREASURY_ACCOUNT_ID).ok_or(ExecError::AccountNotFound(TREASURY_ACCOUNT_ID))?.balance;
        if treasury_balance < amount {
            return Err(ExecError::InsufficientFunds);
        }
        {
            let t = accounts.get_mut(&TREASURY_ACCOUNT_ID).unwrap();
            t.balance = crate::arith::sub_u64(t.balance, amount)?;
        }
        let dest = accounts.entry(dest_pk).or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()));
        dest.balance = crate::arith::add_u64(dest.balance, amount)?;
        Ok(())
    }
}

impl crate::native::NativeProgram for TreasuryV7Program {
    fn process(
        &self,
        accounts: &mut HashMap<Pubkey, Account>,
        instruction: &Instruction,
        payer: &Pubkey,
        current_round: qchain_core::Round,
    ) -> Result<(), ExecError> {
        TreasuryV7Program::execute(accounts, instruction, payer, current_round)
    }
}

/// Build the genesis treasury account: `balance` QCH-units locked, owned by the
/// treasury program, controlled by the M-of-N multisig `state`. Seeded at genesis
/// by the node when `economics_v7` is on and a treasury is configured.
pub fn genesis_treasury_account_multisig(state: TreasuryState, balance: u64) -> Account {
    let mut acct = Account::new_wallet(crate::ids::TREASURY_V7_PROGRAM_ID);
    acct.balance = balance;
    acct.data = borsh::to_vec(&state).expect("TreasuryState serializes");
    acct
}

/// Convenience for the simple single-signer case (and the legacy path): a 1-of-1
/// treasury controlled by `authority`, no timelock, no limits.
pub fn genesis_treasury_account(authority: Pubkey, balance: u64) -> Account {
    genesis_treasury_account_multisig(TreasuryState::single(authority), balance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::TREASURY_V7_PROGRAM_ID;

    fn pk(n: u8) -> Pubkey {
        Pubkey::new([n; 32])
    }

    fn ix(instr: &TreasuryV7Instruction, accounts: Vec<Pubkey>) -> Instruction {
        Instruction { program_id: TREASURY_V7_PROGRAM_ID, accounts, data: borsh::to_vec(instr).unwrap() }
    }

    /// A 3-of-5 treasury with a timelock and limits.
    fn multisig_world(locked: u64, timelock: u64, per_op: u64, per_window: u64, window: u64) -> (HashMap<Pubkey, Account>, Vec<Pubkey>) {
        let signers: Vec<Pubkey> = (1..=5).map(pk).collect();
        let state = TreasuryState {
            signers: signers.clone(),
            threshold: 3,
            timelock_rounds: timelock,
            max_per_release: per_op,
            max_per_window: per_window,
            window_rounds: window,
            window_start_round: 0,
            released_in_window: 0,
            next_op_id: 0,
            pending: Vec::new(),
            policy_threshold: 3,
            signers_threshold: 3,
            op_expiry_rounds: 0,
        };
        let mut a = HashMap::new();
        a.insert(TREASURY_ACCOUNT_ID, genesis_treasury_account_multisig(state, locked));
        (a, signers)
    }

    fn exec(accounts: &mut HashMap<Pubkey, Account>, instr: &TreasuryV7Instruction, accts: Vec<Pubkey>, payer: Pubkey, round: Round) -> Result<(), ExecError> {
        TreasuryV7Program::execute(accounts, &ix(instr, accts), &payer, round)
    }

    #[test]
    fn a_release_needs_the_threshold_then_the_timelock_then_conserves_supply() {
        let (mut a, s) = multisig_world(100_000, 10, 0, 0, 0);
        let dest = pk(9);
        let t = TREASURY_ACCOUNT_ID;
        // signer 1 proposes (1/3)
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 30_000, destination: dest } }, vec![s[0], t], s[0], 100).unwrap();
        // executing now fails: below threshold
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 0 }, vec![s[0], t, dest], s[0], 100), Err(ExecError::Unauthorized(_))));
        // signer 2 approves (2/3), still below
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 0 }, vec![s[1], t], s[1], 101).unwrap();
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 0 }, vec![s[0], t, dest], s[0], 101), Err(ExecError::Unauthorized(_))));
        // signer 3 approves (3/3) → threshold reached at round 102, timelock 10 → ready at 112
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 0 }, vec![s[2], t], s[2], 102).unwrap();
        // still timelocked at 111
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 0 }, vec![s[0], t, dest], s[0], 111), Err(ExecError::Unauthorized(_))));
        // executes at 112 (permissionless — a non-signer executor)
        exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 0 }, vec![pk(99), t, dest], pk(99), 112).unwrap();
        assert_eq!(a[&t].balance, 70_000);
        assert_eq!(a[&dest].balance, 30_000);
        assert_eq!(70_000 + 30_000, 100_000); // conserved
        // the op is gone
        assert!(read_state(&a).unwrap().pending.is_empty());
    }

    #[test]
    fn a_non_signer_cannot_propose_or_approve() {
        let (mut a, s) = multisig_world(100_000, 0, 0, 0, 0);
        let t = TREASURY_ACCOUNT_ID;
        let attacker = pk(80);
        // attacker proposes (payer=attacker, not a signer)
        assert!(matches!(
            exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 1, destination: pk(9) } }, vec![attacker, t], attacker, 1),
            Err(ExecError::Unauthorized(_))
        ));
        // a real signer proposes; the attacker cannot approve
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 1000, destination: pk(9) } }, vec![s[0], t], s[0], 1).unwrap();
        assert!(matches!(
            exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 0 }, vec![attacker, t], attacker, 1),
            Err(ExecError::Unauthorized(_))
        ));
        assert_eq!(a[&t].balance, 100_000);
    }

    #[test]
    fn the_same_signer_cannot_approve_twice() {
        let (mut a, s) = multisig_world(100_000, 0, 0, 0, 0);
        let t = TREASURY_ACCOUNT_ID;
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 1000, destination: pk(9) } }, vec![s[0], t], s[0], 1).unwrap();
        // s0 already approved via the proposal
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 0 }, vec![s[0], t], s[0], 1), Err(ExecError::ProgramError(_))));
        // 3-of-5 not reached with only s0's approval → still not executable
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 0 }, vec![s[0], t, pk(9)], s[0], 1), Err(ExecError::Unauthorized(_))));
    }

    #[test]
    fn per_operation_and_per_window_limits_are_enforced() {
        // per-op cap 40k, per-window cap 50k over 100 rounds.
        let (mut a, s) = multisig_world(1_000_000, 0, 40_000, 50_000, 100);
        let t = TREASURY_ACCOUNT_ID;
        let dest = pk(9);
        let approve3 = |a: &mut HashMap<Pubkey, Account>, id: u64, r: Round| {
            exec(a, &TreasuryV7Instruction::Approve { op_id: id }, vec![s[1], t], s[1], r).unwrap();
            exec(a, &TreasuryV7Instruction::Approve { op_id: id }, vec![s[2], t], s[2], r).unwrap();
        };
        // op0: 50k > per-op cap 40k → rejected at execute
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 50_000, destination: dest } }, vec![s[0], t], s[0], 10).unwrap();
        approve3(&mut a, 0, 10);
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 0 }, vec![s[0], t, dest], s[0], 10), Err(ExecError::Unauthorized(_))));
        // op1: 30k ok (window now 30k/50k)
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 30_000, destination: dest } }, vec![s[0], t], s[0], 11).unwrap();
        approve3(&mut a, 1, 11);
        exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 1 }, vec![s[0], t, dest], s[0], 11).unwrap();
        assert_eq!(a[&dest].balance, 30_000);
        // op2: another 30k within the same window → 60k > 50k cap → rejected
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 30_000, destination: dest } }, vec![s[0], t], s[0], 12).unwrap();
        approve3(&mut a, 2, 12);
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 2 }, vec![s[0], t, dest], s[0], 12), Err(ExecError::Unauthorized(_))));
        // after the window elapses (round >= 11+100 = 111) the same op executes
        exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 2 }, vec![s[0], t, dest], s[0], 120).unwrap();
        assert_eq!(a[&dest].balance, 60_000);
    }

    #[test]
    fn set_signers_rotates_control_and_drops_stale_ops() {
        let (mut a, s) = multisig_world(100_000, 0, 0, 0, 0);
        let t = TREASURY_ACCOUNT_ID;
        // a stale pending release proposed by the OLD set
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 1000, destination: pk(9) } }, vec![s[0], t], s[0], 1).unwrap();
        // propose + approve a signer rotation to a fresh 2-of-3 set
        let new: Vec<Pubkey> = vec![pk(20), pk(21), pk(22)];
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::SetSigners { signers: new.clone(), threshold: 2, policy_threshold: 2, signers_threshold: 2 } }, vec![s[0], t], s[0], 2).unwrap();
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 1 }, vec![s[1], t], s[1], 2).unwrap();
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 1 }, vec![s[2], t], s[2], 2).unwrap();
        exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 1 }, vec![pk(99), t], pk(99), 2).unwrap();
        let st = read_state(&a).unwrap();
        assert_eq!(st.signers, new);
        assert_eq!(st.threshold, 2);
        assert!(st.pending.is_empty(), "the stale op from the old set was dropped");
        // an old signer can no longer propose
        assert!(matches!(
            exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 1, destination: pk(9) } }, vec![s[0], t], s[0], 3),
            Err(ExecError::Unauthorized(_))
        ));
        // a new signer can
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 1, destination: pk(9) } }, vec![new[0], t], new[0], 3).unwrap();
    }

    #[test]
    fn a_legacy_single_authority_treasury_still_works_as_1_of_1() {
        // A network deployed before #222 stored just the 32-byte authority pubkey.
        let authority = pk(1);
        let mut a = HashMap::new();
        let mut acct = Account::new_wallet(TREASURY_V7_PROGRAM_ID);
        acct.balance = 100_000;
        acct.data = borsh::to_vec(&authority).unwrap(); // legacy layout: bare Pubkey
        a.insert(TREASURY_ACCOUNT_ID, acct);
        // read_state lifts it to a 1-of-1 multisig
        let st = read_state(&a).unwrap();
        assert_eq!(st.signers, vec![authority]);
        assert_eq!(st.threshold, 1);
        let t = TREASURY_ACCOUNT_ID;
        // propose (1/1 → threshold immediately reached, timelock 0) then execute
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 5000, destination: pk(9) } }, vec![authority, t], authority, 1).unwrap();
        exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 0 }, vec![authority, t, pk(9)], authority, 1).unwrap();
        assert_eq!(a[&pk(9)].balance, 5000);
        // and it can upgrade itself to a real multisig via SetSigners
        let new: Vec<Pubkey> = vec![pk(10), pk(11), pk(12)];
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::SetSigners { signers: new.clone(), threshold: 2, policy_threshold: 2, signers_threshold: 2 } }, vec![authority, t], authority, 2).unwrap();
        exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 1 }, vec![authority, t], authority, 2).unwrap();
        assert_eq!(read_state(&a).unwrap().threshold, 2);
    }

    #[test]
    fn a_corrupt_treasury_blob_fails_loud() {
        let mut a = HashMap::new();
        let mut acct = Account::new_wallet(TREASURY_V7_PROGRAM_ID);
        acct.data = vec![0xFF; 9]; // neither the new layout nor a 32-byte legacy authority
        a.insert(TREASURY_ACCOUNT_ID, acct);
        assert!(std::panic::catch_unwind(|| read_state(&a)).is_err(), "a genuinely corrupt treasury blob must fail loud");
    }

    #[test]
    fn cannot_release_zero_to_itself_or_a_bad_signer_set() {
        let (mut a, s) = multisig_world(100_000, 0, 0, 0, 0);
        let t = TREASURY_ACCOUNT_ID;
        // zero
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 0, destination: pk(9) } }, vec![s[0], t], s[0], 1), Err(ExecError::ProgramError(_))));
        // to itself
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 1, destination: t } }, vec![s[0], t], s[0], 1), Err(ExecError::ProgramError(_))));
        // a SetSigners with threshold > signers is rejected at propose (validate_op)
        assert!(matches!(
            exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::SetSigners { signers: vec![pk(1), pk(2)], threshold: 3, policy_threshold: 3, signers_threshold: 3 } }, vec![s[0], t], s[0], 1),
            Err(ExecError::ProgramError(_))
        ));
    }

    #[test]
    fn treasury_instruction_encoding_is_stable() {
        // Guards the on-chain wire encoding (the wallet/CLI hand-encode this).
        // Propose(discriminant 0) + TreasuryOp::Release(discriminant 0) + amount + dest
        let dest = pk(7);
        let mut expect = vec![0u8, 0u8]; // Propose, Release
        expect.extend_from_slice(&1u64.to_le_bytes()); // amount
        expect.extend_from_slice(&dest.0); // destination
        assert_eq!(borsh::to_vec(&TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 1, destination: dest } }).unwrap(), expect);
        assert_eq!(borsh::to_vec(&TreasuryV7Instruction::Approve { op_id: 5 }).unwrap(), { let mut v = vec![1u8]; v.extend_from_slice(&5u64.to_le_bytes()); v });
        assert_eq!(borsh::to_vec(&TreasuryV7Instruction::Execute { op_id: 5 }).unwrap(), { let mut v = vec![2u8]; v.extend_from_slice(&5u64.to_le_bytes()); v });
        assert_eq!(borsh::to_vec(&TreasuryV7Instruction::Cancel { op_id: 5 }).unwrap(), { let mut v = vec![3u8]; v.extend_from_slice(&5u64.to_le_bytes()); v });
    }

    /// A 3-tier treasury (roadmap #17) with the given tiers, timelock/expiry off.
    fn tiered_world(threshold: u8, policy: u8, signers_th: u8, expiry: u64) -> (HashMap<Pubkey, Account>, Vec<Pubkey>) {
        let signers: Vec<Pubkey> = (1..=5).map(pk).collect();
        let state = TreasuryState {
            signers: signers.clone(),
            threshold,
            timelock_rounds: 0,
            max_per_release: 0,
            max_per_window: 0,
            window_rounds: 0,
            window_start_round: 0,
            released_in_window: 0,
            next_op_id: 0,
            pending: Vec::new(),
            policy_threshold: policy,
            signers_threshold: signers_th,
            op_expiry_rounds: expiry,
        };
        let mut a = HashMap::new();
        a.insert(TREASURY_ACCOUNT_ID, genesis_treasury_account_multisig(state, 1_000_000));
        (a, signers)
    }

    #[test]
    fn the_threshold_hierarchy_gates_more_sensitive_ops_more_strictly() {
        // Release needs 2 (liberar), SetPolicy needs 3 (política), SetSigners needs 4 (firmantes).
        let (mut a, s) = tiered_world(2, 3, 4, 0);
        let t = TREASURY_ACCOUNT_ID;

        // liberar: a Release executes with just 2 approvals.
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 10_000, destination: pk(9) } }, vec![s[0], t], s[0], 1).unwrap();
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 0 }, vec![s[1], t], s[1], 1).unwrap(); // 2/2
        exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 0 }, vec![s[0], t, pk(9)], s[0], 1).unwrap();
        assert_eq!(a[&pk(9)].balance, 10_000);

        // política: a SetPolicy needs 3 — 2 approvals is NOT enough.
        let policy = TreasuryOp::SetPolicy { timelock_rounds: 0, max_per_release: 0, max_per_window: 0, window_rounds: 0, op_expiry_rounds: 0 };
        exec(&mut a, &TreasuryV7Instruction::Propose { op: policy }, vec![s[0], t], s[0], 2).unwrap(); // 1/3
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 1 }, vec![s[1], t], s[1], 2).unwrap(); // 2/3
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 1 }, vec![s[0], t], s[0], 2), Err(ExecError::Unauthorized(_))), "política tier needs 3");
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 1 }, vec![s[2], t], s[2], 2).unwrap(); // 3/3
        exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 1 }, vec![s[0], t], s[0], 2).unwrap();

        // firmantes: a SetSigners needs 4 — 3 approvals is NOT enough.
        let rotate = TreasuryOp::SetSigners { signers: vec![pk(20), pk(21), pk(22)], threshold: 2, policy_threshold: 2, signers_threshold: 2 };
        exec(&mut a, &TreasuryV7Instruction::Propose { op: rotate }, vec![s[0], t], s[0], 3).unwrap(); // 1/4
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 2 }, vec![s[1], t], s[1], 3).unwrap(); // 2/4
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 2 }, vec![s[2], t], s[2], 3).unwrap(); // 3/4
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 2 }, vec![s[0], t], s[0], 3), Err(ExecError::Unauthorized(_))), "firmantes tier needs 4");
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 2 }, vec![s[3], t], s[3], 3).unwrap(); // 4/4
        exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 2 }, vec![pk(99), t], pk(99), 3).unwrap();
        assert_eq!(read_state(&a).unwrap().signers, vec![pk(20), pk(21), pk(22)]);
    }

    #[test]
    fn an_op_expires_after_its_window_and_is_pruned() {
        // 2-of-5, no timelock, expiry 50 rounds.
        let (mut a, s) = tiered_world(2, 2, 2, 50);
        let t = TREASURY_ACCOUNT_ID;
        // proposed + approved at round 100 (fully authorized, but never executed)
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 1000, destination: pk(9) } }, vec![s[0], t], s[0], 100).unwrap();
        exec(&mut a, &TreasuryV7Instruction::Approve { op_id: 0 }, vec![s[1], t], s[1], 100).unwrap();
        // at round 150 (100+50) it is still executable (boundary inclusive)
        assert_eq!(read_state(&a).unwrap().pending.len(), 1);
        // at round 151 it has EXPIRED → Execute can't find it (pruned)
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Execute { op_id: 0 }, vec![s[0], t, pk(9)], s[0], 151), Err(ExecError::ProgramError(_))), "an expired op is not executable");
        assert_eq!(a.get(&pk(9)).map(|x| x.balance).unwrap_or(0), 0, "the expired release moved nothing");
        // a new proposal at 151 prunes the expired op in the preamble → only the new op remains
        exec(&mut a, &TreasuryV7Instruction::Propose { op: TreasuryOp::Release { amount: 2000, destination: pk(9) } }, vec![s[0], t], s[0], 151).unwrap();
        let st = read_state(&a).unwrap();
        assert_eq!(st.pending.len(), 1, "the expired op was pruned; only the fresh one remains");
        assert_eq!(st.pending[0].proposed_round, 151);

        // A SetPolicy whose expiry would be <= the timelock is rejected (footgun guard).
        let bad = TreasuryOp::SetPolicy { timelock_rounds: 20, max_per_release: 0, max_per_window: 0, window_rounds: 0, op_expiry_rounds: 10 };
        assert!(matches!(exec(&mut a, &TreasuryV7Instruction::Propose { op: bad }, vec![s[0], t], s[0], 151), Err(ExecError::ProgramError(_))));
    }

    #[test]
    fn read_or_legacy_migrates_a_pre17_treasury_and_round_trips_a_new_one() {
        // A pre-#17 blob (TreasuryStateV0, no tiers/expiry) migrates with all tiers
        // equal to `threshold` and expiry 0 — byte-identical behavior.
        let v0 = TreasuryStateV0 {
            signers: vec![pk(1), pk(2), pk(3)],
            threshold: 2,
            timelock_rounds: 10,
            max_per_release: 5,
            max_per_window: 9,
            window_rounds: 100,
            window_start_round: 3,
            released_in_window: 4,
            next_op_id: 7,
            pending: Vec::new(),
        };
        let legacy_bytes = borsh::to_vec(&v0).unwrap();
        let migrated = TreasuryState::read_or_legacy(&legacy_bytes).unwrap();
        assert_eq!(migrated.threshold, 2);
        assert_eq!(migrated.policy_threshold, 2, "pre-#17 policy tier = threshold");
        assert_eq!(migrated.signers_threshold, 2, "pre-#17 signers tier = threshold");
        assert_eq!(migrated.op_expiry_rounds, 0, "pre-#17 expiry off");
        assert_eq!(migrated.next_op_id, 7);

        // A current record round-trips exactly, and its blob is 3 fields longer.
        let (a, _) = tiered_world(2, 3, 4, 500);
        let full = read_state(&a).unwrap();
        let full_bytes = borsh::to_vec(&full).unwrap();
        assert_eq!(TreasuryState::read_or_legacy(&full_bytes).unwrap(), full);
        // The two layouts never cross-decode (borsh rejects the new blob's trailing bytes as V0).
        assert!(borsh::from_slice::<TreasuryStateV0>(&full_bytes).is_err());
    }
}
