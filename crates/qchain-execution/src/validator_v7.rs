//! v7 validators — the 500 QCH bond model (SPEC: `docs/ECONOMIC-REDESIGN.md`
//! §6/§9/§10). **Fase 1d core.** Self-contained and INERT (nothing wires it into
//! `Ledger`/consensus yet), so a v6 node is byte-identical. Operates on a working
//! set of accounts like the other native programs.
//!
//! A validator posts a bond of **exactly 500 QCH** as pure collateral: it locks
//! in `VALIDATOR_BOND_ESCROW_ID`, mints no shares, earns no emission/yield, and
//! is slashable on proven equivocation. Every active validator posts the same
//! bond → one equal unit of consensus power each (a linear economic Sybil
//! barrier, not an absolute one — a richer actor can register several).
//!
//! ## Lifecycle
//! `BondedPending` → `Active` (at the next quanto) → `Exiting`/`Unbonding` →
//! `Withdrawable` → `Removed`, or `Slashed`. Exit starts the bond unbonding
//! clock; the bond stays slashable through the evidence window
//! (`SLASH_EVIDENCE_WINDOW_QUANTOS ≤ VALIDATOR_BOND_UNBONDING_QUANTOS`), so a
//! departing equivocator can't outrun a report.
//!
//! ## Slashing taxonomy (SPEC §10)
//! The full bond is burned ONLY for provable equivocation (two conflicting
//! signed vertices for the same round — the same evidence the v6 slashing
//! verifies). Downtime/latency/restart never burns the bond; that is jailing +
//! loss of the quanto's fees, handled in the fee/eligibility phase (1e), not here.
//!
//! ## Deferred to the ledger boundary / later phases (documented, not hidden)
//! - The role rules (a registered validator can't open a staking position; a
//!   staker with an active position can't register) are cross-module and are
//!   enforced where both registries are visible (the ledger dispatch), like the
//!   WASM authorization boundary check.
//! - Jailing / participation counters live with the fee eligibility (1e).
//! - The crash-safe `become-validator` CLI flow (bond deposited but register
//!   failed → recover via `BeginExit`+`WithdrawBond` after the window) is fase 3;
//!   the on-chain primitives it needs are here.

use crate::economics_v7::{
    moniker_is_valid, normalize_moniker, SLASH_EVIDENCE_WINDOW_QUANTOS, VALIDATOR_BOND_ATOMS,
    VALIDATOR_BOND_UNBONDING_QUANTOS,
};
use crate::error::ExecError;
use crate::ids::{
    STAKING_GLOBAL_ID, STAKING_PROGRAM_ID, VALIDATOR_BOND_ESCROW_ID,
    VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, VALIDATOR_RECOVERY_REGISTRY_ID,
    VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_UNBONDING_POOL_ID,
};
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{Account, EquivocationEvidence, Instruction};
use qchain_crypto::{MultiSignature, Pubkey, PublicKeyBundle};
use std::collections::HashMap;

/// Cap on the on-chain validator registry (anti-bloat/DoS; a bond is required to
/// add an entry, so this is a defensive backstop, not the primary limit).
pub const MAX_V7_VALIDATORS: usize = 1_000;

/// Cap on the ACTIVE consensus committee derived from the v7 registry. Bounds
/// certificate size / quorum work at the top; a bonded validator beyond this cap
/// stays registered and eligible for a slot but doesn't sit in the committee
/// until one frees. Deterministic order (by consensus address) makes the cut
/// identical on every node.
pub const MAX_ACTIVE_V7_VALIDATORS: usize = 100;

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub enum ValidatorV7State {
    BondedPending,
    Active,
    Jailed,
    Exiting,
    Unbonding,
    Withdrawable,
    Slashed,
    Removed,
    /// **Revocado por el comité de recuperación (KM#4).** Un validador cuya clave
    /// de consenso/operador se comprometió, neutralizado por M-de-N firmas de
    /// recuperación OFFLINE sin ninguna de las claves comprometidas. Como
    /// `BeginExit`, el bono se mueve al pool de unbonding y queda slasheable en la
    /// ventana de evidencia; `Revoked` (distinto de `Unbonding`) hace que la causa
    /// sea auditable. Excluido del comité activo y de la elegibilidad de fees (no
    /// es `Active`). Se APENDA al final del enum → discriminantes previos estables.
    Revoked,
}

/// (#20) At most this many consensus keys a validator has ROTATED AWAY FROM are
/// kept slashable at once. Bounded so an operator can't grow the registry without
/// limit by rapid-fire rotations (a rotation without a prior would be pointless);
/// the oldest still-in-window key is dropped if a rotation would exceed the cap.
/// A retired key past its slash window is pruned at the quanto close.
pub const MAX_RETIRED_CONSENSUS_KEYS: usize = 4;

/// (#20) A consensus key a validator ROTATED AWAY FROM (or was REVOKED and then
/// rotated), kept slashable until `slash_until_quanto` so an equivocation by the
/// old key within its evidence window is still punished even though the registry
/// entry's live `address` is now the new key.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct RetiredConsensusKey {
    pub address: Pubkey,
    pub slash_until_quanto: u64,
}

/// (KM#4) Cap on the number of OFFLINE recovery signers a validator may register.
/// Generous for a real 3-of-5 / 5-of-9 committee, bounded so the recovery
/// registry account can't be bloated. A bond is required to be a validator, so
/// this is a defensive backstop.
pub const MAX_RECOVERY_SIGNERS: usize = 15;

/// (KM#4) A validator's OFFLINE recovery committee: M-of-N recovery pubkeys held
/// offline (e.g. Shamir 3-of-5). If the validator's consensus/operator keys are
/// lost or compromised, `threshold` DISTINCT recovery signers — signing OFFLINE,
/// never touching an online machine — can REVOKE the validator without any of the
/// compromised keys. `signers` are addresses (an approval carries the full
/// `PublicKeyBundle` so the handler can verify); `threshold` is M (1..=N).
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq, Default)]
pub struct RecoveryConfig {
    pub signers: Vec<Pubkey>,
    pub threshold: u8,
}

impl RecoveryConfig {
    /// Validate the committee: `1 ≤ threshold ≤ N`, `1 ≤ N ≤ MAX_RECOVERY_SIGNERS`,
    /// all signers pairwise DISTINCT (a duplicate signer would let one key count
    /// twice toward the threshold). Rejects an empty/zero-threshold config.
    pub fn validate(&self) -> Result<(), ExecError> {
        let n = self.signers.len();
        if n == 0 || n > MAX_RECOVERY_SIGNERS {
            return Err(ExecError::ProgramError(format!("recovery signers count {n} out of range 1..={MAX_RECOVERY_SIGNERS}")));
        }
        if self.threshold == 0 || self.threshold as usize > n {
            return Err(ExecError::ProgramError(format!("recovery threshold {} out of range 1..={n}", self.threshold)));
        }
        let distinct: std::collections::HashSet<&Pubkey> = self.signers.iter().collect();
        if distinct.len() != n {
            return Err(ExecError::ProgramError("recovery signers must be distinct".into()));
        }
        Ok(())
    }
}

/// (KM#4) One validator's recovery record in the recovery registry singleton:
/// its committee plus a monotonic `nonce` that every successful revoke bumps, so
/// a collected set of offline authorizations can never be replayed within the
/// network.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct RecoveryEntry {
    pub consensus_address: Pubkey,
    pub config: RecoveryConfig,
    pub nonce: u64,
}

/// (KM#4) The v7 recovery registry singleton
/// (`VALIDATOR_RECOVERY_REGISTRY_ID.data`). Additive: absent/empty on a network
/// that hasn't opted in.
#[derive(Clone, Default, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct RecoveryRegistry {
    pub entries: Vec<RecoveryEntry>,
}

impl RecoveryRegistry {
    fn find(&self, addr: &Pubkey) -> Option<usize> {
        self.entries.iter().position(|e| &e.consensus_address == addr)
    }
}

/// (KM#4) One recovery signer's OFFLINE authorization of a recovery op: the
/// signer's `bundle` (so the handler can check `to_address()` is a registered
/// committee member and verify the signature) and its `signature` over
/// `RECOVERY_AUTH_V1 ‖ consensus_address ‖ op_tag ‖ nonce_le`.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct RecoveryApproval {
    pub bundle: PublicKeyBundle,
    pub signature: MultiSignature,
}

/// (KM#4) The recovery operation a committee authorizes. Only `Revoke` this
/// increment; the `op_tag` byte binds the authorization so a future op's
/// approval can never be replayed as a Revoke. REPLACE/rotate (→KM#6, already has
/// the operator-authorized `RotateConsensusKey`) and FREEZE (→KM#9) are separate.
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub enum RecoveryOp {
    Revoke,
}

/// (KM#4) The preimage each recovery signer signs OFFLINE (domain
/// `RECOVERY_AUTH_V1`). Binds the target validator, the op, and the current
/// per-validator recovery nonce (anti-replay within the network — consistent with
/// `pop_message`, which also does not bind chain_id).
pub fn recovery_message(consensus_address: &Pubkey, op: RecoveryOp, nonce: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + 1 + 8);
    m.extend_from_slice(&consensus_address.0);
    m.push(match op {
        RecoveryOp::Revoke => 0x01,
    });
    m.extend_from_slice(&nonce.to_le_bytes());
    m
}

// ── KM#5: on-chain TIMELOCKS for cold-key changes ───────────────────────────
//
// A change to a validator's cold OPERATOR key, WITHDRAWAL address, or RECOVERY
// committee is PROPOSED and only takes effect after a mandatory window. The window
// gives the real owner (or an already-registered recovery committee) time to react
// to a compromise — e.g. an attacker who steals the operator key can't INSTANTLY
// rotate the withdrawal to itself and drain the bond/fees; the 72h window lets a
// recovery-committee REVOKE (KM#4) neutralize the validator first.
//
// Windows are expressed in QUANTOS, the same deterministic time unit the bond
// unbonding/activation already use. Under the standard cadence
// (`DEFAULT_ROUNDS_PER_QUANTO`/`DEFAULT_QUANTOS_PER_YEAR` ⇒ ~365 quantos/year, so
// 1 quanto ≈ 1 day) these map to the audit's wall-clock intent:
//   operator ≈ 24h, withdrawal ≈ 72h, recovery ≈ 7d.
// (The auditor's other two timelocks are already satisfied: consensus-key rotation
// takes effect at the next epoch boundary via committee derivation, and the bond
// withdrawal already waits the unbonding+evidence window ≈ 7d.)

/// Operator-rotation timelock, in quantos (~24h under the standard cadence).
pub const KEY_TIMELOCK_OPERATOR_QUANTOS: u64 = 1;
/// Withdrawal-rotation timelock, in quantos (~72h).
pub const KEY_TIMELOCK_WITHDRAWAL_QUANTOS: u64 = 3;
/// Recovery-committee-change timelock, in quantos (~7d). A change to the OFFLINE
/// recovery committee waits this window, so a compromised operator can't instantly
/// swap in its own committee; you configure the committee in advance during calm
/// operation, not under duress (honest tradeoff: the FIRST set is also delayed,
/// which is fine because you set it up ahead of any attack).
pub const KEY_TIMELOCK_RECOVERY_QUANTOS: u64 = 7;

/// (KM#5) Which cold-key change a pending entry carries — the key naming an entry
/// for `ApplyPendingKeyChange`/`CancelPendingKeyChange` (at most one pending change
/// per validator per kind).
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub enum KeyChangeKind {
    Operator,
    Withdrawal,
    RecoveryCommittee,
}

/// (KM#5) The pending cold-key change itself, carrying the proposed new value.
/// `RecoveryCommittee` with an empty `RecoveryConfig` means "clear the committee".
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub enum PendingKeyChange {
    Operator(Pubkey),
    Withdrawal(Pubkey),
    RecoveryCommittee(RecoveryConfig),
}

impl PendingKeyChange {
    pub fn kind(&self) -> KeyChangeKind {
        match self {
            PendingKeyChange::Operator(_) => KeyChangeKind::Operator,
            PendingKeyChange::Withdrawal(_) => KeyChangeKind::Withdrawal,
            PendingKeyChange::RecoveryCommittee(_) => KeyChangeKind::RecoveryCommittee,
        }
    }
    /// The timelock window (quantos) for this change's kind.
    pub fn window_quantos(&self) -> u64 {
        match self.kind() {
            KeyChangeKind::Operator => KEY_TIMELOCK_OPERATOR_QUANTOS,
            KeyChangeKind::Withdrawal => KEY_TIMELOCK_WITHDRAWAL_QUANTOS,
            KeyChangeKind::RecoveryCommittee => KEY_TIMELOCK_RECOVERY_QUANTOS,
        }
    }
}

/// (KM#5) One pending, timelocked cold-key change of a validator.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct PendingKeyChangeEntry {
    pub consensus_address: Pubkey,
    pub proposed_quanto: u64,
    /// The change applies only at/after this quanto (`proposed_quanto + window`).
    pub ready_quanto: u64,
    pub change: PendingKeyChange,
}

/// (KM#5) The key-timelock registry singleton
/// (`VALIDATOR_KEY_TIMELOCK_REGISTRY_ID.data`). Additive: absent/empty on a network
/// with no pending changes.
#[derive(Clone, Default, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct KeyTimelockRegistry {
    pub pending: Vec<PendingKeyChangeEntry>,
}

impl KeyTimelockRegistry {
    fn find(&self, addr: &Pubkey, kind: KeyChangeKind) -> Option<usize> {
        self.pending
            .iter()
            .position(|p| &p.consensus_address == addr && p.change.kind() == kind)
    }
    /// Drop every pending change for `addr` (used when the validator is revoked /
    /// terminal — a pending cold-key change is then moot).
    fn purge(&mut self, addr: &Pubkey) {
        self.pending.retain(|p| &p.consensus_address != addr);
    }
}

/// One validator's on-chain record (SPEC §7). The bond is always
/// `VALIDATOR_BOND_ATOMS`; `moniker` is normalized + unique while registered.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct ValidatorV7Entry {
    /// **Consensus address** — the online, block-signing hot key
    /// (`pubkey_bundle.to_address()`). This is the validator's consensus identity:
    /// slashing names THIS key as the vertex author, and the active-set/eligibility
    /// read it. A leak of this most-exposed key can sign/equivocate (slashable) but
    /// CANNOT move the bond or the fee earnings — those are controlled by the
    /// separate cold `operator_address`/`withdrawal_address` (#193-B on-chain: a hot
    /// key leak can't drain the bond or spend what the validator earned).
    pub address: Pubkey,
    /// **Operator (cold) address** — the offline key that authorizes this
    /// validator's lifecycle (begin-exit / withdraw-bond) and was the transaction
    /// payer that posted the bond. The consensus key can NEVER exit or withdraw.
    pub operator_address: Pubkey,
    /// **Withdrawal (cold) address** — where the bond returns on withdrawal AND
    /// where this validator's fee commissions accrue (`fees_v7::eligible_addresses`).
    /// Defaults to the operator when unset at registration.
    pub withdrawal_address: Pubkey,
    /// Normalized, unique consensus identifier.
    pub moniker: String,
    /// Consensus key bundle (its `to_address()` equals `address`; possession proven
    /// at registration by `consensus_pop`).
    pub pubkey_bundle: PublicKeyBundle,
    /// P2P "ip:port" peers dial for discovery.
    pub p2p_address: String,
    /// Locked bond, always `VALIDATOR_BOND_ATOMS`.
    pub bond: u64,
    pub state: ValidatorV7State,
    pub registered_quanto: u64,
    /// The validator joins the active set at this quanto (registration + 1), so
    /// it can't register just before a close and collect the same reward.
    pub activation_quanto: u64,
    /// Quanto the exit was requested (0 = not exiting).
    pub exit_requested_quanto: u64,
    /// Quanto the bond becomes withdrawable (past the unbonding + evidence
    /// window). 0 until exit.
    pub bond_release_quanto: u64,
    /// Participation this quanto: events where the validator did its job. The
    /// node increments this + `participation_opportunities` per round (what
    /// exactly counts as an "event" is finalized in the node phase — SPEC §21.2);
    /// the fee eligibility (1e) reads the ratio, and the quanto close resets both.
    pub participation_credits: u64,
    /// Total participation events this quanto (the denominator).
    pub participation_opportunities: u64,
    /// (#20) Forced-rotation deadline for the CONSENSUS key: the quanto at/after
    /// which this validator is EXCLUDED from the active committee AND fee
    /// eligibility until the operator rotates in a fresh consensus key. 0 = never
    /// expires — the default, so an entry that never uses expiry is byte-identical
    /// in BEHAVIOR to the pre-#20 layout (the honest path).
    pub consensus_key_expiry_quanto: u64,
    /// (#20) The cold operator REVOKED the consensus key (suspected leak):
    /// excluded from the committee AND fees at the next epoch. The key stays as the
    /// live `address` (so an in-epoch equivocation remains slashable via the normal
    /// path); cleared by `RotateConsensusKey`. false = default (not revoked).
    pub consensus_key_revoked: bool,
    /// (#20) Consensus keys this validator ROTATED AWAY FROM, each kept slashable
    /// until its quanto. Empty by default. Bounded by `MAX_RETIRED_CONSENSUS_KEYS`;
    /// pruned when a key's window passes.
    pub retired_consensus_keys: Vec<RetiredConsensusKey>,
}

impl ValidatorV7Entry {
    /// (#20) Whether the CONSENSUS key is currently disabled — revoked by the
    /// operator, or past its forced-rotation expiry — so this validator is excluded
    /// from BOTH the active committee and fee eligibility until the operator rotates
    /// in a fresh key. Deterministic (reads committed state). A default entry
    /// (`expiry 0`, not revoked) is NEVER disabled → byte-identical honest path.
    pub fn consensus_key_disabled(&self, current_quanto: u64) -> bool {
        self.consensus_key_revoked
            || (self.consensus_key_expiry_quanto != 0 && self.consensus_key_expiry_quanto <= current_quanto)
    }

    /// (#20) Record `old` as a retired-but-still-slashable consensus key, slashable
    /// through the evidence window, and drop any retired key whose window already
    /// passed. Keeps the list bounded (`MAX_RETIRED_CONSENSUS_KEYS`): if full after
    /// pruning, the earliest-expiring retired key is evicted (its window would end
    /// soonest anyway). Deterministic.
    fn retire_consensus_key(&mut self, old: Pubkey, current_quanto: u64, slash_window: u64) {
        self.retired_consensus_keys.retain(|r| r.slash_until_quanto > current_quanto);
        self.retired_consensus_keys.push(RetiredConsensusKey {
            address: old,
            slash_until_quanto: current_quanto.saturating_add(slash_window),
        });
        if self.retired_consensus_keys.len() > MAX_RETIRED_CONSENSUS_KEYS {
            // Evict the soonest-to-expire (its slashable window ends first).
            if let Some((i, _)) = self
                .retired_consensus_keys
                .iter()
                .enumerate()
                .min_by_key(|(_, r)| r.slash_until_quanto)
            {
                self.retired_consensus_keys.remove(i);
            }
        }
    }
    /// Participation this quanto, in basis points. No recorded opportunities yet
    /// → treated as full (10000): a freshly-activated validator the node hasn't
    /// scored is not penalized. Once real data accrues the ratio gates eligibility.
    pub fn participation_bps(&self) -> u16 {
        if self.participation_opportunities == 0 {
            return 10_000;
        }
        let bps = (self.participation_credits as u128 * 10_000 / self.participation_opportunities as u128).min(10_000);
        bps as u16
    }
}

/// The v7 validator registry singleton (`VALIDATOR_REGISTRY_ACCOUNT_ID.data`).
#[derive(Clone, Default, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct ValidatorV7Registry {
    pub validators: Vec<ValidatorV7Entry>,
}

impl ValidatorV7Registry {
    fn find(&self, addr: &Pubkey) -> Option<usize> {
        self.validators.iter().position(|v| &v.address == addr)
    }
    /// (#20) The validator slashable for an equivocation signed by `author`: its
    /// LIVE consensus key, or — if `author` was ROTATED AWAY FROM — a validator
    /// whose `retired_consensus_keys` still holds `author` within its slash window
    /// (`slash_until_quanto >= current_quanto`). Ensures a rotated-out (e.g. leaked)
    /// key stays punishable through the evidence window even after the operator
    /// rotates the live address to a fresh key. Deterministic.
    fn find_slashable(&self, author: &Pubkey, current_quanto: u64) -> Option<usize> {
        if let Some(i) = self.find(author) {
            return Some(i);
        }
        self.validators.iter().position(|v| {
            v.retired_consensus_keys
                .iter()
                .any(|r| &r.address == author && r.slash_until_quanto >= current_quanto)
        })
    }
    fn moniker_taken(&self, moniker: &str, except: Option<&Pubkey>) -> bool {
        self.validators
            .iter()
            .any(|v| v.moniker == moniker && v.state != ValidatorV7State::Removed && Some(&v.address) != except)
    }
    /// Every address currently bound (as consensus key, cold operator, OR cold
    /// withdrawal) by a LIVE (non-Removed) validator, EXCLUDING the slot keyed by
    /// `except` (a Removed consensus address being re-registered in place). A new
    /// registration is rejected if its consensus/operator/withdrawal address hits
    /// this set — no two live validators may share ANY key/operator/withdrawal
    /// identity. (This tightens the earlier "one operator may run several
    /// validators" allowance: the unification requirement is to forbid duplicate
    /// registrations of key, operator, withdrawal, OR identity, so an operator
    /// running N validators must use N distinct operator keys.)
    fn addresses_in_use(&self, except: Option<&Pubkey>) -> std::collections::HashSet<Pubkey> {
        let mut s = std::collections::HashSet::new();
        for v in &self.validators {
            if v.state == ValidatorV7State::Removed || Some(&v.address) == except {
                continue;
            }
            s.insert(v.address);
            s.insert(v.operator_address);
            s.insert(v.withdrawal_address);
        }
        s
    }
}

/// One member of the ACTIVE consensus committee derived from the v7 registry.
/// Carries exactly what consensus needs: the consensus identity (`address`), its
/// block-signing key bundle, its dial address, and its (equal) bond weight.
#[derive(Clone, Debug)]
pub struct ActiveV7Member {
    pub address: Pubkey,
    pub pubkey_bundle: PublicKeyBundle,
    pub p2p_address: String,
    pub bond: u64,
}

/// The consensus-eligible ACTIVE committee derived from the v7 registry — the
/// SINGLE canonical source that unifies economics and consensus. A validator is
/// in the committee iff it is `Active`, its `activation_quanto` has arrived
/// (`<= current_quanto`), it holds the full bond (`bond == VALIDATOR_BOND_ATOMS`),
/// and its consensus key is not disabled (revoked/expired — #20).
///
/// Every bonded validator carries EQUAL consensus weight (one bond = one unit),
/// so each member's reported weight is `VALIDATOR_BOND_ATOMS`. Deterministic:
/// filtered from the committed registry and ordered by consensus address, capped
/// at `MAX_ACTIVE_V7_VALIDATORS` (equal weight → the cap deterministically keeps
/// the lowest addresses). Every honest node computing this from the identical
/// committed registry gets the byte-identical committee → fork-free.
///
/// This is the SAME lifecycle the fee eligibility reads (`fees_v7::is_eligible`
/// also requires `Active` + activation), so "who is in the committee", "who can
/// produce/vote blocks", and "who can receive fees" are now ONE decision from ONE
/// registry. Excludes `BondedPending` (not yet activated), `Jailed` (down —
/// excluded from BOTH committee and fees), and `Exiting`/`Unbonding`/
/// `Withdrawable`/`Slashed`/`Removed` (leaving or gone).
pub fn active_committee(reg: &ValidatorV7Registry, current_quanto: u64) -> Vec<ActiveV7Member> {
    let mut members: Vec<ActiveV7Member> = reg
        .validators
        .iter()
        // (#20) A validator whose consensus key is REVOKED or EXPIRED is excluded
        // from the committee until the operator rotates in a fresh key — the same
        // deterministic gate the fee eligibility uses (`fees_v7::is_eligible`).
        .filter(|v| v.state == ValidatorV7State::Active && v.activation_quanto <= current_quanto && v.bond == VALIDATOR_BOND_ATOMS && !v.consensus_key_disabled(current_quanto))
        .map(|v| ActiveV7Member { address: v.address, pubkey_bundle: v.pubkey_bundle.clone(), p2p_address: v.p2p_address.clone(), bond: v.bond })
        .collect();
    members.sort_by(|a, b| a.address.cmp(&b.address));
    members.truncate(MAX_ACTIVE_V7_VALIDATORS);
    members
}

/// Jail every `Active` validator that was TOTALLY INACTIVE over the scored quanto
/// (`participation_opportunities > 0 && participation_credits == 0` — it had
/// chances to have a committed certificate and produced NONE, i.e. it was
/// down/disconnected the whole quanto), flipping it `Active → Jailed` so the next
/// epoch's `active_committee` drops it AND `fees_v7::is_eligible` excludes it.
/// Deterministic (reads the committed participation counters the quanto close just
/// wrote). A jailed validator recovers only via an explicit operator `Unjail`
/// (Cosmos-style — auto-unjail is impossible since a jailed validator gets no
/// committee opportunities to earn participation back, and would flap otherwise).
/// Returns whether anything changed. A conservative rule: a validator that
/// participated even once keeps its slot; only a full-quanto blackout jails.
pub fn jail_inactive(reg: &mut ValidatorV7Registry) -> bool {
    let mut changed = false;
    for v in reg.validators.iter_mut() {
        if v.state == ValidatorV7State::Active && v.participation_opportunities > 0 && v.participation_credits == 0 {
            v.state = ValidatorV7State::Jailed;
            changed = true;
        }
    }
    changed
}

/// The proof-of-possession preimage a consensus key signs to prove it consents to
/// being registered under this cold operator/withdrawal/moniker (binds the three
/// so a PoP can't be replayed for a different operator, and a bundle can't be
/// registered by someone who doesn't hold its private key — closing the register-
/// someone-else's-consensus-key front-run). Verified with `verify_domain` under
/// `domains::VALIDATOR_POP_V1`.
fn pop_message(operator: &Pubkey, withdrawal: &Pubkey, moniker: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(64 + moniker.len());
    m.extend_from_slice(&operator.0);
    m.extend_from_slice(&withdrawal.0);
    m.extend_from_slice(moniker.as_bytes());
    m
}

#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub enum ValidatorV7Instruction {
    /// Bond 500 QCH and register. The PAYER is the cold **operator** key (it funds
    /// and controls the validator); `pubkey_bundle` is the SEPARATE consensus
    /// (block-signing) key, whose possession is proven by `consensus_pop` (a
    /// signature by the consensus key over `VALIDATOR_POP_V1 ‖ operator ‖ withdrawal
    /// ‖ moniker`). The bond + fee earnings are controlled by `withdrawal_address`
    /// (defaults to the operator), NEVER by the consensus key.
    /// accounts = [operator(payer), REGISTRY, VALIDATOR_BOND_ESCROW_ID, STAKING_GLOBAL_ID].
    BondAndRegister {
        moniker: String,
        pubkey_bundle: PublicKeyBundle,
        p2p_address: String,
        withdrawal_address: Option<Pubkey>,
        consensus_pop: MultiSignature,
    },
    /// Start exiting `consensus_address` (must be the payer's own validator: the
    /// entry's `operator_address` must equal the payer). Moves the bond to the
    /// unbonding pool + starts the clock. Only the cold operator can do this — a
    /// leaked consensus key cannot begin an exit.
    /// accounts = [operator(payer), REGISTRY, BOND_ESCROW, VALIDATOR_UNBONDING_POOL, STAKING_GLOBAL].
    BeginExit { consensus_address: Pubkey },
    /// Withdraw the bond of `consensus_address` after the unbonding + evidence
    /// window, to its **withdrawal address** (which must be named in accounts[4] so
    /// the ledger persists the credit). Only the cold operator can do this.
    /// accounts = [operator(payer), REGISTRY, VALIDATOR_UNBONDING_POOL, STAKING_GLOBAL, withdrawal_dest].
    WithdrawBond { consensus_address: Pubkey },
    /// Slash a proven equivocator's full bond (permissionless). accounts =
    /// [reporter(payer), REGISTRY, BOND_ESCROW, VALIDATOR_UNBONDING_POOL].
    ReportEquivocation { evidence: Box<EquivocationEvidence> },
    /// Un-jail `consensus_address` (must be the payer's own validator: the entry's
    /// `operator_address` must equal the payer), flipping it `Jailed → Active` and
    /// resetting its participation counters so it rejoins the committee at the next
    /// epoch. The recovery path for a validator jailed for downtime (Cosmos-style
    /// manual unjail — the operator fixes the node, then explicitly re-enters). The
    /// bond was never touched by jailing, so nothing moves here.
    /// accounts = [operator(payer), REGISTRY].
    Unjail { consensus_address: Pubkey },
    /// (#20/KM#5) PROPOSE handing off the cold OPERATOR role of `consensus_address`
    /// to `new_operator` (authorized by the CURRENT operator, the payer). KM#5:
    /// TIMELOCKED (~24h) — recorded pending and applied later via
    /// `ApplyPendingKeyChange`, so a leaked operator key can't instantly lock out
    /// the owner. Keeps the bond/activation/consensus key. `new_operator` must not
    /// already be a live validator's consensus/operator/withdrawal key. accounts =
    /// [operator(payer), REGISTRY, KEY_TIMELOCK_REGISTRY, STAKING_GLOBAL].
    RotateOperator { consensus_address: Pubkey, new_operator: Pubkey },
    /// (#20/KM#5) PROPOSE changing the cold WITHDRAWAL address of `consensus_address`
    /// (authorized by the operator, the payer) — where the bond returns AND where
    /// fee commissions accrue. KM#5: TIMELOCKED (~72h) — recorded pending and
    /// applied later via `ApplyPendingKeyChange`, so a leaked operator key can't
    /// instantly redirect the bond/earnings. `new_withdrawal` must not collide with
    /// another live validator's key. accounts = [operator(payer), REGISTRY,
    /// KEY_TIMELOCK_REGISTRY, STAKING_GLOBAL].
    RotateWithdrawal { consensus_address: Pubkey, new_withdrawal: Pubkey },
    /// (#20) Rotate the CONSENSUS (block-signing) key of `consensus_address` to a
    /// fresh `new_bundle` (authorized by the operator, the payer), proving
    /// possession of the new key via `new_pop` (a signature by the NEW consensus
    /// key over `VALIDATOR_POP_V1 ‖ operator ‖ withdrawal ‖ moniker`). Keeps the
    /// bond/activation/participation and identity; the OLD key is recorded as
    /// slashable through the evidence window, and any revocation/expiry is cleared.
    /// The rotation takes effect at the next epoch boundary via the standard
    /// deterministic committee derivation. accounts = [operator(payer), REGISTRY,
    /// STAKING_GLOBAL].
    RotateConsensusKey { consensus_address: Pubkey, new_bundle: PublicKeyBundle, new_p2p_address: String, new_pop: MultiSignature },
    /// (#20) REVOKE the consensus key of `consensus_address` (operator emergency —
    /// suspected leak). Excludes the validator from the committee AND fees at the
    /// next epoch, but the key stays as `address` so an in-epoch equivocation is
    /// still slashable. Recovery: `RotateConsensusKey`. accounts =
    /// [operator(payer), REGISTRY, STAKING_GLOBAL].
    RevokeConsensusKey { consensus_address: Pubkey },
    /// (#20) Set (or clear, with 0) the forced-rotation EXPIRY quanto of the
    /// consensus key of `consensus_address` (authorized by the operator). At/after
    /// `expiry_quanto` the validator is excluded from the committee AND fees until
    /// the operator rotates in a fresh key. accounts = [operator(payer), REGISTRY].
    SetConsensusKeyExpiry { consensus_address: Pubkey, expiry_quanto: u64 },
    /// (KM#4/KM#5) PROPOSE setting (or replacing/clearing) the OFFLINE recovery
    /// committee of `consensus_address` (authorized by the cold OPERATOR — set
    /// BEFORE any compromise). KM#5: TIMELOCKED (~7d) — recorded pending and applied
    /// later via `ApplyPendingKeyChange` (which writes the SEPARATE recovery
    /// registry singleton, additive — no validator-entry format change). `config`
    /// empty → clears the committee. accounts = [operator(payer), REGISTRY,
    /// KEY_TIMELOCK_REGISTRY, STAKING_GLOBAL].
    SetRecoveryCommittee { consensus_address: Pubkey, config: RecoveryConfig },
    /// (KM#4) REVOKE `consensus_address` using its OFFLINE recovery committee —
    /// neutralize a validator whose consensus/operator keys are lost or
    /// compromised, WITHOUT any of those keys. `approvals` carries M offline
    /// signatures collected out-of-band; the handler verifies ≥ threshold DISTINCT
    /// valid signatures from REGISTERED recovery signers over the current recovery
    /// nonce, then hard-exits the validator (bond → unbonding pool, state →
    /// `Revoked`, nonce bumped). PERMISSIONLESS: the payer is just a fee relayer
    /// (like `ReportEquivocation`) — the M signatures are the authorization.
    /// accounts = [payer, REGISTRY, RECOVERY_REGISTRY, BOND_ESCROW, VALIDATOR_UNBONDING_POOL, STAKING_GLOBAL].
    RecoverRevoke { consensus_address: Pubkey, op: RecoveryOp, approvals: Vec<RecoveryApproval> },
    /// (KM#5) Apply a validator's timelocked cold-key change once its window has
    /// elapsed. PERMISSIONLESS (the operator authorized it at propose; the payer is
    /// a fee relayer). `kind` names which pending change (operator/withdrawal/
    /// recovery). accounts = [payer, REGISTRY, KEY_TIMELOCK_REGISTRY,
    /// RECOVERY_REGISTRY, STAKING_GLOBAL].
    ApplyPendingKeyChange { consensus_address: Pubkey, kind: KeyChangeKind },
    /// (KM#5) Cancel a still-pending timelocked cold-key change (operator-
    /// authorized) — abort a legitimate proposal before it applies. accounts =
    /// [operator(payer), REGISTRY, KEY_TIMELOCK_REGISTRY].
    CancelPendingKeyChange { consensus_address: Pubkey, kind: KeyChangeKind },
}

pub struct ValidatorV7Program;

// ─── Versioned registry migration (pre-mainnet #1) ────────────────────────────
//
// The validator registry singleton has had layout evolutions across versions. A
// node must NEVER silently fall back to an EMPTY registry on a present-but-old
// one — that would drop the committee to the genesis fallback and can diverge a
// multi-validator network. Instead it MIGRATES a known old layout to the current
// one, and treats a genuinely unrecognizable one as CORRUPT (fail-loud / halt),
// never as empty.
//
// Known layouts at `VALIDATOR_REGISTRY_ACCOUNT_ID`:
//   V3 (current) — `ValidatorV7Entry` with the #20 advanced key-role fields
//                  (`consensus_key_expiry_quanto` / `consensus_key_revoked` /
//                  `retired_consensus_keys`) appended after the participation
//                  counters, since v8.6.16.
//   V2 (prior)   — the role-separated `ValidatorV7Entry` WITHOUT the #20 fields
//                  (v6.19.0 .. v8.6.15): byte-identical to V3 minus the three
//                  appended fields → migrate by defaulting them (expiry 0, not
//                  revoked, no retired keys), i.e. behavior-identical.
//   V1 (legacy)  — the pre-role-separation `ValidatorV7Entry` (v6.3.x .. v6.19.0):
//                  lacks the two cold-key fields AND the #20 fields. Migrate:
//                  operator = withdrawal = the consensus address (the pre-#193-B
//                  behavior, where one key held every role) + the #20 defaults.
//
// borsh appends fields and rejects trailing bytes, so a shorter layout never
// cross-decodes as a longer one: V3 is tried first; a V2 registry (fewer bytes)
// fails V3 with EOF and falls to the V2 mirror; a V3 registry has trailing bytes
// for the V2 mirror and is rejected there (but V3 already matched). No ambiguity.

/// The prior role-separated (V2) validator entry layout — the #193-B entry WITHOUT
/// the #20 advanced key-role fields. Kept ONLY to decode a V2 on-disk registry and
/// migrate it forward — never written.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub(crate) struct ValidatorV7EntryV2 {
    pub(crate) address: Pubkey,
    pub(crate) operator_address: Pubkey,
    pub(crate) withdrawal_address: Pubkey,
    pub(crate) moniker: String,
    pub(crate) pubkey_bundle: PublicKeyBundle,
    pub(crate) p2p_address: String,
    pub(crate) bond: u64,
    pub(crate) state: ValidatorV7State,
    pub(crate) registered_quanto: u64,
    pub(crate) activation_quanto: u64,
    pub(crate) exit_requested_quanto: u64,
    pub(crate) bond_release_quanto: u64,
    pub(crate) participation_credits: u64,
    pub(crate) participation_opportunities: u64,
}

/// The prior (V2) registry container — a `Vec` of the pre-#20 entry.
#[derive(Clone, Default, BorshSerialize, BorshDeserialize, Debug)]
pub(crate) struct ValidatorV7RegistryV2 {
    pub(crate) validators: Vec<ValidatorV7EntryV2>,
}

impl ValidatorV7EntryV2 {
    fn migrate(self) -> ValidatorV7Entry {
        ValidatorV7Entry {
            address: self.address,
            operator_address: self.operator_address,
            withdrawal_address: self.withdrawal_address,
            moniker: self.moniker,
            pubkey_bundle: self.pubkey_bundle,
            p2p_address: self.p2p_address,
            bond: self.bond,
            state: self.state,
            registered_quanto: self.registered_quanto,
            activation_quanto: self.activation_quanto,
            exit_requested_quanto: self.exit_requested_quanto,
            bond_release_quanto: self.bond_release_quanto,
            participation_credits: self.participation_credits,
            participation_opportunities: self.participation_opportunities,
            // #20 defaults: no forced expiry, not revoked, no retired keys →
            // behavior-identical to the pre-#20 entry.
            consensus_key_expiry_quanto: 0,
            consensus_key_revoked: false,
            retired_consensus_keys: Vec::new(),
        }
    }
}

/// The pre-role-separation (V1) validator entry layout. Kept ONLY to decode a
/// legacy on-disk registry and migrate it forward — never written.
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub(crate) struct ValidatorV7EntryV1 {
    pub(crate) address: Pubkey,
    pub(crate) moniker: String,
    pub(crate) pubkey_bundle: PublicKeyBundle,
    pub(crate) p2p_address: String,
    pub(crate) bond: u64,
    pub(crate) state: ValidatorV7State,
    pub(crate) registered_quanto: u64,
    pub(crate) activation_quanto: u64,
    pub(crate) exit_requested_quanto: u64,
    pub(crate) bond_release_quanto: u64,
    pub(crate) participation_credits: u64,
    pub(crate) participation_opportunities: u64,
}

/// The legacy (V1) registry container — a `Vec` of the pre-role-separation entry.
#[derive(Clone, Default, BorshSerialize, BorshDeserialize, Debug)]
pub(crate) struct ValidatorV7RegistryV1 {
    pub(crate) validators: Vec<ValidatorV7EntryV1>,
}

impl ValidatorV7EntryV1 {
    fn migrate(self) -> ValidatorV7Entry {
        ValidatorV7Entry {
            // pre-#193-B: one key held consensus + operator + withdrawal roles.
            operator_address: self.address,
            withdrawal_address: self.address,
            address: self.address,
            moniker: self.moniker,
            pubkey_bundle: self.pubkey_bundle,
            p2p_address: self.p2p_address,
            bond: self.bond,
            state: self.state,
            registered_quanto: self.registered_quanto,
            activation_quanto: self.activation_quanto,
            exit_requested_quanto: self.exit_requested_quanto,
            bond_release_quanto: self.bond_release_quanto,
            participation_credits: self.participation_credits,
            participation_opportunities: self.participation_opportunities,
            // #20 defaults.
            consensus_key_expiry_quanto: 0,
            consensus_key_revoked: false,
            retired_consensus_keys: Vec::new(),
        }
    }
}

/// Decode the validator registry from its on-disk `data`, MIGRATING a known
/// legacy layout forward. Returns `None` ONLY when the bytes are neither the
/// current format nor a recognized older one — i.e. GENUINELY CORRUPT, which the
/// caller must treat as fail-loud (halt), never as an empty registry.
///
/// Deterministic and side-effect-free: every node decodes/migrates the same
/// bytes to the same `ValidatorV7Registry`, so reading a V1 registry as its
/// migrated V2 form never diverges a network. The migration is applied on READ
/// only (the stored bytes are NOT rewritten here), so it introduces no
/// state-root change; the first real registry write persists the V2 form.
pub fn decode_registry(data: &[u8]) -> Option<ValidatorV7Registry> {
    // Current format first: a real V3 registry always decodes here. A shorter V2
    // or V1 one won't (V3 appends the #20 fields, so a V2/V1 registry runs out of
    // bytes and borsh fails cleanly with EOF). An empty registry (`[0,0,0,0]`) is a
    // valid empty V3 and decodes here directly.
    if let Ok(v3) = ValidatorV7Registry::try_from_slice(data) {
        return Some(v3);
    }
    // Prior role-separated layout without the #20 fields → migrate (default them).
    if let Ok(v2) = ValidatorV7RegistryV2::try_from_slice(data) {
        return Some(ValidatorV7Registry {
            validators: v2.validators.into_iter().map(|e| e.migrate()).collect(),
        });
    }
    // Legacy pre-role-separation layout → migrate each entry forward.
    if let Ok(v1) = ValidatorV7RegistryV1::try_from_slice(data) {
        return Some(ValidatorV7Registry {
            validators: v1.validators.into_iter().map(|e| e.migrate()).collect(),
        });
    }
    None
}

/// The EXPLICIT on-disk schema of the validator registry — the "schema_version"
/// (pre-mainnet #3). Detection is still structural (Borsh layout), but the
/// result is a first-class, named, reportable value rather than a silent probe
/// buried in `decode_registry`: `qchain-inspect-state` and
/// `qchain-migrate-registry` report it, so an operator always knows exactly
/// which version is on disk before touching a live network.
///
/// Honest note on why the schema tag isn't (yet) a byte stored INSIDE the
/// account: a leading version byte would change the registry account's on-disk
/// bytes for every already-V2 network, which changes that account's Merkle leaf
/// and therefore the state root — a coordinated / fresh-genesis change. That
/// explicit-tag-for-every-singleton work is roadmap #19 (done uniformly across
/// all singletons at one cutover); here the schema is detected+reported, and the
/// persisted bytes stay the plain V2 form the running node already understands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RegistrySchema {
    /// Pre-role-separation layout (v6.3.x .. v6.19.0) — migratable to V3.
    V1Legacy,
    /// Role-separated layout WITHOUT the #20 advanced key-role fields
    /// (v6.19.0 .. v8.6.15) — migratable to V3 (default the #20 fields).
    V2Prior,
    /// Current layout, with the #20 advanced key-role fields (v8.6.16+).
    V3Current,
}

impl RegistrySchema {
    /// The explicit numeric schema version (1, 2, or 3).
    pub fn version(&self) -> u16 {
        match self {
            RegistrySchema::V1Legacy => 1,
            RegistrySchema::V2Prior => 2,
            RegistrySchema::V3Current => 3,
        }
    }
}

impl std::fmt::Display for RegistrySchema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistrySchema::V1Legacy => write!(f, "V1 (legacy, pre-role-separation)"),
            RegistrySchema::V2Prior => write!(f, "V2 (prior, pre-#20 key-role fields)"),
            RegistrySchema::V3Current => write!(f, "V3 (current)"),
        }
    }
}

/// Report the EXPLICIT schema of a registry's on-disk `data`, or `None` if the
/// bytes match no known version (genuinely corrupt — the caller must fail-loud,
/// never guess). Same structural detection `decode_registry` uses, surfaced as a
/// named value (see [`RegistrySchema`]). V3 is tried first (a V2/V1 registry has
/// fewer bytes and fails it cleanly), so the newest matching layout is reported.
pub fn detect_registry_schema(data: &[u8]) -> Option<RegistrySchema> {
    if ValidatorV7Registry::try_from_slice(data).is_ok() {
        return Some(RegistrySchema::V3Current);
    }
    if ValidatorV7RegistryV2::try_from_slice(data).is_ok() {
        return Some(RegistrySchema::V2Prior);
    }
    if ValidatorV7RegistryV1::try_from_slice(data).is_ok() {
        return Some(RegistrySchema::V1Legacy);
    }
    None
}

/// The canonical (current V2) Borsh encoding of a registry — what a migration
/// persists and what the running node writes on its first registry mutation.
pub fn encode_registry(reg: &ValidatorV7Registry) -> Vec<u8> {
    borsh::to_vec(reg).expect("registry serialization is infallible")
}

/// The plan for migrating a registry's on-disk bytes forward to the current
/// (V2) format — computed WITHOUT touching disk, so `qchain-migrate-registry`
/// can preview it (`--dry-run`) exactly as it would apply it. Deterministic and
/// lossless: a V1 registry migrates to the byte-for-byte V2 `decode_registry`
/// already yields on read (operator = withdrawal = the consensus address).
pub enum RegistryMigration {
    /// Already the current V2 format — migrating is a no-op.
    AlreadyCurrent { validators: usize },
    /// A legacy V1 registry — `new_bytes` is the V2 encoding to persist.
    Migrated { validators: usize, new_bytes: Vec<u8> },
    /// Bytes match no known version — genuinely corrupt; refuse to migrate.
    Corrupt,
}

/// Compute the migration plan for a registry's on-disk `data`. Pure (no I/O).
/// Idempotent by construction: re-planning the `new_bytes` of a `Migrated`
/// result yields `AlreadyCurrent` (migrating twice is a no-op).
pub fn plan_registry_migration(data: &[u8]) -> RegistryMigration {
    match detect_registry_schema(data) {
        Some(RegistrySchema::V3Current) => {
            let reg = ValidatorV7Registry::try_from_slice(data).expect("just detected as V3");
            RegistryMigration::AlreadyCurrent { validators: reg.validators.len() }
        }
        Some(RegistrySchema::V2Prior) | Some(RegistrySchema::V1Legacy) => {
            // `decode_registry` migrates V2/V1 -> V3 in memory; encode that as the
            // bytes to persist.
            let reg = decode_registry(data).expect("V2/V1 detected, so it decodes+migrates");
            let new_bytes = encode_registry(&reg);
            RegistryMigration::Migrated { validators: reg.validators.len(), new_bytes }
        }
        None => RegistryMigration::Corrupt,
    }
}

/// Rehearsal helper: encode a legacy (pre-role-separation V1) registry holding
/// one entry, so tests AND operators can produce genuinely old-format bytes to
/// rehearse the V1→V2 migration (`qchain-migrate-registry`) and the node's
/// fail-loud/migrate behavior on a throwaway testnet. Never used on a
/// production path (nothing writes V1 — the current node only ever writes V2).
#[doc(hidden)]
pub fn legacy_v1_registry_bytes(
    address: Pubkey,
    moniker: &str,
    pubkey_bundle: PublicKeyBundle,
    p2p_address: &str,
) -> Vec<u8> {
    let reg = ValidatorV7RegistryV1 {
        validators: vec![ValidatorV7EntryV1 {
            address,
            moniker: moniker.to_string(),
            pubkey_bundle,
            p2p_address: p2p_address.to_string(),
            bond: VALIDATOR_BOND_ATOMS,
            state: ValidatorV7State::Active,
            registered_quanto: 0,
            activation_quanto: 0,
            exit_requested_quanto: 0,
            bond_release_quanto: 0,
            participation_credits: 0,
            participation_opportunities: 0,
        }],
    };
    borsh::to_vec(&reg).unwrap()
}

fn read_registry(accounts: &HashMap<Pubkey, Account>) -> ValidatorV7Registry {
    // Pre-mainnet #1: MIGRATE a known legacy layout forward; NEVER fall back to
    // an empty registry on a present-but-undecodable one (that would silently
    // drop to the genesis committee and can diverge a multi-validator network).
    // A truly unrecognizable registry is CORRUPT → fail-loud (halt), matching the
    // money/authority singletons. The startup gate
    // (`Ledger::validate_critical_singletons`) already halts on a corrupt
    // registry before the node runs, so this read-time panic is defense-in-depth
    // for runtime disk corruption — deterministic in the committed-state sense
    // (a per-node disk fault stops that node, it never forks).
    match accounts.get(&VALIDATOR_REGISTRY_ACCOUNT_ID) {
        // Absent = a network with no v7 registry (a v6 chain / not-yet-seeded) →
        // legitimately empty. Presence is separately required by the startup gate.
        None => ValidatorV7Registry::default(),
        Some(a) => decode_registry(&a.data).unwrap_or_else(|| {
            panic!(
                "VALIDATOR_REGISTRY (v7) is present but decodes as neither the current \
                 nor a known legacy format — refusing to run on a corrupt validator \
                 registry (restore from a good backup / re-sync a fresh data_dir)"
            )
        }),
    }
}

fn write_registry(accounts: &mut HashMap<Pubkey, Account>, r: &ValidatorV7Registry) -> Result<(), ExecError> {
    let acct = accounts.entry(VALIDATOR_REGISTRY_ACCOUNT_ID).or_insert_with(|| Account::new_wallet(STAKING_PROGRAM_ID));
    acct.data = borsh::to_vec(r).map_err(|e| ExecError::ProgramError(e.to_string()))?;
    Ok(())
}

/// (KM#4) Read the recovery registry singleton, LAZILY DEFAULTED: absent OR empty
/// data (an existing v7 network that hasn't opted in) → an empty registry. A
/// PRESENT-but-undecodable one is fail-loud (like the validator registry): a
/// per-node disk fault stops that node, it never forks. Additive: never touches
/// the validator registry format, so the live network is byte-identical until a
/// validator first opts in.
fn read_recovery_registry(accounts: &HashMap<Pubkey, Account>) -> RecoveryRegistry {
    match accounts.get(&VALIDATOR_RECOVERY_REGISTRY_ID) {
        None => RecoveryRegistry::default(),
        Some(a) if a.data.is_empty() => RecoveryRegistry::default(),
        Some(a) => RecoveryRegistry::try_from_slice(&a.data).unwrap_or_else(|_| {
            panic!(
                "VALIDATOR_RECOVERY_REGISTRY (v7) is present but does not decode — refusing \
                 to run on a corrupt recovery registry (restore from a good backup / re-sync)"
            )
        }),
    }
}

fn write_recovery_registry(accounts: &mut HashMap<Pubkey, Account>, r: &RecoveryRegistry) -> Result<(), ExecError> {
    let acct = accounts.entry(VALIDATOR_RECOVERY_REGISTRY_ID).or_insert_with(|| Account::new_wallet(STAKING_PROGRAM_ID));
    acct.data = borsh::to_vec(r).map_err(|e| ExecError::ProgramError(e.to_string()))?;
    Ok(())
}

/// (KM#5) Read the key-timelock registry singleton, LAZILY DEFAULTED like the
/// recovery registry: absent OR empty data → an empty registry; a PRESENT-but-
/// undecodable one is fail-loud (a per-node disk fault stops that node, never
/// forks). Additive — the live network is byte-identical until a validator first
/// proposes a timelocked key change.
fn read_key_timelock_registry(accounts: &HashMap<Pubkey, Account>) -> KeyTimelockRegistry {
    match accounts.get(&VALIDATOR_KEY_TIMELOCK_REGISTRY_ID) {
        None => KeyTimelockRegistry::default(),
        Some(a) if a.data.is_empty() => KeyTimelockRegistry::default(),
        Some(a) => KeyTimelockRegistry::try_from_slice(&a.data).unwrap_or_else(|_| {
            panic!(
                "VALIDATOR_KEY_TIMELOCK_REGISTRY (v7) is present but does not decode — refusing \
                 to run on a corrupt key-timelock registry (restore from a good backup / re-sync)"
            )
        }),
    }
}

fn write_key_timelock_registry(accounts: &mut HashMap<Pubkey, Account>, r: &KeyTimelockRegistry) -> Result<(), ExecError> {
    let acct = accounts.entry(VALIDATOR_KEY_TIMELOCK_REGISTRY_ID).or_insert_with(|| Account::new_wallet(STAKING_PROGRAM_ID));
    acct.data = borsh::to_vec(r).map_err(|e| ExecError::ProgramError(e.to_string()))?;
    Ok(())
}

fn current_quanto(accounts: &HashMap<Pubkey, Account>) -> u64 {
    crate::staking_v7::global_state(accounts).current_quanto
}

fn credit(accounts: &mut HashMap<Pubkey, Account>, pk: &Pubkey, owner_if_new: Pubkey, amount: u64) -> Result<(), ExecError> {
    let acct = accounts.entry(*pk).or_insert_with(|| Account::new_wallet(owner_if_new));
    acct.balance = crate::arith::add_u64(acct.balance, amount)?; // #218 checked money
    Ok(())
}

impl crate::native::NativeProgram for ValidatorV7Program {
    fn process(&self, accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey, _current_round: qchain_core::Round) -> Result<(), ExecError> {
        ValidatorV7Program::execute(accounts, instruction, payer)
    }
}

impl ValidatorV7Program {
    pub fn execute(accounts: &mut HashMap<Pubkey, Account>, instruction: &Instruction, payer: &Pubkey) -> Result<(), ExecError> {
        let instr = ValidatorV7Instruction::try_from_slice(&instruction.data)
            .map_err(|e| ExecError::ProgramError(format!("bad v7 validator instruction: {e}")))?;
        match instr {
            ValidatorV7Instruction::BondAndRegister { moniker, pubkey_bundle, p2p_address, withdrawal_address, consensus_pop } => {
                Self::bond_and_register(accounts, instruction, payer, moniker, pubkey_bundle, p2p_address, withdrawal_address, consensus_pop)
            }
            ValidatorV7Instruction::BeginExit { consensus_address } => Self::begin_exit(accounts, instruction, payer, consensus_address),
            ValidatorV7Instruction::WithdrawBond { consensus_address } => Self::withdraw_bond(accounts, instruction, payer, consensus_address),
            ValidatorV7Instruction::ReportEquivocation { evidence } => Self::report_equivocation(accounts, instruction, payer, *evidence),
            ValidatorV7Instruction::Unjail { consensus_address } => Self::unjail(accounts, instruction, payer, consensus_address),
            ValidatorV7Instruction::RotateOperator { consensus_address, new_operator } => Self::rotate_operator(accounts, instruction, payer, consensus_address, new_operator),
            ValidatorV7Instruction::RotateWithdrawal { consensus_address, new_withdrawal } => Self::rotate_withdrawal(accounts, instruction, payer, consensus_address, new_withdrawal),
            ValidatorV7Instruction::RotateConsensusKey { consensus_address, new_bundle, new_p2p_address, new_pop } => {
                Self::rotate_consensus_key(accounts, instruction, payer, consensus_address, new_bundle, new_p2p_address, new_pop)
            }
            ValidatorV7Instruction::RevokeConsensusKey { consensus_address } => Self::revoke_consensus_key(accounts, instruction, payer, consensus_address),
            ValidatorV7Instruction::SetConsensusKeyExpiry { consensus_address, expiry_quanto } => Self::set_consensus_key_expiry(accounts, instruction, payer, consensus_address, expiry_quanto),
            ValidatorV7Instruction::SetRecoveryCommittee { consensus_address, config } => Self::set_recovery_committee(accounts, instruction, payer, consensus_address, config),
            ValidatorV7Instruction::RecoverRevoke { consensus_address, op, approvals } => Self::recover_revoke(accounts, instruction, payer, consensus_address, op, approvals),
            ValidatorV7Instruction::ApplyPendingKeyChange { consensus_address, kind } => Self::apply_pending_key_change(accounts, instruction, payer, consensus_address, kind),
            ValidatorV7Instruction::CancelPendingKeyChange { consensus_address, kind } => Self::cancel_pending_key_change(accounts, instruction, payer, consensus_address, kind),
        }
    }

    /// (KM#4/KM#5) The OPERATOR PROPOSES setting/replacing/clearing the OFFLINE
    /// recovery committee of its own validator (before any compromise — it doesn't
    /// need the recovery keys). KM#5: the change is TIMELOCKED
    /// (`KEY_TIMELOCK_RECOVERY_QUANTOS` ≈ 7d) — recorded as a pending change and
    /// applied later via `ApplyPendingKeyChange`, so a compromised operator can't
    /// instantly swap in its own committee. Validated upfront so a doomed change
    /// isn't queued. accounts = [operator(payer), REGISTRY, KEY_TIMELOCK_REGISTRY,
    /// STAKING_GLOBAL].
    fn set_recovery_committee(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, consensus_address: Pubkey, config: RecoveryConfig) -> Result<(), ExecError> {
        // Only the cold operator of a LIVE validator may configure its recovery.
        let (reg, idx) = Self::require_operator(accounts, ix, payer, &consensus_address, "SetRecoveryCommittee")?;
        if matches!(reg.validators[idx].state, ValidatorV7State::Revoked | ValidatorV7State::Removed) {
            return Err(ExecError::ProgramError("validator is not in a state that can configure recovery".into()));
        }
        let clearing = config.signers.is_empty() && config.threshold == 0;
        if !clearing {
            config.validate()?;
        }
        Self::propose_key_change(accounts, ix, consensus_address, PendingKeyChange::RecoveryCommittee(config))
    }

    /// (KM#5) Pin the key-timelock registry + staking global, read the current
    /// quanto, and record (or REPLACE, resetting the clock) a pending timelocked
    /// cold-key change. The caller has already required the operator + validated the
    /// new value. accounts[2] = KEY_TIMELOCK_REGISTRY, accounts[3] = STAKING_GLOBAL.
    fn propose_key_change(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, consensus_address: Pubkey, change: PendingKeyChange) -> Result<(), ExecError> {
        let timelock_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("propose key change requires accounts[2] (key timelock registry)".into()))?;
        let global_pk = *ix.accounts.get(3).ok_or_else(|| ExecError::ProgramError("propose key change requires accounts[3] (staking global)".into()))?;
        if timelock_pk != VALIDATOR_KEY_TIMELOCK_REGISTRY_ID || global_pk != STAKING_GLOBAL_ID {
            return Err(ExecError::Unauthorized("propose key change must name the canonical key-timelock registry and staking global".into()));
        }
        let q = current_quanto(accounts);
        let ready = q.saturating_add(change.window_quantos());
        let kind = change.kind();
        let entry = PendingKeyChangeEntry { consensus_address, proposed_quanto: q, ready_quanto: ready, change };
        let mut tl = read_key_timelock_registry(accounts);
        match tl.find(&consensus_address, kind) {
            // Re-proposing the same kind RESETS the clock (standard timelock behavior).
            Some(i) => tl.pending[i] = entry,
            None => {
                if tl.pending.len() >= MAX_V7_VALIDATORS * 3 {
                    return Err(ExecError::ProgramError("key timelock registry is full".into()));
                }
                tl.pending.push(entry);
            }
        }
        write_key_timelock_registry(accounts, &tl)?;
        Ok(())
    }

    /// (KM#5) Apply a validator's timelocked cold-key change once its window has
    /// elapsed. PERMISSIONLESS: the operator already authorized it at propose; the
    /// payer is a fee relayer. Re-validates against the CURRENT committed state (the
    /// validator must not be terminal, the new value must still not collide, and the
    /// entry must not have been re-registered after the change was proposed — a
    /// staleness guard against a re-registration replay). accounts = [payer,
    /// REGISTRY, KEY_TIMELOCK_REGISTRY, RECOVERY_REGISTRY, STAKING_GLOBAL].
    fn apply_pending_key_change(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, _payer: &Pubkey, consensus_address: Pubkey, kind: KeyChangeKind) -> Result<(), ExecError> {
        let registry_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("ApplyPendingKeyChange requires accounts[1]".into()))?;
        let timelock_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("ApplyPendingKeyChange requires accounts[2]".into()))?;
        let recovery_pk = *ix.accounts.get(3).ok_or_else(|| ExecError::ProgramError("ApplyPendingKeyChange requires accounts[3]".into()))?;
        let global_pk = *ix.accounts.get(4).ok_or_else(|| ExecError::ProgramError("ApplyPendingKeyChange requires accounts[4]".into()))?;
        if registry_pk != VALIDATOR_REGISTRY_ACCOUNT_ID
            || timelock_pk != VALIDATOR_KEY_TIMELOCK_REGISTRY_ID
            || recovery_pk != VALIDATOR_RECOVERY_REGISTRY_ID
            || global_pk != STAKING_GLOBAL_ID
        {
            return Err(ExecError::Unauthorized("ApplyPendingKeyChange must name the canonical accounts".into()));
        }
        let mut tl = read_key_timelock_registry(accounts);
        let ti = tl.find(&consensus_address, kind).ok_or_else(|| ExecError::ProgramError("no pending key change of that kind for this validator".into()))?;
        let q = current_quanto(accounts);
        if q < tl.pending[ti].ready_quanto {
            return Err(ExecError::Unauthorized(format!(
                "key change is still timelocked: ready at quanto {}, now {q}",
                tl.pending[ti].ready_quanto
            )));
        }
        let proposed_quanto = tl.pending[ti].proposed_quanto;
        let change = tl.pending[ti].change.clone();
        // Re-validate against current committed state.
        let mut reg = read_registry(accounts);
        let vidx = reg.find(&consensus_address).ok_or_else(|| ExecError::ProgramError("not a registered validator".into()))?;
        if matches!(reg.validators[vidx].state, ValidatorV7State::Revoked | ValidatorV7State::Removed) {
            return Err(ExecError::ProgramError("validator is not in a state that can apply a key change".into()));
        }
        // Staleness guard: if the slot was re-registered AFTER this change was
        // proposed, the pending change belongs to a prior incarnation — reject it so
        // a re-registration can't inherit a stale (e.g. attacker-proposed) change.
        if reg.validators[vidx].registered_quanto > proposed_quanto {
            return Err(ExecError::ProgramError("pending key change predates the validator's current registration — stale".into()));
        }
        match change {
            PendingKeyChange::Operator(new_operator) => {
                let in_use = reg.addresses_in_use(Some(&consensus_address));
                if in_use.contains(&new_operator) {
                    return Err(ExecError::ProgramError("new operator address is already registered to another validator".into()));
                }
                reg.validators[vidx].operator_address = new_operator;
                write_registry(accounts, &reg)?;
            }
            PendingKeyChange::Withdrawal(new_withdrawal) => {
                let in_use = reg.addresses_in_use(Some(&consensus_address));
                if in_use.contains(&new_withdrawal) {
                    return Err(ExecError::ProgramError("new withdrawal address is already registered to another validator".into()));
                }
                reg.validators[vidx].withdrawal_address = new_withdrawal;
                write_registry(accounts, &reg)?;
            }
            PendingKeyChange::RecoveryCommittee(config) => {
                let clearing = config.signers.is_empty() && config.threshold == 0;
                let mut rec = read_recovery_registry(accounts);
                match rec.find(&consensus_address) {
                    Some(i) => {
                        if clearing {
                            rec.entries.remove(i);
                        } else {
                            // Keep the nonce MONOTONIC across a committee change so a
                            // stale offline authorization can never be replayed.
                            rec.entries[i].config = config;
                        }
                    }
                    None => {
                        if !clearing {
                            if rec.entries.len() >= MAX_V7_VALIDATORS {
                                return Err(ExecError::ProgramError("recovery registry is full".into()));
                            }
                            rec.entries.push(RecoveryEntry { consensus_address, config, nonce: 0 });
                        }
                    }
                }
                write_recovery_registry(accounts, &rec)?;
            }
        }
        tl.pending.remove(ti);
        write_key_timelock_registry(accounts, &tl)?;
        Ok(())
    }

    /// (KM#5) Cancel a still-pending timelocked key change (operator-authorized) —
    /// abort a legitimate proposal before it applies. accounts = [operator(payer),
    /// REGISTRY, KEY_TIMELOCK_REGISTRY].
    fn cancel_pending_key_change(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, consensus_address: Pubkey, kind: KeyChangeKind) -> Result<(), ExecError> {
        let _ = Self::require_operator(accounts, ix, payer, &consensus_address, "CancelPendingKeyChange")?;
        let timelock_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("CancelPendingKeyChange requires accounts[2]".into()))?;
        if timelock_pk != VALIDATOR_KEY_TIMELOCK_REGISTRY_ID {
            return Err(ExecError::Unauthorized("CancelPendingKeyChange must name the canonical key-timelock registry".into()));
        }
        let mut tl = read_key_timelock_registry(accounts);
        let ti = tl.find(&consensus_address, kind).ok_or_else(|| ExecError::ProgramError("no pending key change of that kind for this validator".into()))?;
        tl.pending.remove(ti);
        write_key_timelock_registry(accounts, &tl)?;
        Ok(())
    }

    /// (KM#4) REVOKE a validator using its OFFLINE recovery committee — WITHOUT any
    /// of the (possibly compromised) consensus/operator keys. Permissionless: the M
    /// offline signatures are the authorization; the payer is a fee relayer.
    /// accounts = [payer, REGISTRY, RECOVERY_REGISTRY, BOND_ESCROW, VALIDATOR_UNBONDING_POOL, STAKING_GLOBAL].
    fn recover_revoke(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, _payer: &Pubkey, consensus_address: Pubkey, op: RecoveryOp, approvals: Vec<RecoveryApproval>) -> Result<(), ExecError> {
        let registry_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("RecoverRevoke requires accounts[1]".into()))?;
        let recovery_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("RecoverRevoke requires accounts[2]".into()))?;
        let escrow_pk = *ix.accounts.get(3).ok_or_else(|| ExecError::ProgramError("RecoverRevoke requires accounts[3]".into()))?;
        let unbonding_pk = *ix.accounts.get(4).ok_or_else(|| ExecError::ProgramError("RecoverRevoke requires accounts[4]".into()))?;
        let global_pk = *ix.accounts.get(5).ok_or_else(|| ExecError::ProgramError("RecoverRevoke requires accounts[5]".into()))?;
        if registry_pk != VALIDATOR_REGISTRY_ACCOUNT_ID
            || recovery_pk != VALIDATOR_RECOVERY_REGISTRY_ID
            || escrow_pk != VALIDATOR_BOND_ESCROW_ID
            || unbonding_pk != VALIDATOR_UNBONDING_POOL_ID
            || global_pk != STAKING_GLOBAL_ID
        {
            return Err(ExecError::Unauthorized("RecoverRevoke must name the canonical accounts".into()));
        }
        // Recovery committee + current nonce.
        let mut rec = read_recovery_registry(accounts);
        let ridx = rec.find(&consensus_address).ok_or_else(|| ExecError::ProgramError("no recovery committee registered for this validator".into()))?;
        let threshold = rec.entries[ridx].config.threshold;
        if threshold == 0 || rec.entries[ridx].config.signers.is_empty() {
            return Err(ExecError::ProgramError("recovery committee is empty".into()));
        }
        let signer_set: std::collections::HashSet<Pubkey> = rec.entries[ridx].config.signers.iter().copied().collect();
        let nonce = rec.entries[ridx].nonce;
        // The exact bytes each recovery signer signed OFFLINE.
        let msg = recovery_message(&consensus_address, op, nonce);
        // Count DISTINCT valid approvals from REGISTERED signers. An approval whose
        // signer isn't registered, or whose signature doesn't verify, is IGNORED
        // (not counted) — so padded/garbage approvals can't grief a real quorum.
        let mut counted: std::collections::HashSet<Pubkey> = std::collections::HashSet::new();
        for a in &approvals {
            let addr = a.bundle.to_address();
            if !signer_set.contains(&addr) || counted.contains(&addr) {
                continue;
            }
            if qchain_crypto::verify_domain(&a.bundle, qchain_crypto::domains::RECOVERY_AUTH_V1, &msg, &a.signature) {
                counted.insert(addr);
            }
        }
        if (counted.len() as u8) < threshold {
            return Err(ExecError::Unauthorized(format!(
                "recovery quorum not met: {} distinct valid recovery signatures, need {threshold}",
                counted.len()
            )));
        }
        // Authorized. Hard-exit the validator (bond → unbonding, state → Revoked),
        // mirroring `begin_exit`'s money move so the bond stays slashable through
        // the evidence window; `Revoked` is terminal and the (compromised) operator
        // cannot undo it.
        let mut reg = read_registry(accounts);
        let vidx = reg.find(&consensus_address).ok_or_else(|| ExecError::ProgramError("not a registered validator".into()))?;
        let state = reg.validators[vidx].state;
        if !matches!(state, ValidatorV7State::BondedPending | ValidatorV7State::Active | ValidatorV7State::Jailed) {
            return Err(ExecError::ProgramError("validator is not in a revocable state".into()));
        }
        let escrow_bal = accounts.get(&escrow_pk).map(|a| a.balance).unwrap_or(0);
        if escrow_bal < VALIDATOR_BOND_ATOMS {
            return Err(ExecError::ProgramError("bond escrow underfunded (invariant violation)".into()));
        }
        { let a = accounts.get_mut(&escrow_pk).unwrap(); a.balance = crate::arith::sub_u64(a.balance, VALIDATOR_BOND_ATOMS)?; }
        credit(accounts, &unbonding_pk, STAKING_PROGRAM_ID, VALIDATOR_BOND_ATOMS)?;
        let q = current_quanto(accounts);
        {
            let e = &mut reg.validators[vidx];
            e.state = ValidatorV7State::Revoked;
            e.exit_requested_quanto = q;
            e.bond_release_quanto = q.saturating_add(VALIDATOR_BOND_UNBONDING_QUANTOS.max(SLASH_EVIDENCE_WINDOW_QUANTOS));
        }
        write_registry(accounts, &reg)?;
        // (KM#5) A revoked validator is terminal; any pending timelocked cold-key
        // change for it is moot (and must never apply post-revoke) — drop it.
        let mut tl = read_key_timelock_registry(accounts);
        if tl.find(&consensus_address, KeyChangeKind::Operator).is_some()
            || tl.find(&consensus_address, KeyChangeKind::Withdrawal).is_some()
            || tl.find(&consensus_address, KeyChangeKind::RecoveryCommittee).is_some()
        {
            tl.purge(&consensus_address);
            write_key_timelock_registry(accounts, &tl)?;
        }
        // Bump the recovery nonce so this collected authorization can't be replayed.
        rec.entries[ridx].nonce = nonce.saturating_add(1);
        write_recovery_registry(accounts, &rec)?;
        Ok(())
    }

    fn unjail(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, consensus_address: Pubkey) -> Result<(), ExecError> {
        let registry_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("Unjail requires accounts[1]".into()))?;
        if registry_pk != VALIDATOR_REGISTRY_ACCOUNT_ID {
            return Err(ExecError::Unauthorized("Unjail must name the canonical registry account".into()));
        }
        let mut reg = read_registry(accounts);
        let idx = reg.find(&consensus_address).ok_or_else(|| ExecError::ProgramError("not a registered validator".into()))?;
        // Only the cold OPERATOR key may un-jail its own validator.
        if reg.validators[idx].operator_address != *payer {
            return Err(ExecError::Unauthorized("only the validator's operator (cold) key can un-jail it".into()));
        }
        if reg.validators[idx].state != ValidatorV7State::Jailed {
            return Err(ExecError::ProgramError("validator is not jailed".into()));
        }
        let e = &mut reg.validators[idx];
        e.state = ValidatorV7State::Active;
        // Reset participation so the fresh Active window isn't judged on the
        // blackout that jailed it (a clean slate; `participation_bps()` reads
        // full until the node scores the next quanto).
        e.participation_credits = 0;
        e.participation_opportunities = 0;
        write_registry(accounts, &reg)?;
        Ok(())
    }

    /// (#20) Shared gate for the operator-authorized key-role instructions: pin the
    /// canonical registry account, read it, find `consensus_address`, and require
    /// the payer to be its cold OPERATOR. Returns the decoded registry + the found
    /// index for the caller to mutate.
    fn require_operator(
        accounts: &HashMap<Pubkey, Account>,
        ix: &Instruction,
        payer: &Pubkey,
        consensus_address: &Pubkey,
        op: &str,
    ) -> Result<(ValidatorV7Registry, usize), ExecError> {
        let registry_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError(format!("{op} requires accounts[1]")))?;
        if registry_pk != VALIDATOR_REGISTRY_ACCOUNT_ID {
            return Err(ExecError::Unauthorized(format!("{op} must name the canonical registry account")));
        }
        let reg = read_registry(accounts);
        let idx = reg.find(consensus_address).ok_or_else(|| ExecError::ProgramError("not a registered validator".into()))?;
        if matches!(reg.validators[idx].state, ValidatorV7State::Removed) {
            return Err(ExecError::ProgramError("validator has been removed".into()));
        }
        if reg.validators[idx].operator_address != *payer {
            return Err(ExecError::Unauthorized(format!("only the validator's operator (cold) key can {op}")));
        }
        Ok((reg, idx))
    }

    /// (#20/KM#5) PROPOSE handing off the cold OPERATOR role to `new_operator`
    /// (authorized by the CURRENT operator). KM#5: TIMELOCKED
    /// (`KEY_TIMELOCK_OPERATOR_QUANTOS` ≈ 24h) — recorded pending, applied later via
    /// `ApplyPendingKeyChange`, so a leaked operator key can't instantly lock out
    /// the owner. Validated upfront (no collision with another live validator).
    /// accounts = [operator(payer), REGISTRY, KEY_TIMELOCK_REGISTRY, STAKING_GLOBAL].
    fn rotate_operator(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, consensus_address: Pubkey, new_operator: Pubkey) -> Result<(), ExecError> {
        let (reg, _idx) = Self::require_operator(accounts, ix, payer, &consensus_address, "RotateOperator")?;
        // The new operator must not collide with ANY live validator's identity
        // (consensus/operator/withdrawal), except this validator's own slot.
        let in_use = reg.addresses_in_use(Some(&consensus_address));
        if in_use.contains(&new_operator) {
            return Err(ExecError::ProgramError("new operator address is already registered to another validator".into()));
        }
        Self::propose_key_change(accounts, ix, consensus_address, PendingKeyChange::Operator(new_operator))
    }

    /// (#20/KM#5) PROPOSE changing the cold WITHDRAWAL address (where the bond
    /// returns AND fee commissions accrue), authorized by the operator. KM#5:
    /// TIMELOCKED (`KEY_TIMELOCK_WITHDRAWAL_QUANTOS` ≈ 72h) — recorded pending,
    /// applied later via `ApplyPendingKeyChange`, so a leaked operator key can't
    /// instantly redirect the bond/earnings to itself. accounts = [operator(payer),
    /// REGISTRY, KEY_TIMELOCK_REGISTRY, STAKING_GLOBAL].
    fn rotate_withdrawal(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, consensus_address: Pubkey, new_withdrawal: Pubkey) -> Result<(), ExecError> {
        let (reg, _idx) = Self::require_operator(accounts, ix, payer, &consensus_address, "RotateWithdrawal")?;
        let in_use = reg.addresses_in_use(Some(&consensus_address));
        if in_use.contains(&new_withdrawal) {
            return Err(ExecError::ProgramError("new withdrawal address is already registered to another validator".into()));
        }
        Self::propose_key_change(accounts, ix, consensus_address, PendingKeyChange::Withdrawal(new_withdrawal))
    }

    fn rotate_consensus_key(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, consensus_address: Pubkey, new_bundle: PublicKeyBundle, new_p2p_address: String, new_pop: MultiSignature) -> Result<(), ExecError> {
        let global_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("RotateConsensusKey requires accounts[2]".into()))?;
        if global_pk != STAKING_GLOBAL_ID {
            return Err(ExecError::Unauthorized("RotateConsensusKey must name the canonical global account".into()));
        }
        if !(1..=128).contains(&new_p2p_address.len()) {
            return Err(ExecError::ProgramError("p2p address length out of range".into()));
        }
        let (mut reg, idx) = Self::require_operator(accounts, ix, payer, &consensus_address, "RotateConsensusKey")?;
        let new_addr = new_bundle.to_address();
        let old_addr = reg.validators[idx].address;
        if new_addr == old_addr {
            return Err(ExecError::ProgramError("new consensus key is identical to the current one".into()));
        }
        // The NEW consensus key must prove possession, bound to THIS validator's
        // operator/withdrawal/moniker (the same PoP the registration requires), so
        // nobody can rotate in a key they don't hold, nor replay a PoP elsewhere.
        let operator = reg.validators[idx].operator_address;
        let withdrawal = reg.validators[idx].withdrawal_address;
        let moniker = reg.validators[idx].moniker.clone();
        if !qchain_crypto::verify_domain(&new_bundle, qchain_crypto::domains::VALIDATOR_POP_V1, &pop_message(&operator, &withdrawal, &moniker), &new_pop) {
            return Err(ExecError::Unauthorized("new_pop does not prove possession of the new consensus key for this operator/withdrawal/moniker".into()));
        }
        // The new consensus address must not collide with another LIVE validator's
        // identity (its own slot is excepted via `except = old consensus address`).
        let in_use = reg.addresses_in_use(Some(&consensus_address));
        if in_use.contains(&new_addr) {
            return Err(ExecError::ProgramError("new consensus key is already registered to another validator".into()));
        }
        let q = current_quanto(accounts);
        let e = &mut reg.validators[idx];
        // Keep the OLD key slashable through the evidence window: an equivocation by
        // the rotated-out key (e.g. a leaked key still in the current epoch's fixed
        // committee) is still punished even though the live `address` is now new.
        e.retire_consensus_key(old_addr, q, SLASH_EVIDENCE_WINDOW_QUANTOS);
        e.address = new_addr;
        e.pubkey_bundle = new_bundle;
        e.p2p_address = new_p2p_address;
        // A fresh key clears any revocation/expiry that excluded the validator.
        e.consensus_key_revoked = false;
        e.consensus_key_expiry_quanto = 0;
        write_registry(accounts, &reg)?;
        Ok(())
    }

    fn revoke_consensus_key(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, consensus_address: Pubkey) -> Result<(), ExecError> {
        let global_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("RevokeConsensusKey requires accounts[2]".into()))?;
        if global_pk != STAKING_GLOBAL_ID {
            return Err(ExecError::Unauthorized("RevokeConsensusKey must name the canonical global account".into()));
        }
        let (mut reg, idx) = Self::require_operator(accounts, ix, payer, &consensus_address, "RevokeConsensusKey")?;
        reg.validators[idx].consensus_key_revoked = true;
        write_registry(accounts, &reg)?;
        Ok(())
    }

    fn set_consensus_key_expiry(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, consensus_address: Pubkey, expiry_quanto: u64) -> Result<(), ExecError> {
        let (mut reg, idx) = Self::require_operator(accounts, ix, payer, &consensus_address, "SetConsensusKeyExpiry")?;
        reg.validators[idx].consensus_key_expiry_quanto = expiry_quanto;
        write_registry(accounts, &reg)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn bond_and_register(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, moniker: String, bundle: PublicKeyBundle, p2p_address: String, withdrawal_address: Option<Pubkey>, consensus_pop: MultiSignature) -> Result<(), ExecError> {
        // accounts[0] is the OPERATOR (cold key, the payer that funds + controls).
        let operator = *ix.accounts.first().ok_or_else(|| ExecError::ProgramError("BondAndRegister requires accounts[0]".into()))?;
        let registry_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("BondAndRegister requires accounts[1]".into()))?;
        let escrow_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("BondAndRegister requires accounts[2]".into()))?;
        let global_pk = *ix.accounts.get(3).ok_or_else(|| ExecError::ProgramError("BondAndRegister requires accounts[3]".into()))?;
        if registry_pk != VALIDATOR_REGISTRY_ACCOUNT_ID || escrow_pk != VALIDATOR_BOND_ESCROW_ID || global_pk != STAKING_GLOBAL_ID {
            return Err(ExecError::Unauthorized("BondAndRegister must name the canonical registry/escrow/global accounts".into()));
        }
        if operator != *payer {
            return Err(ExecError::Unauthorized("the operator account must be the transaction payer".into()));
        }
        let norm = normalize_moniker(&moniker);
        if !moniker_is_valid(&norm) {
            return Err(ExecError::ProgramError("invalid moniker (3-32 chars, [a-z0-9_-], not reserved)".into()));
        }
        if !(1..=128).contains(&p2p_address.len()) {
            return Err(ExecError::ProgramError("p2p address length out of range".into()));
        }

        // ROLE SEPARATION: the CONSENSUS key (a distinct hot key) is proven via a
        // proof-of-possession binding it to this operator/withdrawal/moniker, so:
        // (1) an operator can register a consensus key it genuinely holds WITHOUT
        // that key being the payer (consensus ≠ funds), and (2) an attacker can't
        // register someone else's consensus key (they can't produce the PoP), nor
        // replay a PoP for a different operator/withdrawal. The consensus address
        // is derived from the bundle, NOT from the payer.
        let consensus_addr = bundle.to_address();
        let withdrawal = withdrawal_address.unwrap_or(*payer);
        if !qchain_crypto::verify_domain(&bundle, qchain_crypto::domains::VALIDATOR_POP_V1, &pop_message(payer, &withdrawal, &norm), &consensus_pop) {
            return Err(ExecError::Unauthorized("consensus_pop does not prove possession of the consensus key for this operator/withdrawal/moniker".into()));
        }

        let mut reg = read_registry(accounts);
        // Uniqueness is keyed on the CONSENSUS address (a consensus key backs at
        // most one live validator). One operator MAY run several validators.
        if let Some(idx) = reg.find(&consensus_addr) {
            if reg.validators[idx].state != ValidatorV7State::Removed {
                return Err(ExecError::ProgramError("this consensus key already has an active validator registration".into()));
            }
        }
        if reg.moniker_taken(&norm, Some(&consensus_addr)) {
            return Err(ExecError::ProgramError("moniker already taken".into()));
        }
        // Reject duplicate registrations of key/operator/withdrawal/identity: no
        // new validator may claim a consensus key, operator address, or withdrawal
        // address already bound by another LIVE validator (moniker uniqueness is
        // the identity check just above). Excludes a Removed slot with this same
        // consensus key being re-registered in place.
        let in_use = reg.addresses_in_use(Some(&consensus_addr));
        for (label, addr) in [("consensus key", &consensus_addr), ("operator", payer), ("withdrawal", &withdrawal)] {
            if in_use.contains(addr) {
                return Err(ExecError::ProgramError(format!("{label} address is already registered to another validator")));
            }
        }
        if reg.validators.len() >= MAX_V7_VALIDATORS && reg.find(&consensus_addr).is_none() {
            return Err(ExecError::ProgramError("validator registry is full".into()));
        }

        // Take EXACTLY the bond from the OPERATOR (payer) into escrow.
        let bal = accounts.get(&operator).ok_or(ExecError::AccountNotFound(operator))?.balance;
        if bal < VALIDATOR_BOND_ATOMS {
            return Err(ExecError::InsufficientFunds);
        }
        { let a = accounts.get_mut(&operator).unwrap(); a.balance = crate::arith::sub_u64(a.balance, VALIDATOR_BOND_ATOMS)?; }
        credit(accounts, &escrow_pk, STAKING_PROGRAM_ID, VALIDATOR_BOND_ATOMS)?;

        let q = current_quanto(accounts);
        let entry = ValidatorV7Entry {
            address: consensus_addr,
            operator_address: *payer,
            withdrawal_address: withdrawal,
            moniker: norm,
            pubkey_bundle: bundle,
            p2p_address,
            bond: VALIDATOR_BOND_ATOMS,
            state: ValidatorV7State::BondedPending,
            registered_quanto: q,
            activation_quanto: q.saturating_add(1),
            exit_requested_quanto: 0,
            bond_release_quanto: 0,
            participation_credits: 0,
            participation_opportunities: 0,
            // #20: a fresh registration starts with no forced expiry, not revoked,
            // and no retired keys.
            consensus_key_expiry_quanto: 0,
            consensus_key_revoked: false,
            retired_consensus_keys: Vec::new(),
        };
        match reg.find(&consensus_addr) {
            Some(idx) => reg.validators[idx] = entry, // re-register a Removed slot
            None => reg.validators.push(entry),
        }
        write_registry(accounts, &reg)?;
        Ok(())
    }

    fn begin_exit(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, consensus_address: Pubkey) -> Result<(), ExecError> {
        let registry_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("BeginExit requires accounts[1]".into()))?;
        let escrow_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("BeginExit requires accounts[2]".into()))?;
        let unbonding_pk = *ix.accounts.get(3).ok_or_else(|| ExecError::ProgramError("BeginExit requires accounts[3]".into()))?;
        let global_pk = *ix.accounts.get(4).ok_or_else(|| ExecError::ProgramError("BeginExit requires accounts[4]".into()))?;
        if registry_pk != VALIDATOR_REGISTRY_ACCOUNT_ID || escrow_pk != VALIDATOR_BOND_ESCROW_ID || unbonding_pk != VALIDATOR_UNBONDING_POOL_ID || global_pk != STAKING_GLOBAL_ID {
            return Err(ExecError::Unauthorized("BeginExit must name the canonical accounts".into()));
        }
        let mut reg = read_registry(accounts);
        let idx = reg.find(&consensus_address).ok_or_else(|| ExecError::ProgramError("not a registered validator".into()))?;
        // Only the cold OPERATOR key may exit — a leaked consensus key cannot.
        if reg.validators[idx].operator_address != *payer {
            return Err(ExecError::Unauthorized("only the validator's operator (cold) key can begin an exit".into()));
        }
        let state = reg.validators[idx].state;
        if !matches!(state, ValidatorV7State::BondedPending | ValidatorV7State::Active | ValidatorV7State::Jailed) {
            return Err(ExecError::ProgramError("validator is not in an exitable state".into()));
        }
        // Move the bond escrow → unbonding pool (still slashable through the window).
        let escrow_bal = accounts.get(&escrow_pk).map(|a| a.balance).unwrap_or(0);
        if escrow_bal < VALIDATOR_BOND_ATOMS {
            return Err(ExecError::ProgramError("bond escrow underfunded (invariant violation)".into()));
        }
        { let a = accounts.get_mut(&escrow_pk).unwrap(); a.balance = crate::arith::sub_u64(a.balance, VALIDATOR_BOND_ATOMS)?; }
        credit(accounts, &unbonding_pk, STAKING_PROGRAM_ID, VALIDATOR_BOND_ATOMS)?;

        let q = current_quanto(accounts);
        let e = &mut reg.validators[idx];
        e.state = ValidatorV7State::Unbonding;
        e.exit_requested_quanto = q;
        // Release only after BOTH the unbonding period and the evidence window
        // (take the max so the bond is never withdrawn while still slashable).
        e.bond_release_quanto = q.saturating_add(VALIDATOR_BOND_UNBONDING_QUANTOS.max(SLASH_EVIDENCE_WINDOW_QUANTOS));
        write_registry(accounts, &reg)?;
        Ok(())
    }

    fn withdraw_bond(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, payer: &Pubkey, consensus_address: Pubkey) -> Result<(), ExecError> {
        let registry_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("WithdrawBond requires accounts[1]".into()))?;
        let unbonding_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("WithdrawBond requires accounts[2]".into()))?;
        let global_pk = *ix.accounts.get(3).ok_or_else(|| ExecError::ProgramError("WithdrawBond requires accounts[3]".into()))?;
        let withdrawal_dest = *ix.accounts.get(4).ok_or_else(|| ExecError::ProgramError("WithdrawBond requires accounts[4] (the withdrawal destination)".into()))?;
        if registry_pk != VALIDATOR_REGISTRY_ACCOUNT_ID || unbonding_pk != VALIDATOR_UNBONDING_POOL_ID || global_pk != STAKING_GLOBAL_ID {
            return Err(ExecError::Unauthorized("WithdrawBond must name the canonical accounts".into()));
        }
        let mut reg = read_registry(accounts);
        let idx = reg.find(&consensus_address).ok_or_else(|| ExecError::ProgramError("not a registered validator".into()))?;
        let state = reg.validators[idx].state;
        if !matches!(state, ValidatorV7State::Unbonding | ValidatorV7State::Revoked) {
            return Err(ExecError::ProgramError("bond is not unbonding".into()));
        }
        // For a normal exit (`Unbonding`), only the cold OPERATOR key may withdraw —
        // a leaked consensus key cannot. For a RECOVERY REVOKE (`Revoked`), the
        // operator key may itself be lost/compromised, so withdrawal is
        // PERMISSIONLESS: the destination is FIXED to the recorded (cold) withdrawal
        // address, so even a stranger triggering it can only push the bond to that
        // address — never steal it. This makes the bond recoverable after the window
        // even when the operator key is gone (KM#4).
        if state == ValidatorV7State::Unbonding && reg.validators[idx].operator_address != *payer {
            return Err(ExecError::Unauthorized("only the validator's operator (cold) key can withdraw the bond".into()));
        }
        // The bond returns to the recorded WITHDRAWAL (cold) address, which must be
        // named in accounts[4] so the ledger persists the credit. This is what keeps
        // the funds out of the consensus key's reach even at withdrawal time.
        let dest = reg.validators[idx].withdrawal_address;
        if withdrawal_dest != dest {
            return Err(ExecError::Unauthorized("WithdrawBond accounts[4] must be the validator's recorded withdrawal address".into()));
        }
        let q = current_quanto(accounts);
        if q < reg.validators[idx].bond_release_quanto {
            return Err(ExecError::ProgramError(format!(
                "bond still unbonding until quanto {} (now {})",
                reg.validators[idx].bond_release_quanto, q
            )));
        }
        let pool_bal = accounts.get(&unbonding_pk).map(|a| a.balance).unwrap_or(0);
        if pool_bal < VALIDATOR_BOND_ATOMS {
            return Err(ExecError::ProgramError("validator unbonding pool underfunded (invariant violation)".into()));
        }
        { let a = accounts.get_mut(&unbonding_pk).unwrap(); a.balance = crate::arith::sub_u64(a.balance, VALIDATOR_BOND_ATOMS)?; }
        credit(accounts, &dest, Pubkey::system_program_id(), VALIDATOR_BOND_ATOMS)?;
        reg.validators[idx].state = ValidatorV7State::Removed;
        reg.validators[idx].bond = 0;
        write_registry(accounts, &reg)?;
        Ok(())
    }

    fn report_equivocation(accounts: &mut HashMap<Pubkey, Account>, ix: &Instruction, _payer: &Pubkey, evidence: EquivocationEvidence) -> Result<(), ExecError> {
        let registry_pk = *ix.accounts.get(1).ok_or_else(|| ExecError::ProgramError("ReportEquivocation requires accounts[1]".into()))?;
        let escrow_pk = *ix.accounts.get(2).ok_or_else(|| ExecError::ProgramError("ReportEquivocation requires accounts[2]".into()))?;
        let unbonding_pk = *ix.accounts.get(3).ok_or_else(|| ExecError::ProgramError("ReportEquivocation requires accounts[3]".into()))?;
        if registry_pk != VALIDATOR_REGISTRY_ACCOUNT_ID || escrow_pk != VALIDATOR_BOND_ESCROW_ID || unbonding_pk != VALIDATOR_UNBONDING_POOL_ID {
            return Err(ExecError::Unauthorized("ReportEquivocation must name the canonical accounts".into()));
        }
        // Verify the evidence exactly as the v6 slashing does: same (round,
        // author), distinct vertices, bundle matches the accused, both signatures
        // verify under the accused's own bundle.
        if evidence.vertex_a.round != evidence.vertex_b.round || evidence.vertex_a.author != evidence.vertex_b.author {
            return Err(ExecError::ProgramError("evidence must reference the same (round, author)".into()));
        }
        let author = evidence.vertex_a.author;
        if evidence.vertex_a.digest() == evidence.vertex_b.digest() {
            return Err(ExecError::ProgramError("evidence vertices are identical - not a conflict".into()));
        }
        if evidence.author_bundle.to_address() != author {
            return Err(ExecError::ProgramError("author_bundle does not match the accused validator's address".into()));
        }
        // #187 domain envelope: a real consensus vote/vertex is signed as
        // `VERTEX_VOTE_V1 ‖ digest` (via `sign_vertex_vote`), so the evidence
        // MUST be verified with `verify_vertex_vote`, exactly like the v6
        // slashing path (`staking.rs`). Using the bare `verify` here (as the
        // code did) would reject every REAL equivocation evidence produced by
        // consensus → a v7 equivocator would go unslashed. A raw (domain-less)
        // signature must NOT be accepted as vote evidence.
        if !qchain_crypto::verify_vertex_vote(&evidence.author_bundle, &evidence.vertex_a.digest(), &evidence.signature_a) {
            return Err(ExecError::ProgramError("evidence signature_a does not verify".into()));
        }
        if !qchain_crypto::verify_vertex_vote(&evidence.author_bundle, &evidence.vertex_b.digest(), &evidence.signature_b) {
            return Err(ExecError::ProgramError("evidence signature_b does not verify".into()));
        }

        let mut reg = read_registry(accounts);
        // #20: also slash a validator that ROTATED AWAY FROM this key, while the
        // old key is still within its evidence window (a leaked rotated-out key).
        let q = current_quanto(accounts);
        let idx = reg.find_slashable(&author, q).ok_or_else(|| ExecError::ProgramError("accused is not a registered validator".into()))?;
        let e = &reg.validators[idx];
        if matches!(e.state, ValidatorV7State::Slashed | ValidatorV7State::Removed) {
            return Err(ExecError::ProgramError("nothing to slash".into()));
        }
        // Burn the full bond from wherever it currently sits: the escrow (Active/
        // BondedPending/Jailed) or the unbonding pool (Exiting/Unbonding/Revoked —
        // a recovery-revoked validator's bond was moved to the unbonding pool, and
        // stays slashable there through the evidence window). Burning = the QCH
        // leaves circulation (real supply reduction).
        let from_escrow = !matches!(e.state, ValidatorV7State::Unbonding | ValidatorV7State::Revoked);
        let (pool_pk, bal) = if from_escrow {
            (escrow_pk, accounts.get(&escrow_pk).map(|a| a.balance).unwrap_or(0))
        } else {
            (unbonding_pk, accounts.get(&unbonding_pk).map(|a| a.balance).unwrap_or(0))
        };
        if bal < VALIDATOR_BOND_ATOMS {
            return Err(ExecError::ProgramError("nothing to slash".into()));
        }
        // burned: the full bond leaves circulation (slash for equivocation)
        { let a = accounts.get_mut(&pool_pk).unwrap(); a.balance = crate::arith::sub_u64(a.balance, VALIDATOR_BOND_ATOMS)?; }
        let e = &mut reg.validators[idx];
        e.state = ValidatorV7State::Slashed;
        e.bond = 0;
        write_registry(accounts, &reg)?;
        Ok(())
    }
}

/// Read the v7 validator registry from a working set. Public for the ledger's
/// role-rule check (a registered validator can't stake) and the node's peer
/// discovery / active-set derivation.
pub fn registry_of(accounts: &HashMap<Pubkey, Account>) -> ValidatorV7Registry {
    read_registry(accounts)
}

/// Whether `addr` is a currently-registered validator (any non-Removed state),
/// matching EITHER its consensus address OR its cold operator address — the ledger
/// uses this to reject a staking position from a validator's key (either role).
pub fn is_registered_validator(accounts: &HashMap<Pubkey, Account>, addr: &Pubkey) -> bool {
    read_registry(accounts)
        .validators
        .iter()
        .any(|v| v.state != ValidatorV7State::Removed && (&v.address == addr || &v.operator_address == addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_core::UNITS_PER_QCH;
    use qchain_crypto::Keypair;

    fn wallet(balance: u64, owner: Pubkey) -> Account {
        let mut a = Account::new_wallet(owner);
        a.balance = balance;
        a
    }
    fn ix(data: &ValidatorV7Instruction, accts: Vec<Pubkey>) -> Instruction {
        Instruction { program_id: STAKING_PROGRAM_ID, accounts: accts, data: borsh::to_vec(data).unwrap() }
    }
    fn set_quanto(accounts: &mut HashMap<Pubkey, Account>, q: u64) {
        let g = crate::staking_v7::GlobalStakingState { current_quanto: q, ..crate::staking_v7::GlobalStakingState::genesis() };
        let acct = accounts.entry(STAKING_GLOBAL_ID).or_insert_with(|| Account::new_wallet(STAKING_PROGRAM_ID));
        acct.data = borsh::to_vec(&g).unwrap();
    }

    /// Register with the SAME key as operator and consensus (the simple/backward-
    /// compatible case). The consensus key signs the PoP over (operator=self,
    /// withdrawal=self, moniker).
    fn register(accounts: &mut HashMap<Pubkey, Account>, kp: &Keypair, moniker: &str) -> Result<(), ExecError> {
        register_full(accounts, kp, kp, None, moniker)
    }

    /// Register with a distinct cold `operator` (the payer/funder) and a separate
    /// `consensus` (hot, block-signing) key, optionally routing to a cold
    /// `withdrawal` address. The consensus key produces the proof-of-possession.
    fn register_full(accounts: &mut HashMap<Pubkey, Account>, operator: &Keypair, consensus: &Keypair, withdrawal: Option<Pubkey>, moniker: &str) -> Result<(), ExecError> {
        let norm = normalize_moniker(moniker);
        let wd = withdrawal.unwrap_or(operator.pubkey());
        let pop = qchain_crypto::sign_domain(consensus, qchain_crypto::domains::VALIDATOR_POP_V1, &pop_message(&operator.pubkey(), &wd, &norm)).unwrap();
        let data = ValidatorV7Instruction::BondAndRegister {
            moniker: moniker.into(),
            pubkey_bundle: consensus.public_key_bundle(),
            p2p_address: "1.2.3.4:9000".into(),
            withdrawal_address: withdrawal,
            consensus_pop: pop,
        };
        ValidatorV7Program::execute(accounts, &ix(&data, vec![operator.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_BOND_ESCROW_ID, STAKING_GLOBAL_ID]), &operator.pubkey())
    }

    #[test]
    fn bond_is_exactly_500_and_funds_the_escrow() {
        let mut accounts = HashMap::new();
        let v = Keypair::generate().unwrap();
        accounts.insert(v.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register(&mut accounts, &v, "node-alpha").unwrap();
        assert_eq!(accounts.get(&v.pubkey()).unwrap().balance, 100 * UNITS_PER_QCH, "exactly 500 taken");
        assert_eq!(accounts.get(&VALIDATOR_BOND_ESCROW_ID).unwrap().balance, VALIDATOR_BOND_ATOMS);
        let reg = registry_of(&accounts);
        assert_eq!(reg.validators.len(), 1);
        assert_eq!(reg.validators[0].bond, VALIDATOR_BOND_ATOMS);
        assert_eq!(reg.validators[0].state, ValidatorV7State::BondedPending);
        assert_eq!(reg.validators[0].activation_quanto, 1, "activates next quanto");
        assert!(is_registered_validator(&accounts, &v.pubkey()));
    }

    #[test]
    fn insufficient_balance_and_double_register_and_moniker_rules() {
        let mut accounts = HashMap::new();
        let poor = Keypair::generate().unwrap();
        accounts.insert(poor.pubkey(), wallet(100 * UNITS_PER_QCH, Pubkey::system_program_id()));
        assert!(register(&mut accounts, &poor, "poor-node").is_err(), "< 500 QCH can't bond");

        let v = Keypair::generate().unwrap();
        accounts.insert(v.pubkey(), wallet(2000 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register(&mut accounts, &v, "good-node").unwrap();
        assert!(register(&mut accounts, &v, "good-node-2").is_err(), "can't register twice");

        // Invalid + reserved + taken monikers.
        let v2 = Keypair::generate().unwrap();
        accounts.insert(v2.pubkey(), wallet(2000 * UNITS_PER_QCH, Pubkey::system_program_id()));
        assert!(register(&mut accounts, &v2, "ab").is_err(), "too short");
        assert!(register(&mut accounts, &v2, "validator").is_err(), "reserved");
        assert!(register(&mut accounts, &v2, "good-node").is_err(), "moniker already taken");
        register(&mut accounts, &v2, "second-node").unwrap();
    }

    #[test]
    fn registering_a_consensus_key_without_a_valid_pop_is_rejected() {
        let mut accounts = HashMap::new();
        let operator = Keypair::generate().unwrap();
        let victim_consensus = Keypair::generate().unwrap();
        accounts.insert(operator.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        // Forge a PoP by signing with the OPERATOR key instead of the (victim's)
        // consensus key — it can't verify under the victim's bundle, so registering
        // a consensus key you don't hold (a front-run of someone's identity) fails.
        let norm = normalize_moniker("spoof");
        let forged = qchain_crypto::sign_domain(&operator, qchain_crypto::domains::VALIDATOR_POP_V1, &pop_message(&operator.pubkey(), &operator.pubkey(), &norm)).unwrap();
        let data = ValidatorV7Instruction::BondAndRegister {
            moniker: "spoof".into(),
            pubkey_bundle: victim_consensus.public_key_bundle(),
            p2p_address: "1.2.3.4:9000".into(),
            withdrawal_address: None,
            consensus_pop: forged,
        };
        let e = ValidatorV7Program::execute(&mut accounts, &ix(&data, vec![operator.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_BOND_ESCROW_ID, STAKING_GLOBAL_ID]), &operator.pubkey());
        assert!(e.is_err(), "registering a consensus key without a valid proof-of-possession is rejected");
        assert_eq!(accounts.get(&VALIDATOR_BOND_ESCROW_ID).map(|a| a.balance).unwrap_or(0), 0, "no bond taken on a rejected register");
    }

    #[test]
    fn exit_then_withdraw_after_the_window_returns_the_bond() {
        let mut accounts = HashMap::new();
        let v = Keypair::generate().unwrap();
        accounts.insert(v.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register(&mut accounts, &v, "exiting-node").unwrap();

        // Begin exit: bond moves escrow → unbonding pool.
        let exit = ValidatorV7Instruction::BeginExit { consensus_address: v.pubkey() };
        ValidatorV7Program::execute(&mut accounts, &ix(&exit, vec![v.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_BOND_ESCROW_ID, VALIDATOR_UNBONDING_POOL_ID, STAKING_GLOBAL_ID]), &v.pubkey()).unwrap();
        assert_eq!(accounts.get(&VALIDATOR_BOND_ESCROW_ID).unwrap().balance, 0);
        assert_eq!(accounts.get(&VALIDATOR_UNBONDING_POOL_ID).unwrap().balance, VALIDATOR_BOND_ATOMS);

        // Withdraw before the window → rejected. accounts[4] = withdrawal dest (self here).
        let wd = ValidatorV7Instruction::WithdrawBond { consensus_address: v.pubkey() };
        let early = ValidatorV7Program::execute(&mut accounts, &ix(&wd, vec![v.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_UNBONDING_POOL_ID, STAKING_GLOBAL_ID, v.pubkey()]), &v.pubkey());
        assert!(early.is_err(), "can't withdraw before the unbonding + evidence window");

        // Advance quantos past the release, then withdraw.
        set_quanto(&mut accounts, 10);
        let before = accounts.get(&v.pubkey()).unwrap().balance;
        ValidatorV7Program::execute(&mut accounts, &ix(&wd, vec![v.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_UNBONDING_POOL_ID, STAKING_GLOBAL_ID, v.pubkey()]), &v.pubkey()).unwrap();
        assert_eq!(accounts.get(&v.pubkey()).unwrap().balance, before + VALIDATOR_BOND_ATOMS, "bond returned");
        assert_eq!(registry_of(&accounts).validators[0].state, ValidatorV7State::Removed);
        assert!(!is_registered_validator(&accounts, &v.pubkey()));
    }

    // ─── KM#4: recovery committee + REVOKE ────────────────────────────────────

    fn recovery_of(accounts: &HashMap<Pubkey, Account>) -> RecoveryRegistry {
        read_recovery_registry(accounts)
    }
    /// PROPOSE setting the recovery committee of `consensus` (authorized by
    /// `operator`). KM#5: this only records a pending, timelocked change.
    fn set_recovery(accounts: &mut HashMap<Pubkey, Account>, operator: &Keypair, consensus: Pubkey, signers: &[Pubkey], threshold: u8) -> Result<(), ExecError> {
        let cfg = RecoveryConfig { signers: signers.to_vec(), threshold };
        let data = ValidatorV7Instruction::SetRecoveryCommittee { consensus_address: consensus, config: cfg };
        ValidatorV7Program::execute(accounts, &ix(&data, vec![operator.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, STAKING_GLOBAL_ID]), &operator.pubkey())
    }
    /// Apply a pending key change of `kind` (permissionless — any payer).
    fn apply_key_change(accounts: &mut HashMap<Pubkey, Account>, payer: &Keypair, consensus: Pubkey, kind: KeyChangeKind) -> Result<(), ExecError> {
        let data = ValidatorV7Instruction::ApplyPendingKeyChange { consensus_address: consensus, kind };
        ValidatorV7Program::execute(accounts, &ix(&data, vec![payer.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, VALIDATOR_RECOVERY_REGISTRY_ID, STAKING_GLOBAL_ID]), &payer.pubkey())
    }
    /// Propose + cross the recovery timelock window + apply, so the committee is
    /// ACTIVE — for tests that exercise the downstream revoke path. Advances the
    /// mock quanto to the ready point (leaves it there).
    fn set_recovery_now(accounts: &mut HashMap<Pubkey, Account>, operator: &Keypair, consensus: Pubkey, signers: &[Pubkey], threshold: u8) -> Result<(), ExecError> {
        set_recovery(accounts, operator, consensus, signers, threshold)?;
        let ready = current_quanto(accounts) + KEY_TIMELOCK_RECOVERY_QUANTOS;
        set_quanto(accounts, ready);
        let relayer = Keypair::generate().unwrap();
        apply_key_change(accounts, &relayer, consensus, KeyChangeKind::RecoveryCommittee)
    }
    /// One recovery signer's OFFLINE approval of a Revoke of `consensus` at `nonce`.
    fn approve(signer: &Keypair, consensus: Pubkey, nonce: u64) -> RecoveryApproval {
        let msg = recovery_message(&consensus, RecoveryOp::Revoke, nonce);
        let sig = qchain_crypto::sign_domain(signer, qchain_crypto::domains::RECOVERY_AUTH_V1, &msg).unwrap();
        RecoveryApproval { bundle: signer.public_key_bundle(), signature: sig }
    }
    fn revoke(accounts: &mut HashMap<Pubkey, Account>, relayer: &Keypair, consensus: Pubkey, approvals: Vec<RecoveryApproval>) -> Result<(), ExecError> {
        let data = ValidatorV7Instruction::RecoverRevoke { consensus_address: consensus, op: RecoveryOp::Revoke, approvals };
        ValidatorV7Program::execute(accounts, &ix(&data, vec![relayer.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_RECOVERY_REGISTRY_ID, VALIDATOR_BOND_ESCROW_ID, VALIDATOR_UNBONDING_POOL_ID, STAKING_GLOBAL_ID]), &relayer.pubkey())
    }

    #[test]
    fn recovery_config_validation_bounds_and_distinctness() {
        let s: Vec<Pubkey> = (0..5).map(|_| Keypair::generate().unwrap().pubkey()).collect();
        assert!(RecoveryConfig { signers: s.clone(), threshold: 3 }.validate().is_ok(), "valid 3-of-5");
        assert!(RecoveryConfig { signers: s.clone(), threshold: 0 }.validate().is_err(), "threshold 0 rejected");
        assert!(RecoveryConfig { signers: s.clone(), threshold: 6 }.validate().is_err(), "threshold > N rejected");
        assert!(RecoveryConfig { signers: vec![], threshold: 1 }.validate().is_err(), "empty signers rejected");
        let mut dup = s.clone();
        dup[1] = dup[0];
        assert!(RecoveryConfig { signers: dup, threshold: 2 }.validate().is_err(), "duplicate signers rejected");
        let too_many: Vec<Pubkey> = (0..MAX_RECOVERY_SIGNERS + 1).map(|_| Keypair::generate().unwrap().pubkey()).collect();
        assert!(RecoveryConfig { signers: too_many, threshold: 2 }.validate().is_err(), "over MAX_RECOVERY_SIGNERS rejected");
    }

    #[test]
    fn set_recovery_committee_is_operator_only_and_stored_in_the_separate_singleton() {
        let mut accounts = HashMap::new();
        let op = Keypair::generate().unwrap();
        let cons = Keypair::generate().unwrap();
        accounts.insert(op.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register_full(&mut accounts, &op, &cons, None, "rec-node").unwrap();
        // The validator registry format is UNCHANGED (recovery lives in its own account).
        let reg_bytes_before = accounts.get(&VALIDATOR_REGISTRY_ACCOUNT_ID).unwrap().data.clone();

        let signers: Vec<Pubkey> = (0..5).map(|_| Keypair::generate().unwrap().pubkey()).collect();
        // A NON-operator cannot propose the committee.
        let stranger = Keypair::generate().unwrap();
        assert!(set_recovery(&mut accounts, &stranger, cons.pubkey(), &signers, 3).is_err(), "only the operator can set recovery");
        // The operator PROPOSES a 3-of-5 committee → recorded pending (KM#5 timelock),
        // NOT yet in the recovery registry.
        set_recovery(&mut accounts, &op, cons.pubkey(), &signers, 3).unwrap();
        assert!(recovery_of(&accounts).entries.is_empty(), "committee is not active until the timelock elapses");
        assert_eq!(read_key_timelock_registry(&accounts).pending.len(), 1, "one pending recovery-committee change");
        // Applying before the ~7d window → rejected.
        let relayer = Keypair::generate().unwrap();
        assert!(apply_key_change(&mut accounts, &relayer, cons.pubkey(), KeyChangeKind::RecoveryCommittee).is_err(), "can't apply before the window");
        // Cross the window and apply (permissionless) → now stored in the recovery singleton.
        set_quanto(&mut accounts, KEY_TIMELOCK_RECOVERY_QUANTOS);
        apply_key_change(&mut accounts, &relayer, cons.pubkey(), KeyChangeKind::RecoveryCommittee).unwrap();
        let rec = recovery_of(&accounts);
        assert_eq!(rec.entries.len(), 1);
        assert_eq!(rec.entries[0].consensus_address, cons.pubkey());
        assert_eq!(rec.entries[0].config.threshold, 3);
        assert_eq!(rec.entries[0].nonce, 0);
        assert!(read_key_timelock_registry(&accounts).pending.is_empty(), "pending cleared after apply");
        // The validator registry bytes did NOT change (purely additive).
        assert_eq!(accounts.get(&VALIDATOR_REGISTRY_ACCOUNT_ID).unwrap().data, reg_bytes_before, "recovery config does not touch the validator registry");
        // Clearing: propose empty + apply removes the entry.
        set_recovery(&mut accounts, &op, cons.pubkey(), &[], 0).unwrap();
        set_quanto(&mut accounts, KEY_TIMELOCK_RECOVERY_QUANTOS * 2);
        apply_key_change(&mut accounts, &relayer, cons.pubkey(), KeyChangeKind::RecoveryCommittee).unwrap();
        assert!(recovery_of(&accounts).entries.is_empty(), "empty config clears the committee");
    }

    #[test]
    fn recover_revoke_requires_a_quorum_of_distinct_registered_signers() {
        let mut accounts = HashMap::new();
        let op = Keypair::generate().unwrap();
        let cons = Keypair::generate().unwrap();
        accounts.insert(op.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register_full(&mut accounts, &op, &cons, None, "revoke-node").unwrap();
        let signer_kps: Vec<Keypair> = (0..5).map(|_| Keypair::generate().unwrap()).collect();
        let signers: Vec<Pubkey> = signer_kps.iter().map(|k| k.pubkey()).collect();
        set_recovery_now(&mut accounts, &op, cons.pubkey(), &signers, 3).unwrap();
        let relayer = Keypair::generate().unwrap();
        accounts.insert(relayer.pubkey(), wallet(10 * UNITS_PER_QCH, Pubkey::system_program_id()));

        // < threshold (2 of 3 needed) → rejected, bond untouched.
        let two = vec![approve(&signer_kps[0], cons.pubkey(), 0), approve(&signer_kps[1], cons.pubkey(), 0)];
        assert!(revoke(&mut accounts, &relayer, cons.pubkey(), two).is_err(), "2 < threshold 3 rejected");
        assert_eq!(accounts.get(&VALIDATOR_BOND_ESCROW_ID).unwrap().balance, VALIDATOR_BOND_ATOMS, "bond untouched below quorum");
        assert_eq!(registry_of(&accounts).validators[0].state, ValidatorV7State::BondedPending);

        // A duplicate approval from the same signer counts ONCE; a NON-registered
        // signer's approval is IGNORED. So [s0, s0, stranger, s1] = only 2 distinct.
        let stranger = Keypair::generate().unwrap();
        let padded = vec![
            approve(&signer_kps[0], cons.pubkey(), 0),
            approve(&signer_kps[0], cons.pubkey(), 0),
            approve(&stranger, cons.pubkey(), 0),
            approve(&signer_kps[1], cons.pubkey(), 0),
        ];
        assert!(revoke(&mut accounts, &relayer, cons.pubkey(), padded).is_err(), "duplicates + non-members don't reach quorum");

        // Exactly threshold (3) DISTINCT registered signers → accepted.
        let three = vec![
            approve(&signer_kps[0], cons.pubkey(), 0),
            approve(&signer_kps[2], cons.pubkey(), 0),
            approve(&signer_kps[4], cons.pubkey(), 0),
        ];
        revoke(&mut accounts, &relayer, cons.pubkey(), three).unwrap();
        // Neutralized: state Revoked, bond → unbonding pool, nonce bumped.
        assert_eq!(registry_of(&accounts).validators[0].state, ValidatorV7State::Revoked);
        assert_eq!(accounts.get(&VALIDATOR_BOND_ESCROW_ID).unwrap().balance, 0);
        assert_eq!(accounts.get(&VALIDATOR_UNBONDING_POOL_ID).unwrap().balance, VALIDATOR_BOND_ATOMS);
        assert_eq!(recovery_of(&accounts).entries[0].nonce, 1, "recovery nonce bumped");

        // A REPLAYED authorization over the OLD nonce (0) is rejected — nonce moved.
        let replay = vec![
            approve(&signer_kps[0], cons.pubkey(), 0),
            approve(&signer_kps[2], cons.pubkey(), 0),
            approve(&signer_kps[4], cons.pubkey(), 0),
        ];
        assert!(revoke(&mut accounts, &relayer, cons.pubkey(), replay).is_err(), "replayed old-nonce authorization rejected");
    }

    #[test]
    fn a_revoked_validator_is_dropped_from_the_committee_bond_recoverable_and_still_slashable() {
        use qchain_core::Vertex;
        let mut accounts = HashMap::new();
        let op = Keypair::generate().unwrap();
        let cons = Keypair::generate().unwrap();
        let withdrawal = Keypair::generate().unwrap().pubkey();
        accounts.insert(op.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register_full(&mut accounts, &op, &cons, Some(withdrawal), "slash-node").unwrap();
        // Activate it (flip the committed state) so it would be in the committee.
        { let mut r = read_registry(&accounts); r.validators[0].state = ValidatorV7State::Active; write_registry(&mut accounts, &r).unwrap(); }
        assert_eq!(active_committee(&registry_of(&accounts), 1).len(), 1, "active before revoke");

        let signer_kps: Vec<Keypair> = (0..3).map(|_| Keypair::generate().unwrap()).collect();
        let signers: Vec<Pubkey> = signer_kps.iter().map(|k| k.pubkey()).collect();
        set_recovery_now(&mut accounts, &op, cons.pubkey(), &signers, 2).unwrap();
        let relayer = Keypair::generate().unwrap();
        accounts.insert(relayer.pubkey(), wallet(10 * UNITS_PER_QCH, Pubkey::system_program_id()));
        revoke(&mut accounts, &relayer, cons.pubkey(), vec![approve(&signer_kps[0], cons.pubkey(), 0), approve(&signer_kps[1], cons.pubkey(), 0)]).unwrap();

        // Dropped from the active committee (not Active).
        assert!(active_committee(&registry_of(&accounts), 1).is_empty(), "revoked validator is not in the committee");

        // Still slashable from the unbonding pool if it equivocated (compromised key).
        let mut accounts_slash = accounts.clone();
        let va = Vertex { round: 7, author: cons.pubkey(), batch_digests: vec![(0, [1u8; 32])], parents: vec![] };
        let vb = Vertex { round: 7, author: cons.pubkey(), batch_digests: vec![(0, [2u8; 32])], parents: vec![] };
        let sa = qchain_crypto::sign_vertex_vote(&cons, &va.digest()[..]).unwrap();
        let sb = qchain_crypto::sign_vertex_vote(&cons, &vb.digest()[..]).unwrap();
        let evidence = EquivocationEvidence { vertex_a: va, vertex_b: vb, signature_a: sa, signature_b: sb, author_bundle: cons.public_key_bundle() };
        let rep = ValidatorV7Instruction::ReportEquivocation { evidence: Box::new(evidence) };
        ValidatorV7Program::execute(&mut accounts_slash, &ix(&rep, vec![relayer.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_BOND_ESCROW_ID, VALIDATOR_UNBONDING_POOL_ID]), &relayer.pubkey()).unwrap();
        assert_eq!(accounts_slash.get(&VALIDATOR_UNBONDING_POOL_ID).unwrap().balance, 0, "revoked equivocator's bond burned from the unbonding pool");
        assert_eq!(registry_of(&accounts_slash).validators[0].state, ValidatorV7State::Slashed);

        // Or, no equivocation: the bond is withdrawable PERMISSIONLESSLY to the cold
        // withdrawal address after the window (operator key may be lost).
        set_quanto(&mut accounts, 20);
        let wd = ValidatorV7Instruction::WithdrawBond { consensus_address: cons.pubkey() };
        // A stranger (not the operator) can push it — but ONLY to the recorded cold address.
        let stranger = Keypair::generate().unwrap();
        accounts.insert(stranger.pubkey(), wallet(10 * UNITS_PER_QCH, Pubkey::system_program_id()));
        ValidatorV7Program::execute(&mut accounts, &ix(&wd, vec![stranger.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_UNBONDING_POOL_ID, STAKING_GLOBAL_ID, withdrawal]), &stranger.pubkey()).unwrap();
        assert_eq!(accounts.get(&withdrawal).unwrap().balance, VALIDATOR_BOND_ATOMS, "revoked bond recovered to the cold withdrawal address");
    }

    #[test]
    fn validator_v7_instruction_encoding_is_stable() {
        // Pin the borsh discriminants so a CLI/relayer encoder can't silently drift.
        let cons = Pubkey::new([9u8; 32]);
        let cases: [(ValidatorV7Instruction, u8); 6] = [
            (ValidatorV7Instruction::BeginExit { consensus_address: cons }, 1),
            (ValidatorV7Instruction::Unjail { consensus_address: cons }, 4),
            (ValidatorV7Instruction::SetRecoveryCommittee { consensus_address: cons, config: RecoveryConfig::default() }, 10),
            (ValidatorV7Instruction::RecoverRevoke { consensus_address: cons, op: RecoveryOp::Revoke, approvals: vec![] }, 11),
            (ValidatorV7Instruction::ApplyPendingKeyChange { consensus_address: cons, kind: KeyChangeKind::Operator }, 12),
            (ValidatorV7Instruction::CancelPendingKeyChange { consensus_address: cons, kind: KeyChangeKind::RecoveryCommittee }, 13),
        ];
        for (instr, disc) in cases {
            let bytes = borsh::to_vec(&instr).unwrap();
            assert_eq!(bytes[0], disc, "discriminant of {instr:?} must stay {disc}");
        }
        // RecoveryOp::Revoke is discriminant 0 (the op_tag in the signed message is 0x01, separate).
        assert_eq!(borsh::to_vec(&RecoveryOp::Revoke).unwrap(), vec![0u8]);
    }

    /// Role separation (the on-chain part of #193-B): a cold OPERATOR key registers
    /// a SEPARATE consensus key, routing bond + fees to a cold WITHDRAWAL address.
    /// The consensus (hot) key can neither begin an exit nor withdraw the bond, and
    /// the bond returns to the withdrawal address, not the consensus key.
    #[test]
    fn consensus_key_cannot_control_the_bond_only_the_cold_operator_can() {
        let mut accounts = HashMap::new();
        let operator = Keypair::generate().unwrap(); // cold key: funds + controls
        let consensus = Keypair::generate().unwrap(); // hot key: signs blocks only
        let withdrawal = Keypair::generate().unwrap().pubkey(); // cold: bond + fees land here
        accounts.insert(operator.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register_full(&mut accounts, &operator, &consensus, Some(withdrawal), "cold-node").unwrap();

        let reg = registry_of(&accounts);
        assert_eq!(reg.validators[0].address, consensus.pubkey(), "identity is the consensus key");
        assert_eq!(reg.validators[0].operator_address, operator.pubkey());
        assert_eq!(reg.validators[0].withdrawal_address, withdrawal);
        // The consensus key IS a registered validator identity; so is the operator.
        assert!(is_registered_validator(&accounts, &consensus.pubkey()));
        assert!(is_registered_validator(&accounts, &operator.pubkey()));

        // The CONSENSUS (hot) key cannot begin an exit — only the operator can.
        let exit = ValidatorV7Instruction::BeginExit { consensus_address: consensus.pubkey() };
        let by_hot = ValidatorV7Program::execute(&mut accounts, &ix(&exit, vec![consensus.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_BOND_ESCROW_ID, VALIDATOR_UNBONDING_POOL_ID, STAKING_GLOBAL_ID]), &consensus.pubkey());
        assert!(by_hot.is_err(), "a leaked consensus key must NOT be able to exit/withdraw the bond");
        assert_eq!(accounts.get(&VALIDATOR_BOND_ESCROW_ID).unwrap().balance, VALIDATOR_BOND_ATOMS, "bond untouched by the hot key");

        // The cold OPERATOR exits and withdraws → bond returns to the WITHDRAWAL address.
        ValidatorV7Program::execute(&mut accounts, &ix(&exit, vec![operator.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_BOND_ESCROW_ID, VALIDATOR_UNBONDING_POOL_ID, STAKING_GLOBAL_ID]), &operator.pubkey()).unwrap();
        set_quanto(&mut accounts, 10);
        // The withdrawal must name the recorded withdrawal address in accounts[4];
        // naming a different address (e.g. the operator) is rejected.
        let wd = ValidatorV7Instruction::WithdrawBond { consensus_address: consensus.pubkey() };
        let wrong_dest = ValidatorV7Program::execute(&mut accounts, &ix(&wd, vec![operator.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_UNBONDING_POOL_ID, STAKING_GLOBAL_ID, operator.pubkey()]), &operator.pubkey());
        assert!(wrong_dest.is_err(), "withdrawal must land at the recorded cold address, not an arbitrary one");
        ValidatorV7Program::execute(&mut accounts, &ix(&wd, vec![operator.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_UNBONDING_POOL_ID, STAKING_GLOBAL_ID, withdrawal]), &operator.pubkey()).unwrap();
        assert_eq!(accounts.get(&withdrawal).unwrap().balance, VALIDATOR_BOND_ATOMS, "bond landed at the cold withdrawal address");
    }

    #[test]
    fn equivocation_burns_the_full_bond() {
        use qchain_core::Vertex;
        let mut accounts = HashMap::new();
        let v = Keypair::generate().unwrap();
        accounts.insert(v.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register(&mut accounts, &v, "byzantine").unwrap();
        assert_eq!(accounts.get(&VALIDATOR_BOND_ESCROW_ID).unwrap().balance, VALIDATOR_BOND_ATOMS);

        // Two conflicting signed vertices for the same (round, author).
        let va = Vertex { round: 5, author: v.pubkey(), batch_digests: vec![(0, [1u8; 32])], parents: vec![] };
        let vb = Vertex { round: 5, author: v.pubkey(), batch_digests: vec![(0, [2u8; 32])], parents: vec![] };
        assert_ne!(va.digest(), vb.digest());
        // #187: sign the way REAL consensus does — domain-tagged
        // (`VERTEX_VOTE_V1 ‖ digest`), NOT a bare digest sign. This is exactly
        // the evidence a Byzantine validator's `VertexProposal` produces.
        let sig_a = qchain_crypto::sign_vertex_vote(&v, &va.digest()[..]).unwrap();
        let sig_b = qchain_crypto::sign_vertex_vote(&v, &vb.digest()[..]).unwrap();
        let evidence = EquivocationEvidence {
            vertex_a: va.clone(),
            vertex_b: vb.clone(),
            signature_a: sig_a,
            signature_b: sig_b,
            author_bundle: v.public_key_bundle(),
        };
        let data = ValidatorV7Instruction::ReportEquivocation { evidence: Box::new(evidence) };
        // Permissionless: a third party reports.
        let reporter = Keypair::generate().unwrap();
        ValidatorV7Program::execute(&mut accounts, &ix(&data, vec![reporter.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_BOND_ESCROW_ID, VALIDATOR_UNBONDING_POOL_ID]), &reporter.pubkey()).unwrap();
        assert_eq!(accounts.get(&VALIDATOR_BOND_ESCROW_ID).unwrap().balance, 0, "the full bond was burned");
        assert_eq!(registry_of(&accounts).validators[0].state, ValidatorV7State::Slashed);
    }

    /// #209 unification: the ACTIVE consensus committee is derived from the v7
    /// registry (the single canonical source). Only `Active`, activated, fully-
    /// bonded validators sit; `BondedPending`/`Jailed`/`Exiting` are excluded, and
    /// the order is deterministic by consensus address with equal weight.
    #[test]
    fn active_committee_is_the_bonded_active_set_from_the_registry() {
        use crate::validator_v7::{active_committee, ValidatorV7Entry};
        let mk = |addr: u8, state: ValidatorV7State, activation: u64, bond: u64| ValidatorV7Entry {
            address: Pubkey::new([addr; 32]),
            operator_address: Pubkey::new([addr; 32]),
            withdrawal_address: Pubkey::new([addr; 32]),
            moniker: format!("v{addr}"),
            pubkey_bundle: Keypair::generate().unwrap().public_key_bundle(),
            p2p_address: format!("10.0.0.{addr}:9000"),
            bond,
            state,
            registered_quanto: 0,
            activation_quanto: activation,
            exit_requested_quanto: 0,
            bond_release_quanto: 0,
            participation_credits: 0,
            participation_opportunities: 0,
            consensus_key_expiry_quanto: 0,
            consensus_key_revoked: false,
            retired_consensus_keys: Vec::new(),
        };
        let reg = ValidatorV7Registry {
            validators: vec![
                mk(3, ValidatorV7State::Active, 0, VALIDATOR_BOND_ATOMS),        // in
                mk(1, ValidatorV7State::Active, 0, VALIDATOR_BOND_ATOMS),        // in (sorts first)
                mk(2, ValidatorV7State::BondedPending, 0, VALIDATOR_BOND_ATOMS), // out: not active
                mk(4, ValidatorV7State::Active, 99, VALIDATOR_BOND_ATOMS),       // out at q=5: activation ahead
                mk(5, ValidatorV7State::Jailed, 0, VALIDATOR_BOND_ATOMS),        // out: jailed
                mk(6, ValidatorV7State::Active, 0, 1),                           // out: partial bond
            ],
        };
        let c = active_committee(&reg, 5);
        let addrs: Vec<u8> = c.iter().map(|m| m.address.0[0]).collect();
        assert_eq!(addrs, vec![1, 3], "only Active+activated+fully-bonded, ordered by address");
        assert!(c.iter().all(|m| m.bond == VALIDATOR_BOND_ATOMS), "equal weight");
        // At q=99 the ahead-activation validator (4) joins.
        let c2 = active_committee(&reg, 99);
        assert_eq!(c2.iter().map(|m| m.address.0[0]).collect::<Vec<_>>(), vec![1, 3, 4]);
    }

    /// #209: no two live validators may share a consensus key, operator address,
    /// or withdrawal address (moniker uniqueness was already enforced). A second
    /// registration reusing ANY of the three is rejected, and the bond isn't taken.
    #[test]
    fn duplicate_key_operator_or_withdrawal_is_rejected() {
        let mut accounts = HashMap::new();
        let op1 = Keypair::generate().unwrap();
        let op2 = Keypair::generate().unwrap();
        let shared_withdrawal = Keypair::generate().unwrap().pubkey();
        accounts.insert(op1.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        accounts.insert(op2.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register_full(&mut accounts, &op1, &op1, Some(shared_withdrawal), "node-one").unwrap();

        // op2 tries to reuse op1's withdrawal address → rejected, no bond taken.
        let before = accounts.get(&op2.pubkey()).unwrap().balance;
        let dup_wd = register_full(&mut accounts, &op2, &op2, Some(shared_withdrawal), "node-two");
        assert!(dup_wd.is_err(), "cannot reuse another validator's withdrawal address");
        assert_eq!(accounts.get(&op2.pubkey()).unwrap().balance, before, "no bond taken on rejection");

        // op2 tries to reuse op1's operator address as its OWN consensus key →
        // rejected (op1's operator == op1's consensus is already in use).
        let dup_op = register_full(&mut accounts, &op2, &op1, None, "node-three");
        assert!(dup_op.is_err(), "cannot reuse another validator's key/operator");

        // A genuinely fresh operator+key+withdrawal succeeds.
        register_full(&mut accounts, &op2, &op2, None, "node-two").unwrap();
        assert_eq!(registry_of(&accounts).validators.len(), 2);
    }

    /// #209: total inactivity over a quanto jails an Active validator (excluded
    /// from committee + fees), and the operator can un-jail it to re-enter.
    #[test]
    fn total_inactivity_jails_and_operator_can_unjail() {
        use crate::validator_v7::{active_committee, jail_inactive};
        let mut accounts = HashMap::new();
        let up = Keypair::generate().unwrap();
        let down = Keypair::generate().unwrap();
        accounts.insert(up.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        accounts.insert(down.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register(&mut accounts, &up, "up-node").unwrap();
        register(&mut accounts, &down, "down-node").unwrap();
        let mut reg = registry_of(&accounts);
        // Activate both (genesis path activates at close; here flip directly).
        for v in reg.validators.iter_mut() {
            v.state = ValidatorV7State::Active;
            v.activation_quanto = 0;
        }
        // Score a quanto: `up` had a committed cert every round, `down` none.
        for v in reg.validators.iter_mut() {
            if v.address == up.pubkey() {
                v.participation_credits = 10;
                v.participation_opportunities = 10;
            } else {
                v.participation_credits = 0;
                v.participation_opportunities = 10;
            }
        }
        assert!(jail_inactive(&mut reg), "the down validator is jailed");
        assert_eq!(reg.validators.iter().find(|v| v.address == down.pubkey()).unwrap().state, ValidatorV7State::Jailed);
        assert_eq!(reg.validators.iter().find(|v| v.address == up.pubkey()).unwrap().state, ValidatorV7State::Active, "the up validator stays active");
        // Committee excludes the jailed one.
        assert_eq!(active_committee(&reg, 0).iter().map(|m| m.address).collect::<Vec<_>>(), vec![up.pubkey()]);
        write_registry(&mut accounts, &reg).unwrap();

        // The DOWN validator's operator un-jails it; a non-operator cannot.
        let stranger = Keypair::generate().unwrap();
        let unjail = ValidatorV7Instruction::Unjail { consensus_address: down.pubkey() };
        let by_stranger = ValidatorV7Program::execute(&mut accounts, &ix(&unjail, vec![stranger.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID]), &stranger.pubkey());
        assert!(by_stranger.is_err(), "only the operator can un-jail");
        ValidatorV7Program::execute(&mut accounts, &ix(&unjail, vec![down.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID]), &down.pubkey()).unwrap();
        let after = registry_of(&accounts);
        let d = after.validators.iter().find(|v| v.address == down.pubkey()).unwrap();
        assert_eq!(d.state, ValidatorV7State::Active, "un-jailed back to Active");
        assert_eq!(d.participation_opportunities, 0, "participation reset on un-jail");
    }

    /// #187 regression (the exact bug an external audit flagged): a raw,
    /// DOMAIN-LESS signature (`sign` over the bare digest, not
    /// `sign_vertex_vote`) must NOT be accepted as equivocation evidence — the
    /// v7 slashing verifies with `verify_vertex_vote` just like v6, so a real
    /// domain-signed equivocation slashes (above) and a bare-digest forgery is
    /// rejected here (the bond is untouched).
    #[test]
    fn equivocation_with_undomained_signatures_is_rejected() {
        use qchain_core::Vertex;
        let mut accounts = HashMap::new();
        let v = Keypair::generate().unwrap();
        accounts.insert(v.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register(&mut accounts, &v, "byzantine").unwrap();
        let va = Vertex { round: 5, author: v.pubkey(), batch_digests: vec![(0, [1u8; 32])], parents: vec![] };
        let vb = Vertex { round: 5, author: v.pubkey(), batch_digests: vec![(0, [2u8; 32])], parents: vec![] };
        // RAW sign (no VERTEX_VOTE_V1 domain) — this is NOT how consensus signs.
        let sig_a = v.sign(&va.digest()[..]).unwrap();
        let sig_b = v.sign(&vb.digest()[..]).unwrap();
        let evidence = EquivocationEvidence { vertex_a: va, vertex_b: vb, signature_a: sig_a, signature_b: sig_b, author_bundle: v.public_key_bundle() };
        let data = ValidatorV7Instruction::ReportEquivocation { evidence: Box::new(evidence) };
        let reporter = Keypair::generate().unwrap();
        let r = ValidatorV7Program::execute(&mut accounts, &ix(&data, vec![reporter.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_BOND_ESCROW_ID, VALIDATOR_UNBONDING_POOL_ID]), &reporter.pubkey());
        assert!(r.is_err(), "a domain-less (raw) signature must not verify as vote evidence");
        assert_eq!(accounts.get(&VALIDATOR_BOND_ESCROW_ID).unwrap().balance, VALIDATOR_BOND_ATOMS, "the bond must be untouched when the evidence is rejected");
        assert_eq!(registry_of(&accounts).validators[0].state, ValidatorV7State::BondedPending, "state unchanged");
    }

    /// Pre-mainnet #1: a legacy (pre-role-separation V1) validator registry is
    /// MIGRATED forward by `decode_registry` — operator = withdrawal = the
    /// consensus address, every other field carried over — and a genuinely-
    /// unrecognizable one returns `None` so the caller can fail loud instead of
    /// silently using an empty registry (which would drop to the genesis
    /// committee and can diverge a multi-validator network).
    #[test]
    fn decode_registry_migrates_a_legacy_v1_registry_and_rejects_garbage() {
        let v = Keypair::generate().unwrap();
        let addr = v.pubkey();
        let v1 = ValidatorV7RegistryV1 {
            validators: vec![ValidatorV7EntryV1 {
                address: addr,
                moniker: "legacy".to_string(),
                pubkey_bundle: v.public_key_bundle(),
                p2p_address: "1.2.3.4:9000".to_string(),
                bond: VALIDATOR_BOND_ATOMS,
                state: ValidatorV7State::Active,
                registered_quanto: 3,
                activation_quanto: 4,
                exit_requested_quanto: 0,
                bond_release_quanto: 0,
                participation_credits: 7,
                participation_opportunities: 9,
            }],
        };
        let bytes = borsh::to_vec(&v1).unwrap();
        // A real (non-empty) V1 registry must NOT clean-decode as the current V3
        // layout — a V3 entry carries the cold-key + #20 fields, so it runs out of
        // bytes (EOF) reading them.
        assert!(
            ValidatorV7Registry::try_from_slice(&bytes).is_err(),
            "a non-empty V1 registry must not decode as V3"
        );
        // ...but `decode_registry` migrates it forward.
        let migrated = decode_registry(&bytes).expect("a legacy V1 registry migrates, never None");
        assert_eq!(migrated.validators.len(), 1);
        let e = &migrated.validators[0];
        assert_eq!(e.address, addr);
        assert_eq!(e.operator_address, addr, "pre-#193-B: operator == consensus address");
        assert_eq!(e.withdrawal_address, addr, "pre-#193-B: withdrawal == consensus address");
        assert_eq!(e.moniker, "legacy");
        assert_eq!(e.bond, VALIDATOR_BOND_ATOMS);
        assert_eq!(e.state, ValidatorV7State::Active);
        assert_eq!(e.registered_quanto, 3);
        assert_eq!(e.activation_quanto, 4);
        assert_eq!(e.participation_credits, 7);
        assert_eq!(e.participation_opportunities, 9);
        // #20 defaults on migration: no forced expiry, not revoked, no retired keys.
        assert_eq!(e.consensus_key_expiry_quanto, 0);
        assert!(!e.consensus_key_revoked);
        assert!(e.retired_consensus_keys.is_empty());
        // The migrated registry round-trips as the current V3 format.
        let v3_bytes = borsh::to_vec(&migrated).unwrap();
        assert_eq!(decode_registry(&v3_bytes).unwrap().validators.len(), 1);
        // A current empty registry decodes directly (no migration path).
        assert!(decode_registry(&borsh::to_vec(&ValidatorV7Registry::default()).unwrap()).is_some());
        // Genuinely-corrupt bytes → None: the caller halts, never uses empty.
        assert!(decode_registry(&[0xFFu8; 7]).is_none(), "garbage must be rejected, not silently emptied");
    }

    /// The offline persistent-migration primitives (pre-mainnet #3): explicit
    /// schema detection, and a pure migration plan that `qchain-migrate-registry`
    /// previews (`--dry-run`) and applies identically — V1 -> byte-exact V2,
    /// idempotent, corrupt refused.
    #[test]
    fn registry_migration_plan_is_explicit_lossless_and_idempotent() {
        let v = Keypair::generate().unwrap();
        let addr = v.pubkey();

        // A legacy V1 registry: schema detected as V1, plan says "Migrated".
        let v1_bytes = legacy_v1_registry_bytes(addr, "legacy", v.public_key_bundle(), "1.2.3.4:9000");
        assert_eq!(detect_registry_schema(&v1_bytes), Some(RegistrySchema::V1Legacy));
        assert_eq!(RegistrySchema::V1Legacy.version(), 1);
        let new_bytes = match plan_registry_migration(&v1_bytes) {
            RegistryMigration::Migrated { validators, new_bytes } => {
                assert_eq!(validators, 1);
                new_bytes
            }
            _ => panic!("a V1 registry must plan as Migrated"),
        };
        // The persisted bytes are the exact V3 form the running node reads: they
        // detect as V3, decode losslessly, and match `decode_registry` of the V1.
        assert_eq!(detect_registry_schema(&new_bytes), Some(RegistrySchema::V3Current));
        assert_eq!(RegistrySchema::V3Current.version(), 3);
        let migrated = ValidatorV7Registry::try_from_slice(&new_bytes).expect("new bytes are valid V3");
        assert_eq!(encode_registry(&decode_registry(&v1_bytes).unwrap()), new_bytes, "persist == decode_registry's V3");
        assert_eq!(migrated.validators[0].operator_address, addr);
        assert_eq!(migrated.validators[0].withdrawal_address, addr);

        // Idempotent: re-planning the migrated V3 bytes is a no-op.
        match plan_registry_migration(&new_bytes) {
            RegistryMigration::AlreadyCurrent { validators } => assert_eq!(validators, 1),
            _ => panic!("re-migrating V3 must be AlreadyCurrent (no-op)"),
        }

        // An empty V3 registry is AlreadyCurrent (0 validators), not V1.
        let empty = encode_registry(&ValidatorV7Registry::default());
        assert_eq!(detect_registry_schema(&empty), Some(RegistrySchema::V3Current));
        assert!(matches!(plan_registry_migration(&empty), RegistryMigration::AlreadyCurrent { validators: 0 }));

        // Genuinely corrupt bytes: no schema, plan refuses (Corrupt).
        assert_eq!(detect_registry_schema(&[0xFFu8; 9]), None);
        assert!(matches!(plan_registry_migration(&[0xFFu8; 9]), RegistryMigration::Corrupt));
    }

    /// #20: a prior (V2, pre-#20) registry migrates to V3 on read with the #20
    /// fields DEFAULTED (byte-identical behavior), and the schema/plan report V2
    /// as a migratable prior. A V3 registry round-trips; a V2 one doesn't
    /// cross-decode as V3.
    #[test]
    fn a_pre20_v2_registry_migrates_to_v3_with_defaulted_key_role_fields() {
        let v = Keypair::generate().unwrap();
        let (op, wd) = (Pubkey::new([9u8; 32]), Pubkey::new([8u8; 32]));
        // Build a genuine V2 (pre-#20) registry via the crate-internal mirror.
        let v2 = ValidatorV7RegistryV2 {
            validators: vec![ValidatorV7EntryV2 {
                address: v.pubkey(),
                operator_address: op,
                withdrawal_address: wd,
                moniker: "prior".to_string(),
                pubkey_bundle: v.public_key_bundle(),
                p2p_address: "1.2.3.4:9000".to_string(),
                bond: VALIDATOR_BOND_ATOMS,
                state: ValidatorV7State::Active,
                registered_quanto: 2,
                activation_quanto: 3,
                exit_requested_quanto: 0,
                bond_release_quanto: 0,
                participation_credits: 5,
                participation_opportunities: 5,
            }],
        };
        let bytes = borsh::to_vec(&v2).unwrap();
        assert_eq!(detect_registry_schema(&bytes), Some(RegistrySchema::V2Prior));
        assert_eq!(RegistrySchema::V2Prior.version(), 2);
        // A V2 registry must NOT clean-decode as the current V3 (fewer bytes → EOF).
        assert!(ValidatorV7Registry::try_from_slice(&bytes).is_err(), "V2 must not decode as V3");
        let migrated = decode_registry(&bytes).expect("V2 migrates, never None");
        let e = &migrated.validators[0];
        assert_eq!(e.operator_address, op, "cold operator preserved");
        assert_eq!(e.withdrawal_address, wd, "cold withdrawal preserved");
        assert_eq!(e.participation_credits, 5);
        // #20 defaults applied → behavior-identical (never disabled).
        assert_eq!(e.consensus_key_expiry_quanto, 0);
        assert!(!e.consensus_key_revoked);
        assert!(e.retired_consensus_keys.is_empty());
        assert!(!e.consensus_key_disabled(1_000_000), "a migrated V2 entry is never disabled");
        // plan_registry_migration classifies V2 as Migrated; re-planning the V3 is a no-op.
        let new_bytes = match plan_registry_migration(&bytes) {
            RegistryMigration::Migrated { validators, new_bytes } => { assert_eq!(validators, 1); new_bytes }
            _ => panic!("a V2 registry must plan as Migrated"),
        };
        assert_eq!(detect_registry_schema(&new_bytes), Some(RegistrySchema::V3Current));
        assert!(matches!(plan_registry_migration(&new_bytes), RegistryMigration::AlreadyCurrent { validators: 1 }));
    }

    /// #20/KM#5: the cold OPERATOR PROPOSES rotating the operator + withdrawal keys
    /// (keeping the bond/activation); a non-operator is rejected; a collision is
    /// rejected. KM#5: the change is TIMELOCKED — proposed now, applied only after
    /// its window (operator ≈24h/1q, withdrawal ≈72h/3q) via a permissionless
    /// `ApplyPendingKeyChange`. Apply-before-the-window is rejected; the operator can
    /// CANCEL a pending change.
    #[test]
    fn cold_key_rotation_is_timelocked_operator_authorized_and_collision_checked() {
        let mut accounts = HashMap::new();
        let op = Keypair::generate().unwrap();
        let consensus = Keypair::generate().unwrap();
        accounts.insert(op.pubkey(), wallet(2000 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register_full(&mut accounts, &op, &consensus, None, "node-x").unwrap();
        let caddr = consensus.pubkey();
        let bond_before = registry_of(&accounts).validators[0].bond;
        let anyone = Keypair::generate().unwrap();
        // Propose helpers with the KM#5 account layout [operator, REGISTRY, KEY_TIMELOCK, GLOBAL].
        let propose_wd = |new_wd: Pubkey| ix(&ValidatorV7Instruction::RotateWithdrawal { consensus_address: caddr, new_withdrawal: new_wd }, vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, STAKING_GLOBAL_ID]);
        let apply = |kind: KeyChangeKind| ix(&ValidatorV7Instruction::ApplyPendingKeyChange { consensus_address: caddr, kind }, vec![anyone.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, VALIDATOR_RECOVERY_REGISTRY_ID, STAKING_GLOBAL_ID]);

        // A NON-operator can't propose a withdrawal rotation.
        let stranger = Keypair::generate().unwrap();
        let bad = ix(&ValidatorV7Instruction::RotateWithdrawal { consensus_address: caddr, new_withdrawal: stranger.pubkey() }, vec![stranger.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, STAKING_GLOBAL_ID]);
        assert!(ValidatorV7Program::execute(&mut accounts, &bad, &stranger.pubkey()).is_err(), "non-operator rejected");

        // The operator PROPOSES a withdrawal rotation → recorded pending, NOT applied.
        let new_wd = Pubkey::new([77u8; 32]);
        ValidatorV7Program::execute(&mut accounts, &propose_wd(new_wd), &op.pubkey()).unwrap();
        assert_ne!(registry_of(&accounts).validators[0].withdrawal_address, new_wd, "not applied at propose");
        // Apply BEFORE the ~72h window → rejected.
        assert!(ValidatorV7Program::execute(&mut accounts, &apply(KeyChangeKind::Withdrawal), &anyone.pubkey()).is_err(), "can't apply before the window");
        // Cross the withdrawal window (3 quantos) and apply (permissionless).
        set_quanto(&mut accounts, KEY_TIMELOCK_WITHDRAWAL_QUANTOS);
        ValidatorV7Program::execute(&mut accounts, &apply(KeyChangeKind::Withdrawal), &anyone.pubkey()).unwrap();
        assert_eq!(registry_of(&accounts).validators[0].withdrawal_address, new_wd);
        assert_eq!(registry_of(&accounts).validators[0].bond, bond_before, "bond untouched by rotation");

        // The operator can CANCEL a pending change before it applies.
        ValidatorV7Program::execute(&mut accounts, &propose_wd(Pubkey::new([88u8; 32])), &op.pubkey()).unwrap();
        let cancel = ix(&ValidatorV7Instruction::CancelPendingKeyChange { consensus_address: caddr, kind: KeyChangeKind::Withdrawal }, vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID]);
        ValidatorV7Program::execute(&mut accounts, &cancel, &op.pubkey()).unwrap();
        assert!(read_key_timelock_registry(&accounts).find(&caddr, KeyChangeKind::Withdrawal).is_none(), "cancelled");
        set_quanto(&mut accounts, KEY_TIMELOCK_WITHDRAWAL_QUANTOS * 3);
        assert!(ValidatorV7Program::execute(&mut accounts, &apply(KeyChangeKind::Withdrawal), &anyone.pubkey()).is_err(), "nothing to apply after cancel");
        assert_eq!(registry_of(&accounts).validators[0].withdrawal_address, new_wd, "cancelled change never took effect");

        // The operator rotates the OPERATOR key (window 1 quanto); old operator then can't act.
        let now = current_quanto(&accounts);
        let new_op = Keypair::generate().unwrap();
        let prop_op = ix(&ValidatorV7Instruction::RotateOperator { consensus_address: caddr, new_operator: new_op.pubkey() }, vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, STAKING_GLOBAL_ID]);
        ValidatorV7Program::execute(&mut accounts, &prop_op, &op.pubkey()).unwrap();
        set_quanto(&mut accounts, now + KEY_TIMELOCK_OPERATOR_QUANTOS);
        ValidatorV7Program::execute(&mut accounts, &apply(KeyChangeKind::Operator), &anyone.pubkey()).unwrap();
        assert_eq!(registry_of(&accounts).validators[0].operator_address, new_op.pubkey());
        // Old operator now unauthorized to propose; new operator authorized.
        let by_old = ix(&ValidatorV7Instruction::RotateWithdrawal { consensus_address: caddr, new_withdrawal: Pubkey::new([1u8; 32]) }, vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, STAKING_GLOBAL_ID]);
        assert!(ValidatorV7Program::execute(&mut accounts, &by_old, &op.pubkey()).is_err(), "rotated-out operator can't act");
        let by_new = ix(&ValidatorV7Instruction::RotateWithdrawal { consensus_address: caddr, new_withdrawal: Pubkey::new([2u8; 32]) }, vec![new_op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, STAKING_GLOBAL_ID]);
        ValidatorV7Program::execute(&mut accounts, &by_new, &new_op.pubkey()).unwrap();
    }

    /// KM#5: the three cold-key timelock windows are exactly operator ≈24h (1
    /// quanto), withdrawal ≈72h (3 quantos), recovery ≈7d (7 quantos), computed from
    /// the current quanto; re-proposing the same kind RESETS the clock.
    #[test]
    fn key_timelock_windows_are_operator_24h_withdrawal_72h_recovery_7d() {
        let mut accounts = HashMap::new();
        let op = Keypair::generate().unwrap();
        let cons = Keypair::generate().unwrap();
        accounts.insert(op.pubkey(), wallet(2000 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register_full(&mut accounts, &op, &cons, None, "win-node").unwrap();
        let c = cons.pubkey();
        set_quanto(&mut accounts, 100);
        let tl_accts = || vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, STAKING_GLOBAL_ID];
        let rot_op = ValidatorV7Instruction::RotateOperator { consensus_address: c, new_operator: Pubkey::new([70u8; 32]) };
        ValidatorV7Program::execute(&mut accounts, &ix(&rot_op, tl_accts()), &op.pubkey()).unwrap();
        let rot_wd = ValidatorV7Instruction::RotateWithdrawal { consensus_address: c, new_withdrawal: Pubkey::new([71u8; 32]) };
        ValidatorV7Program::execute(&mut accounts, &ix(&rot_wd, tl_accts()), &op.pubkey()).unwrap();
        let signers: Vec<Pubkey> = (0..3).map(|_| Keypair::generate().unwrap().pubkey()).collect();
        let set_rec = ValidatorV7Instruction::SetRecoveryCommittee { consensus_address: c, config: RecoveryConfig { signers, threshold: 2 } };
        ValidatorV7Program::execute(&mut accounts, &ix(&set_rec, tl_accts()), &op.pubkey()).unwrap();

        let ready = |accts: &HashMap<Pubkey, Account>, k: KeyChangeKind| {
            read_key_timelock_registry(accts).pending.iter().find(|p| p.change.kind() == k).unwrap().ready_quanto
        };
        assert_eq!(ready(&accounts, KeyChangeKind::Operator), 101, "operator ≈24h = +1 quanto");
        assert_eq!(ready(&accounts, KeyChangeKind::Withdrawal), 103, "withdrawal ≈72h = +3 quantos");
        assert_eq!(ready(&accounts, KeyChangeKind::RecoveryCommittee), 107, "recovery ≈7d = +7 quantos");
        assert_eq!(read_key_timelock_registry(&accounts).pending.len(), 3, "one pending per kind");

        // Re-proposing the operator change at a later quanto REPLACES it (one entry)
        // and resets the clock.
        set_quanto(&mut accounts, 200);
        let rot_op2 = ValidatorV7Instruction::RotateOperator { consensus_address: c, new_operator: Pubkey::new([72u8; 32]) };
        ValidatorV7Program::execute(&mut accounts, &ix(&rot_op2, tl_accts()), &op.pubkey()).unwrap();
        assert_eq!(read_key_timelock_registry(&accounts).pending.iter().filter(|p| p.change.kind() == KeyChangeKind::Operator).count(), 1, "still one pending operator change (replaced)");
        assert_eq!(ready(&accounts, KeyChangeKind::Operator), 201, "re-propose reset the clock");
    }

    /// KM#5: a recovery-committee REVOKE (KM#4) drops any pending timelocked cold-key
    /// change of the validator — an attacker who proposed (e.g.) a withdrawal
    /// rotation to itself can be neutralized within the window, and the pending
    /// change never applies.
    #[test]
    fn a_pending_key_change_is_dropped_when_the_validator_is_revoked() {
        let mut accounts = HashMap::new();
        let op = Keypair::generate().unwrap();
        let cons = Keypair::generate().unwrap();
        let orig_wd = Keypair::generate().unwrap().pubkey();
        accounts.insert(op.pubkey(), wallet(600 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register_full(&mut accounts, &op, &cons, Some(orig_wd), "purge-node").unwrap();
        let c = cons.pubkey();

        // Recovery committee is configured IN ADVANCE (before any compromise).
        let signer_kps: Vec<Keypair> = (0..3).map(|_| Keypair::generate().unwrap()).collect();
        let signers: Vec<Pubkey> = signer_kps.iter().map(|k| k.pubkey()).collect();
        set_recovery_now(&mut accounts, &op, c, &signers, 2).unwrap(); // quanto now 7

        // The (compromised) operator proposes redirecting the withdrawal to an attacker.
        let attacker = Pubkey::new([0xAA; 32]);
        let prop = ix(&ValidatorV7Instruction::RotateWithdrawal { consensus_address: c, new_withdrawal: attacker }, vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, STAKING_GLOBAL_ID]);
        ValidatorV7Program::execute(&mut accounts, &prop, &op.pubkey()).unwrap();
        assert!(read_key_timelock_registry(&accounts).find(&c, KeyChangeKind::Withdrawal).is_some(), "attacker change is pending");

        // WITHIN the window, the recovery committee REVOKES the validator.
        let relayer = Keypair::generate().unwrap();
        revoke(&mut accounts, &relayer, c, vec![approve(&signer_kps[0], c, 0), approve(&signer_kps[1], c, 0)]).unwrap();
        assert_eq!(registry_of(&accounts).validators[0].state, ValidatorV7State::Revoked);
        // The pending attacker change was PURGED by the revoke.
        assert!(read_key_timelock_registry(&accounts).find(&c, KeyChangeKind::Withdrawal).is_none(), "pending change purged on revoke");

        // Even past the window, there is nothing to apply, and the withdrawal address
        // is unchanged — the attacker's change never took effect.
        set_quanto(&mut accounts, 100);
        let apply = ix(&ValidatorV7Instruction::ApplyPendingKeyChange { consensus_address: c, kind: KeyChangeKind::Withdrawal }, vec![relayer.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_KEY_TIMELOCK_REGISTRY_ID, VALIDATOR_RECOVERY_REGISTRY_ID, STAKING_GLOBAL_ID]);
        assert!(ValidatorV7Program::execute(&mut accounts, &apply, &relayer.pubkey()).is_err(), "nothing to apply after revoke purge");
        assert_eq!(registry_of(&accounts).validators[0].withdrawal_address, orig_wd, "withdrawal stays the original cold address");
    }

    /// #20: rotating the CONSENSUS key keeps the bond/activation, requires a fresh
    /// PoP by the NEW key, records the OLD key as slashable through the window, and
    /// clears any revocation/expiry; a bad PoP is rejected; the rotated-out key is
    /// still slashable via `find_slashable`.
    #[test]
    fn consensus_key_rotation_keeps_bond_and_old_key_stays_slashable() {
        let mut accounts = HashMap::new();
        let op = Keypair::generate().unwrap();
        let consensus = Keypair::generate().unwrap();
        accounts.insert(op.pubkey(), wallet(2000 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register_full(&mut accounts, &op, &consensus, None, "node-r").unwrap();
        let old_addr = consensus.pubkey();
        let activation_before = registry_of(&accounts).validators[0].activation_quanto;

        let new_consensus = Keypair::generate().unwrap();
        // A BAD pop (signed over the wrong operator) is rejected.
        let wrong = qchain_crypto::sign_domain(&new_consensus, qchain_crypto::domains::VALIDATOR_POP_V1, &pop_message(&Pubkey::new([5u8; 32]), &op.pubkey(), "node-r")).unwrap();
        let bad = ix(&ValidatorV7Instruction::RotateConsensusKey { consensus_address: old_addr, new_bundle: new_consensus.public_key_bundle(), new_p2p_address: "5.6.7.8:9000".into(), new_pop: wrong }, vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, STAKING_GLOBAL_ID]);
        assert!(ValidatorV7Program::execute(&mut accounts, &bad, &op.pubkey()).is_err(), "bad PoP rejected");

        // A GOOD pop (operator == payer, withdrawal defaulted to operator, correct moniker).
        let good = qchain_crypto::sign_domain(&new_consensus, qchain_crypto::domains::VALIDATOR_POP_V1, &pop_message(&op.pubkey(), &op.pubkey(), "node-r")).unwrap();
        let rot = ix(&ValidatorV7Instruction::RotateConsensusKey { consensus_address: old_addr, new_bundle: new_consensus.public_key_bundle(), new_p2p_address: "5.6.7.8:9000".into(), new_pop: good }, vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, STAKING_GLOBAL_ID]);
        ValidatorV7Program::execute(&mut accounts, &rot, &op.pubkey()).unwrap();

        let reg = registry_of(&accounts);
        let e = &reg.validators[0];
        assert_eq!(e.address, new_consensus.pubkey(), "live address is the new key");
        assert_eq!(e.bond, VALIDATOR_BOND_ATOMS, "bond preserved across rotation");
        assert_eq!(e.activation_quanto, activation_before, "activation preserved");
        assert_eq!(e.p2p_address, "5.6.7.8:9000");
        // The OLD key is retired-but-slashable, and still findable for slashing.
        assert!(e.retired_consensus_keys.iter().any(|r| r.address == old_addr), "old key retired");
        assert_eq!(reg.find(&old_addr), None, "old key is no longer the live address");
        assert_eq!(reg.find_slashable(&old_addr, 0), Some(0), "old key still slashable within window");
        // Past the slash window the retired key is no longer slashable.
        let window_end = e.retired_consensus_keys[0].slash_until_quanto;
        assert_eq!(reg.find_slashable(&old_addr, window_end + 1), None, "old key not slashable past its window");
    }

    /// #20: REVOKING or EXPIRING the consensus key excludes the validator from BOTH
    /// the active committee and fee eligibility; `RotateConsensusKey` clears it.
    #[test]
    fn revoke_and_expiry_exclude_from_committee_and_fees() {
        let mut accounts = HashMap::new();
        let op = Keypair::generate().unwrap();
        let consensus = Keypair::generate().unwrap();
        accounts.insert(op.pubkey(), wallet(2000 * UNITS_PER_QCH, Pubkey::system_program_id()));
        register_full(&mut accounts, &op, &consensus, None, "node-e").unwrap();
        let caddr = consensus.pubkey();
        // Activate it (and set activation_quanto 0) so it's committee/fee-eligible
        // at quanto 0 to begin with.
        {
            let mut reg = registry_of(&accounts);
            reg.validators[0].state = ValidatorV7State::Active;
            reg.validators[0].activation_quanto = 0;
            write_registry(&mut accounts, &reg).unwrap();
        }
        let reg = registry_of(&accounts);
        assert_eq!(active_committee(&reg, 0).len(), 1, "eligible before");
        assert!(crate::fees_v7::is_eligible(&reg.validators[0], 0), "fee-eligible before");

        // REVOKE → excluded from both.
        let rev = ix(&ValidatorV7Instruction::RevokeConsensusKey { consensus_address: caddr }, vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, STAKING_GLOBAL_ID]);
        ValidatorV7Program::execute(&mut accounts, &rev, &op.pubkey()).unwrap();
        let reg = registry_of(&accounts);
        assert!(reg.validators[0].consensus_key_revoked);
        assert_eq!(active_committee(&reg, 0).len(), 0, "revoked → out of committee");
        assert!(!crate::fees_v7::is_eligible(&reg.validators[0], 0), "revoked → out of fees");
        // The revoked key stays the live address (still slashable in-epoch).
        assert_eq!(reg.find(&caddr), Some(0));

        // Rotating in a fresh key clears the revocation.
        let nk = Keypair::generate().unwrap();
        let pop = qchain_crypto::sign_domain(&nk, qchain_crypto::domains::VALIDATOR_POP_V1, &pop_message(&op.pubkey(), &op.pubkey(), "node-e")).unwrap();
        let rot = ix(&ValidatorV7Instruction::RotateConsensusKey { consensus_address: caddr, new_bundle: nk.public_key_bundle(), new_p2p_address: "9.9.9.9:9000".into(), new_pop: pop }, vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, STAKING_GLOBAL_ID]);
        ValidatorV7Program::execute(&mut accounts, &rot, &op.pubkey()).unwrap();
        let reg = registry_of(&accounts);
        assert!(!reg.validators[0].consensus_key_revoked, "rotation cleared revocation");
        assert_eq!(active_committee(&reg, 0).len(), 1, "back in committee after rotation");

        // EXPIRY at quanto 100 → disabled at/after 100, fine before.
        let exp = ix(&ValidatorV7Instruction::SetConsensusKeyExpiry { consensus_address: nk.pubkey(), expiry_quanto: 100 }, vec![op.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID]);
        ValidatorV7Program::execute(&mut accounts, &exp, &op.pubkey()).unwrap();
        let reg = registry_of(&accounts);
        assert_eq!(active_committee(&reg, 99).len(), 1, "not yet expired at quanto 99");
        assert_eq!(active_committee(&reg, 100).len(), 0, "expired at quanto 100");
        assert!(!crate::fees_v7::is_eligible(&reg.validators[0], 100), "expired → out of fees");
    }
}
