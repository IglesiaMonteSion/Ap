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
    STAKING_GLOBAL_ID, STAKING_PROGRAM_ID, VALIDATOR_BOND_ESCROW_ID, VALIDATOR_REGISTRY_ACCOUNT_ID,
    VALIDATOR_UNBONDING_POOL_ID,
};
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{Account, EquivocationEvidence, Instruction};
use qchain_crypto::{MultiSignature, Pubkey, PublicKeyBundle};
use std::collections::HashMap;

/// Cap on the on-chain validator registry (anti-bloat/DoS; a bond is required to
/// add an entry, so this is a defensive backstop, not the primary limit).
pub const MAX_V7_VALIDATORS: usize = 1_000;

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
}

impl ValidatorV7Entry {
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
    fn moniker_taken(&self, moniker: &str, except: Option<&Pubkey>) -> bool {
        self.validators
            .iter()
            .any(|v| v.moniker == moniker && v.state != ValidatorV7State::Removed && Some(&v.address) != except)
    }
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
}

pub struct ValidatorV7Program;

fn read_registry(accounts: &HashMap<Pubkey, Account>) -> ValidatorV7Registry {
    accounts
        .get(&VALIDATOR_REGISTRY_ACCOUNT_ID)
        .and_then(|a| ValidatorV7Registry::try_from_slice(&a.data).ok())
        .unwrap_or_default()
}

fn write_registry(accounts: &mut HashMap<Pubkey, Account>, r: &ValidatorV7Registry) -> Result<(), ExecError> {
    let acct = accounts.entry(VALIDATOR_REGISTRY_ACCOUNT_ID).or_insert_with(|| Account::new_wallet(STAKING_PROGRAM_ID));
    acct.data = borsh::to_vec(r).map_err(|e| ExecError::ProgramError(e.to_string()))?;
    Ok(())
}

fn current_quanto(accounts: &HashMap<Pubkey, Account>) -> u64 {
    crate::staking_v7::global_state(accounts).current_quanto
}

fn credit(accounts: &mut HashMap<Pubkey, Account>, pk: &Pubkey, owner_if_new: Pubkey, amount: u64) {
    let acct = accounts.entry(*pk).or_insert_with(|| Account::new_wallet(owner_if_new));
    acct.balance = acct.balance.saturating_add(amount);
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
        }
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
        if reg.validators.len() >= MAX_V7_VALIDATORS && reg.find(&consensus_addr).is_none() {
            return Err(ExecError::ProgramError("validator registry is full".into()));
        }

        // Take EXACTLY the bond from the OPERATOR (payer) into escrow.
        let bal = accounts.get(&operator).ok_or(ExecError::AccountNotFound(operator))?.balance;
        if bal < VALIDATOR_BOND_ATOMS {
            return Err(ExecError::InsufficientFunds);
        }
        accounts.get_mut(&operator).unwrap().balance -= VALIDATOR_BOND_ATOMS;
        credit(accounts, &escrow_pk, STAKING_PROGRAM_ID, VALIDATOR_BOND_ATOMS);

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
        accounts.get_mut(&escrow_pk).unwrap().balance -= VALIDATOR_BOND_ATOMS;
        credit(accounts, &unbonding_pk, STAKING_PROGRAM_ID, VALIDATOR_BOND_ATOMS);

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
        // Only the cold OPERATOR key may withdraw — a leaked consensus key cannot.
        if reg.validators[idx].operator_address != *payer {
            return Err(ExecError::Unauthorized("only the validator's operator (cold) key can withdraw the bond".into()));
        }
        if reg.validators[idx].state != ValidatorV7State::Unbonding {
            return Err(ExecError::ProgramError("bond is not unbonding".into()));
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
        accounts.get_mut(&unbonding_pk).unwrap().balance -= VALIDATOR_BOND_ATOMS;
        credit(accounts, &dest, Pubkey::system_program_id(), VALIDATOR_BOND_ATOMS);
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
        let idx = reg.find(&author).ok_or_else(|| ExecError::ProgramError("accused is not a registered validator".into()))?;
        let e = &reg.validators[idx];
        if matches!(e.state, ValidatorV7State::Slashed | ValidatorV7State::Removed) {
            return Err(ExecError::ProgramError("nothing to slash".into()));
        }
        // Burn the full bond from wherever it currently sits: the escrow (Active/
        // BondedPending/Jailed) or the unbonding pool (Exiting/Unbonding). Burning
        // = the QCH leaves circulation (real supply reduction).
        let from_escrow = !matches!(e.state, ValidatorV7State::Unbonding);
        let (pool_pk, bal) = if from_escrow {
            (escrow_pk, accounts.get(&escrow_pk).map(|a| a.balance).unwrap_or(0))
        } else {
            (unbonding_pk, accounts.get(&unbonding_pk).map(|a| a.balance).unwrap_or(0))
        };
        if bal < VALIDATOR_BOND_ATOMS {
            return Err(ExecError::ProgramError("nothing to slash".into()));
        }
        accounts.get_mut(&pool_pk).unwrap().balance -= VALIDATOR_BOND_ATOMS; // burned
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
}
