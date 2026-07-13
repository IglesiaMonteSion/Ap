//! STARK-based state-transition compression, v1 (design: `ARCHITECTURE.md`
//! §3 - "Compresión de estado vía STARK"). Scope of this increment,
//! stated precisely rather than implied: proves that a batch of System
//! Program `Transfer` operations is *arithmetically self-consistent*
//! (each transfer's before/after balances conserve value per the fee
//! model) using a real Winterfell STARK - the actual polynomial-IOP
//! pipeline (trace -> AIR -> prove -> verify) working end to end on a
//! real, blockchain-relevant computation, not a toy example.
//!
//! What this v1 deliberately does NOT yet do, so scope is never
//! ambiguous:
//! - Not wired into `qchain-execution`/`qchain-node` yet: this is a
//!   standalone circuit operating on plain `u64` tuples, proven against
//!   real Winterfell APIs - not yet connected to
//!   `Ledger::apply_transaction` or served to light clients over RPC.
//!
//! Despite the gaps above, what this *does* prove is real and useful on
//! its own: a verifier can confirm a claimed batch of transfers is
//! internally consistent in constant time (a few milliseconds,
//! independent of batch size), without re-executing the fee arithmetic
//! for every transfer - the core value proposition of "compression for
//! light clients" `ARCHITECTURE.md` §3 names, even before the
//! Merkle-tie-in hardening lands.
//!
//! ## v2: real u64 range checks, without an in-circuit bit-decomposition gadget
//!
//! v1 shipped with an open gap: nothing proved `from_after >= 0` as a
//! real non-negative integer, only that reported values satisfied the
//! two conservation equations as field arithmetic - a malicious prover
//! could report a value that "underflows" and wraps around the field,
//! e.g. an `amount` that's secretly the field-negation of a real value
//! (`0 - 500`, landing near the modulus), which still satisfies both
//! linear equations while representing a reversed, illegitimate
//! transfer.
//!
//! The obvious fix is the textbook one - bit-decompose every value into
//! boolean columns and assert the weighted sum reconstructs it - but
//! that's the wrong tool *here*, and worth explaining why rather than
//! just not doing it. That gadget exists to prove range membership of a
//! value the verifier never sees directly (hidden behind a commitment).
//! In this circuit every trace cell is already a public input
//! (`PublicInputs` exposes the whole trace, per the Merkle-tie-in gap
//! above) - the verifier already holds the exact field element for
//! every value in the plain. Given that, range-checking is not a
//! circuit problem, it's a five-line post-verification bounds check:
//! after `winterfell::verify` accepts the proof (which cryptographically
//! binds every one of those public cells to the trace, boundary
//! constraint by boundary constraint - see `get_assertions`), walk the
//! six columns and reject if any cell's canonical integer value exceeds
//! `u64::MAX`.
//!
//! This is sound, not a shortcut, because of the field/value size gap:
//! `f128::BaseElement`'s modulus is `2^128 - 45*2^40 + 1` (~128 bits),
//! while every genuine value here is u64-scale (at most ~2^64, and a
//! batch's worth of linear combinations of such values stays nowhere
//! near 128 bits). A real underflow (`from_before < amount + fee`)
//! computed over the integers is negative with magnitude at most
//! `2^64`; reduced mod a ~2^128 modulus, that lands within `2^64` of the
//! modulus itself - i.e. an enormous field element, not a small
//! plausible-looking one. There is no way to pick a genuinely
//! out-of-range quantity (an underflowed balance, a field-negated
//! "amount") that reduces to something `<= u64::MAX` without every
//! *other* value in the same equation also having to compensate with
//! its own out-of-range element - and every value in both equations is
//! itself one of the six checked columns. See
//! `an_out_of_range_disguised_negative_amount_is_rejected_even_though_the_stark_proof_alone_would_accept_it`
//! for a concrete, previously-unclosed attack this catches: an `amount`
//! set to the field negation of 500 makes both conservation equations
//! hold exactly (the STARK proof verifies), while silently reversing
//! the direction of value flow - caught only by the range check, not by
//! the polynomial constraints.
//!
//! **This closure is conditional, not permanent**: it holds only as
//! long as every value stays a direct public input. The moment a future
//! version hides these values behind a Merkle commitment or otherwise
//! stops exposing them in the clear (data-hiding, not the "v3" external
//! binding below, which keeps every value public), this argument stops
//! applying and an in-circuit bit-decomposition range check becomes
//! necessary again - re-derive this reasoning at that point, don't
//! assume the shortcut still holds.
//!
//! Behavior discovered by testing against the real Winterfell prover
//! (not assumed from docs): `winter_prover::Trace::validate` runs an
//! internal sanity re-check of every transition constraint before
//! generating a proof, but only `#[cfg(debug_assertions)]` (it's
//! documented upstream as "a very expensive operation"). In a debug
//! build, proving over an inconsistent trace `panic!`s from inside
//! Winterfell rather than returning a `ProverError` - callers of
//! `prove_batch` in a debug build must be prepared for a panic, not
//! just an `Err`, if fed inconsistent `TransferStep`s. In a release
//! build that internal check is compiled out, so an inconsistent trace
//! proves "successfully" and the inconsistency only ever surfaces at
//! `verify_batch` time. Either way, no inconsistent batch ends up with a
//! proof that verifies - only the point of failure changes.
//!
//! ## v3: real Merkle tie-in via an external binding check, not an in-circuit hash
//!
//! v1/v2 proved a batch of transfers is arithmetically self-consistent,
//! but the before/after balances were anonymous numbers - nothing tied
//! `from_before`/`from_after` to a *specific account*, let alone to the
//! real SHA3-256 sparse Merkle root `qchain-storage` actually maintains.
//! A light client trusting this proof still had to take the claimed
//! values on faith.
//!
//! Two ways to close that, named in v1's original docs: an in-circuit
//! Merkle-friendly hash (Poseidon2/Rescue-Prime), or an external binding
//! check. This project's real state tree (`qchain-storage::tree`) uses
//! plain SHA3-256 - the conservative, non-arithmetization-friendly
//! default this project deliberately chose for the outer state tree (see
//! `stark-proofs-and-hash-commitments`) - so reimplementing SHA3-256 as
//! AIR constraints would mean thousands of constraints per hash call,
//! solving a problem by fighting the tree's own design choice rather
//! than working with it. The external binding check is the honest fit:
//! keep proving the arithmetic in-circuit (unchanged), and verify
//! *outside* the circuit, via qchain-storage's own real
//! `MerkleProof`/`hash_leaf`/`verify_proof`, that the specific accounts
//! and balances the STARK's public inputs name are genuinely part of
//! the real tree's transition from one root to the next.
//!
//! This requires the circuit to know *whose* balance each row is about,
//! not just the numbers - so `TransferStep` gained `from_address`/
//! `to_address` (`[u8; 32]`, the same raw bytes as `Pubkey::to_bytes()`),
//! carried through the trace as two more sets of public-input columns
//! (four `u64` limbs each, since a 32-byte address doesn't fit in one
//! ~128-bit field element). No new transition constraints reference
//! them - they're pure pass-through public data, asserted public the
//! same way every other cell already is.
//!
//! `verify_batch_bound_to_state` composes the existing `verify_batch`
//! (STARK + range check) with, per row, four real Merkle inclusion
//! checks (from-before, from-after, to-before, to-after) against a
//! caller-supplied `root_before`/`root_after` pair, plus a check that
//! consecutive rows' roots actually chain (`root_after` of row *i* must
//! equal `root_before` of row *i+1`) - without that, a prover could
//! supply valid-looking but *disconnected* Merkle proofs for each row
//! independently, never actually representing one coherent state
//! transition.
//!
//! **Explicit, deliberate scope limits, not silently assumed away:**
//! - Assumes every account in a bound batch already exists before *and*
//!   after (both are real, non-empty leaves) - the new-account-creation
//!   case (an exclusion proof for "before") isn't handled by this
//!   function yet.
//! - The caller supplies the full `Account` snapshots (not just a
//!   balance) because the real tree's leaf hash commits to the whole
//!   struct (`balance`, `nonce`, `algorithm_id`, `owner`, `code_hash`,
//!   `data`) - this function only checks that the snapshot's `balance`
//!   field matches what the STARK publicly proved, and that the
//!   snapshot's full hash matches the supplied Merkle proof; it does
//!   *not* independently verify nonce/fee bookkeeping matches
//!   `Ledger::apply_transaction`'s real semantics (a real Transfer also
//!   bumps the payer's nonce and deducts a byte-scaled fee separately
//!   from `amount` - already an existing v1 simplification, not
//!   reopened here).
//! - Still not wired into `qchain-execution`/`qchain-node`/RPC - a real
//!   light-client-facing endpoint needs the prover to actually walk a
//!   live `Ledger`'s applied transactions and a real `StateTree`, which
//!   is a separate, larger integration deliberately not started without
//!   explicit confirmation, same as this gap itself was until asked for.

use qchain_core::Account;
use qchain_storage::{hash_leaf, verify_proof, MerkleProof, StateTree};
use winterfell::crypto::hashers::Blake3_256;
use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
use winterfell::math::fields::f128::BaseElement;
use winterfell::math::{FieldElement, StarkField, ToElements};
use winterfell::matrix::ColMatrix;
use winterfell::{
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, ProofOptions, Prover, ProverError, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

// Re-exported so a downstream consumer (RPC serving/light-client verifying
// code, e.g. `qchain-node`/`qchain-cli`) can name this type without also
// taking a direct `winterfell` dependency of its own.
pub use winterfell::Proof;

/// Splits a 32-byte address into 4 big-endian `u64` limbs - each limb is
/// always `< 2^64`, safely representable as an `f128::BaseElement`
/// (modulus ~`2^128`) with no risk of the wraparound a naive 128-bit
/// split could hit (the modulus is *slightly* below `2^128`).
fn address_limbs(addr: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = u64::from_be_bytes(addr[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    limbs
}

/// Inverse of [`address_limbs`].
fn limbs_to_address(limbs: [u64; 4]) -> [u8; 32] {
    let mut addr = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        addr[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_be_bytes());
    }
    addr
}

/// One System Program `Transfer`'s before/after state, as plain u64s -
/// exactly the semantics of `qchain_execution::SystemInstruction::Transfer`
/// plus the byte-scaled base fee - plus which two addresses (raw
/// `Pubkey::to_bytes()`) this row is about, for the real Merkle tie-in
/// (`verify_batch_bound_to_state`, see module docs' "v3" section).
#[derive(Clone, Copy, Debug)]
pub struct TransferStep {
    pub from_address: [u8; 32],
    pub to_address: [u8; 32],
    pub from_before: u64,
    pub to_before: u64,
    pub amount: u64,
    pub fee: u64,
    pub from_after: u64,
    pub to_after: u64,
}

impl TransferStep {
    /// Builds a step from the two conservation equations directly,
    /// rather than requiring the caller to compute `from_after`/`to_after`
    /// by hand - a mismatch here is exactly what the AIR's transition
    /// constraints are meant to catch, so tests can deliberately break it.
    pub fn conserving(from_address: [u8; 32], to_address: [u8; 32], from_before: u64, to_before: u64, amount: u64, fee: u64) -> Self {
        TransferStep {
            from_address,
            to_address,
            from_before,
            to_before,
            amount,
            fee,
            from_after: from_before - amount - fee,
            to_after: to_before + amount,
        }
    }
}

// Column layout: 0-5 are the numeric conservation-equation values
// (unchanged since v1/v2 - `evaluate_transition` only ever reads these
// six); 6-9 and 10-13 are `from_address`/`to_address`'s four `u64` limbs
// each, added in v3 - pure public pass-through data, no transition
// constraint references them.
const COL_FROM_BEFORE: usize = 0;
const COL_TO_BEFORE: usize = 1;
const COL_AMOUNT: usize = 2;
const COL_FEE: usize = 3;
const COL_FROM_AFTER: usize = 4;
const COL_TO_AFTER: usize = 5;
const COL_FROM_ADDRESS: usize = 6;
const COL_TO_ADDRESS: usize = 10;
const TRACE_WIDTH: usize = 14;

/// Builds the padded execution trace for a batch of transfers. Trace
/// length is the next power of two strictly greater than `steps.len()`
/// (Winterfell requires a power-of-two length, and every real row needs
/// a following "next" row - even a no-op padding one - for its
/// transition constraint to actually be evaluated). Padding rows are
/// all-zero, which trivially satisfies both conservation equations.
fn build_trace(steps: &[TransferStep]) -> TraceTable<BaseElement> {
    let padded_len = (steps.len() + 1)
        .next_power_of_two()
        .max(TraceInfo::MIN_TRACE_LENGTH);
    let mut columns: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; padded_len]; TRACE_WIDTH];
    for (i, step) in steps.iter().enumerate() {
        columns[COL_FROM_BEFORE][i] = BaseElement::new(step.from_before as u128);
        columns[COL_TO_BEFORE][i] = BaseElement::new(step.to_before as u128);
        columns[COL_AMOUNT][i] = BaseElement::new(step.amount as u128);
        columns[COL_FEE][i] = BaseElement::new(step.fee as u128);
        columns[COL_FROM_AFTER][i] = BaseElement::new(step.from_after as u128);
        columns[COL_TO_AFTER][i] = BaseElement::new(step.to_after as u128);
        for (limb_idx, limb) in address_limbs(&step.from_address).into_iter().enumerate() {
            columns[COL_FROM_ADDRESS + limb_idx][i] = BaseElement::new(limb as u128);
        }
        for (limb_idx, limb) in address_limbs(&step.to_address).into_iter().enumerate() {
            columns[COL_TO_ADDRESS + limb_idx][i] = BaseElement::new(limb as u128);
        }
    }
    TraceTable::init(columns)
}

/// Public inputs: the entire trace's content, column by column - see
/// module docs for why everything is public in this v1 (no data-hiding
/// yet, just succinct verification of the arithmetic).
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub columns: [Vec<BaseElement>; TRACE_WIDTH],
}

impl PublicInputs {
    fn from_trace(trace: &TraceTable<BaseElement>) -> Self {
        let mut columns: [Vec<BaseElement>; TRACE_WIDTH] = Default::default();
        for (c, col) in columns.iter_mut().enumerate() {
            *col = trace.get_column(c).to_vec();
        }
        PublicInputs { columns }
    }
}

// `BaseElement` (Winterfell's f128 field element) has no serde impl of its
// own, so `PublicInputs` can't just `#[derive(Serialize, Deserialize)]` -
// every value here is a real, already-range-checked `u64` by the time
// `verify_batch` accepts it (see the v2 module docs), and `as_int()`/`new()`
// round-trip a field element through its underlying `u128` losslessly, so
// the wire format is just nested `u128` arrays - a light client over RPC
// needs this to receive `PublicInputs` at all, not just use it in-process.
impl serde::Serialize for PublicInputs {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let raw: Vec<Vec<u128>> = self.columns.iter().map(|col| col.iter().map(|e| e.as_int()).collect()).collect();
        raw.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PublicInputs {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: Vec<Vec<u128>> = serde::Deserialize::deserialize(deserializer)?;
        if raw.len() != TRACE_WIDTH {
            return Err(serde::de::Error::custom(format!("expected {TRACE_WIDTH} PublicInputs columns, got {}", raw.len())));
        }
        let mut columns: [Vec<BaseElement>; TRACE_WIDTH] = Default::default();
        for (col, raw_col) in columns.iter_mut().zip(raw) {
            *col = raw_col.into_iter().map(BaseElement::new).collect();
        }
        Ok(PublicInputs { columns })
    }
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.columns.iter().flat_map(|c| c.iter().copied()).collect()
    }
}

pub struct TransferAir {
    context: AirContext<BaseElement>,
    pub_inputs: PublicInputs,
}

impl Air for TransferAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(TRACE_WIDTH, trace_info.width(), "this AIR always has a fixed 14-column trace (6 numeric + 4+4 address limbs)");
        // Both conservation equations are linear (degree 1) in the
        // trace's current-row values.
        let degrees = vec![TransitionConstraintDegree::new(1), TransitionConstraintDegree::new(1)];
        let trace_length = trace_info.length();
        // One `Assertion::single` per (column, step) - `Assertion::sequence`
        // requires a stride >= 2, so asserting *every* consecutive row
        // publicly means one assertion per cell, not one per column.
        let num_assertions = TRACE_WIDTH * trace_length;
        TransferAir { context: AirContext::new(trace_info, degrees, num_assertions, options), pub_inputs }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let from_before = cur[0];
        let to_before = cur[1];
        let amount = cur[2];
        let fee = cur[3];
        let from_after = cur[4];
        let to_after = cur[5];
        // from_after == from_before - amount - fee
        result[0] = from_after - (from_before - amount - fee);
        // to_after == to_before + amount
        result[1] = to_after - (to_before + amount);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let trace_length = self.trace_length();
        let mut assertions = Vec::with_capacity(TRACE_WIDTH * trace_length);
        for (col, values) in self.pub_inputs.columns.iter().enumerate() {
            for (step, &value) in values.iter().enumerate() {
                assertions.push(Assertion::single(col, step, value));
            }
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

/// Default STARK security parameters (~96-bit conjectured security) -
/// an explicit starting point, not a modeled/audited choice, matching
/// this project's established pattern for placeholder constants
/// (`DUST_THRESHOLD_UNITS` etc. in `qchain_core`).
pub fn default_proof_options() -> ProofOptions {
    ProofOptions::new(32, 8, 0, FieldExtension::None, 8, 31, BatchingMethod::Linear, BatchingMethod::Linear)
}

struct TransferProver {
    options: ProofOptions,
}

impl TransferProver {
    fn new(options: ProofOptions) -> Self {
        TransferProver { options }
    }
}

impl Prover for TransferProver {
    type BaseField = BaseElement;
    type Air = TransferAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> = DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> = DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        PublicInputs::from_trace(trace)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(composition_poly_trace, num_constraint_composition_columns, domain, partition_options)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

/// Proves that `steps` is a batch of arithmetically-consistent transfers
/// (see module docs for exactly what "consistent" means here, and what
/// it doesn't yet cover). Returns the proof and the public inputs a
/// verifier needs alongside it.
pub fn prove_batch(steps: &[TransferStep]) -> Result<(Proof, PublicInputs), ProverError> {
    prove_batch_with_options(steps, default_proof_options())
}

pub fn prove_batch_with_options(steps: &[TransferStep], options: ProofOptions) -> Result<(Proof, PublicInputs), ProverError> {
    let trace = build_trace(steps);
    let prover = TransferProver::new(options);
    let pub_inputs = prover.get_pub_inputs(&trace);
    let proof = prover.prove(trace)?;
    Ok((proof, pub_inputs))
}

/// Everything that can make a claimed batch of transfers unacceptable:
/// either the STARK proof itself doesn't check out, or it does but one
/// of the public values it binds isn't a real `u64` (see the module
/// docs' "v2: real u64 range checks" section for why this second check
/// is necessary and why it's sound to do outside the circuit).
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("STARK proof did not verify: {0}")]
    Stark(#[from] winterfell::VerifierError),
    #[error("public value at column {column}, step {step} exceeds u64::MAX - not a real non-negative u64")]
    ValueOutOfU64Range { column: usize, step: usize },
    #[error("malformed proof rejected before verification (e.g. wrong trace width)")]
    Malformed,
}

fn is_valid_u64(value: BaseElement) -> bool {
    value.as_int() <= u64::MAX as u128
}

/// Verifies a proof produced by [`prove_batch`]. Accepts proofs meeting
/// or exceeding ~95-bit conjectured security - matches
/// [`default_proof_options`]'s target. Beyond the STARK proof itself,
/// also rejects any public value that isn't representable as a real
/// non-negative `u64` - closes the range-check gap described in the
/// module docs without an in-circuit bit-decomposition gadget.
pub fn verify_batch(proof: Proof, pub_inputs: PublicInputs) -> Result<(), VerifyError> {
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    // `catch_unwind`: `winterfell::verify` reconstructs the AIR from the
    // *proof's own* trace metadata, and `TransferAir::new` asserts a fixed
    // 14-column trace width (`assert_eq!`). A proof is untrusted input here -
    // it arrives over RPC from a possibly-malicious node (the light client's
    // `light-client-verify`, including its multi-node `--cross-check-rpc`
    // path, and the node's own pre-serve self-verify). A proof declaring a
    // different width would otherwise panic and crash the verifier instead of
    // being cleanly rejected - a DoS, though not a soundness break (a genuine
    // forge still can't verify). Same tool this crate already uses for
    // Winterfell's debug-only internal panics.
    let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        winterfell::verify::<TransferAir, Blake3_256<BaseElement>, DefaultRandomCoin<Blake3_256<BaseElement>>, MerkleTree<Blake3_256<BaseElement>>>(
            proof,
            pub_inputs.clone(),
            &min_opts,
        )
    }))
    .map_err(|_| VerifyError::Malformed)?;
    verified?;
    for (column, values) in pub_inputs.columns.iter().enumerate() {
        for (step, &value) in values.iter().enumerate() {
            if !is_valid_u64(value) {
                return Err(VerifyError::ValueOutOfU64Range { column, step });
            }
        }
    }
    Ok(())
}

/// Ties one proven row to a real, sequential Merkle root transition in
/// `qchain-storage`'s state tree - see module docs' "v3" section for
/// exactly what this does and does not check (in particular: assumes
/// every account already exists before *and* after, and only checks the
/// `balance` field against the STARK's public values, not full
/// nonce/fee bookkeeping). Serialize/Deserialize added for real RPC
/// transport - every field is already serde-capable (`Account`,
/// `qchain_storage::MerkleProof`, `[u8; 32]`), so this derives cleanly.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RowStateBinding {
    pub root_before: [u8; 32],
    pub root_after: [u8; 32],
    pub from_before: Account,
    pub from_after: Account,
    pub to_before: Account,
    pub to_after: Account,
    pub from_proof_before: MerkleProof,
    pub from_proof_after: MerkleProof,
    pub to_proof_before: MerkleProof,
    pub to_proof_after: MerkleProof,
}

/// Everything that can make a claimed state-bound batch unacceptable:
/// the underlying STARK/range-check failing, a malformed binding list,
/// or a binding that doesn't actually match what the STARK publicly
/// proved or the real Merkle tree it claims to be rooted in.
#[derive(Debug, thiserror::Error)]
pub enum StateBindingError {
    #[error(transparent)]
    Stark(#[from] VerifyError),
    #[error("expected at most {max} row bindings (one per real or padding row), got {got}")]
    TooManyBindings { max: usize, got: usize },
    #[error("row {row}: root_after does not chain into the next binding's root_before - not one coherent state transition")]
    RootSequenceMismatch { row: usize },
    #[error("row {row}: {field}'s balance in the supplied Account snapshot doesn't match the STARK's public value")]
    BalanceMismatch { row: usize, field: &'static str },
    #[error("row {row}: the supplied {field} Merkle proof's key doesn't match the address the STARK publicly proved")]
    AddressMismatch { row: usize, field: &'static str },
    #[error("row {row}: {field}'s Merkle inclusion proof does not verify against the claimed root")]
    MerkleProofFailed { row: usize, field: &'static str },
    /// A real, non-hypothetical case: a first-ever transfer *to* an
    /// address means `to_before`'s proof is a genuine *exclusion* proof
    /// (the address has no row in the tree yet) - `leaf_value_hash` is
    /// `None`, so there is no real leaf hash to compare the snapshot
    /// against. The only claim that can be soundly checked against an
    /// absent leaf is "the true prior balance is zero" (nothing there
    /// means nothing to have a balance) - a snapshot claiming otherwise
    /// for an excluded key is rejected here, not silently accepted.
    #[error("row {row}: {field}'s Merkle proof claims the account doesn't exist yet, but the supplied snapshot claims a non-zero balance")]
    ExclusionProofClaimsNonzeroBalance { row: usize, field: &'static str },
}

/// Verifies a proof produced by [`prove_batch`] *and* that `bindings`
/// genuinely ties each proven row's addresses/balances to a real
/// `qchain-storage` state transition - the real Merkle tie-in named as
/// an open gap in v1/v2's docs, now closed via an external binding check
/// (see module docs' "v3" section for why that's the right tool here,
/// not an in-circuit hash). `bindings` may cover fewer rows than the
/// padded trace length (bind only the real steps, not the zero-padding);
/// it may not cover more.
pub fn verify_batch_bound_to_state(proof: Proof, pub_inputs: PublicInputs, bindings: &[RowStateBinding]) -> Result<(), StateBindingError> {
    verify_batch(proof, pub_inputs.clone())?;

    let max_rows = pub_inputs.columns[COL_FROM_BEFORE].len();
    if bindings.len() > max_rows {
        return Err(StateBindingError::TooManyBindings { max: max_rows, got: bindings.len() });
    }

    for (row, pair) in bindings.windows(2).enumerate() {
        if pair[0].root_after != pair[1].root_before {
            return Err(StateBindingError::RootSequenceMismatch { row });
        }
    }

    let tree = StateTree::new();
    let empty_leaf_hash = tree.empty_leaf_hash();

    for (row, binding) in bindings.iter().enumerate() {
        let from_addr = limbs_to_address(std::array::from_fn(|i| pub_inputs.columns[COL_FROM_ADDRESS + i][row].as_int() as u64));
        let to_addr = limbs_to_address(std::array::from_fn(|i| pub_inputs.columns[COL_TO_ADDRESS + i][row].as_int() as u64));

        let from_before_pub = pub_inputs.columns[COL_FROM_BEFORE][row].as_int() as u64;
        let from_after_pub = pub_inputs.columns[COL_FROM_AFTER][row].as_int() as u64;
        let to_before_pub = pub_inputs.columns[COL_TO_BEFORE][row].as_int() as u64;
        let to_after_pub = pub_inputs.columns[COL_TO_AFTER][row].as_int() as u64;

        if binding.from_before.balance != from_before_pub {
            return Err(StateBindingError::BalanceMismatch { row, field: "from_before" });
        }
        if binding.from_after.balance != from_after_pub {
            return Err(StateBindingError::BalanceMismatch { row, field: "from_after" });
        }
        if binding.to_before.balance != to_before_pub {
            return Err(StateBindingError::BalanceMismatch { row, field: "to_before" });
        }
        if binding.to_after.balance != to_after_pub {
            return Err(StateBindingError::BalanceMismatch { row, field: "to_after" });
        }

        if binding.from_proof_before.key != from_addr || binding.from_proof_after.key != from_addr {
            return Err(StateBindingError::AddressMismatch { row, field: "from" });
        }
        if binding.to_proof_before.key != to_addr || binding.to_proof_after.key != to_addr {
            return Err(StateBindingError::AddressMismatch { row, field: "to" });
        }

        let checks: [(&Account, &MerkleProof, [u8; 32], &'static str); 4] = [
            (&binding.from_before, &binding.from_proof_before, binding.root_before, "from_before"),
            (&binding.from_after, &binding.from_proof_after, binding.root_after, "from_after"),
            (&binding.to_before, &binding.to_proof_before, binding.root_before, "to_before"),
            (&binding.to_after, &binding.to_proof_after, binding.root_after, "to_after"),
        ];
        for (account, proof, root, field) in checks {
            // A proof with `leaf_value_hash: None` is a real exclusion
            // proof - the account genuinely has no row in the tree yet
            // (e.g. `to_before` on the very first transfer an address
            // ever receives, see `qchain-execution`'s receipt-capture
            // docs). There is no leaf to hash-compare the snapshot
            // against in that case; the only thing that can be soundly
            // required is that the claimed balance is zero, since an
            // absent key cannot hold a real positive balance.
            match proof.leaf_value_hash {
                Some(h) if h == hash_leaf(account) => {}
                Some(_) => return Err(StateBindingError::MerkleProofFailed { row, field }),
                None if account.balance == 0 => {}
                None => return Err(StateBindingError::ExclusionProofClaimsNonzeroBalance { row, field }),
            }
            if !verify_proof(root, proof, empty_leaf_hash) {
                return Err(StateBindingError::MerkleProofFailed { row, field });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dummy, deterministic 32-byte address for tests that don't care
    /// about the real Merkle tie-in - fills every byte with `n`.
    fn addr(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn a_valid_batch_of_transfers_proves_and_verifies() {
        let steps = vec![
            TransferStep::conserving(addr(1), addr(2), 1_000, 200, 300, 10),
            TransferStep::conserving(addr(3), addr(4), 500, 50, 100, 5),
            TransferStep::conserving(addr(5), addr(6), 2_000, 0, 1_500, 20),
        ];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();
        verify_batch(proof, pub_inputs).expect("a genuinely conserving batch must verify");
    }

    #[test]
    fn tampering_with_a_reported_balance_after_proving_is_rejected() {
        let steps = vec![TransferStep::conserving(addr(1), addr(2), 1_000, 200, 300, 10)];
        let (proof, mut pub_inputs) = prove_batch(&steps).unwrap();
        // Flip the claimed from_after value (column 4, step 0) to
        // something that no longer satisfies the conservation equation -
        // the proof was computed against the *original* trace, so it
        // must not verify against these tampered public inputs.
        pub_inputs.columns[COL_FROM_AFTER][0] += BaseElement::ONE;
        assert!(verify_batch(proof, pub_inputs).is_err(), "a forged public input must be rejected");
    }

    #[test]
    fn an_inconsistent_batch_produces_no_proof_that_verifies() {
        // A "broken prover" claiming from_after doesn't actually equal
        // from_before - amount - fee. Proving over an inconsistent trace
        // must never end up with a proof that verifies. In a debug
        // build, Winterfell's own internal (debug-only) consistency
        // check catches this by panicking inside `prove_batch` itself
        // (see module docs) - that panic is as acceptable a rejection as
        // an `Err` or a failed `verify_batch`, so it's caught here rather
        // than allowed to fail the test.
        let mut steps = vec![TransferStep::conserving(addr(1), addr(2), 1_000, 200, 300, 10)];
        steps[0].from_after += 1; // break conservation

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prove_batch(&steps)));
        match result {
            Err(_) => {} // Winterfell's debug-only internal check panicked - rejected
            Ok(Err(_)) => {} // rejected at proving time via a real ProverError
            Ok(Ok((proof, pub_inputs))) => {
                assert!(verify_batch(proof, pub_inputs).is_err(), "an inconsistent batch must never produce a verifying proof");
            }
        }
    }

    #[test]
    fn padding_rows_are_transparent_and_dont_affect_verification() {
        // 3 real steps need a padded length of 4 (next power of two
        // strictly greater than 3), but Winterfell's TraceInfo enforces
        // MIN_TRACE_LENGTH = 8, so the actual trace clamps up to 8 -
        // confirms the padding scheme itself (all-zero rows) doesn't
        // break proving/verification even when padding is mostly
        // padding rather than real data.
        let steps = vec![
            TransferStep::conserving(addr(1), addr(2), 10, 10, 1, 0),
            TransferStep::conserving(addr(3), addr(4), 20, 20, 2, 0),
            TransferStep::conserving(addr(5), addr(6), 30, 30, 3, 0),
        ];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();
        assert_eq!(pub_inputs.columns[COL_FROM_BEFORE].len(), 8, "3 real rows clamp up to MIN_TRACE_LENGTH (8)");
        verify_batch(proof, pub_inputs).unwrap();
    }

    #[test]
    fn is_valid_u64_accepts_the_full_u64_range_and_rejects_beyond_it() {
        assert!(is_valid_u64(BaseElement::ZERO));
        assert!(is_valid_u64(BaseElement::new(u64::MAX as u128)));
        assert!(!is_valid_u64(BaseElement::new(u64::MAX as u128 + 1)));
        // The field's modulus itself, and a value just below it (as a
        // field-negation of a small number would produce), are both
        // enormously out of u64 range.
        assert!(!is_valid_u64(BaseElement::ZERO - BaseElement::ONE));
        assert!(!is_valid_u64(BaseElement::ZERO - BaseElement::new(500)));
    }

    #[test]
    fn an_out_of_range_disguised_negative_amount_is_rejected_even_though_the_stark_proof_alone_would_accept_it() {
        // The exact attack the module docs' "v2" section names: set
        // `amount` to the field negation of 500 (a field element near
        // the modulus, nowhere close to a real u64) instead of a real
        // positive value. Both conservation equations still hold
        // *exactly* as field arithmetic:
        //   to_after   = to_before + amount   = to_before - 500 (mod p)
        //   from_after = from_before - amount - fee = from_before + 500 - fee (mod p)
        // and both results land on small, plausible-looking numbers -
        // so the STARK's polynomial constraints are satisfied and the
        // proof verifies. Only the post-verification range check (on
        // `amount` itself, column 2) catches that this "transfer" was
        // actually built from a value that isn't a real u64 at all.
        let from_before = BaseElement::new(1_000);
        let to_before = BaseElement::new(1_000);
        let fee = BaseElement::new(10);
        let amount = BaseElement::ZERO - BaseElement::new(500); // "-500", disguised as a huge field element
        let from_after = from_before - amount - fee;
        let to_after = to_before + amount;

        let padded_len = TraceInfo::MIN_TRACE_LENGTH;
        let mut columns: Vec<Vec<BaseElement>> = vec![vec![BaseElement::ZERO; padded_len]; TRACE_WIDTH];
        columns[0][0] = from_before;
        columns[1][0] = to_before;
        columns[2][0] = amount;
        columns[3][0] = fee;
        columns[4][0] = from_after;
        columns[5][0] = to_after;
        let trace = TraceTable::init(columns);

        let prover = TransferProver::new(default_proof_options());
        let pub_inputs = prover.get_pub_inputs(&trace);
        let proof = prover.prove(trace).expect("both conservation equations hold as field arithmetic, so the STARK proof itself succeeds");

        match verify_batch(proof, pub_inputs) {
            Err(VerifyError::ValueOutOfU64Range { column: 2, step: 0 }) => {} // caught exactly where expected
            Err(other) => panic!("expected the range check on column 2 (amount) to reject this, got a different error: {other:?}"),
            Ok(()) => panic!("a disguised out-of-range amount must never verify"),
        }
    }

    // --- v3: real Merkle tie-in, tested against a genuine qchain-storage StateTree ---

    use qchain_crypto::{Keypair, Pubkey};
    use qchain_storage::{InMemoryStore, StateStore};

    fn wallet(balance: u64) -> Account {
        Account { balance, nonce: 0, algorithm_id: qchain_crypto::COMBO_HYBRID_ED25519_ML_DSA_65, owner: Pubkey::system_program_id(), code_hash: [0u8; 32], data: vec![] }
    }

    #[test]
    fn a_genuine_transfer_binds_to_a_real_merkle_root_transition() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));
        store.set(bob, wallet(200));

        let tree = StateTree::new();
        let root_before = tree.root(&store);
        let alice_before = store.get(&alice).unwrap();
        let bob_before = store.get(&bob).unwrap();
        let proof_alice_before = tree.prove(&store, &alice);
        let proof_bob_before = tree.prove(&store, &bob);

        // Apply the same transfer the STARK will prove: amount=300, fee=10.
        store.set(alice, wallet(690));
        store.set(bob, wallet(500));
        let root_after = tree.root(&store);
        let alice_after = store.get(&alice).unwrap();
        let bob_after = store.get(&bob).unwrap();
        let proof_alice_after = tree.prove(&store, &alice);
        let proof_bob_after = tree.prove(&store, &bob);

        let steps = vec![TransferStep::conserving(alice.to_bytes(), bob.to_bytes(), 1_000, 200, 300, 10)];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();

        let binding = RowStateBinding {
            root_before,
            root_after,
            from_before: alice_before,
            from_after: alice_after,
            to_before: bob_before,
            to_after: bob_after,
            from_proof_before: proof_alice_before,
            from_proof_after: proof_alice_after,
            to_proof_before: proof_bob_before,
            to_proof_after: proof_bob_after,
        };

        verify_batch_bound_to_state(proof, pub_inputs, &[binding]).expect("a genuine transfer must bind to the real Merkle root transition");
    }

    /// Real, non-hypothetical case found via a live 3-node testnet run: the
    /// very first transfer to a brand-new address means `to_before` is a
    /// genuine *exclusion* proof (the address has no row in the tree at
    /// all yet), not merely "an inclusion proof for a zero balance." An
    /// earlier version of `verify_batch_bound_to_state` unconditionally
    /// compared `leaf_value_hash` against `Some(hash_leaf(account))`,
    /// which can never equal `None` - so this exact (extremely common)
    /// case always failed with a spurious `MerkleProofFailed` on
    /// `to_before`, even though everything about the transfer was genuine.
    #[test]
    fn a_transfer_to_a_brand_new_recipient_binds_correctly() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey(); // never set in the store - genuinely new
        store.set(alice, wallet(1_000));

        let tree = StateTree::new();
        let root_before = tree.root(&store);
        let alice_before = store.get(&alice).unwrap();
        let to_before = Account::new_wallet(Pubkey::system_program_id()); // balance 0, matching the exclusion proof
        let proof_alice_before = tree.prove(&store, &alice);
        let proof_bob_before = tree.prove(&store, &bob);
        assert!(proof_bob_before.leaf_value_hash.is_none(), "bob must not have a row yet - this test only means something if he's genuinely absent");

        store.set(alice, wallet(690));
        store.set(bob, wallet(300));
        let root_after = tree.root(&store);
        let alice_after = store.get(&alice).unwrap();
        let bob_after = store.get(&bob).unwrap();
        let proof_alice_after = tree.prove(&store, &alice);
        let proof_bob_after = tree.prove(&store, &bob);

        let steps = vec![TransferStep::conserving(alice.to_bytes(), bob.to_bytes(), 1_000, 0, 300, 10)];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();

        let binding = RowStateBinding {
            root_before,
            root_after,
            from_before: alice_before,
            from_after: alice_after,
            to_before,
            to_after: bob_after,
            from_proof_before: proof_alice_before,
            from_proof_after: proof_alice_after,
            to_proof_before: proof_bob_before,
            to_proof_after: proof_bob_after,
        };

        verify_batch_bound_to_state(proof, pub_inputs, &[binding])
            .expect("a transfer to a genuinely brand-new recipient must bind correctly via its real exclusion proof");
    }

    #[test]
    fn an_exclusion_proof_claiming_a_nonzero_balance_is_rejected() {
        // A malicious/buggy binding: `to_before`'s proof is a real
        // exclusion proof (bob has no row), but the supplied snapshot
        // claims he already had a balance - unsound if accepted, since an
        // absent key cannot hold a real positive balance.
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));

        let tree = StateTree::new();
        let root_before = tree.root(&store);
        let alice_before = store.get(&alice).unwrap();
        let forged_to_before = wallet(500); // claims bob already had 500, despite no real row
        let proof_alice_before = tree.prove(&store, &alice);
        let proof_bob_before = tree.prove(&store, &bob);

        store.set(alice, wallet(690));
        store.set(bob, wallet(800));
        let root_after = tree.root(&store);
        let alice_after = store.get(&alice).unwrap();
        let bob_after = store.get(&bob).unwrap();
        let proof_alice_after = tree.prove(&store, &alice);
        let proof_bob_after = tree.prove(&store, &bob);

        let steps = vec![TransferStep::conserving(alice.to_bytes(), bob.to_bytes(), 1_000, 500, 300, 10)];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();

        let binding = RowStateBinding {
            root_before,
            root_after,
            from_before: alice_before,
            from_after: alice_after,
            to_before: forged_to_before,
            to_after: bob_after,
            from_proof_before: proof_alice_before,
            from_proof_after: proof_alice_after,
            to_proof_before: proof_bob_before,
            to_proof_after: proof_bob_after,
        };

        match verify_batch_bound_to_state(proof, pub_inputs, &[binding]) {
            Err(StateBindingError::ExclusionProofClaimsNonzeroBalance { row: 0, field: "to_before" }) => {}
            other => panic!("expected ExclusionProofClaimsNonzeroBalance on to_before, got {other:?}"),
        }
    }

    #[test]
    fn a_sequence_of_two_transfers_chains_real_roots_correctly() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();
        let carol = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));
        store.set(bob, wallet(200));
        store.set(carol, wallet(50));

        let tree = StateTree::new();
        let root_0 = tree.root(&store);

        // Row 0: alice -(300, fee 10)-> bob.
        let alice_before_0 = store.get(&alice).unwrap();
        let bob_before_0 = store.get(&bob).unwrap();
        let proof_alice_before_0 = tree.prove(&store, &alice);
        let proof_bob_before_0 = tree.prove(&store, &bob);
        store.set(alice, wallet(690));
        store.set(bob, wallet(500));
        let root_1 = tree.root(&store);
        let alice_after_0 = store.get(&alice).unwrap();
        let bob_after_0 = store.get(&bob).unwrap();
        let proof_alice_after_0 = tree.prove(&store, &alice);
        let proof_bob_after_0 = tree.prove(&store, &bob);

        // Row 1: bob -(100, fee 5)-> carol - bob's "before" here is its
        // real post-row-0 state (500), proving the roots genuinely chain.
        let bob_before_1 = store.get(&bob).unwrap();
        let carol_before_1 = store.get(&carol).unwrap();
        let proof_bob_before_1 = tree.prove(&store, &bob);
        let proof_carol_before_1 = tree.prove(&store, &carol);
        store.set(bob, wallet(395));
        store.set(carol, wallet(150));
        let root_2 = tree.root(&store);
        let bob_after_1 = store.get(&bob).unwrap();
        let carol_after_1 = store.get(&carol).unwrap();
        let proof_bob_after_1 = tree.prove(&store, &bob);
        let proof_carol_after_1 = tree.prove(&store, &carol);

        let steps = vec![
            TransferStep::conserving(alice.to_bytes(), bob.to_bytes(), 1_000, 200, 300, 10),
            TransferStep::conserving(bob.to_bytes(), carol.to_bytes(), 500, 50, 100, 5),
        ];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();

        let bindings = vec![
            RowStateBinding {
                root_before: root_0,
                root_after: root_1,
                from_before: alice_before_0,
                from_after: alice_after_0,
                to_before: bob_before_0,
                to_after: bob_after_0,
                from_proof_before: proof_alice_before_0,
                from_proof_after: proof_alice_after_0,
                to_proof_before: proof_bob_before_0,
                to_proof_after: proof_bob_after_0,
            },
            RowStateBinding {
                root_before: root_1,
                root_after: root_2,
                from_before: bob_before_1,
                from_after: bob_after_1,
                to_before: carol_before_1,
                to_after: carol_after_1,
                from_proof_before: proof_bob_before_1,
                from_proof_after: proof_bob_after_1,
                to_proof_before: proof_carol_before_1,
                to_proof_after: proof_carol_after_1,
            },
        ];

        verify_batch_bound_to_state(proof, pub_inputs, &bindings).expect("a real two-step chain of root transitions must bind successfully");
    }

    #[test]
    fn a_binding_with_broken_root_sequencing_is_rejected() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));
        store.set(bob, wallet(200));
        let tree = StateTree::new();
        let root_before = tree.root(&store);
        let alice_before = store.get(&alice).unwrap();
        let bob_before = store.get(&bob).unwrap();
        let proof_alice_before = tree.prove(&store, &alice);
        let proof_bob_before = tree.prove(&store, &bob);
        store.set(alice, wallet(690));
        store.set(bob, wallet(500));
        let root_after = tree.root(&store);
        let alice_after = store.get(&alice).unwrap();
        let bob_after = store.get(&bob).unwrap();
        let proof_alice_after = tree.prove(&store, &alice);
        let proof_bob_after = tree.prove(&store, &bob);

        let steps = vec![
            TransferStep::conserving(alice.to_bytes(), bob.to_bytes(), 1_000, 200, 300, 10),
            TransferStep::conserving(alice.to_bytes(), bob.to_bytes(), 1_000, 200, 300, 10),
        ];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();

        // Both rows claim the *same* root_before/root_after pair instead
        // of the second row's root_before chaining from the first row's
        // root_after - two disconnected, independently-valid-looking
        // proofs, not one coherent state transition.
        let binding = RowStateBinding {
            root_before,
            root_after,
            from_before: alice_before,
            from_after: alice_after,
            to_before: bob_before,
            to_after: bob_after,
            from_proof_before: proof_alice_before,
            from_proof_after: proof_alice_after,
            to_proof_before: proof_bob_before,
            to_proof_after: proof_bob_after,
        };
        let bindings = vec![binding.clone(), binding];

        match verify_batch_bound_to_state(proof, pub_inputs, &bindings) {
            Err(StateBindingError::RootSequenceMismatch { row: 0 }) => {}
            other => panic!("expected a RootSequenceMismatch at row 0, got {other:?}"),
        }
    }

    #[test]
    fn a_binding_whose_balance_doesnt_match_the_stark_is_rejected() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));
        store.set(bob, wallet(200));
        let tree = StateTree::new();
        let root_before = tree.root(&store);
        let proof_alice_before = tree.prove(&store, &alice);
        let proof_bob_before = tree.prove(&store, &bob);
        store.set(alice, wallet(690));
        store.set(bob, wallet(500));
        let root_after = tree.root(&store);
        let alice_after = store.get(&alice).unwrap();
        let bob_after = store.get(&bob).unwrap();
        let proof_alice_after = tree.prove(&store, &alice);
        let proof_bob_after = tree.prove(&store, &bob);

        let steps = vec![TransferStep::conserving(alice.to_bytes(), bob.to_bytes(), 1_000, 200, 300, 10)];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();

        let binding = RowStateBinding {
            root_before,
            root_after,
            from_before: wallet(999), // doesn't match the STARK's public from_before (1_000)
            from_after: alice_after,
            to_before: wallet(200),
            to_after: bob_after,
            from_proof_before: proof_alice_before,
            from_proof_after: proof_alice_after,
            to_proof_before: proof_bob_before,
            to_proof_after: proof_bob_after,
        };

        match verify_batch_bound_to_state(proof, pub_inputs, &[binding]) {
            Err(StateBindingError::BalanceMismatch { row: 0, field: "from_before" }) => {}
            other => panic!("expected a BalanceMismatch on from_before at row 0, got {other:?}"),
        }
    }

    #[test]
    fn a_binding_whose_merkle_proof_is_for_the_wrong_address_is_rejected() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();
        let mallory = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));
        store.set(bob, wallet(200));
        store.set(mallory, wallet(50));
        let tree = StateTree::new();
        let root_before = tree.root(&store);
        let alice_before = store.get(&alice).unwrap();
        let bob_before = store.get(&bob).unwrap();
        // Wrong proof: mallory's inclusion proof, not alice's.
        let proof_mallory_before = tree.prove(&store, &mallory);
        let proof_bob_before = tree.prove(&store, &bob);
        store.set(alice, wallet(690));
        store.set(bob, wallet(500));
        let root_after = tree.root(&store);
        let alice_after = store.get(&alice).unwrap();
        let bob_after = store.get(&bob).unwrap();
        let proof_alice_after = tree.prove(&store, &alice);
        let proof_bob_after = tree.prove(&store, &bob);

        let steps = vec![TransferStep::conserving(alice.to_bytes(), bob.to_bytes(), 1_000, 200, 300, 10)];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();

        let binding = RowStateBinding {
            root_before,
            root_after,
            from_before: alice_before,
            from_after: alice_after,
            to_before: bob_before,
            to_after: bob_after,
            from_proof_before: proof_mallory_before,
            from_proof_after: proof_alice_after,
            to_proof_before: proof_bob_before,
            to_proof_after: proof_bob_after,
        };

        match verify_batch_bound_to_state(proof, pub_inputs, &[binding]) {
            Err(StateBindingError::AddressMismatch { row: 0, field: "from" }) => {}
            other => panic!("expected an AddressMismatch on 'from' at row 0, got {other:?}"),
        }
    }

    #[test]
    fn a_binding_against_a_stale_root_is_rejected() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));
        store.set(bob, wallet(200));
        let tree = StateTree::new();
        let root_before = tree.root(&store);
        let alice_before = store.get(&alice).unwrap();
        let bob_before = store.get(&bob).unwrap();
        let proof_alice_before = tree.prove(&store, &alice);
        let proof_bob_before = tree.prove(&store, &bob);
        store.set(alice, wallet(690));
        store.set(bob, wallet(500));
        let alice_after = store.get(&alice).unwrap();
        let bob_after = store.get(&bob).unwrap();
        let proof_alice_after = tree.prove(&store, &alice);
        let proof_bob_after = tree.prove(&store, &bob);

        let steps = vec![TransferStep::conserving(alice.to_bytes(), bob.to_bytes(), 1_000, 200, 300, 10)];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();

        let binding = RowStateBinding {
            root_before,
            root_after: root_before, // wrong: claims the state never changed
            from_before: alice_before,
            from_after: alice_after,
            to_before: bob_before,
            to_after: bob_after,
            from_proof_before: proof_alice_before,
            from_proof_after: proof_alice_after,
            to_proof_before: proof_bob_before,
            to_proof_after: proof_bob_after,
        };

        match verify_batch_bound_to_state(proof, pub_inputs, &[binding]) {
            Err(StateBindingError::MerkleProofFailed { row: 0, .. }) => {}
            other => panic!("expected a MerkleProofFailed (the 'after' proofs don't verify against the stale root), got {other:?}"),
        }
    }

    #[test]
    fn public_inputs_and_row_state_binding_round_trip_through_real_json_and_a_verify_call() {
        // Exercises exactly what `qchain-node`'s RPC layer will do: prove
        // and bind against a real Merkle transition, serialize everything
        // to JSON (including the `Proof` itself via its real
        // `to_bytes`/`from_bytes`, hex-encoded - the wire format a light
        // client actually receives), deserialize it back, and confirm
        // `verify_batch_bound_to_state` still accepts the round-tripped
        // values. A derive that merely compiles wouldn't catch a lossy
        // conversion (e.g. `BaseElement`'s u128 truncating through a
        // smaller wire type) - only an end-to-end verify call would.
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));
        store.set(bob, wallet(200));

        let tree = StateTree::new();
        let root_before = tree.root(&store);
        let alice_before = store.get(&alice).unwrap();
        let bob_before = store.get(&bob).unwrap();
        let proof_alice_before = tree.prove(&store, &alice);
        let proof_bob_before = tree.prove(&store, &bob);

        store.set(alice, wallet(690));
        store.set(bob, wallet(500));
        let root_after = tree.root(&store);
        let alice_after = store.get(&alice).unwrap();
        let bob_after = store.get(&bob).unwrap();
        let proof_alice_after = tree.prove(&store, &alice);
        let proof_bob_after = tree.prove(&store, &bob);

        let steps = vec![TransferStep::conserving(alice.to_bytes(), bob.to_bytes(), 1_000, 200, 300, 10)];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();
        let binding = RowStateBinding {
            root_before,
            root_after,
            from_before: alice_before,
            from_after: alice_after,
            to_before: bob_before,
            to_after: bob_after,
            from_proof_before: proof_alice_before,
            from_proof_after: proof_alice_after,
            to_proof_before: proof_bob_before,
            to_proof_after: proof_bob_after,
        };

        // Round-trip the proof bytes, the public inputs, and the binding
        // through real JSON - the same serialization RPC/HTTP transport uses.
        let proof_hex = hex::encode(proof.to_bytes());
        let pub_inputs_json = serde_json::to_string(&pub_inputs).unwrap();
        let bindings_json = serde_json::to_string(&std::slice::from_ref(&binding)).unwrap();

        let round_tripped_proof = Proof::from_bytes(&hex::decode(&proof_hex).unwrap()).unwrap();
        let round_tripped_pub_inputs: PublicInputs = serde_json::from_str(&pub_inputs_json).unwrap();
        let round_tripped_bindings: Vec<RowStateBinding> = serde_json::from_str(&bindings_json).unwrap();

        verify_batch_bound_to_state(round_tripped_proof, round_tripped_pub_inputs, &round_tripped_bindings)
            .expect("a proof/public-inputs/binding round-tripped through real JSON must still verify");
    }
}
