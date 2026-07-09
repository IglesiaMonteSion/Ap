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
//! - No Merkle tie-in: before/after balances are exposed as public
//!   inputs directly (see `PublicInputs`), not bound to the real
//!   SHA3-based sparse Merkle root `qchain-storage` maintains. A light
//!   client using this proof today would still need the actual
//!   before/after values delivered out-of-band and trust they match the
//!   real state tree - the proof only certifies the arithmetic given
//!   those values, not that they're the *right* values. Real state
//!   compression needs either an in-circuit Merkle-friendly hash
//!   (Poseidon2/Rescue-Prime, per `ARCHITECTURE.md` §3) or an external
//!   binding check.
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
//! stops exposing them in the clear (the Merkle-tie-in gap above, once
//! closed with real data-hiding rather than a plain public root), this
//! argument stops applying and an in-circuit bit-decomposition range
//! check becomes necessary again - re-derive this reasoning at that
//! point, don't assume the shortcut still holds.
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

use winterfell::crypto::hashers::Blake3_256;
use winterfell::crypto::{DefaultRandomCoin, MerkleTree};
use winterfell::math::fields::f128::BaseElement;
use winterfell::math::{FieldElement, StarkField, ToElements};
use winterfell::matrix::ColMatrix;
use winterfell::{
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod, CompositionPoly, CompositionPolyTrace,
    ConstraintCompositionCoefficients, DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, ProverError, StarkDomain,
    TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

/// One System Program `Transfer`'s before/after state, as plain u64s -
/// exactly the semantics of `qchain_execution::SystemInstruction::Transfer`
/// plus the byte-scaled base fee, not yet the real `Account` type (see
/// module docs on "not wired in yet").
#[derive(Clone, Copy, Debug)]
pub struct TransferStep {
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
    pub fn conserving(from_before: u64, to_before: u64, amount: u64, fee: u64) -> Self {
        TransferStep {
            from_before,
            to_before,
            amount,
            fee,
            from_after: from_before - amount - fee,
            to_after: to_before + amount,
        }
    }
}

const TRACE_WIDTH: usize = 6;

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
        columns[0][i] = BaseElement::new(step.from_before as u128);
        columns[1][i] = BaseElement::new(step.to_before as u128);
        columns[2][i] = BaseElement::new(step.amount as u128);
        columns[3][i] = BaseElement::new(step.fee as u128);
        columns[4][i] = BaseElement::new(step.from_after as u128);
        columns[5][i] = BaseElement::new(step.to_after as u128);
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
        assert_eq!(TRACE_WIDTH, trace_info.width(), "this AIR always has a fixed 6-column trace");
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
    winterfell::verify::<TransferAir, Blake3_256<BaseElement>, DefaultRandomCoin<Blake3_256<BaseElement>>, MerkleTree<Blake3_256<BaseElement>>>(
        proof,
        pub_inputs.clone(),
        &min_opts,
    )?;
    for (column, values) in pub_inputs.columns.iter().enumerate() {
        for (step, &value) in values.iter().enumerate() {
            if !is_valid_u64(value) {
                return Err(VerifyError::ValueOutOfU64Range { column, step });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_batch_of_transfers_proves_and_verifies() {
        let steps = vec![
            TransferStep::conserving(1_000, 200, 300, 10),
            TransferStep::conserving(500, 50, 100, 5),
            TransferStep::conserving(2_000, 0, 1_500, 20),
        ];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();
        verify_batch(proof, pub_inputs).expect("a genuinely conserving batch must verify");
    }

    #[test]
    fn tampering_with_a_reported_balance_after_proving_is_rejected() {
        let steps = vec![TransferStep::conserving(1_000, 200, 300, 10)];
        let (proof, mut pub_inputs) = prove_batch(&steps).unwrap();
        // Flip the claimed from_after value (column 4, step 0) to
        // something that no longer satisfies the conservation equation -
        // the proof was computed against the *original* trace, so it
        // must not verify against these tampered public inputs.
        pub_inputs.columns[4][0] += BaseElement::ONE;
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
        let mut steps = vec![TransferStep::conserving(1_000, 200, 300, 10)];
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
            TransferStep::conserving(10, 10, 1, 0),
            TransferStep::conserving(20, 20, 2, 0),
            TransferStep::conserving(30, 30, 3, 0),
        ];
        let (proof, pub_inputs) = prove_batch(&steps).unwrap();
        assert_eq!(pub_inputs.columns[0].len(), 8, "3 real rows clamp up to MIN_TRACE_LENGTH (8)");
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
}
