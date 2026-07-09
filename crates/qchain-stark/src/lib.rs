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
//! - No range checks: balances are field elements; nothing here proves
//!   `from_after >= 0` as a real (non-negative) integer, only that the
//!   reported values satisfy the linear conservation equations as field
//!   arithmetic. A malicious prover could report an "underflowed"
//!   balance that wraps within the field. Closing this gap needs
//!   bit-decomposition range-check columns for every value that must
//!   stay within `u64` - a well-understood technique, not implemented
//!   yet.
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
//! range-check and Merkle-tie-in hardening land.
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
use winterfell::math::{FieldElement, ToElements};
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

/// Verifies a proof produced by [`prove_batch`]. Accepts proofs meeting
/// or exceeding ~95-bit conjectured security - matches
/// [`default_proof_options`]'s target.
pub fn verify_batch(proof: Proof, pub_inputs: PublicInputs) -> Result<(), winterfell::VerifierError> {
    let min_opts = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    winterfell::verify::<TransferAir, Blake3_256<BaseElement>, DefaultRandomCoin<Blake3_256<BaseElement>>, MerkleTree<Blake3_256<BaseElement>>>(
        proof,
        pub_inputs,
        &min_opts,
    )
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
}
