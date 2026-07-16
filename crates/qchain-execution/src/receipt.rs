//! Real, captured before/after state for a `SystemProgram::Transfer` -
//! the ingredients a light client needs to independently verify a
//! `qchain-stark` state-bound proof (`qchain_stark::verify_batch_bound_to_state`)
//! against this specific transfer. Deliberately narrow: `Ledger`'s store
//! (`qchain-storage::StateStore`) has no history at all (see
//! `project-lessons-learned`), so a receipt can only ever be captured
//! *at the moment* a transfer executes, not reconstructed after the
//! fact - `Ledger::apply_transaction` is the only place this is built.
//!
//! Scoped to the exact shape `qchain-stark`'s AIR models: a
//! single-instruction transaction whose one instruction is
//! `SystemInstruction::Transfer`. `SystemProgram` already enforces
//! `from == payer` unconditionally (see `native.rs`), so the STARK's
//! `fee` field can only mean "this transaction's byte-scaled base fee"
//! when there's exactly one instruction - a transaction with several
//! instructions could touch the same account more than once, or split
//! one transaction's single fee charge across multiple transfers, which
//! the circuit's per-row conservation equation doesn't model. Multi-
//! instruction transactions are deliberately not captured, not silently
//! mismodeled.
//!
//! Kept as an unbounded, in-memory `Vec` on `Ledger` - the same "no
//! persistence, no pruning" simplification already accepted project-wide
//! (see `ARCHITECTURE.md`'s phase-1 simplifications) - a real deployment
//! needs to cap/evict/persist this, not implemented here.
//!
//! One more explicit gap: `from_after`/`to_after` are captured
//! *immediately* after the transfer instruction runs, before
//! `Ledger::apply_transaction`'s dust-sweep pass - the STARK's
//! conservation equations model the transfer's own raw arithmetic, not
//! the dust-sweep adjustment that may still zero a small resulting
//! balance afterward. A receipt (and any proof built from it) is
//! therefore honest about the instruction's arithmetic, not necessarily
//! about the account's *final* committed balance if dust-sweep touched
//! it - the same class of simplification `qchain-stark`'s own docs
//! already flag ("doesn't re-derive full Ledger fee/nonce semantics").

use qchain_core::Account;
use qchain_crypto::Pubkey;
use qchain_storage::compressed::CompressedProof;
use qchain_storage::MerkleProof;

/// The four O(log n) path-compressed proofs a transfer receipt carries when the
/// ledger runs the compressed state tree (`Ledger::is_compressed()`). Present
/// (`Some`) only in compressed mode; in legacy mode the receipt's four
/// `*_proof_*: MerkleProof` fields carry the 256-deep proofs instead and this is
/// `None`. Directly convertible to `qchain_stark::CompressedRowStateBinding`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CompressedProofSet {
    pub from_proof_before: CompressedProof,
    pub from_proof_after: CompressedProof,
    pub to_proof_before: CompressedProof,
    pub to_proof_after: CompressedProof,
}

/// Which staking action a `StakingEvent` records. Kept as an explicit enum
/// (not a string) so the wire/JSON is stable and a consumer can switch on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StakingEventKind {
    /// Funds moved *into* staking (a new/topped-up delegation). This is the
    /// "transfers to staking" the block explorer's transfer list can't show,
    /// because staking instructions never produce a `TransferReceipt`.
    Delegate,
    /// A withdrawal request/closure of a stake position.
    Undelegate,
    /// A claim of accrued staking rewards.
    ClaimReward,
}

/// A captured staking action, so the validator dashboard can show staking
/// activity alongside plain transfers. Captured live in
/// `Ledger::apply_transaction` (the store has no history to reconstruct from,
/// same as `TransferReceipt`), only for single-instruction staking
/// transactions - the exact shape `qchain-cli`/the wallet build. In-memory,
/// unbounded, reset on restart - the same documented simplification as
/// `TransferReceipt`. `amount` is exact for `Delegate` (the deposited amount);
/// for `Undelegate`/`ClaimReward` it reflects the position's state read just
/// before the call (principal / pending reward), which is what actually moves
/// for an ordinary delegator.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StakingEvent {
    pub tx_hash: [u8; 32],
    pub kind: StakingEventKind,
    /// The delegator (the transaction payer / the stake account's owner).
    pub staker: Pubkey,
    /// The validator the stake is bonded to.
    pub validator: Pubkey,
    /// The (deterministic, seed-derived in the wallet) stake account address.
    pub stake_account: Pubkey,
    /// Amount that moved: deposited (Delegate) / principal (Undelegate) /
    /// reward (ClaimReward).
    pub amount: u64,
    /// The consensus round this executed in.
    pub round: u64,
}

/// Real before/after state for one `SystemProgram::Transfer`, captured
/// live as it executed - see module docs for exactly what's captured and
/// why. Directly convertible to `qchain_stark::TransferStep`/
/// `RowStateBinding` by whoever builds a proof from a range of these
/// (`qchain-node`'s RPC layer, kept free of a `qchain-stark` dependency
/// here in `qchain-execution` deliberately - proof generation is a
/// presentation-layer concern, not an execution-layer one).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TransferReceipt {
    pub tx_hash: [u8; 32],
    /// The consensus round this transfer executed in. `#[serde(default)]` so
    /// receipts persisted before this field existed still deserialize (round 0).
    /// Lets a merged activity view (transfers + staking) order both by round.
    #[serde(default)]
    pub round: u64,
    pub from: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
    pub fee: u64,
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
    /// In compressed-state-tree mode, the O(log n) proofs for this transfer
    /// (see `CompressedProofSet`). `None` in legacy mode. `#[serde(default)]` so
    /// receipts persisted before this field existed still deserialize as `None`
    /// (legacy). When `Some`, the four `MerkleProof` fields above are unused
    /// address-only placeholders and the node's `/stark_proof` builder reads
    /// this instead.
    #[serde(default)]
    pub compressed_proofs: Option<CompressedProofSet>,
}
