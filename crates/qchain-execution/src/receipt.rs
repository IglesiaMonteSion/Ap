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
#[derive(
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
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
    /// A withdrawal request/closure of a stake position that actually returned
    /// funds (a normal delegator, or a self-stake's completing second step).
    Undelegate,
    /// The FIRST step of a self-stake (owner == validator) withdrawal: it only
    /// starts the 100-round unbonding clock and returns NO funds yet - a second
    /// `Undelegate` after the period actually withdraws. Recorded distinctly so
    /// the activity log never misleadingly claims the principal came back when
    /// it only entered unbonding (the exact confusion a real user hit).
    UnbondingStarted,
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
#[derive(
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
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
    /// The four legacy 256-deep Merkle proofs (each ~8KB = 256 siblings) - the
    /// heavy part of a receipt (~32KB of the ~33KB total). `Option` so they can
    /// be STRIPPED for old receipts: `/stark_proof` only ever needs the most
    /// recent `<= 500`, so the node keeps full proofs for the last few hundred
    /// and drops them (`None`) for older receipts, which are still fully useful
    /// for `/transfers` (from/to/amount/fee + before/after account snapshots).
    /// This is what keeps the receipt log's RAM/disk from tracking chain age at
    /// 32KB/receipt. `#[serde(default)]` so a receipt persisted with full proofs
    /// (or none) still deserializes.
    #[serde(default)]
    pub from_proof_before: Option<MerkleProof>,
    #[serde(default)]
    pub from_proof_after: Option<MerkleProof>,
    #[serde(default)]
    pub to_proof_before: Option<MerkleProof>,
    #[serde(default)]
    pub to_proof_after: Option<MerkleProof>,
    /// In compressed-state-tree mode, the O(log n) proofs for this transfer
    /// (see `CompressedProofSet`). `None` in legacy mode. `#[serde(default)]` so
    /// receipts persisted before this field existed still deserialize as `None`
    /// (legacy). When `Some`, the four `MerkleProof` fields above are unused
    /// address-only placeholders and the node's `/stark_proof` builder reads
    /// this instead.
    #[serde(default)]
    pub compressed_proofs: Option<CompressedProofSet>,
}

impl TransferReceipt {
    /// Whether this receipt still carries its Merkle proofs (legacy or
    /// compressed) - i.e. it can back a `/stark_proof`. `false` for an old
    /// receipt whose proofs were stripped to save RAM/disk (still valid for
    /// `/transfers`).
    pub fn has_proofs(&self) -> bool {
        self.from_proof_before.is_some() || self.compressed_proofs.is_some()
    }

    /// A copy with the heavy Merkle proofs dropped - the ~600-byte "light" form
    /// kept for older receipts and persisted for `/transfers` history. Keeps
    /// everything the explorer needs (addresses, amounts, fee, round, roots,
    /// before/after account snapshots); drops only the ~32KB of proofs.
    pub fn without_proofs(&self) -> TransferReceipt {
        TransferReceipt {
            from_proof_before: None,
            from_proof_after: None,
            to_proof_before: None,
            to_proof_after: None,
            compressed_proofs: None,
            ..self.clone()
        }
    }

    /// Drops this receipt's proofs in place (see `without_proofs`).
    pub fn strip_proofs(&mut self) {
        self.from_proof_before = None;
        self.from_proof_after = None;
        self.to_proof_before = None;
        self.to_proof_after = None;
        self.compressed_proofs = None;
    }
}
