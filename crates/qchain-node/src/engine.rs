//! Wires storage, execution, and consensus into a running validator
//! (design: `ARCHITECTURE.md` §1/§4). Implements the real Narwhal
//! propose -> vote -> certificate -> broadcast cycle over
//! `qchain-network`'s TCP transport, and drives `qchain-consensus`'s
//! Bullshark ordering to decide what gets executed and when.
//!
//! Phase-1 simplifications, called out explicitly rather than left
//! implicit: no garbage collection of stale vote entries for vertices that
//! never reach quorum, and worker "processes" are simulated as concurrent
//! lanes inside this same validator process rather than genuinely separate
//! OS processes/ports (a real deployment-topology simplification - see the
//! worker-tier paragraph below for what *is* real about it). Both are noted
//! as later hardening work in the `blockchain-core-rust` skill.
//!
//! **Worker tier: batch dissemination is now genuinely separate from
//! primary (vertex/certificate) exchange, not gossiped inline.** Each
//! round, ready transactions are partitioned across `WORKER_COUNT` lanes
//! (by payer address, so one account's transactions always land in the
//! same lane and keep their relative order) into up to `WORKER_COUNT`
//! independent `Batch`es, each gossiped as its own
//! `NetMessage::WorkerBatchGossip { worker_id, batch }` - a small,
//! separately-addressable message, not one bundled with the vertex. The
//! vertex itself only ever carries `(WorkerId, Digest)` pairs
//! (`Vertex::batch_digests`), keeping primary-tier messages small
//! regardless of how much transaction data a round actually carries (see
//! `ARCHITECTURE.md` §2's bandwidth analysis for why this separation
//! exists at all). A lost `WorkerBatchGossip` gets the same real-retry
//! treatment `CertificateRequest`/`CertificateResponse` already give lost
//! certificates: `WorkerBatchRequest`/`WorkerBatchResponse`, triggered
//! whenever a `VertexProposal` or certificate references a batch digest not
//! yet locally known, and naturally retried on every occasion that
//! referencing message itself gets retried (vertex-proposal retry,
//! certificate re-sync) - no separate timer needed. `try_commit` still
//! keeps its lenient warn-and-skip fallback for a batch that's missing at
//! the exact moment of commit (the request/response round-trip is
//! asynchronous and not guaranteed to finish first) - not a regression,
//! the same real limitation phase 1 already had for a single inline batch,
//! now applying per-worker-lane instead of to one batch at a time.
//!
//! **Mempool nonce-ordering bug (found via load testing, see
//! `project-lessons-learned`) - fixed.** The mempool used to be a flat
//! `Vec<Transaction>`, drained wholesale into a batch every round in
//! whatever order transactions happened to arrive. Two transactions from
//! the same account submitted concurrently could land in mempool - and
//! therefore in the same batch - out of nonce order; `try_commit` applies
//! a batch's transactions in order and never retries a failure, so a
//! higher-nonce transaction processed before its lower-nonce predecessor
//! failed with a nonce mismatch and was silently dropped forever. Worse,
//! a transaction that simply hadn't arrived at this validator yet by the
//! time its round's batch was formed suffered the same fate: included
//! without its predecessor, rejected, gone. Fixed by keying the mempool
//! per-account and by nonce (`drain_ready_transactions`) - a transaction
//! only ever enters a batch once every lower nonce for its account is
//! already accounted for, and anything with a gap ahead of it just stays
//! queued for a later round instead of being drained blindly.

use qchain_consensus::{verify_certificate, ConsensusState, DagStore, ValidatorSet};
use qchain_core::{Batch, Certificate, Digest, EquivocationEvidence, Round, Transaction, ValidatorId, Vertex, WorkerId};
use qchain_crypto::{MultiSignature, Keypair, Pubkey};
use qchain_execution::Ledger;
use qchain_network::{NetMessage, Network};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex;

/// How many worker lanes each validator partitions its ready transactions
/// across per round - a per-validator implementation choice, not a
/// consensus parameter (batches are content-addressed by digest, so
/// different validators running different `WORKER_COUNT` values doesn't
/// threaten agreement; it only changes how one validator's own
/// dissemination load is spread). See the module docs above.
const WORKER_COUNT: u8 = 4;

/// Hard cap on how many receipts a single `GET /stark_proof` call will
/// ever prove, regardless of what the caller requests or omits - see
/// `Engine::stark_proof`'s doc comment for the real, live-measured CPU-
/// exhaustion DoS this closes. 500 is comfortably fast on this project's
/// own measured numbers (n=100 proved in ~16.5ms), while still covering a
/// generous "recent activity" window for a real light-client caller.
const MAX_STARK_PROOF_RECEIPTS: usize = 500;

/// Hard cap on how many not-yet-ready transactions a single payer may have
/// queued in this validator's mempool at once. Bounds the real,
/// unbounded-growth mempool OOM this closes: `payer_can_afford_admission`
/// checks only that the payer can afford *one* transaction's byte fee, and
/// `drain_ready_transactions` only ever removes transactions at or
/// consecutively above the account's current nonce - so a payer that submits
/// at nonces `1, 2, 3, …` (deliberately never nonce 0, or leaving any gap)
/// has *nothing* drain, and every one still passes admission (the balance is
/// never decremented at admission time) and is gossiped network-wide. Left
/// generous - far above the ~300 `qchain-cli load-test` legitimately queues -
/// so real burst submission is never the limiting factor, while still
/// bounding worst-case memory per account to a fixed multiple of one
/// transaction's size instead of "however many the attacker cares to send."
const MAX_MEMPOOL_TXS_PER_PAYER: usize = 4_096;

/// Hard cap on cached worker batches. `batches` is fed by unauthenticated
/// `WorkerBatchGossip`/`WorkerBatchResponse` whose keys are content-derived
/// digests an attacker fully controls, so without a bound a peer can stream
/// unlimited distinct junk batches into it - the same unbounded-growth OOM
/// class. Consumed batches are dropped as their certificates commit (see
/// `try_commit`); this cap is the backstop for batches that are gossiped but
/// never end up committed. Generous relative to `WORKER_COUNT` lanes across a
/// realistic in-flight round window.
const MAX_CACHED_BATCHES: usize = 65_536;

/// How many rounds of `(round, author)`-keyed bookkeeping (`voted_for`,
/// `first_seen_vertex`) to retain behind the current round before pruning.
/// These maps gain ~one entry per validator per round *forever* otherwise -
/// a slow but certain OOM on a long-running validator with no attacker at
/// all. A round this far behind the current one can no longer be voted on or
/// have a first-seen vertex that still matters (any equivocation already
/// observed for it is preserved separately in `equivocation_evidence`, which
/// only grows on genuine, slashable misbehavior). Comfortably larger than any
/// resync gap a live validator recovers across in practice.
const ROUND_STATE_RETENTION: Round = 512;

/// How many of `available` receipts a single `/stark_proof` call actually
/// proves, given what the caller requested (`None` meaning "all of them").
/// Always `<= MAX_STARK_PROOF_RECEIPTS` and `<= available` - see
/// `Engine::stark_proof`'s doc comment for the DoS this bound closes.
fn effective_stark_proof_limit(requested: Option<usize>, available: usize) -> usize {
    requested.map_or(available, |n| n.min(available)).min(MAX_STARK_PROOF_RECEIPTS)
}

/// Splits ready transactions into up to `WORKER_COUNT` batches, one per
/// non-empty lane. Lane assignment is by the payer's address so a given
/// account's transactions always land in the same lane and keep their
/// relative (already nonce-ordered, see `drain_ready_transactions`) order
/// within that lane's batch - cross-account ordering never matters since
/// accounts apply independently.
/// Writes `state.next_round` to `state.round_checkpoint_path`, if this node
/// is running with a `data_dir` - see `propose_round`'s doc comment for the
/// real bug this closes. Best-effort: a transient write failure only risks
/// resuming from a slightly stale round on the *next* restart (which
/// self-heals the same way the very first restart after this fix does -
/// the quorum-of-previous-round gate in `propose_round` blocks any
/// malformed proposal until resync catches up), not a new failure mode, so
/// this warns rather than treating a single failed write as fatal to an
/// otherwise-healthy running validator.
fn persist_round_checkpoint(state: &EngineState) {
    let Some(path) = &state.round_checkpoint_path else { return };
    if let Err(e) = std::fs::write(path, state.next_round.to_string()) {
        tracing::warn!("failed to persist round checkpoint: {e}");
    }
}

fn partition_into_worker_batches(txs: Vec<Transaction>) -> Vec<(WorkerId, Batch)> {
    let mut lanes: Vec<Vec<Transaction>> = vec![Vec::new(); WORKER_COUNT as usize];
    for tx in txs {
        let lane = tx.message.payer.to_bytes()[0] as usize % WORKER_COUNT as usize;
        lanes[lane].push(tx);
    }
    lanes
        .into_iter()
        .enumerate()
        .filter(|(_, txs)| !txs.is_empty())
        .map(|(worker_id, txs)| (worker_id as WorkerId, Batch { transactions: txs }))
        .collect()
}

pub struct EngineState {
    pub ledger: Ledger,
    pub dag: DagStore,
    pub consensus: ConsensusState,
    /// Per-account, nonce-ordered mempool - see the module docs above for
    /// the real bug a flat `Vec` had. Keyed by payer, then by nonce; a
    /// resubmission for a (payer, nonce) pair that's already queued is
    /// ignored, keeping whichever transaction arrived first.
    pub mempool: HashMap<Pubkey, BTreeMap<u64, Transaction>>,
    pub batches: HashMap<Digest, Batch>,
    pub pending_votes: HashMap<Digest, HashMap<ValidatorId, MultiSignature>>,
    pub own_pending_vertex: Option<(Vertex, MultiSignature)>,
    pub next_round: Round,
    /// Where `next_round` gets checkpointed on every advance, if this node
    /// was started with a `data_dir` - see the real stall bug this closes,
    /// documented on `propose_round`. `None` for an in-memory node (nothing
    /// to persist; it's always fresh on the next process start anyway).
    pub round_checkpoint_path: Option<std::path::PathBuf>,
    pub executed: u64,
    /// Which vertex digest this validator has already voted for, per
    /// (round, author) - the equivocation lock. Without it, a Byzantine
    /// author could get two *different* vertices for the same round each
    /// certified by an overlapping-but-distinct 2f+1 quorum, since with
    /// n=3f+1 stake, any two 2f+1 quorums must share at least f+1
    /// validators; refusing to sign a second, conflicting vertex for a
    /// (round, author) already voted on keeps that overlap below what a
    /// Byzantine minority (at most f) can supply on its own.
    pub voted_for: HashMap<(Round, ValidatorId), Digest>,
    /// Outstanding `CertificateRequest`/`WorkerBatchRequest`s this
    /// validator has sent but not yet gotten a response for, keyed by
    /// what's missing, valued by who to (re-)ask - see
    /// `Engine::retry_pending_resync_requests`'s doc comment for the real,
    /// confirmed-live bug this closes: without an independent retry, a
    /// single lost response (not just a lost original broadcast) left a
    /// permanent gap.
    pub pending_cert_requests: HashMap<Digest, ValidatorId>,
    pub pending_batch_requests: HashMap<(WorkerId, Digest), ValidatorId>,
    /// Outstanding `Vote` replies this validator owes to a vertex's author,
    /// keyed by the vertex digest being voted for, valued by (who to send
    /// it to, the signature itself) - see `retry_pending_resync_requests`'s
    /// doc comment for the real, confirmed-live bug this closes: unlike
    /// `VertexProposal`/`CertificateRequest`/`WorkerBatchRequest`, a `Vote`
    /// was a single-attempt send with no retry at all.
    pub pending_votes_to_send: HashMap<Digest, (ValidatorId, MultiSignature)>,
    /// The most recent certificate this validator itself authored -
    /// unconditionally re-broadcast every tick (see
    /// `retry_pending_resync_requests`'s doc comment for the real,
    /// confirmed-live bootstrap deadlock this closes: `CertificateBroadcast`
    /// is a one-shot send with no retry of its own, and the reactive
    /// resync (`request_missing_parents`) can only be triggered by a
    /// *later* message that references the missing certificate as a
    /// parent - which never happens for the very first round, since
    /// nothing has proposed a next round yet).
    pub own_last_certificate: Option<Certificate>,
    /// The first validly author-signed vertex seen per (round, author) -
    /// purely for equivocation-evidence purposes, decoupled from
    /// `voted_for`'s voting-lock role. See `handle_message`'s
    /// `VertexProposal` arm for how a conflicting second arrival turns
    /// this into an `EquivocationEvidence`.
    pub first_seen_vertex: HashMap<(Round, ValidatorId), (Vertex, MultiSignature)>,
    /// Real, independently-verifiable equivocation evidence this validator
    /// has observed, served via `GET /equivocation_evidence` so anyone can
    /// fetch it and submit `StakingInstruction::ReportEquivocation` to
    /// slash the offending validator's self-stake.
    pub equivocation_evidence: HashMap<(Round, ValidatorId), EquivocationEvidence>,
}

pub struct Engine {
    pub self_id: ValidatorId,
    pub keypair: Keypair,
    pub validators: ValidatorSet,
    pub network: Arc<Network>,
    pub state: Mutex<EngineState>,
    /// This network's own genesis-derived identity - see
    /// `qchain_node::config::NodeConfig::chain_id`'s doc comment. Checked
    /// against every transaction at admission (`submit_transaction`/the
    /// `TransactionGossip` handler), the real, live-confirmed fix for the
    /// cross-network replay gap documented on `qchain_core::Message::
    /// chain_id`.
    pub chain_id: [u8; 32],
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub validator: String,
    pub next_round: Round,
    pub dag_certificates: usize,
    pub executed_transactions: u64,
}

/// What `GET /stark_proof` hands back to a light client - a real
/// Winterfell proof (hex-encoded via its own `to_bytes`, since `Proof`
/// itself has no serde impl) alongside the public inputs and Merkle
/// bindings needed to call `qchain_stark::verify_batch_bound_to_state`
/// independently.
#[derive(Serialize)]
pub struct StarkProofResponse {
    #[serde(serialize_with = "serialize_proof_as_hex")]
    pub proof: qchain_stark::Proof,
    pub pub_inputs: qchain_stark::PublicInputs,
    pub bindings: Vec<qchain_stark::RowStateBinding>,
    pub row_count: usize,
}

fn serialize_proof_as_hex<S: serde::Serializer>(proof: &qchain_stark::Proof, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(proof.to_bytes()))
}

#[derive(Debug, thiserror::Error)]
pub enum StarkProofError {
    #[error("no transfer receipts captured yet - nothing to prove")]
    NoReceipts,
    #[error("failed to build STARK proof: {0}")]
    Prove(String),
    /// See `Engine::stark_proof`'s doc comment for the real, non-hypothetical
    /// way this fires: a non-transfer transaction executed between two
    /// included transfer receipts, breaking the contiguous root chain
    /// `verify_batch_bound_to_state` requires.
    #[error("captured receipts don't form one contiguous state transition: {0}")]
    ChainBroken(String),
}

/// A real, live-confirmed mempool-spam gap this closes (see
/// `project-lessons-learned`): `submit_transaction`/the `TransactionGossip`
/// handler used to admit anything with a valid signature, no balance check
/// at all - a freshly generated, never-funded keypair could sign an
/// unbounded run of consecutive-nonce garbage transfers (each one
/// individually cheap to produce, no PoW or stake required) and have every
/// single one accepted, gossiped to every validator (amplifying the cost,
/// not just to the one RPC it targeted), batched, and only rejected at
/// execution time with `InsufficientFunds` - real signature-verification
/// and batch-construction CPU spent network-wide for zero attacker cost.
/// Confirmed live: 5,000 transfers signed by an unfunded keypair were all
/// accepted by one validator, and CPU rose measurably on all three
/// validators in the testnet, not just the one whose RPC received them.
/// Closed by requiring the payer to currently afford at least this
/// transaction's own byte fee before it's admitted anywhere - it doesn't
/// (and can't, without duplicating `Ledger::apply_transaction`'s full nonce
/// bookkeeping here) guarantee every queued transaction for an account will
/// still be affordable by the time its turn comes, only that an account
/// with no funds at all can never get even one transaction into any
/// validator's mempool, which is what the demonstrated attack needed.
fn payer_can_afford_admission(state: &EngineState, tx: &Transaction) -> bool {
    let balance = state.ledger.store().get(&tx.message.payer).map(|a| a.balance).unwrap_or(0);
    // `saturating_mul`, not `*`: `base_fee_per_byte` is governance-settable
    // (Low tier, no hard upper bound), so a near-`u64::MAX` value times a
    // multi-KB `byte_size` overflows. A plain `*` would wrap to a small
    // number in release and wrongly admit; saturating pins it at `u64::MAX`
    // so an over-large fee simply makes nothing affordable, matching intent.
    let byte_fee = state.ledger.current_params().base_fee_per_byte.saturating_mul(tx.byte_size() as u64);
    balance >= byte_fee
}

/// Inserts `tx` into the per-account, nonce-ordered mempool, enforcing the
/// per-payer queue cap (`MAX_MEMPOOL_TXS_PER_PAYER`). Returns `false`
/// (without inserting) if this payer is already at the cap and `tx` is a new
/// nonce for it - the bound that closes the unbounded-mempool OOM (see
/// `MAX_MEMPOOL_TXS_PER_PAYER`'s doc comment). A resubmission of a
/// (payer, nonce) pair already queued is accepted as a no-op (returns
/// `true`, keeps the first-seen transaction) and never counts against the
/// cap, so an honest client retrying is never turned away. Shared by both
/// admission entry points (RPC `submit_transaction` and the gossip handler)
/// so the bound can't be enforced in one and forgotten in the other.
fn admit_to_mempool(state: &mut EngineState, tx: Transaction) -> bool {
    let queue = state.mempool.entry(tx.message.payer).or_default();
    if !queue.contains_key(&tx.message.nonce) && queue.len() >= MAX_MEMPOOL_TXS_PER_PAYER {
        return false;
    }
    queue.entry(tx.message.nonce).or_insert(tx);
    true
}

/// Caches a gossiped/served worker batch by its content digest, enforcing
/// the `MAX_CACHED_BATCHES` bound (see its doc comment for the unauthenticated
/// flood this closes). A batch whose digest is already cached is a no-op; a
/// genuinely new one is dropped, not inserted, once the cap is reached -
/// consumed batches are already evicted as their certificates commit
/// (`try_commit`), so hitting the cap means an abnormal volume of batches
/// that were gossiped but never committed, i.e. exactly the flood this guards
/// against. Dropping here is safe: a validator that later genuinely needs a
/// dropped batch re-requests it by digest (`request_missing_batches`).
fn cache_batch(state: &mut EngineState, batch: Batch) {
    let digest = batch.digest();
    if state.batches.contains_key(&digest) || state.batches.len() < MAX_CACHED_BATCHES {
        state.batches.entry(digest).or_insert(batch);
    }
}

/// Pulls every transaction that's actually ready to execute out of the
/// mempool, per account, in nonce order - see the module docs for the real
/// bug this replaces. For each account with queued transactions: first
/// drop anything at or below the account's current on-chain nonce (already
/// applied, whether by this validator or - in a multi-node network - by
/// whichever validator's batch got committed first; it can never apply
/// again), then consume consecutive nonces starting from the account's
/// current nonce for as long as they're present. The first gap stops that
/// account's contribution for this round; everything after the gap stays
/// queued, not silently dropped.
fn drain_ready_transactions(state: &mut EngineState) -> Vec<Transaction> {
    let mut ready = Vec::new();
    let mut empty_accounts = Vec::new();
    for (payer, queue) in state.mempool.iter_mut() {
        let mut expected_nonce = state.ledger.store().get(payer).map(|a| a.nonce).unwrap_or(0);
        while queue.keys().next().is_some_and(|&n| n < expected_nonce) {
            queue.pop_first();
        }
        while let Some(tx) = queue.remove(&expected_nonce) {
            ready.push(tx);
            expected_nonce += 1;
        }
        if queue.is_empty() {
            empty_accounts.push(*payer);
        }
    }
    for payer in empty_accounts {
        state.mempool.remove(&payer);
    }
    ready
}

impl Engine {
    /// Admits a client-submitted transaction into the local mempool once
    /// its hybrid signature checks out and its payer can currently afford
    /// its own byte fee (see `payer_can_afford_admission`'s doc comment for
    /// the real mempool-spam gap this closes). Full nonce/balance
    /// correctness is still only checked once for real at execution time
    /// (`Ledger::apply_transaction`); a transaction that turns out invalid
    /// once its batch is ordered is simply skipped (see `try_commit`).
    ///
    /// Broadcasts it to every peer immediately afterward (see
    /// `NetMessage::TransactionGossip`'s doc comment for the real
    /// censorship gap this closes) - the client only ever talks to this
    /// one validator's RPC, but every validator now learns about the
    /// transaction regardless of whether this one later includes it in a
    /// worker batch.
    pub async fn submit_transaction(&self, tx: Transaction) -> anyhow::Result<[u8; 32]> {
        if !tx.verify_signature() {
            anyhow::bail!("invalid transaction signature");
        }
        // Real, live-confirmed cross-network replay gap closed here - see
        // `qchain_core::Message::chain_id`'s doc comment for the full
        // reproduction (one signed transfer, replayed verbatim across two
        // genuinely separate testnet processes, executed identically on
        // both).
        if tx.message.chain_id != self.chain_id {
            anyhow::bail!("transaction's chain_id does not match this network");
        }
        let hash = tx.hash();
        {
            let mut state = self.state.lock().await;
            if !payer_can_afford_admission(&state, &tx) {
                anyhow::bail!("payer cannot afford this transaction's byte fee");
            }
            if !admit_to_mempool(&mut state, tx.clone()) {
                anyhow::bail!("payer already has the maximum number of queued transactions ({MAX_MEMPOOL_TXS_PER_PAYER})");
            }
        }
        self.network.broadcast(&NetMessage::TransactionGossip(tx)).await;
        Ok(hash)
    }

    pub async fn get_account(&self, pk: &Pubkey) -> Option<qchain_core::Account> {
        let state = self.state.lock().await;
        state.ledger.store().get(pk)
    }

    /// Current state-tree Merkle root, plus how many `TransferReceipt`s
    /// this validator has captured so far - what a light client polls to
    /// notice the root has advanced before asking for a proof.
    pub async fn merkle_root(&self) -> ([u8; 32], usize) {
        let state = self.state.lock().await;
        (state.ledger.merkle_root(), state.ledger.transfer_receipts().len())
    }

    /// The most recent `limit` captured `TransferReceipt`s (newest
    /// first), skipping `offset` from the newest end first - the real
    /// "recent activity" list a Qscan-style status page paginates
    /// through. Backed by the same in-memory, unbounded `Vec` `Ledger`
    /// already keeps for `/stark_proof` (see `qchain-execution::receipt`'s
    /// module docs on that limitation) - this endpoint doesn't add any
    /// new persistence, just a paginated read of what was already there.
    pub async fn list_transfers(&self, limit: usize, offset: usize) -> Vec<qchain_execution::TransferReceipt> {
        let state = self.state.lock().await;
        let all = state.ledger.transfer_receipts();
        if offset >= all.len() {
            return Vec::new();
        }
        let end = all.len() - offset;
        let start = end.saturating_sub(limit);
        all[start..end].iter().rev().cloned().collect()
    }

    /// A single captured receipt by its transaction hash, full detail
    /// (before/after balances and Merkle proofs) - `O(receipts)` linear
    /// scan, acceptable for the same reason the list above is: this is a
    /// read over an already-bounded-by-session in-memory `Vec`, not a
    /// real indexed store.
    pub async fn get_transfer(&self, tx_hash: [u8; 32]) -> Option<qchain_execution::TransferReceipt> {
        let state = self.state.lock().await;
        state.ledger.transfer_receipts().iter().find(|r| r.tx_hash == tx_hash).cloned()
    }

    /// Every equivocation this validator has independently witnessed and
    /// cryptographically verified so far - see `handle_message`'s
    /// `VertexProposal` arm for how each entry gets constructed.
    pub async fn equivocation_evidence(&self) -> Vec<EquivocationEvidence> {
        let state = self.state.lock().await;
        state.equivocation_evidence.values().cloned().collect()
    }

    /// Builds a real `qchain-stark` proof over the most recent `limit`
    /// captured transfer receipts (all of them if `limit` is `None`, up to
    /// `MAX_STARK_PROOF_RECEIPTS`), binds it to the real Merkle root
    /// transitions those receipts recorded, and self-verifies via
    /// `verify_batch_bound_to_state` before ever handing it to a caller -
    /// a validator should never serve a proof it hasn't itself confirmed
    /// verifies.
    ///
    /// Real limitation, not silently glossed over: `verify_batch_bound_to_state`
    /// requires the bound rows to be one *contiguous* run of state
    /// transitions (each row's `root_after` must equal the next row's
    /// `root_before`). Receipts are only captured for single-instruction
    /// `Transfer` transactions (see `qchain_execution::receipt`'s module
    /// docs) - if any other transaction (staking, governance, a
    /// multi-instruction transaction) executed in between two included
    /// transfers, the real root moved without a receipt recording it, and
    /// self-verification below fails with `RootSequenceMismatch`. That is
    /// surfaced as `StarkProofError::ChainBroken`, not swallowed.
    pub async fn stark_proof(&self, limit: Option<usize>) -> Result<StarkProofResponse, StarkProofError> {
        let receipts: Vec<qchain_execution::TransferReceipt> = {
            let state = self.state.lock().await;
            let all = state.ledger.transfer_receipts();
            // A real, live-measured DoS this closes: `qchain_stark::prove_batch`
            // scales far worse than linearly with receipt count (measured on
            // this same machine: n=100 -> 16.5ms, n=1,000 -> 948ms, n=5,000 ->
            // 71.8s, n=20,000 -> still running after 5+ minutes of CPU before
            // being killed). `transfer_receipts` is an unbounded in-memory log
            // (already-documented simplification, see `qchain_execution::
            // receipt`'s module docs) that only grows over a validator's real
            // lifetime, and this endpoint is a plain, unauthenticated GET with
            // no per-call cost to the caller - proving "all of them" (the
            // default when `limit` is omitted) turns chain age directly into
            // free, repeatable CPU-exhaustion leverage for anyone. Clamped
            // here, unconditionally, regardless of what the caller requests
            // or omits - the same "bound the worst case of a single call"
            // principle already used for message size limits and bytecode
            // size caps elsewhere in this codebase.
            let effective_limit = effective_stark_proof_limit(limit, all.len());
            all[all.len() - effective_limit..].to_vec()
        };
        if receipts.is_empty() {
            return Err(StarkProofError::NoReceipts);
        }

        let steps: Vec<qchain_stark::TransferStep> = receipts
            .iter()
            .map(|r| {
                qchain_stark::TransferStep::conserving(
                    r.from.to_bytes(),
                    r.to.to_bytes(),
                    r.from_before.balance,
                    r.to_before.balance,
                    r.amount,
                    r.fee,
                )
            })
            .collect();
        let bindings: Vec<qchain_stark::RowStateBinding> = receipts
            .iter()
            .map(|r| qchain_stark::RowStateBinding {
                root_before: r.root_before,
                root_after: r.root_after,
                from_before: r.from_before.clone(),
                from_after: r.from_after.clone(),
                to_before: r.to_before.clone(),
                to_after: r.to_after.clone(),
                from_proof_before: r.from_proof_before.clone(),
                from_proof_after: r.from_proof_after.clone(),
                to_proof_before: r.to_proof_before.clone(),
                to_proof_after: r.to_proof_after.clone(),
            })
            .collect();

        let (proof, pub_inputs) = qchain_stark::prove_batch(&steps).map_err(|e| StarkProofError::Prove(e.to_string()))?;
        qchain_stark::verify_batch_bound_to_state(proof.clone(), pub_inputs.clone(), &bindings)
            .map_err(|e| StarkProofError::ChainBroken(e.to_string()))?;

        Ok(StarkProofResponse { proof, pub_inputs, bindings, row_count: receipts.len() })
    }

    pub async fn status(&self) -> StatusResponse {
        let state = self.state.lock().await;
        StatusResponse {
            validator: self.self_id.to_string(),
            next_round: state.next_round,
            dag_certificates: state.dag.len(),
            executed_transactions: state.executed,
        }
    }

    pub async fn handle_message(&self, from: ValidatorId, msg: NetMessage) {
        match msg {
            NetMessage::TransactionGossip(tx) => {
                // Real defense-in-depth, not just trusting a peer: verify
                // the signature independently rather than assuming a peer
                // only ever gossips what it already checked - the same
                // posture `submit_transaction` already has for its own
                // RPC-submitted transactions.
                if !tx.verify_signature() {
                    tracing::warn!("dropping gossiped transaction from {from} with an invalid signature");
                    return;
                }
                if tx.message.chain_id != self.chain_id {
                    tracing::warn!("dropping gossiped transaction from {from} with a mismatched chain_id");
                    return;
                }
                let mut state = self.state.lock().await;
                // Same admission check `submit_transaction` applies to its
                // own RPC-submitted transactions (see
                // `payer_can_afford_admission`'s doc comment) - a peer
                // re-broadcasting spam it should have rejected itself
                // doesn't get a free pass here.
                if !payer_can_afford_admission(&state, &tx) {
                    tracing::warn!("dropping gossiped transaction from {from} whose payer cannot afford its byte fee");
                    return;
                }
                if !admit_to_mempool(&mut state, tx) {
                    tracing::warn!("dropping gossiped transaction from {from}: payer already at the mempool queue cap");
                }
                // Not re-broadcast further - this project's validator sets
                // are fully connected (see `NetMessage::TransactionGossip`'s
                // doc comment), so the originating validator's own
                // broadcast already reached every peer in one hop.
            }
            NetMessage::WorkerBatchGossip { worker_id: _, batch } => {
                let mut state = self.state.lock().await;
                cache_batch(&mut state, batch);
            }
            NetMessage::VertexProposal { vertex, author_signature } => {
                if vertex.author != from {
                    tracing::warn!("dropping vertex proposal with mismatched author/sender");
                    return;
                }
                // Verified *before* anything else: `NetMessage::VertexProposal`'s
                // doc comment has the full rationale - without this check, a
                // forged or misattributed vertex could never be told apart
                // from a genuine one, and no equivocation evidence could ever
                // be trusted (see `EquivocationEvidence` below).
                let digest = vertex.digest();
                let Some(author_info) = self.validators.get(&vertex.author) else {
                    tracing::warn!("dropping vertex proposal from unknown validator {from}");
                    return;
                };
                if !qchain_crypto::verify(&author_info.pubkey_bundle, &digest[..], &author_signature) {
                    tracing::warn!("dropping vertex proposal from {from} - author_signature does not verify");
                    return;
                }
                self.request_missing_parents(&vertex.parents, from).await;
                self.request_missing_batches(&vertex.batch_digests, from).await;
                let key = (vertex.round, vertex.author);
                {
                    let mut state = self.state.lock().await;
                    // Real equivocation evidence, not just a local defense:
                    // the *first* validly-signed vertex seen for this
                    // (round, author) is kept around so that if a second,
                    // different one ever arrives, both signed vertices can
                    // be packaged into an `EquivocationEvidence` that anyone
                    // can verify independently and submit on-chain to slash
                    // the offending validator's self-stake (see
                    // `qchain-execution::staking::StakingInstruction::ReportEquivocation`).
                    let prior = state.first_seen_vertex.get(&key).cloned();
                    match prior {
                        Some((prior_vertex, prior_signature)) if prior_vertex.digest() != digest => {
                            tracing::error!(
                                "equivocation detected: {from} signed two different vertices for round {} - evidence captured",
                                vertex.round
                            );
                            state.equivocation_evidence.entry(key).or_insert_with(|| EquivocationEvidence {
                                vertex_a: prior_vertex,
                                signature_a: prior_signature,
                                vertex_b: vertex.clone(),
                                signature_b: author_signature.clone(),
                                author_bundle: author_info.pubkey_bundle.clone(),
                            });
                        }
                        Some(_) => {} // the exact same vertex, seen again - not new evidence
                        None => {
                            state.first_seen_vertex.insert(key, (vertex.clone(), author_signature.clone()));
                        }
                    }
                    match state.voted_for.get(&key) {
                        Some(existing) if *existing != digest => {
                            tracing::warn!(
                                "refusing to vote for a second, conflicting vertex from {from} at round {} - possible equivocation",
                                vertex.round
                            );
                            return;
                        }
                        Some(_) => {} // already voted for exactly this vertex - re-signing is harmless, fall through
                        None => {
                            state.voted_for.insert(key, digest);
                        }
                    }
                }
                let sig = match self.keypair.sign(&digest[..]) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("failed to sign vote: {e}");
                        return;
                    }
                };
                // Registered as outstanding *before* the first send attempt,
                // regardless of whether that attempt succeeds - see
                // `retry_pending_resync_requests`'s doc comment for the real
                // bug this closes: a `Vote` used to be a single-attempt send
                // with no way to recover if it raced a peer's listener
                // socket that wasn't bound yet.
                {
                    let mut state = self.state.lock().await;
                    state.pending_votes_to_send.insert(digest, (from, sig.clone()));
                }
                if let Some(addr) = self.network.addr_of(&from) {
                    if let Err(e) = self.network.send_to(addr, &NetMessage::Vote { vertex_digest: digest, signature: sig }).await {
                        tracing::warn!("failed to send vote to {from}: {e}");
                    }
                }
            }
            NetMessage::Vote { vertex_digest, signature } => {
                // Verify the vote BEFORE it is ever recorded - closes two
                // real problems at once, both live-confirmed as a class this
                // project keeps hitting (unbounded/unauthenticated growth):
                //
                // (1) DoS/OOM: `record_vote` used to insert into
                //     `pending_votes` unconditionally, before any check.
                //     The P2P transport is unauthenticated (see
                //     `qchain-network`'s `message.rs`), so anyone who can
                //     reach the port could stream `Vote { random_digest,
                //     garbage_sig }` with a spoofed sender - each distinct
                //     random digest a new never-pruned map key holding a
                //     full `MultiSignature` (~KB). No funding, no valid key,
                //     no restart needed - the cheapest OOM in the codebase.
                // (2) Soundness of quorum counting: `record_vote` sums
                //     `stake_of(voter)` over the recorded voters to decide
                //     when its own vertex reaches quorum. Counting an
                //     unverified (or spoofed-sender) vote toward that sum let
                //     a peer inflate the apparent tally and trigger a
                //     `CertificateBroadcast` that every honest receiver then
                //     rejects in `verify_certificate` - wasted work at best.
                //
                // Requiring the sender to be a known validator and the
                // signature to verify over the exact voted digest (the same
                // `qchain_crypto::verify` check the `VertexProposal` arm
                // already applies to an author's signature) means only real,
                // attributable votes are ever stored or counted.
                let Some(voter_info) = self.validators.get(&from) else {
                    tracing::warn!("dropping vote from unknown validator {from}");
                    return;
                };
                if !qchain_crypto::verify(&voter_info.pubkey_bundle, &vertex_digest[..], &signature) {
                    tracing::warn!("dropping vote from {from} whose signature does not verify over the voted digest");
                    return;
                }
                if let Some(cert) = self.record_vote(vertex_digest, from, signature).await {
                    self.network.broadcast(&NetMessage::CertificateBroadcast(cert)).await;
                    self.try_commit().await;
                }
            }
            NetMessage::CertificateBroadcast(cert) => {
                if !verify_certificate(&cert, &self.validators) {
                    tracing::warn!("dropping certificate that fails quorum verification");
                    return;
                }
                let parents = cert.vertex.parents.clone();
                let batch_digests = cert.vertex.batch_digests.clone();
                {
                    let mut state = self.state.lock().await;
                    state.dag.insert(cert);
                }
                self.request_missing_parents(&parents, from).await;
                self.request_missing_batches(&batch_digests, from).await;
                self.try_commit().await;
            }
            NetMessage::CertificateRequest { digest } => {
                let found = {
                    let state = self.state.lock().await;
                    state.dag.get(&digest).cloned()
                };
                if let (Some(cert), Some(addr)) = (found, self.network.addr_of(&from)) {
                    if let Err(e) = self.network.send_to(addr, &NetMessage::CertificateResponse(cert)).await {
                        tracing::warn!("failed to send certificate response to {from}: {e}");
                    }
                }
            }
            NetMessage::CertificateResponse(cert) => {
                if !verify_certificate(&cert, &self.validators) {
                    tracing::warn!("dropping certificate response that fails quorum verification");
                    return;
                }
                let parents = cert.vertex.parents.clone();
                let batch_digests = cert.vertex.batch_digests.clone();
                {
                    let mut state = self.state.lock().await;
                    state.dag.insert(cert);
                }
                self.request_missing_parents(&parents, from).await;
                self.request_missing_batches(&batch_digests, from).await;
                self.try_commit().await;
            }
            NetMessage::WorkerBatchRequest { worker_id, digest } => {
                let found = {
                    let state = self.state.lock().await;
                    state.batches.get(&digest).cloned()
                };
                if let (Some(batch), Some(addr)) = (found, self.network.addr_of(&from)) {
                    if let Err(e) = self.network.send_to(addr, &NetMessage::WorkerBatchResponse { worker_id, batch }).await {
                        tracing::warn!("failed to send worker batch response to {from}: {e}");
                    }
                }
            }
            NetMessage::WorkerBatchResponse { worker_id: _, batch } => {
                let mut state = self.state.lock().await;
                cache_batch(&mut state, batch);
            }
        }
    }

    /// Requests, from `from`, any of `parents` this validator doesn't
    /// already have locally - see `NetMessage::CertificateRequest`'s doc
    /// comment for why this exists: a `CertificateBroadcast` is a one-shot
    /// send with no retry, so without this, a single dropped copy leaves
    /// the missing certificate (and anything in the DAG only reachable
    /// through it) permanently unrecoverable - a real, confirmed
    /// complete-stall liveness bug found via `qchain-simulation` before
    /// this existed (see `project-lessons-learned`), not a hypothetical
    /// gap. `from` is asked because it just sent a message referencing
    /// these digests as parents, so it must have had them itself.
    async fn request_missing_parents(&self, parents: &[Digest], from: ValidatorId) {
        let missing: Vec<Digest> = {
            let mut state = self.state.lock().await;
            let missing: Vec<Digest> = parents.iter().copied().filter(|d| !state.dag.contains(d)).collect();
            for &digest in &missing {
                state.pending_cert_requests.insert(digest, from);
            }
            missing
        };
        if missing.is_empty() {
            return;
        }
        let Some(addr) = self.network.addr_of(&from) else { return };
        // Awaited sequentially - see `Network::send_to`'s doc comment for
        // why a bounded write timeout there, not spawning here, is the
        // real fix for a stuck peer write.
        for digest in missing {
            if let Err(e) = self.network.send_to(addr, &NetMessage::CertificateRequest { digest }).await {
                tracing::warn!("failed to request missing certificate {digest:?} from {from}: {e}");
            }
        }
    }

    /// The worker-tier counterpart to `request_missing_parents`: requests,
    /// from `from`, any batch digest referenced in `batch_digests` this
    /// validator doesn't already have cached locally. Same rationale as
    /// certificate re-sync - `WorkerBatchGossip` is a one-shot send with no
    /// retry of its own, so a single dropped copy would otherwise leave the
    /// referencing vertex's transactions permanently unresolved at commit
    /// time (see the module docs).
    async fn request_missing_batches(&self, batch_digests: &[(WorkerId, Digest)], from: ValidatorId) {
        let missing: Vec<(WorkerId, Digest)> = {
            let mut state = self.state.lock().await;
            let missing: Vec<(WorkerId, Digest)> = batch_digests.iter().copied().filter(|(_, d)| !state.batches.contains_key(d)).collect();
            for &(worker_id, digest) in &missing {
                state.pending_batch_requests.insert((worker_id, digest), from);
            }
            missing
        };
        if missing.is_empty() {
            return;
        }
        let Some(addr) = self.network.addr_of(&from) else { return };
        // Awaited sequentially - see `request_missing_parents`'s matching
        // comment just above.
        for (worker_id, digest) in missing {
            if let Err(e) = self.network.send_to(addr, &NetMessage::WorkerBatchRequest { worker_id, digest }).await {
                tracing::warn!("failed to request missing worker batch {digest:?} (worker {worker_id}) from {from}: {e}");
            }
        }
    }

    /// Re-sends any still-outstanding `CertificateRequest`/
    /// `WorkerBatchRequest`s/`Vote`s, called on the same tick as
    /// `propose_round`.
    ///
    /// **Second real bug closed here, found live running an actual n=20
    /// validator testnet (not simulated) - a genuine `Vote` reply, unlike
    /// every other resync message in this function, was a single-attempt
    /// send with no retry at all.** With 20 real processes started nearly
    /// simultaneously via a shell loop, each one's P2P listener binds at a
    /// slightly different moment; a `VertexProposal` that reaches a peer
    /// before *that peer's own* listener is up can still be received fine
    /// (it's inbound), but the `Vote` reply the peer sends *back* to the
    /// proposer races the proposer's own listener the same way, and if it
    /// loses that race it's dropped with only a one-line warning and never
    /// retried - unlike `VertexProposal` (retried via `own_pending_vertex`)
    /// and `CertificateRequest`/`WorkerBatchRequest` (retried just below).
    /// Confirmed live: a real 20-validator testnet on this sandbox got
    /// permanently stuck at `next_round: 1`, `dag_certificates: 1` on
    /// *every single node* - i.e. only one validator's round-0 vertex ever
    /// reached quorum, because most of the other 19 validators' peers lost
    /// exactly this race for at least one vote each. Since round N+1
    /// requires 2f+1 stake worth of round-N certificates (see
    /// `propose_round`), one validator short of quorum for its own vertex
    /// freezes not just that validator but the *entire* network forever -
    /// confirmed by watching all 20 nodes' `next_round`/`dag_certificates`
    /// sit frozen simultaneously with CPU idle (not contended, not
    /// deadlocked - just legitimately blocked on `propose_round`'s
    /// prior-round quorum check returning early, tick after tick). This is
    /// distinct from the pure CPU-contention slowdown already documented at
    /// n=50 (throughput degrading under load) and from the ephemeral-port
    /// exhaustion found at n=27 (TCP port range exhausted by message
    /// volume) - this one is a genuine startup-ordering race that a *fixed*
    /// small validator count (e.g. n=3) is unlikely to ever hit (fewer
    /// simultaneous connection attempts, smaller window), but a real
    /// deployment bringing up dozens of validators at once - or restarting
    /// several together - could hit in production.
    ///
    /// **Third real bug closed here, found live immediately after fixing
    /// the `Vote` retry above - fixing that one exposed this one, it did
    /// not cause it.** Even with every `Vote` reliably delivered, a real
    /// n=6 testnet plateaued forever at a handful of certificates instead
    /// of reaching the 5-of-6 quorum needed to unlock round 1.
    /// Instrumented live (temporary `tracing::info!` calls, removed once
    /// diagnosed - same technique used for the round-checkpoint recovery
    /// timing question, see `project-lessons-learned`): every validator's
    /// own round-0 vertex *did* reach quorum stake locally (confirmed by
    /// the vote tally reaching the threshold), but `record_vote`'s
    /// resulting `CertificateBroadcast` - like `Vote` before this fix - is
    /// a one-shot send with no retry, and unlike a missing *parent*
    /// reference (handled by `request_missing_parents`'s reactive
    /// resync), nothing ever asks for a missing round-0 certificate by
    /// digest: that reactive path only triggers when a *later* vertex
    /// lists the missing certificate as a parent, which cannot happen
    /// before *someone* has reached round-0 quorum and proposed round 1 -
    /// a genuine bootstrap chicken-and-egg gap specific to the very first
    /// round every validator ever proposes. Fixed by having every
    /// validator unconditionally re-broadcast its own most recently
    /// self-certified certificate (`EngineState.own_last_certificate`)
    /// every tick, forever - cheap (one certificate, one tick, one
    /// validator), and sufficient: as long as at least one honest
    /// validator keeps ticking, every peer eventually receives every
    /// author's certificate through repeated direct pushes, the same
    /// reasoning `own_pending_vertex`'s existing retry already relies on
    /// one step earlier in the same pipeline. Once *any* validator moves
    /// past round 0, `request_missing_parents`'s existing by-digest resync
    /// takes over for all later rounds, so this only needed to cover the
    /// bootstrap case.
    ///
    /// **Real bug closed here, found live via a deeper adversarial audit
    /// (rapid crash-loop of one validator, four kills/restarts within a
    /// few seconds, on a network with real accumulated round history).**
    /// `request_missing_parents`/`request_missing_batches` only ever fired
    /// reactively - triggered by processing a *fresh* incoming message
    /// that happened to reference the same missing digest again. That's
    /// fine when the *original* request or its response is merely delayed
    /// (a later message re-triggers a fresh request). It's not fine when
    /// the *response* itself is lost and nothing else will ever reference
    /// that exact digest again - which is exactly what a burst of catch-up
    /// re-sync traffic can cause: confirmed live, the crash-loop's
    /// resulting flood of `CertificateRequest`s exhausted the responder's
    /// file descriptors (`qchain-network`'s transport opens a fresh
    /// connection per send, a known, documented simplification), so over a
    /// thousand `CertificateResponse` sends failed with "too many open
    /// files." Each failure was for a specific digest with no other
    /// message left anywhere in the system that would ever reference it
    /// again - a permanent, silent gap. With quorum requiring support from
    /// (near-)all validators, one validator permanently missing even one
    /// certificate froze the *entire* network forever, confirmed by
    /// watching `next_round`/`dag_certificates` sit completely frozen
    /// across all three nodes for minutes while CPU usage stayed high (the
    /// stuck validator's Bullshark ordering repeatedly re-walking the same
    /// unresolved gap on every incoming message, silently, since a
    /// re-walk that doesn't newly commit anything logs nothing).
    ///
    /// Fixed the same way `own_pending_vertex` already handles exactly
    /// this class of problem: track every outstanding request
    /// (`EngineState.pending_cert_requests`/`pending_batch_requests`,
    /// populated wherever a request is first sent) and unconditionally
    /// re-send anything still outstanding on every tick, independent of
    /// whether any other message happens to reference it - pruning an
    /// entry the moment the real content actually arrives, whichever way
    /// it arrives.
    pub async fn retry_pending_resync_requests(&self) {
        let (cert_retries, batch_retries, vote_retries, own_cert_retry) = {
            let mut state = self.state.lock().await;
            let resolved_certs: Vec<Digest> = state.pending_cert_requests.keys().copied().filter(|d| state.dag.contains(d)).collect();
            for digest in &resolved_certs {
                state.pending_cert_requests.remove(digest);
            }
            let resolved_batches: Vec<(WorkerId, Digest)> =
                state.pending_batch_requests.keys().copied().filter(|(_, d)| state.batches.contains_key(d)).collect();
            for key in &resolved_batches {
                state.pending_batch_requests.remove(key);
            }
            // A vote is no longer owed once its vertex is already certified
            // - whether that quorum was reached through this validator's
            // own vote or through others', including via a certificate that
            // arrived by some other path entirely (broadcast, or cert/batch
            // re-sync).
            let resolved_votes: Vec<Digest> = state.pending_votes_to_send.keys().copied().filter(|d| state.dag.contains(d)).collect();
            for digest in &resolved_votes {
                state.pending_votes_to_send.remove(digest);
            }
            let cert_retries: Vec<(Digest, ValidatorId)> = state.pending_cert_requests.iter().map(|(&d, &from)| (d, from)).collect();
            let batch_retries: Vec<(WorkerId, Digest, ValidatorId)> =
                state.pending_batch_requests.iter().map(|(&(worker_id, d), &from)| (worker_id, d, from)).collect();
            let vote_retries: Vec<(Digest, ValidatorId, MultiSignature)> =
                state.pending_votes_to_send.iter().map(|(&d, (from, sig))| (d, *from, sig.clone())).collect();
            let own_cert_retry = state.own_last_certificate.clone();
            (cert_retries, batch_retries, vote_retries, own_cert_retry)
        };

        // Awaited sequentially, deliberately not spawned per item - see
        // `Network::send_to`'s doc comment for the full story, including a
        // first fix attempt (spawning each retry independently) that closed
        // a real hang here but reintroduced unbounded concurrent task
        // growth severe enough to OOM-kill a peer under a real resync
        // backlog. `send_to` now has its own bounded write timeout, so a
        // single stuck peer here costs at most `SEND_TIMEOUT` once per
        // pending item per tick, never blocks forever - sequential
        // awaiting is what keeps this function's own concurrency bounded
        // (at most one in-flight send at a time), the same property that
        // made this class of bug possible to reintroduce by spawning.
        for (digest, from) in cert_retries {
            let Some(addr) = self.network.addr_of(&from) else { continue };
            if let Err(e) = self.network.send_to(addr, &NetMessage::CertificateRequest { digest }).await {
                tracing::warn!("retry: failed to request missing certificate {digest:?} from {from}: {e}");
            }
        }
        for (worker_id, digest, from) in batch_retries {
            let Some(addr) = self.network.addr_of(&from) else { continue };
            if let Err(e) = self.network.send_to(addr, &NetMessage::WorkerBatchRequest { worker_id, digest }).await {
                tracing::warn!("retry: failed to request missing worker batch {digest:?} (worker {worker_id}) from {from}: {e}");
            }
        }
        for (vertex_digest, from, signature) in vote_retries {
            let Some(addr) = self.network.addr_of(&from) else { continue };
            if let Err(e) = self.network.send_to(addr, &NetMessage::Vote { vertex_digest, signature }).await {
                tracing::warn!("retry: failed to send vote to {from}: {e}");
            }
        }
        // Unconditional, every tick, forever - see this function's doc
        // comment for the real bootstrap deadlock this closes. Cheap: at
        // most one certificate, once per tick, per validator.
        if let Some(cert) = own_cert_retry {
            self.network.broadcast(&NetMessage::CertificateBroadcast(cert)).await;
        }
    }

    /// Drops `(round, author)`-keyed bookkeeping for rounds more than
    /// `ROUND_STATE_RETENTION` behind the current round - the bound that
    /// closes the slow, attacker-free `voted_for`/`first_seen_vertex` OOM
    /// (see `ROUND_STATE_RETENTION`'s doc comment: without this these maps
    /// gain ~one entry per validator per round forever). Called every tick.
    /// `equivocation_evidence` is deliberately NOT pruned here - it only ever
    /// grows on genuine, slashable misbehavior (rare, and each entry is
    /// real evidence someone may still want to submit), unlike the two maps
    /// pruned here which gain an entry every single round unconditionally.
    pub async fn prune_stale_round_state(&self) {
        let mut state = self.state.lock().await;
        let horizon = state.next_round.saturating_sub(ROUND_STATE_RETENTION);
        if horizon == 0 {
            return;
        }
        state.voted_for.retain(|(round, _), _| *round >= horizon);
        state.first_seen_vertex.retain(|(round, _), _| *round >= horizon);
    }

    /// Records a vote toward whichever vertex this validator currently has
    /// pending certification. Returns the freshly-formed certificate the
    /// moment quorum stake is reached, `None` otherwise (including when the
    /// vote is for a vertex that isn't this validator's own proposal - only
    /// a vertex's author collects its votes).
    async fn record_vote(&self, vertex_digest: Digest, voter: ValidatorId, sig: MultiSignature) -> Option<Certificate> {
        let mut state = self.state.lock().await;

        // Only a vertex's own author collects its votes, so only ever store
        // votes for THIS validator's current pending proposal - checked
        // before the insert, not after. Storing votes for any other digest
        // (a vote for a peer's vertex, a late vote for an already-certified
        // one, or - now that votes are verified at ingestion but a
        // tolerated-Byzantine validator can still sign a vote over any
        // 32-byte value it likes - a flood of validly-signed votes for
        // fabricated digests) would leave permanent, never-pruned entries
        // in `pending_votes`, the same unbounded-growth OOM class this
        // project keeps closing. Bounded here to at most the vote set of a
        // single proposal (~one entry per validator), cleared the moment
        // that proposal certifies (below) or is replaced by the next one.
        let own_digest = state.own_pending_vertex.as_ref().map(|(v, _)| v.digest());
        if own_digest != Some(vertex_digest) {
            return None;
        }
        state.pending_votes.entry(vertex_digest).or_default().insert(voter, sig);

        let stake: u64 = state.pending_votes[&vertex_digest].keys().map(|id| self.validators.stake_of(id)).sum();
        if stake < self.validators.quorum_threshold() {
            return None;
        }

        let (vertex, _) = state.own_pending_vertex.take().unwrap();
        let signatures = state.pending_votes.remove(&vertex_digest).unwrap().into_iter().collect();
        let cert = Certificate { vertex, signatures };
        state.dag.insert(cert.clone());
        state.own_last_certificate = Some(cert.clone());
        Some(cert)
    }

    /// Re-runs Bullshark ordering over the current DAG and executes every
    /// newly-finalized certificate's batch, crediting that certificate's
    /// author as the fee collector - the same deterministic choice every
    /// validator makes, keeping ledger state consistent across the
    /// network.
    async fn try_commit(&self) {
        let mut state = self.state.lock().await;
        let state = &mut *state;
        let newly_ordered = state.consensus.advance(&state.dag, &self.validators);
        for digest in newly_ordered {
            let Some(cert) = state.dag.get(&digest).cloned() else { continue };
            // Applied in the vertex's own `batch_digests` order (worker lane
            // order at proposal time) - every validator sees the identical
            // certified list, so this order is already agreed, not re-derived
            // locally. Each consumed batch is then evicted from the cache: a
            // batch is content-addressed and included by exactly one vertex,
            // and once its transactions are committed they are applied for
            // good (any later re-reference of the same digest would re-run
            // no-ops rejected on the already-advanced nonce), so keeping it
            // cached serves no purpose and would grow `batches` unboundedly.
            // This is what keeps the cache scoped to in-flight (not-yet-
            // committed) batches in steady state; `MAX_CACHED_BATCHES` is the
            // backstop for gossiped-but-never-committed flood, not the
            // primary bound.
            for (worker_id, batch_digest) in &cert.vertex.batch_digests {
                let Some(batch) = state.batches.remove(batch_digest) else {
                    tracing::warn!("committed certificate references an unseen batch from worker {worker_id} - skipping its transactions");
                    continue;
                };
                for tx in &batch.transactions {
                    match state.ledger.apply_transaction(tx, &cert.vertex.author, cert.vertex.round) {
                        Ok(_) => state.executed += 1,
                        Err(e) => tracing::warn!("transaction execution failed: {e}"),
                    }
                }
            }
        }
    }

    /// Proposes this validator's vertex for the next round, once the
    /// previous round has quorum certificates to reference as parents (or
    /// immediately, for round 0). If a proposal is already pending
    /// certification, re-broadcasts that same vertex instead of no-op -
    /// see the retry note below.
    ///
    /// **Real bug closed here, found live while auditing the persistence
    /// work: `next_round` must be checkpointed to disk, or a validator
    /// restart permanently stalls the whole network, not just itself.**
    /// `SledStore` persists account state, but `EngineState.dag`/
    /// `consensus`/`voted_for` never did - a restarted node used to always
    /// resume at `next_round: 0`. Its peers, though, still remember voting
    /// for that validator's *original* vertex at round 0 (and every round
    /// up to wherever it had reached) - so the restarted node's *new*
    /// (necessarily different, since mempool/timing differ) vertex for the
    /// same round number is indistinguishable from real equivocation to
    /// them, and the equivocation lock in `handle_message` permanently
    /// refuses to vote for it. That one validator can then never certify
    /// anything again - and since quorum needs strictly more than 2/3 of
    /// total stake, a single unrecoverable validator is enough to freeze
    /// the *entire* network forever at whatever round it stalled at, not
    /// just itself. Confirmed live: a 3-node testnet (`quorum_threshold`
    /// requires all 3 - `n=3` tolerates zero faults) permanently stopped
    /// advancing within one round-interval of a single node's restart.
    /// Fixed by checkpointing `next_round` to `round_checkpoint_path`
    /// (`persist_round_checkpoint`) every time it advances, and restoring
    /// it on startup (`main.rs`) instead of always starting at 0 - a
    /// restarted validator now resumes at a round number it has genuinely
    /// never used before, so it can never collide with its own prior
    /// history again. The DAG/certificate *content* for earlier rounds is
    /// still not persisted - it doesn't need to be: the existing
    /// quorum-of-previous-round gate a few lines below already blocks this
    /// validator from proposing anything until real certificates for
    /// `next_round - 1` are known, which the *existing* certificate
    /// re-sync mechanism organically supplies as peers' retried broadcasts
    /// arrive - no new catch-up logic was needed once the round number
    /// itself stopped colliding.
    pub async fn propose_round(&self) {
        // Retry path: a proposal is still waiting on quorum votes.
        // Re-broadcasting it every tick until it certifies is what fixes
        // a real liveness bug found via `qchain-simulation`'s
        // healing-partition scenario (see project-lessons-learned):
        // without this, a single dropped copy of a VertexProposal (e.g.
        // during a transient network partition, or the ordinary
        // connection-refused race at validator startup) stalls this
        // validator - and every later round that depends on its
        // certificate - permanently, since nothing else ever resends it.
        // Idempotent for peers who already voted: the equivocation lock
        // in `handle_message`'s `VertexProposal` arm treats a repeat of
        // the exact same digest as a harmless no-op re-vote.
        let retry_vertex = {
            let state = self.state.lock().await;
            state.own_pending_vertex.clone()
        };
        if let Some((vertex, author_signature)) = retry_vertex {
            self.network.broadcast(&NetMessage::VertexProposal { vertex, author_signature }).await;
            return;
        }

        let (vertex, sig, worker_batches) = {
            let mut state = self.state.lock().await;
            let round = state.next_round;
            if round > 0 {
                let prev_round = round - 1;
                let quorum = self.validators.quorum_threshold();
                // Real permanent-freeze regression found live while
                // building the dashboard (restarting a persisted
                // single-validator node for a screenshot): this gate's
                // only source of "round `prev_round` really had quorum"
                // evidence is the in-memory DAG, which `round_checkpoint`
                // deliberately does not persist. In a multi-validator
                // network that's fine - a restarted validator's peers keep
                // proposing new rounds, and receiving those organically
                // re-syncs the missing certificate via the existing
                // missing-parent request path. A validator whose own stake
                // *alone* already meets quorum (always true for n=1, and
                // for any real "dominant validator" topology) has no such
                // peer to rely on and would otherwise stall here forever
                // after every restart - confirmed live: single validator,
                // `data_dir` set, killed and restarted, `next_round`/
                // `dag_certificates` frozen for 10+ real seconds.
                // Sound, not a weakened check: `state.next_round` only
                // ever advances past a round *after* this exact gate
                // passed for it (a few lines below, `state.next_round =
                // round + 1`), so `next_round > 0` alone already proves a
                // prior process lifetime satisfied quorum for every round
                // up to `prev_round` - re-deriving that from DAG content
                // that was never guaranteed to survive a restart is
                // unnecessary when this validator's own stake was always
                // sufficient on its own. Does not change behavior for a
                // real spread-stake network (there, no single validator's
                // stake reaches quorum alone, so the check below still
                // runs exactly as before).
                if self.validators.stake_of(&self.self_id) < quorum {
                    let stake: u64 =
                        state.dag.certificates_in_round(prev_round).map(|c| self.validators.stake_of(&c.vertex.author)).sum();
                    if stake < quorum {
                        return;
                    }
                }
            }

            let txs: Vec<Transaction> = drain_ready_transactions(&mut state);
            let worker_batches = partition_into_worker_batches(txs);
            let mut batch_digests: Vec<(WorkerId, Digest)> = Vec::with_capacity(worker_batches.len());
            for (worker_id, batch) in &worker_batches {
                let digest = batch.digest();
                state.batches.insert(digest, batch.clone());
                batch_digests.push((*worker_id, digest));
            }
            let parents: Vec<Digest> = if round == 0 {
                vec![]
            } else {
                let mut p: Vec<Digest> = state.dag.certificates_in_round(round - 1).map(|c| c.digest()).collect();
                p.sort();
                p
            };
            let vertex = Vertex { round, author: self.self_id, batch_digests, parents };
            // Signed *before* anything is committed to state, so a signing
            // failure (never expected in practice, but not assumed away)
            // leaves `next_round`/`voted_for`/`own_pending_vertex`
            // untouched rather than advancing them with nothing actually
            // broadcast. This is the one and only signature this validator
            // produces over its own vertex - reused as both the wire-level
            // `author_signature` (`NetMessage::VertexProposal`) and this
            // validator's own self-vote (`record_vote` below), since both
            // are mathematically the same thing: this validator's
            // signature over this vertex's digest.
            let digest = vertex.digest();
            let sig = match self.keypair.sign(&digest[..]) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("failed to sign proposed vertex: {e}");
                    return;
                }
            };
            state.own_pending_vertex = Some((vertex.clone(), sig.clone()));
            state.next_round = round + 1;
            persist_round_checkpoint(&state);
            state.voted_for.insert((round, self.self_id), digest);
            (vertex, sig, worker_batches)
        };

        // Each worker lane's batch is its own small, independently
        // retriable message - see the module docs for why this replaced a
        // single inline batch gossiped alongside the vertex.
        for (worker_id, batch) in worker_batches {
            self.network.broadcast(&NetMessage::WorkerBatchGossip { worker_id, batch }).await;
        }
        let digest = vertex.digest();
        self.network.broadcast(&NetMessage::VertexProposal { vertex, author_signature: sig.clone() }).await;

        if let Some(cert) = self.record_vote(digest, self.self_id, sig).await {
            self.network.broadcast(&NetMessage::CertificateBroadcast(cert)).await;
            self.try_commit().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_core::{Account, Transaction};
    use qchain_crypto::Keypair;
    use qchain_execution::Ledger;
    use qchain_storage::InMemoryStore;

    fn new_state() -> EngineState {
        EngineState {
            ledger: Ledger::new(Box::new(InMemoryStore::new())).unwrap(),
            dag: DagStore::new(),
            consensus: ConsensusState::new(),
            mempool: HashMap::new(),
            batches: HashMap::new(),
            pending_votes: HashMap::new(),
            own_pending_vertex: None,
            next_round: 0,
            round_checkpoint_path: None,
            executed: 0,
            voted_for: HashMap::new(),
            pending_cert_requests: HashMap::new(),
            pending_batch_requests: HashMap::new(),
            pending_votes_to_send: HashMap::new(),
            own_last_certificate: None,
            first_seen_vertex: HashMap::new(),
            equivocation_evidence: HashMap::new(),
        }
    }

    fn tx(payer: &Keypair, nonce: u64) -> Transaction {
        Transaction::new_signed(payer, nonce, [0u8; 32], 1, vec![]).unwrap()
    }

    /// The exact bug this replaces: two transactions from the same account
    /// arrive out of nonce order (a real race under concurrent submission).
    /// The old flat-`Vec` mempool would include both in whatever order they
    /// landed - if the higher nonce came first in the batch, it failed and
    /// was dropped forever. The fixed mempool must always emit them in
    /// ascending nonce order regardless of arrival/insertion order.
    #[test]
    fn transactions_are_emitted_in_ascending_nonce_order_regardless_of_arrival_order() {
        let mut state = new_state();
        let alice = Keypair::generate().unwrap();
        state.ledger.seed_account(alice.pubkey(), Account::new_wallet(qchain_crypto::Pubkey::system_program_id()));

        // Insert nonce 1 before nonce 0 - simulating the exact race that
        // used to lose a transaction.
        let tx1 = tx(&alice, 1);
        let tx0 = tx(&alice, 0);
        state.mempool.entry(alice.pubkey()).or_default().insert(1, tx1.clone());
        state.mempool.entry(alice.pubkey()).or_default().insert(0, tx0.clone());

        let ready = drain_ready_transactions(&mut state);
        assert_eq!(ready.len(), 2, "both transactions must be included, not just one");
        assert_eq!(ready[0].message.nonce, 0);
        assert_eq!(ready[1].message.nonce, 1);
    }

    /// A transaction whose predecessor hasn't arrived yet must stay queued,
    /// not be dropped - it should surface in a later round once the gap is
    /// filled, rather than vanishing.
    #[test]
    fn a_transaction_with_a_missing_predecessor_stays_queued_instead_of_being_dropped() {
        let mut state = new_state();
        let alice = Keypair::generate().unwrap();
        state.ledger.seed_account(alice.pubkey(), Account::new_wallet(qchain_crypto::Pubkey::system_program_id()));

        // Only nonce 1 has arrived; nonce 0 (the account's current expected
        // nonce) is still missing.
        state.mempool.entry(alice.pubkey()).or_default().insert(1, tx(&alice, 1));

        let ready = drain_ready_transactions(&mut state);
        assert!(ready.is_empty(), "a transaction with a gap ahead of it must not be included yet");
        assert_eq!(state.mempool.get(&alice.pubkey()).map(|q| q.len()), Some(1), "it must remain queued, not be dropped");

        // Once the missing nonce 0 arrives, both become ready together.
        state.mempool.entry(alice.pubkey()).or_default().insert(0, tx(&alice, 0));
        let ready = drain_ready_transactions(&mut state);
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].message.nonce, 0);
        assert_eq!(ready[1].message.nonce, 1);
    }

    /// Entries at or below the account's current on-chain nonce (already
    /// applied, e.g. via another validator's batch in a multi-node
    /// network) must be garbage-collected rather than left to accumulate
    /// or block newer nonces forever.
    #[test]
    fn stale_entries_below_the_current_nonce_are_garbage_collected() {
        let mut state = new_state();
        let alice = Keypair::generate().unwrap();
        // Account's on-chain nonce is already 2 - nonce 0 and 1 are stale.
        state.ledger.seed_account(
            alice.pubkey(),
            Account { nonce: 2, ..Account::new_wallet(qchain_crypto::Pubkey::system_program_id()) },
        );
        state.mempool.entry(alice.pubkey()).or_default().insert(0, tx(&alice, 0));
        state.mempool.entry(alice.pubkey()).or_default().insert(1, tx(&alice, 1));
        state.mempool.entry(alice.pubkey()).or_default().insert(2, tx(&alice, 2));

        let ready = drain_ready_transactions(&mut state);
        assert_eq!(ready.len(), 1, "only the one transaction matching the real current nonce should be ready");
        assert_eq!(ready[0].message.nonce, 2);
        assert!(!state.mempool.contains_key(&alice.pubkey()), "the now-empty per-account queue must be cleaned up too");
    }

    /// Different accounts are independent - a gap in one account's nonce
    /// sequence must not block another account's ready transactions.
    #[test]
    fn independent_accounts_dont_block_each_other() {
        let mut state = new_state();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();
        state.ledger.seed_account(alice.pubkey(), Account::new_wallet(qchain_crypto::Pubkey::system_program_id()));
        state.ledger.seed_account(bob.pubkey(), Account::new_wallet(qchain_crypto::Pubkey::system_program_id()));

        // Alice has a gap (missing nonce 0); Bob is ready at nonce 0.
        state.mempool.entry(alice.pubkey()).or_default().insert(1, tx(&alice, 1));
        state.mempool.entry(bob.pubkey()).or_default().insert(0, tx(&bob, 0));

        let ready = drain_ready_transactions(&mut state);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].message.payer, bob.pubkey());
    }

    /// A given account's transactions must always land in the same worker
    /// lane, in their original (already nonce-ordered) relative order -
    /// that's what keeps `try_commit`'s per-account application order
    /// correct once transactions are split across independently-gossiped
    /// batches instead of one inline batch.
    #[test]
    fn partition_into_worker_batches_groups_by_payer_and_preserves_order() {
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();

        let mut tx_alice_0 = tx(&alice, 0);
        tx_alice_0.message.payer = Pubkey::new([0u8; 32]);
        let mut tx_alice_1 = tx(&alice, 1);
        tx_alice_1.message.payer = Pubkey::new([0u8; 32]);
        let mut tx_bob_0 = tx(&bob, 0);
        tx_bob_0.message.payer = Pubkey::new([1u8; 32]);

        let batches = partition_into_worker_batches(vec![tx_alice_0, tx_alice_1, tx_bob_0]);

        assert_eq!(batches.len(), 2, "two distinct payer lanes (byte 0 vs byte 1, mod WORKER_COUNT) must produce two batches");
        let lane0 = &batches.iter().find(|(id, _)| *id == 0).expect("lane 0 must be present").1;
        assert_eq!(lane0.transactions.len(), 2, "both of alice's transactions land in the same lane");
        assert_eq!(lane0.transactions[0].message.nonce, 0);
        assert_eq!(lane0.transactions[1].message.nonce, 1, "relative order within the lane must be preserved");
        let lane1 = &batches.iter().find(|(id, _)| *id == 1).expect("lane 1 must be present").1;
        assert_eq!(lane1.transactions.len(), 1);
    }

    /// Lanes with nothing assigned to them must not produce empty batches -
    /// an empty round should gossip nothing, not `WORKER_COUNT` empty
    /// `WorkerBatchGossip` messages.
    #[test]
    fn partition_into_worker_batches_of_no_transactions_produces_no_batches() {
        assert!(partition_into_worker_batches(vec![]).is_empty());
    }

    /// The actual point of the round-checkpoint fix (see `propose_round`'s
    /// doc comment for the live-network stall this closes): a restarted
    /// node must be able to read back the exact round number a previous
    /// life last checkpointed, not silently lose it.
    #[test]
    fn persist_round_checkpoint_writes_a_value_that_reads_back_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("round_checkpoint");
        let mut state = new_state();
        state.round_checkpoint_path = Some(path.clone());
        state.next_round = 468;

        persist_round_checkpoint(&state);

        let resumed: u64 = std::fs::read_to_string(&path).unwrap().trim().parse().unwrap();
        assert_eq!(resumed, 468, "a restarted node must resume at the exact round it last checkpointed, not 0");
    }

    /// A node with no `data_dir` (in-memory only) has no checkpoint path -
    /// this must be a harmless no-op, not a panic on `unwrap`.
    #[test]
    fn persist_round_checkpoint_is_a_no_op_without_a_configured_path() {
        let mut state = new_state();
        state.round_checkpoint_path = None;
        state.next_round = 5;
        persist_round_checkpoint(&state);
    }

    /// The exact live-confirmed attack `payer_can_afford_admission` closes
    /// (see its doc comment): a freshly generated keypair with no seeded
    /// account at all - no funds, ever - must be rejected at admission, not
    /// let through to waste every validator's CPU on a doomed execution
    /// attempt.
    #[test]
    fn a_never_funded_payer_cannot_get_a_transaction_admitted() {
        let state = new_state();
        let attacker = Keypair::generate().unwrap();
        assert!(
            !payer_can_afford_admission(&state, &tx(&attacker, 0)),
            "an account with no balance at all must not pass the admission check"
        );
    }

    /// A legitimately funded payer must still be admitted - the fix
    /// shouldn't reject transactions that can actually pay their own fee.
    #[test]
    fn a_funded_payer_can_get_a_transaction_admitted() {
        let mut state = new_state();
        let alice = Keypair::generate().unwrap();
        state.ledger.seed_account(
            alice.pubkey(),
            Account { balance: 10_000_000, ..Account::new_wallet(qchain_crypto::Pubkey::system_program_id()) },
        );
        assert!(
            payer_can_afford_admission(&state, &tx(&alice, 0)),
            "an account with real balance covering its byte fee must be admitted"
        );
    }

    /// The real, live-measured DoS this closes (see `stark_proof`'s doc
    /// comment): proving cost scales far worse than linearly with receipt
    /// count, so a validator with a long real history must never let a
    /// caller (including one that omits `limit` entirely, asking for
    /// "everything") force proving more than `MAX_STARK_PROOF_RECEIPTS`
    /// receipts in one call.
    #[test]
    fn stark_proof_limit_is_always_capped_regardless_of_what_is_requested() {
        assert_eq!(effective_stark_proof_limit(None, 50), 50, "fewer receipts than the cap exist - prove all of them");
        assert_eq!(effective_stark_proof_limit(None, 10_000), MAX_STARK_PROOF_RECEIPTS, "omitting limit must not mean 'prove everything'");
        assert_eq!(effective_stark_proof_limit(Some(10_000), 10_000), MAX_STARK_PROOF_RECEIPTS, "an explicit huge limit must still be capped");
        assert_eq!(effective_stark_proof_limit(Some(10), 10_000), 10, "a real request smaller than the cap must be honored exactly");
        assert_eq!(effective_stark_proof_limit(Some(10_000), 3), 3, "requesting more than exists must still only prove what exists");
    }
}
