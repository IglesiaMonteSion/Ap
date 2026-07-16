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

use qchain_consensus::{verify_certificate, ConsensusState, DagStore, ValidatorInfo, ValidatorSchedule, ValidatorSet};

/// Derive the active consensus committee from the on-chain validator registry
/// (phase-3.3 rotation). Runs the deterministic `select_active_set` (top-N by
/// stake, min-stake filtered — see `qchain_execution::validator_registry`) and
/// maps each registered validator to a consensus `ValidatorInfo`. Returns
/// `None` when the registry yields no viable committee (empty), so the caller
/// keeps the current committee — the reason a rotation network still runs on
/// its genesis validators until real on-chain registrations exist. **Pure and
/// deterministic**: every honest node computing this from the identical
/// committed registry state gets the byte-identical committee, which is what
/// keeps a live rotation fork-free.
/// `live_stake_of` returns the EFFECTIVE stake of a registered validator: for a
/// genesis-seeded entry (`self_stake_account == None`) it's the snapshot; for a
/// self-registered validator it's the LIVE self-stake read from the store, so a
/// validator that undelegated its bond is dropped (falls below the minimum in
/// `select_active_set`). This closes the v4.1.4 audit's MEDIUM: a registered
/// validator can no longer withdraw its self-stake and keep sitting in the
/// active committee with a stale snapshot, non-slashable. The caller (the epoch
/// ratchet) supplies the closure over committed store state, keeping this
/// deterministic and byte-identical across honest nodes.
pub fn active_committee_from_registry(
    registry: &qchain_execution::validator_registry::ValidatorRegistryData,
    live_stake_of: impl Fn(&qchain_execution::validator_registry::RegisteredValidator) -> u64,
) -> Option<ValidatorSet> {
    use qchain_execution::validator_registry::{select_active_set, MAX_ACTIVE_VALIDATORS, ValidatorRegistryData};
    // Rebuild the registry with each entry's effective (live) stake, then run
    // the same deterministic top-N selection. A withdrawn self-stake becomes 0
    // and `select_active_set`'s min-stake filter removes it.
    let live = ValidatorRegistryData {
        validators: registry
            .validators
            .iter()
            .map(|rv| {
                let mut r = rv.clone();
                r.stake = live_stake_of(rv);
                r
            })
            .collect(),
    };
    let active = select_active_set(&live, MAX_ACTIVE_VALIDATORS);
    if active.is_empty() {
        return None;
    }
    let infos: Vec<ValidatorInfo> = active.into_iter().map(|rv| ValidatorInfo { id: rv.validator, pubkey_bundle: rv.pubkey_bundle, stake: rv.stake }).collect();
    Some(ValidatorSet::new(infos))
}

/// SUPERSEDED (v4.1.0): the epoch ratchet no longer calls this — it now adopts
/// the derived set wholesale (real shrink: `Some(d) => (*d).clone()`), which is
/// safe because the consensus ordering fixes landed first (v4.0.3 `direct_status`
/// liveness under a shrinking committee + cert-availability broadcast, v4.0.4
/// atomic per-leader causal emission that closes the late-cert reorder fork).
/// Kept `pub` and tested as a documented reference for the grow-only model and
/// for anyone wiring rotation without those consensus fixes; do not reintroduce
/// it into the ratchet.
///
/// Grow-only (monotonic) committee adoption for automatic rotation. The next
/// epoch's committee is `current ∪ (derived members not already in current)`,
/// capped at `MAX_ACTIVE_VALIDATORS` — a current member is **never dropped**
/// mid-flight, only newcomers are added (and a current member's stake is
/// refreshed to its newly-derived value).
///
/// Why grow-only rather than adopting the derived set wholesale: automatic
/// *removal* of a live validator is the DAG-BFT **reconfiguration** problem
/// (Sui/Mysticeti solve it with a dedicated epoch-change protocol where the
/// outgoing committee cleanly finalizes everything before the new one starts).
/// A naive mid-flight shrink freezes consensus — confirmed live: after a
/// committee derived 3→2, the DAG still carried a round with three
/// certificates (the dropped validator certified before the drop propagated),
/// so honest round-(r) vertices legitimately referenced 3 parents while the
/// new committee size was 2, and every such proposal was rejected forever
/// (`request_missing_parents` for the now-orphaned third parent never
/// resolving). Grow-only makes that impossible: `for_round(r-1) >= for_round(r)`
/// never holds in the shrinking direction, so a round never references more
/// parents than its own committee allows. Removal (unregister, slash-driven
/// eviction, rank-out beyond `MAX_ACTIVE`) is deliberately deferred to a real
/// reconfiguration protocol; until then a validator that leaves the registry
/// stays in the active committee (still safe — it keeps consensing) but simply
/// isn't auto-evicted.
///
/// Pure and deterministic: every honest node computing this from the identical
/// `current` and identical committed registry gets the byte-identical result.
pub fn merge_committee_grow_only(current: &ValidatorSet, derived: &ValidatorSet) -> ValidatorSet {
    use qchain_execution::validator_registry::MAX_ACTIVE_VALIDATORS;
    // Start from every current member, refreshing stake from `derived` when the
    // registry now records a different value for them.
    let mut infos: Vec<ValidatorInfo> = current
        .infos()
        .into_iter()
        .map(|mut vi| {
            if let Some(d) = derived.get(&vi.id) {
                vi.stake = d.stake;
            }
            vi
        })
        .collect();
    // Add newcomers (derived members not currently seated), in deterministic
    // stake-desc / id-asc order, until the active cap is reached.
    let mut newcomers: Vec<ValidatorInfo> = derived.infos().into_iter().filter(|d| current.get(&d.id).is_none()).collect();
    newcomers.sort_by(|a, b| b.stake.cmp(&a.stake).then_with(|| a.id.cmp(&b.id)));
    for nc in newcomers {
        if infos.len() >= MAX_ACTIVE_VALIDATORS {
            break;
        }
        infos.push(nc);
    }
    ValidatorSet::new(infos)
}

/// Stage-3 peer discovery: the P2P peer set to install when the committee is
/// derived from the on-chain registry — the config mesh **unioned** with the
/// active committee's registered addresses (excluding self, deduped by id,
/// skipping any unparseable address). Union rather than replace so a reachable
/// config peer is never dropped because of a bad registry address, while a
/// genuinely new validator (registered, not in anyone's config) is added and
/// therefore dialed automatically.
pub fn merge_peers(config_peers: &[PeerInfo], active: &[qchain_execution::validator_registry::RegisteredValidator], self_id: &qchain_core::ValidatorId) -> Vec<PeerInfo> {
    let mut peers = config_peers.to_vec();
    for rv in active {
        if &rv.validator == self_id || peers.iter().any(|p| p.id == rv.validator) {
            continue;
        }
        match rv.address.parse::<std::net::SocketAddr>() {
            Ok(addr) => peers.push(PeerInfo { id: rv.validator, addr }),
            Err(e) => tracing::warn!("skipping unparseable registry address '{}' for validator {}: {e}", rv.address, rv.validator),
        }
    }
    peers
}

/// One validator's entry in a persisted epoch committee (phase-3.3 rotation).
/// Borsh-encoded to `data_dir/committees` so a restarted rotation node can
/// reconstruct the committee for each already-finalized epoch — those committees
/// were derived from *historical* registry states the current ledger no longer
/// holds, so without this a restart could not re-resolve the retained DAG
/// window under the right committees.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct PersistedValidator {
    id: qchain_crypto::Pubkey,
    pubkey_bundle: qchain_crypto::PublicKeyBundle,
    stake: u64,
}

/// Borsh-serialize a committee (deterministic order via `ids_sorted`) for the
/// on-disk committee log.
pub fn serialize_committee(committee: &ValidatorSet) -> Vec<u8> {
    let entries: Vec<PersistedValidator> = committee
        .ids_sorted()
        .into_iter()
        .filter_map(|id| committee.get(&id).map(|info| PersistedValidator { id, pubkey_bundle: info.pubkey_bundle.clone(), stake: info.stake }))
        .collect();
    borsh::to_vec(&entries).expect("committee always serializes")
}

/// Reconstruct a committee from the on-disk committee log. `None` on corrupt
/// bytes (a corrupt entry is skipped at reload, not fatal — that epoch simply
/// re-derives from peers/registry, same graceful degradation as a corrupt cert).
pub fn deserialize_committee(bytes: &[u8]) -> Option<ValidatorSet> {
    let entries: Vec<PersistedValidator> = borsh::from_slice(bytes).ok()?;
    Some(ValidatorSet::new(entries.into_iter().map(|p| ValidatorInfo { id: p.id, pubkey_bundle: p.pubkey_bundle, stake: p.stake }).collect()))
}
use qchain_core::{Batch, Certificate, Digest, EquivocationEvidence, Round, Transaction, ValidatorId, Vertex, WorkerId};
use qchain_crypto::{MultiSignature, Keypair, Pubkey};
use qchain_execution::{Ledger, TransferReceipt};
use qchain_network::{NetMessage, Network, PeerInfo};
use serde::{Deserialize, Serialize};
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

/// Bound on the in-memory (and reload/on-disk) transfer-receipt log. Each
/// receipt carries four Merkle proofs (~32 KB), so an unbounded log turns
/// chain age directly into RAM - a 50k-transfer flood is ~1.6 GB, and
/// reloading that many on boot stalled a live node's startup for ~18 s (which
/// read as a false "possible freeze" from the updater's health check, since
/// RPC only binds after the reload). This window keeps the most recent
/// receipts for the explorer and comfortably covers `MAX_STARK_PROOF_RECEIPTS`
/// (the endpoint only ever serves the last 500), while capping RAM at
/// ~160 MB and keeping boot fast. The on-disk log is pruned to the same
/// bound so both reload cost and disk growth stay predictable across repeated
/// stress runs. See `Ledger::cap_receipt_log`.
pub const MAX_INMEM_RECEIPTS: usize = 5_000;

/// Same bound for the staking-activity log (far smaller per entry - no Merkle
/// proofs - but kept bounded for the same predictable-reload reason).
pub const MAX_INMEM_STAKING_EVENTS: usize = 5_000;

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

/// Hard cap on how many activity rows ONE `/transfers` or `/staking_activity`
/// response returns, regardless of the caller-supplied `limit`. The activity
/// logs are unbounded and reloaded in full on restart, so an unauthenticated
/// request with a huge `limit` would otherwise clone the entire history under
/// the global consensus lock (a liveness DoS growing with chain age). Clients
/// page through more with `offset`.
const MAX_ACTIVITY_LIMIT: usize = 1_000;

/// Hard cap on how many rows the FILTERED (`?staker=`) staking-activity scan
/// examines before giving up, so a sparse or never-staked address can't force a
/// full-history walk under the lock. A wallet sees its activity within the most
/// recent `MAX_ACTIVITY_SCAN` network staking events - ample for a recent-view;
/// deeper history is the future real-indexer's job.
const MAX_ACTIVITY_SCAN: usize = 100_000;

/// How many `GET /stark_proof` proofs may be generated concurrently across
/// the whole node. Each proof is already row-capped (`MAX_STARK_PROOF_RECEIPTS`)
/// so one call's cost is bounded, but `prove_batch` is CPU-heavy and the
/// endpoint is unauthenticated - without a concurrency bound, N simultaneous
/// callers each pin a core (the proof is built outside the state lock, so
/// they genuinely run in parallel). This caps total proving CPU to a small
/// fixed multiple of one proof, regardless of how many callers arrive at
/// once; excess callers queue for a permit rather than each starting a fresh
/// parallel proof.
/// This node's software version (`MAJOR.MINOR.PATCH`), taken straight from
/// the crate version so it can never drift from the actual build. Announced
/// periodically to peers and reported on `/version`/`/status`; the whole
/// upgrade-notification mechanism keys off it. Bump the workspace version in
/// the root `Cargo.toml` to cut a new release (started at `1.0.0`).
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Whether semantic version `a` is strictly newer than `b` (both
/// `MAJOR.MINOR.PATCH`). A malformed version compares as not-newer, so a
/// garbage announcement can never raise a false "update available".
fn version_is_newer(a: &str, b: &str) -> bool {
    fn parse(v: &str) -> Option<(u64, u64, u64)> {
        let mut it = v.trim().split('.');
        let major = it.next()?.parse().ok()?;
        let minor = it.next()?.parse().ok()?;
        let patch = it.next()?.parse().ok()?;
        Some((major, minor, patch))
    }
    match (parse(a), parse(b)) {
        (Some(x), Some(y)) => x > y,
        _ => false,
    }
}

const MAX_CONCURRENT_STARK_PROOFS: usize = 2;
static STARK_PROOF_PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_CONCURRENT_STARK_PROOFS);

/// Caps concurrent full-state snapshot serves (`GET /snapshot`). Serving a
/// snapshot copies the entire account set out from under the state lock -
/// cheap per call at testnet scale but linear in state size and
/// unauthenticated, so an unbounded fan-out of concurrent pulls could pin
/// memory/CPU. Excess callers queue for a permit, same pattern as
/// `MAX_CONCURRENT_STARK_PROOFS`.
const MAX_CONCURRENT_SNAPSHOTS: usize = 2;
static SNAPSHOT_PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(MAX_CONCURRENT_SNAPSHOTS);

/// How long a captured point-in-time snapshot stays servable before the node
/// re-captures a fresh one (see `CachedSnapshot`). Long enough that a client
/// can page through a large state within one snapshot without it rotating,
/// short enough that a snapshot's extra `O(state)` memory is not held
/// indefinitely after the last syncing peer finishes.
const SNAPSHOT_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(120);

/// Accounts returned per `snapshot_page` call - bounds a single page's wire
/// size (and JSON-decode memory on the client) regardless of total state
/// size. The client keyset-paginates (`after` the last address it saw) until
/// it gets a short page.
const SNAPSHOT_PAGE_SIZE: usize = 1_000;


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

/// How many rounds a cached worker batch is retained behind the current
/// round before eviction (see `EngineState::batch_seen_round`). Bounds the
/// `batches` map - fed by unauthenticated gossip whose content-addressed
/// digests an attacker fully controls - without breaking resync: a lagging
/// peer that reconnects within this window can still fetch every batch it
/// needs (`WorkerBatchRequest`), while junk batches that are never committed
/// are dropped once they age out. Deliberately larger than
/// `ROUND_STATE_RETENTION` (and than any resync a live validator recovers
/// across in practice); a peer more than this many rounds behind is in
/// snapshot territory, out of scope for reactive per-digest resync.
const BATCH_RETENTION_ROUNDS: Round = 1_024;

/// A vertex proposal whose `round` is more than this far ahead of our own
/// `next_round` is rejected before voting. A legitimate proposal is at most a
/// round or two ahead of the local frontier; a peer genuinely this far behind
/// catches up via certificate resync / snapshot sync, not by having us vote on
/// a round we can't validate. Blocks a Byzantine author from getting a vertex
/// at `round = u64::MAX` certified (which would poison `DagStore::highest_round`
/// and the ordering re-resolution). Generous - never rejects a healthy peer.
const MAX_ROUND_LOOKAHEAD: Round = 1_024;

/// How many rounds of certified DAG history to retain behind the consensus
/// *finalized floor* (`ConsensusState::finalized_floor`) before garbage-
/// collecting older certificates from both the in-memory `DagStore` and the
/// on-disk cert log. Without this the DAG grows one certificate per validator
/// per round forever - an attacker cannot inflate it (only quorum-certified
/// certificates enter), but a genuinely long-lived chain would still climb in
/// RAM and disk without bound. Pruned rounds are permanently committed history
/// whose account effects already persisted; the matching `Bullshark::gc_floor`
/// barrier lets a restarted node re-derive its retained window without walking
/// off the bottom of the pruned DAG. Kept `<=` `BATCH_RETENTION_ROUNDS` so a
/// certificate is never dropped while a peer resyncing it could still fetch it
/// but not its worker batch (which would leave that peer unable to execute the
/// certificate's transactions) - certificates are pruned no later than their
/// batches, never earlier. Comfortably larger than any reactive per-digest
/// resync gap; a peer further behind than this is in snapshot territory,
/// already out of scope for reactive resync (same boundary the batch cache
/// draws).
const DAG_RETENTION_ROUNDS: Round = 1_024;

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

/// Prunes a best-effort append-only `sled` log (the receipt / staking-event
/// logs) down to at most `max` entries, removing the OLDEST first. Keys are
/// monotonic `generate_id()` big-endian ids, so a forward `iter()` yields
/// oldest-first and the first `len - max` keys are exactly the ones to drop.
/// Best-effort like `persist_receipt`: a failed removal only leaves a few
/// extra rows to reload next boot, never a correctness problem. No-op when the
/// log is absent (in-memory node) or already within bound.
fn prune_log_to_last(db: Option<&sled::Db>, max: usize) {
    let Some(db) = db else { return };
    let len = db.len();
    if len <= max {
        return;
    }
    let excess = len - max;
    let mut old_keys: Vec<sled::IVec> = Vec::with_capacity(excess);
    for entry in db.iter().take(excess) {
        match entry {
            Ok((k, _v)) => old_keys.push(k),
            Err(e) => {
                tracing::warn!("failed to scan the on-disk log for pruning: {e}");
                return;
            }
        }
    }
    for k in old_keys {
        if let Err(e) = db.remove(&k) {
            tracing::warn!("failed to prune an old on-disk log entry: {e}");
        }
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
    /// The round at which each cached batch was first seen (this node's
    /// `next_round` at cache time) - used only to evict batches by round
    /// window in `prune_stale_round_state`, closing the unbounded-`batches`
    /// OOM (an unauthenticated `WorkerBatchGossip` flood of distinct junk
    /// digests) without breaking resync: batches stay cached for a generous
    /// `BATCH_RETENTION_ROUNDS` window - long enough for a normal lagging
    /// peer to fetch them (`WorkerBatchRequest`), evicted only once no peer
    /// resyncing within that window could still need them.
    pub batch_seen_round: HashMap<Digest, Round>,
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
    /// Value: (who to ask, the round this request was first made). The round is
    /// what lets `prune_stale_round_state` bound this map by round window - a
    /// Byzantine committee member could otherwise stream `VertexProposal`s each
    /// carrying fresh random parent digests that never resolve, growing this map
    /// (and its per-tick re-send bandwidth) without bound (found in a proactive
    /// audit; the per-message `parents.len()` cap bounds one message, not the
    /// cross-message accumulation).
    pub pending_cert_requests: HashMap<Digest, (ValidatorId, Round)>,
    pub pending_batch_requests: HashMap<(WorkerId, Digest), (ValidatorId, Round)>,
    /// Outstanding `Vote` replies this validator owes to a vertex's author,
    /// keyed by the vertex digest being voted for, valued by (who to send
    /// it to, the signature itself) - see `retry_pending_resync_requests`'s
    /// doc comment for the real, confirmed-live bug this closes: unlike
    /// `VertexProposal`/`CertificateRequest`/`WorkerBatchRequest`, a `Vote`
    /// was a single-attempt send with no retry at all.
    pub pending_votes_to_send: HashMap<Digest, (ValidatorId, MultiSignature, Round)>,
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
    /// The highest software version this node has heard a real validator-set
    /// peer announce (`NetMessage::VersionAnnounce`) that is strictly newer
    /// than this node's own `NODE_VERSION` - i.e. "there is an update out
    /// there." Surfaced on `/status`, `/version`, and the dashboard so the
    /// operator knows to upgrade. `None` means this node is at least as new
    /// as everything it has heard. Never drives any protocol behavior.
    pub update_available: Option<String>,
    /// Certificates whose Bullshark total order is already settled but whose
    /// worker batches are not all locally available yet, held in committed
    /// order awaiting execution. This is the fix for a real, permanent fork:
    /// `consensus.advance` emits a certificate's digest exactly once (its
    /// `seen` set never re-emits it), so a certificate ordered before its
    /// batch arrived MUST NOT be skipped - skipping drops those transactions
    /// on this node forever while other nodes execute them, diverging both
    /// balances AND (since dynamic fees) the on-chain `FeeState`/base-fee
    /// curve, compounding on every subsequent transaction. Instead the
    /// certificate is buffered here (a full clone, so DAG pruning can't lose
    /// it) and execution blocks on it - never reordering past it - until its
    /// batches are re-synced (`request_missing_batches`), at which point the
    /// queue drains in order. Empty in steady state (batches almost always
    /// arrive before or with the certificate); a stall here is the correct,
    /// safe BFT behavior (no fork) for a node lagging far enough that a peer
    /// already pruned the batch - snapshot-sync territory (see task #109).
    pub pending_execution: std::collections::VecDeque<Certificate>,
}

/// One row of the validator directory served by `GET /validators`: the
/// consensus address (derived from the key bundle), the optional human-readable
/// name from the shared genesis config, and the BFT stake weight. Static config
/// data, computed once at startup - lets a wallet show a named list to pick a
/// delegation target instead of asking for a raw address.
#[derive(Clone, serde::Serialize)]
pub struct ValidatorDirEntry {
    pub address: ValidatorId,
    pub name: Option<String>,
    pub stake: u64,
}

/// A batch-re-sync request the executor is blocked on: the missing
/// `(worker, digest)` pairs plus the validator to fetch them from. `None` when
/// execution is not blocked (the steady-state case).
type BlockedResync = Option<(Vec<(WorkerId, Digest)>, ValidatorId)>;

/// Split off the executable prefix of the pending-execution queue: certificates
/// whose worker batches are ALL locally cached, in committed order, stopping at
/// (and leaving buffered) the first certificate with a missing batch and every
/// certificate after it. This is the core of the permanent-fork fix documented
/// on `EngineState::pending_execution`: never skip a certificate for a missing
/// batch (its digest is already consumed from consensus's `seen` set, so it
/// would be lost forever and fork this node), and never reorder execution past
/// it. Returns the ready certificates (removed from the front) and, if the
/// queue is now blocked, the missing `(worker, digest)` pairs plus the author
/// to re-sync them from.
fn take_executable_prefix(
    pending: &mut std::collections::VecDeque<Certificate>,
    batches: &HashMap<Digest, Batch>,
) -> (Vec<Certificate>, BlockedResync) {
    let mut ready = Vec::new();
    let mut blocked = None;
    while let Some(cert) = pending.front() {
        let missing: Vec<(WorkerId, Digest)> = cert
            .vertex
            .batch_digests
            .iter()
            .copied()
            .filter(|(_, d)| !batches.contains_key(d))
            .collect();
        if !missing.is_empty() {
            blocked = Some((missing, cert.vertex.author));
            break;
        }
        ready.push(pending.pop_front().expect("front() was just Some"));
    }
    (ready, blocked)
}

pub struct Engine {
    pub self_id: ValidatorId,
    pub keypair: Keypair,
    /// The consensus committee currently in effect (this epoch). Under fixed
    /// membership (rotation off) it never changes; under phase-3.3 rotation the
    /// epoch ratchet in `try_commit` swaps it at each boundary. Used for
    /// everything that concerns the *current* round — proposing, voting, the
    /// round-advancement quorum, status. `RwLock<Arc<>>` so the frequent reads
    /// are a cheap `Arc` clone and the rare boundary swap is one write.
    pub validators: std::sync::RwLock<Arc<ValidatorSet>>,
    /// The full per-epoch committee schedule (phase-3.3). `for_round` resolves
    /// *any* round's committee — read per round by `ConsensusState::advance`
    /// (ordering) and `verify_certificate` (a certificate can be for an older
    /// round than the current one, e.g. during resync). Under rotation the
    /// epoch ratchet installs each new epoch's committee and raises the
    /// resolvable frontier. Same `RwLock<Arc<>>` rationale as `validators`.
    pub validator_schedule: std::sync::RwLock<Arc<ValidatorSchedule>>,
    /// The validator set as a wallet-facing directory (address, name, stake),
    /// built from the node config at startup and served via `GET /validators`.
    pub validator_directory: Vec<ValidatorDirEntry>,
    pub network: Arc<Network>,
    /// The static P2P mesh from the node config (`validators[].addr`). Under
    /// phase-3.3 rotation the epoch ratchet unions this with the current
    /// committee's on-chain registry addresses and installs the result as the
    /// live peer set (`Network::set_peers`), so a genuinely new validator is
    /// dialed automatically — stage 3 peer discovery. Kept as the base so a
    /// validator dropped from the config mesh is never lost to a bad registry
    /// address (union, not replace). Empty/unused when rotation is off.
    pub config_peers: Vec<PeerInfo>,
    pub state: Mutex<EngineState>,
    /// This network's own genesis-derived identity - see
    /// `qchain_node::config::NodeConfig::chain_id`'s doc comment. Checked
    /// against every transaction at admission (`submit_transaction`/the
    /// `TransactionGossip` handler), the real, live-confirmed fix for the
    /// cross-network replay gap documented on `qchain_core::Message::
    /// chain_id`.
    pub chain_id: [u8; 32],
    /// Optional on-disk log of every certificate this validator has inserted
    /// into its DAG (a `sled` tree at `data_dir/dag`, `None` for an in-memory
    /// node). Persisting the DAG is what lets a restarted validator reload
    /// its certificates from local disk instead of re-fetching the entire
    /// chain history from peers over the network one certificate at a time -
    /// the slow path a restart otherwise takes, since `round_checkpoint`
    /// deliberately persists only `next_round`, not the DAG. Re-execution of
    /// already-applied transactions during the resulting local re-derivation
    /// is harmless: `Ledger::apply_transaction` validates the nonce (rejecting
    /// a replay) BEFORE charging any fee or touching state, so a restart
    /// never double-charges or corrupts balances - the same idempotence the
    /// pre-existing network-refetch restart already relied on.
    pub cert_log: Option<sled::Db>,
    /// On-disk log of every worker batch this validator has cached (a `sled`
    /// tree at `data_dir/batches`, `None` for an in-memory node), keyed by the
    /// batch's content digest. Persisting batches is the necessary companion to
    /// `cert_log`: `cert_log` reloads the certificates, but a certificate only
    /// carries the *digest* of its worker batches, not their transactions. On
    /// restart, a fresh `ConsensusState` re-derives the committed order over the
    /// retained DAG and pushes every committed certificate onto
    /// `pending_execution`; `take_executable_prefix` then BLOCKS at the first
    /// certificate whose batch isn't locally cached (it never skips — see its
    /// docs). A multi-validator node re-syncs that batch from a peer; a **single
    /// validator has no peer**, so without persisting batches its execution
    /// stalls permanently at the first reloaded certificate that carried a
    /// transaction (a real, live-confirmed freeze of the solo-node deploy mode:
    /// rounds keep advancing but no new transaction ever executes). Re-applying
    /// the reloaded batches' transactions is idempotent — `apply_transaction`'s
    /// nonce check rejects an already-applied tx before touching state — so this
    /// only lets execution walk *past* the already-applied history to reach new
    /// transactions; it never double-applies. Best-effort persist, same contract
    /// as `cert_log`.
    pub batch_log: Option<sled::Db>,
    /// Phase-3.3 rotation: on-disk log of each epoch's committee (a `sled` db at
    /// `data_dir/committees`, `Some` only when rotation is on and the node
    /// persists to disk). The epoch ratchet writes each newly-installed
    /// committee here (keyed by epoch), and `main.rs` reloads them at startup to
    /// rebuild the schedule — because a committee was derived from the on-chain
    /// registry as of a *past* epoch boundary, state the current ledger no
    /// longer reflects, so it cannot be re-derived after a restart.
    pub committee_log: Option<sled::Db>,
    /// A cached consistent point-in-time snapshot for paginated serving, so a
    /// far-behind peer can download the state in bounded pages that all hash
    /// to one root (see `CachedSnapshot`/`snapshot_page`). Lazily captured on
    /// first request, refreshed past `SNAPSHOT_CACHE_TTL`.
    pub snapshot_cache: Mutex<Option<std::sync::Arc<CachedSnapshot>>>,
    /// On-disk log of captured `TransferReceipt`s (a `sled` tree at
    /// `data_dir/receipts`, `None` for an in-memory node), keyed by a
    /// monotonic sequence so iteration yields them oldest-first. This is what
    /// makes the transaction *history* (not just balances) survive a restart:
    /// without it, the in-memory receipt `Vec` is empty on every boot and the
    /// dashboard shows no past activity even though the ledger state is intact.
    /// Best-effort persist, same contract as `cert_log`.
    pub receipt_log: Option<sled::Db>,
    /// On-disk log of captured `StakingEvent`s (a `sled` tree at
    /// `data_dir/staking`), so staking activity (Delegate/Undelegate/Claim)
    /// survives a restart just like the transfer history. Same best-effort
    /// contract as `receipt_log`.
    pub staking_log: Option<sled::Db>,
    /// Path to the persisted economics snapshot (`data_dir/economics`), a small
    /// Borsh blob overwritten after each committing round so lifetime
    /// burn/earnings totals survive a restart. `None` for an in-memory node.
    pub economics_path: Option<std::path::PathBuf>,
    /// This node's configured consensus round interval (`config.round_interval_ms`).
    /// Surfaced on `/status` so the dashboard's "consensus stalled" threshold can
    /// scale with the real cadence instead of a hardcoded guess - a node run with
    /// a deliberately slow interval otherwise false-positives the stall alert.
    pub round_interval_ms: u64,
}

impl Engine {
    /// The committee currently in effect (this epoch) — a cheap `Arc` clone of
    /// the current set, guard dropped immediately. Use for anything about the
    /// *current* round (propose/vote/quorum/status). Under fixed membership it
    /// is always the genesis set; under rotation the epoch ratchet swaps it.
    fn committee(&self) -> Arc<ValidatorSet> {
        self.validators.read().expect("validators lock not poisoned").clone()
    }

    /// A snapshot of the full per-epoch schedule (cheap `Arc` clone). Use
    /// `for_round(round)` on it for anything about a *specific* round — chiefly
    /// `verify_certificate` (a cert can be for an older epoch's committee) and
    /// consensus ordering.
    fn schedule(&self) -> Arc<ValidatorSchedule> {
        self.validator_schedule.read().expect("schedule lock not poisoned").clone()
    }

    /// Appends a newly captured transfer receipt to the on-disk log, if this
    /// node persists to disk. Keyed by a sled-generated monotonic id so the
    /// on-disk order matches capture order (oldest first) on reload. Best-
    /// effort: a disk error is logged, not fatal - a receipt that fails to
    /// persist is just missing from history after a restart, never a
    /// correctness problem (balances are the source of truth, via `SledStore`).
    fn persist_receipt(&self, receipt: &TransferReceipt) {
        if let Some(db) = &self.receipt_log {
            let key = match db.generate_id() {
                Ok(id) => id.to_be_bytes(),
                Err(e) => {
                    tracing::warn!("failed to allocate a receipt-log id: {e}");
                    return;
                }
            };
            match serde_json::to_vec(receipt) {
                Ok(bytes) => {
                    if let Err(e) = db.insert(key, bytes) {
                        tracing::warn!("failed to persist a transfer receipt: {e}");
                    }
                }
                Err(e) => tracing::warn!("failed to encode a transfer receipt for the log: {e}"),
            }
        }
    }

    /// Appends a captured staking event to the on-disk log (mirror of
    /// `persist_receipt`). Best-effort; a staking event that fails to persist
    /// is simply missing from history after a restart, never a correctness
    /// problem (balances are the source of truth).
    fn persist_staking_event(&self, ev: &qchain_execution::StakingEvent) {
        if let Some(db) = &self.staking_log {
            let key = match db.generate_id() {
                Ok(id) => id.to_be_bytes(),
                Err(e) => {
                    tracing::warn!("failed to allocate a staking-log id: {e}");
                    return;
                }
            };
            match serde_json::to_vec(ev) {
                Ok(bytes) => {
                    if let Err(e) = db.insert(key, bytes) {
                        tracing::warn!("failed to persist a staking event: {e}");
                    }
                }
                Err(e) => tracing::warn!("failed to encode a staking event for the log: {e}"),
            }
        }
    }

    /// Overwrites the persisted economics snapshot (`data_dir/economics`) with
    /// the ledger's current running totals, so lifetime burn/earnings survive a
    /// restart. Best-effort: written after each committing round, off the state
    /// lock. A failed write just means the snapshot is slightly stale on the
    /// next boot, re-catching up as new transactions commit.
    async fn persist_economics(&self) {
        let Some(path) = &self.economics_path else { return };
        let snap = { self.state.lock().await.ledger.export_economics() };
        match borsh::to_vec(&snap) {
            Ok(bytes) => {
                // Write to a temp file then rename, so a crash mid-write never
                // leaves a truncated (undecodable) economics file.
                let tmp = path.with_extension("tmp");
                if let Err(e) = std::fs::write(&tmp, &bytes).and_then(|_| std::fs::rename(&tmp, path)) {
                    tracing::warn!("failed to persist economics snapshot: {e}");
                }
            }
            Err(e) => tracing::warn!("failed to encode economics snapshot: {e}"),
        }
    }

    /// Inserts a verified certificate into the in-memory DAG and, if this
    /// node persists to disk, appends it to the on-disk cert log so a restart
    /// can reload it locally (see `Engine::cert_log`). Best-effort persist: a
    /// disk error is logged, not fatal - a cert that fails to persist is
    /// simply re-fetched from peers on the next restart, exactly as every
    /// cert was before DAG persistence existed.
    fn insert_certificate(&self, state: &mut EngineState, cert: Certificate) {
        let digest = state.dag.insert(cert.clone());
        if let Some(db) = &self.cert_log {
            match borsh::to_vec(&cert) {
                Ok(bytes) => {
                    if let Err(e) = db.insert(digest, bytes) {
                        tracing::warn!("failed to persist certificate {digest:?} to the DAG log: {e}");
                    }
                }
                Err(e) => tracing::warn!("failed to encode certificate {digest:?} for the DAG log: {e}"),
            }
        }
    }

    /// Force every on-disk store durable before a graceful exit. `sled` buffers
    /// writes and flushes on a ~500ms timer, so between flushes recent account /
    /// certificate / batch writes live only in process memory - while the plain
    /// `round_checkpoint` file (page-cache-durable across process death) can be
    /// ahead of them, so a restart could resume from a round whose state was
    /// never persisted and silently drop committed transactions. Called on
    /// SIGTERM/SIGINT (the `systemctl restart` / `update-node.sh` path) so that
    /// flow is fully durable. Takes the state lock so it flushes a consistent
    /// point-in-time (any in-flight commit finishes first).
    pub async fn flush_all(&self) {
        let state = self.state.lock().await;
        state.ledger.flush();
        for (name, db) in [
            ("dag", &self.cert_log),
            ("batches", &self.batch_log),
            ("committees", &self.committee_log),
            ("receipts", &self.receipt_log),
            ("staking", &self.staking_log),
        ] {
            if let Some(db) = db {
                if let Err(e) = db.flush() {
                    tracing::warn!("failed to flush the {name} log on shutdown: {e}");
                }
            }
        }
        tracing::info!("flushed all persistent stores to disk");
    }

    /// Best-effort persist of a worker batch to `batch_log`, keyed by its
    /// content digest (see the `batch_log` field docs for why this is the
    /// necessary companion to `insert_certificate`). Same contract as the DAG
    /// log: a disk error is logged, not fatal — the batch stays in the in-memory
    /// cache for this run, and on a later restart that certificate just re-syncs
    /// from peers exactly as it did before batch persistence existed (a lone
    /// validator being the one case that can't, which is the freeze this closes).
    fn persist_batch(&self, digest: &Digest, batch: &Batch) {
        if let Some(db) = &self.batch_log {
            match borsh::to_vec(batch) {
                Ok(bytes) => {
                    if let Err(e) = db.insert(digest, bytes) {
                        tracing::warn!("failed to persist batch {digest:?} to the batch log: {e}");
                    }
                }
                Err(e) => tracing::warn!("failed to encode batch {digest:?} for the batch log: {e}"),
            }
        }
    }
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub validator: String,
    pub next_round: Round,
    pub dag_certificates: usize,
    pub executed_transactions: u64,
    /// The software version this node is running (`NODE_VERSION`).
    pub version: String,
    /// A strictly-newer version heard from a validator-set peer, if any -
    /// "there is an update available." `None` when up to date. See
    /// `EngineState::update_available`.
    pub update_available: Option<String>,
    /// Live on-chain `base_fee_per_byte` (governance-settable), so the
    /// dashboard can show the current network fee in real time instead of a
    /// hardcoded guess. The fee of a standard transfer is this times the
    /// transaction's byte size (~5.5 KB for the default hybrid signature).
    pub base_fee_per_byte: u64,
    /// Live on-chain `dust_threshold` (governance-settable): a system-owned
    /// account left holding less than this after a transaction is swept to zero
    /// and BURNED. The wallet reads it so "send max" can deliberately leave a
    /// sub-threshold remainder that the sweep burns (a small deflationary
    /// contribution) instead of leaving the account at exactly zero.
    pub dust_threshold: u64,
    /// This node's configured round interval in ms - lets the dashboard scale
    /// its stall-detection threshold to the real cadence (see `Engine::round_interval_ms`).
    pub round_interval_ms: u64,
    /// Number of transactions sitting in this node's mempool right now (across
    /// all per-payer queues), so a load tool can watch the REAL backlog drain
    /// and settle instead of inferring it from executed counts. Includes txs
    /// parked because they can't yet afford the current fee (see
    /// `drain_ready_transactions`).
    pub mempool_transactions: u64,
}

/// Total size in bytes of every regular file under `dir`, recursively (a plain
/// walk, no symlink following). Used by `/resources` to report the node's
/// on-disk footprint; best-effort - unreadable entries are skipped.
fn dir_size_bytes(dir: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            total = total.saturating_add(dir_size_bytes(&entry.path()));
        } else if ft.is_file() {
            if let Ok(md) = entry.metadata() {
                total = total.saturating_add(md.len());
            }
        }
    }
    total
}

/// Live process resource usage this node self-reports on `GET /resources`, so a
/// load tool (`qchain stress`) can sample and report peak RAM/CPU/disk of the
/// REAL node process without needing shell access to it (works across separate
/// containers/hosts). Read from `/proc/self` and the on-disk `data_dir`, off the
/// consensus state lock - so sampling never contends with block processing.
/// Linux-only (the deployment target); fields are 0 where `/proc` isn't readable.
#[derive(Serialize)]
pub struct ResourcesResponse {
    /// Resident set size (real physical RAM) in bytes, from `/proc/self/status`
    /// `VmRSS`. This is the number that matters for OOM risk under load.
    pub rss_bytes: u64,
    /// Cumulative CPU time (user + system) this process has consumed, in seconds,
    /// from `/proc/self/stat`. A sampler computes CPU% as the delta over the
    /// wall-clock interval between two reads (100% == one full core).
    pub cpu_seconds: f64,
    /// Total bytes on disk under the node's `data_dir` (the sled stores: state,
    /// DAG, batches, receipts, ...), summed by walking it. 0 for an in-memory node.
    pub disk_bytes: u64,
    /// OS thread count from `/proc/self/status` `Threads` - a runaway-task blowup
    /// (the class this project has hit) shows up here before RSS does.
    pub num_threads: u64,
}

/// Real validator economics, served at `GET /economics` and rendered on the
/// node dashboard's validator panel. Answers the operator's real questions:
/// how do validators earn, how much is being burned right now (and how much
/// of that is dust - the "excess left in accounts"), and what are the live
/// network parameters. The running totals are persisted (`EconomicSnapshot`,
/// `data_dir/economics`) so they survive a clean restart. They are REPORT-ONLY
/// (never consensus state, never in the Merkle root) and best-effort: the
/// snapshot is written just after the state lock is released each committing
/// round. The counters and the on-chain state they mirror live in SEPARATE
/// persistence sinks (this `economics` file vs the `SledStore` accounts + the
/// `cert_log`), so an *unclean* crash can leave them out of step in EITHER
/// direction: the last round's burn/earn delta can be lost if the snapshot
/// didn't flush (under-count), OR - now that emission mints on restart-replayed
/// rounds whose account writes were lost but whose `cert_log` survived - the
/// re-execution can re-add those rounds' emission on top of the restored
/// `total_emitted` (over-count). Either way the on-chain balances are
/// deterministically reconstructed and CORRECT (these figures are never in the
/// Merkle root, never consensus state); only the dashboard counters drift. In
/// the steady no-crash path every honest node accrues identical figures (same
/// deterministic `fee_collector`/round stream); after crashes at different
/// points two nodes can differ slightly - expected for a monitoring counter,
/// not a fork.
#[derive(serde::Serialize, Clone)]
pub struct EconomicsResponse {
    /// This validator's own address (the `fee_collector` when it proposes).
    pub validator: String,
    /// This validator's on-chain balance - where its collected commission
    /// accumulates (it earns by being the block proposer / `fee_collector`).
    pub validator_balance: u64,
    /// This validator's stake weight in the BFT quorum (from the genesis
    /// validator set) - not the same as on-chain delegated staking.
    pub validator_stake: u64,
    /// Total value destroyed since node start = `fee_burned + dust_burned`.
    pub total_burned: u64,
    /// Burned from the fee split (half of every fee is burned).
    pub fee_burned: u64,
    /// Burned by the dust sweep - the sub-threshold "excess" left in accounts.
    pub dust_burned: u64,
    /// Total paid to validators as direct commission (network-wide).
    pub validator_earned: u64,
    /// This specific validator's own accumulated commission (as `fee_collector`
    /// when it proposed) - the honest "how much have I earned" number, distinct
    /// from the network-wide `validator_earned`. Persisted, survives restarts.
    pub own_commission: u64,
    /// Total routed into the shared staking rewards pool (network-wide).
    pub pool_earned: u64,
    /// Current balance sitting in the staking rewards pool, claimable by
    /// delegators.
    pub reward_pool_balance: u64,
    /// Total new QCH minted into the staking reward pool by emission since
    /// node start (real inflation, v4.0.0). Persisted, survives restarts.
    pub total_emitted: u64,
    /// Live governance-set economic parameters.
    pub base_fee_per_byte: u64,
    pub dust_threshold: u64,
    pub staking_commission_bps: u16,
    pub gas_price_per_fuel: u64,
    /// Annual QCH emission rate (basis points of `total_staked`), minted into
    /// the reward pool per round to fund the target staking APR.
    pub emission_apr_bps: u16,
    /// The fraction of every fee that is burned (currently a fixed 50%).
    pub burn_pct: u64,
    /// Consensus liveness figures, so the panel is one-stop for an operator.
    pub next_round: Round,
    pub executed_transactions: u64,
    pub dag_certificates: usize,
    /// Number of *other* validators in the set (peers this node talks to).
    pub peer_count: usize,
}

/// Lightweight header of a state snapshot (`GET /snapshot/meta`) - what a
/// far-behind peer or a fresh joining validator reads first to learn a
/// server's current round, account-state Merkle root, and size before
/// deciding to pull the full account set. The `(round, merkle_root)` pair is
/// also what a cross-check or an operator-provided trust anchor compares
/// against (see `main.rs`'s state-sync path).
#[derive(Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub round: Round,
    pub merkle_root: String,
    pub account_count: usize,
}

/// One account in a state snapshot, keyed by its address.
#[derive(Clone, Serialize, Deserialize)]
pub struct SnapshotAccount {
    pub address: Pubkey,
    pub account: qchain_core::Account,
}

/// A full account-state snapshot (`GET /snapshot`): every account this
/// validator holds, sorted by address for determinism, plus the round and
/// Merkle root they are consistent with. A receiver rebuilds the same
/// `IncrementalStateTree` from `accounts` and checks the root matches
/// `merkle_root` before trusting a single byte of it - the snapshot is only
/// as authentic as the source peer (weak subjectivity) unless the operator
/// also pins a `(round, root)` trust anchor, exactly the Cosmos state-sync
/// trust model. This is the real catch-up path for a validator that fell
/// further behind than `DAG_RETENTION_ROUNDS`, whose peers have pruned the
/// old certificates it would otherwise need to replay history.
#[derive(Serialize, Deserialize)]
pub struct StateSnapshot {
    pub round: Round,
    pub merkle_root: String,
    pub accounts: Vec<SnapshotAccount>,
}

/// One page of a paginated snapshot (`GET /snapshot/page`). Carries the
/// `merkle_root` of the consistent point-in-time snapshot it was sliced from
/// so a client can detect the server's cached snapshot rotating mid-download
/// (root changes) and restart, rather than stitching pages from two
/// different states into a set that hashes to neither.
#[derive(Serialize, Deserialize)]
pub struct SnapshotPage {
    pub round: Round,
    pub merkle_root: String,
    pub accounts: Vec<SnapshotAccount>,
}

/// A consistent point-in-time snapshot the node caches so it can serve it in
/// bounded pages (`snapshot_page`) without the account set shifting under a
/// multi-request download - the state advances every round, so paginating the
/// live store directly would make each page a different state and no
/// accumulated set would ever hash to a single root. Held behind a short TTL
/// (`SNAPSHOT_CACHE_TTL`); the `Arc<Vec<..>>` lets pages and the full-snapshot
/// path share one immutable copy instead of re-collecting the store each call.
pub struct CachedSnapshot {
    round: Round,
    merkle_root: String,
    accounts: std::sync::Arc<Vec<SnapshotAccount>>,
    captured: tokio::time::Instant,
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
    // Use the EFFECTIVE base fee at the node's current round, not the stale
    // stored value - the same value `apply_transaction` will actually charge
    // (see `Ledger::effective_base_fee_at`). This is what unlocks a chain whose
    // fee spiked during a flood and then went idle: as the effective fee decays
    // round by round, admission reflects the lower fee, so an ordinary wallet
    // can get a transaction in again without waiting for a funded "unstick" tx.
    // `saturating_mul`, not `*`: a multi-KB `byte_size` times a large base fee
    // overflows `u64`; a plain `*` would wrap to a small number in release and
    // wrongly admit; saturating pins it at `u64::MAX` so an over-large fee simply
    // makes nothing affordable, matching intent.
    let byte_fee = state.ledger.effective_base_fee_at(state.next_round).saturating_mul(tx.byte_size() as u64);
    // Must also cover the declared priority tip, charged up front alongside the
    // base fee (see `Ledger::apply_transaction`).
    balance >= byte_fee.saturating_add(tx.message.priority_fee)
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

/// Caches a gossiped/served worker batch by its content digest, tagging it
/// with the current round so `prune_stale_round_state` can evict it once it
/// ages past `BATCH_RETENTION_ROUNDS` - the round-windowed bound that closes
/// the unbounded-`batches` OOM without breaking resync (see
/// `EngineState::batch_seen_round`). The tag is only set on first insert, so
/// a batch's retention clock starts when this node first sees it and isn't
/// refreshed by re-gossip.
fn cache_batch(state: &mut EngineState, batch: Batch) {
    let digest = batch.digest();
    if state.batches.insert(digest, batch).is_none() {
        state.batch_seen_round.insert(digest, state.next_round);
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
    // Ready txs are collected per payer (a contiguous nonce run each), then the
    // per-payer runs are ordered by priority-fee tip so higher-tip senders are
    // proposed first - an EIP-1559-style priority ordering. Crucially the sort
    // is BY GROUP, never within a group: a single payer's nonce order is
    // preserved (reordering nonce 1 before nonce 0 would just fail at execution),
    // so the tip only reorders *across* independent payers. The tip key is the
    // group's highest tip so a payer that tipped on any of its ready txs is
    // prioritized as a whole.
    // The base fee a transaction committed this round would actually pay (the
    // stored fee rolled forward through idle rounds - see
    // `Ledger::effective_base_fee_at`). Used below to PARK, not drain, any tx
    // that can't afford the current fee.
    let eff_fee = state.ledger.effective_base_fee_at(state.next_round);
    let mut groups: Vec<(u64, Vec<Transaction>)> = Vec::new();
    let mut empty_accounts = Vec::new();
    for (payer, queue) in state.mempool.iter_mut() {
        let acct = state.ledger.store().get(payer);
        let mut expected_nonce = acct.as_ref().map(|a| a.nonce).unwrap_or(0);
        let mut remaining_balance = acct.as_ref().map(|a| a.balance).unwrap_or(0);
        while queue.keys().next().is_some_and(|&n| n < expected_nonce) {
            queue.pop_first();
        }
        let mut run = Vec::new();
        // Only drain a transaction the payer can actually afford at the CURRENT
        // effective fee; PARK the rest (leave them in the queue, don't remove).
        // Before this, a fee spike above a tx's signed `fee_limit` still drained
        // it into a batch where it FAILED (fee>limit / insufficient funds) and
        // was consumed - and because a failed tx doesn't advance the nonce, every
        // later tx of that payer then hit a nonce gap and failed too, so a whole
        // worker's backlog silently VANISHED under a flood instead of waiting.
        // Now an unaffordable tx just waits (Ethereum-style: a tx below the
        // current base fee stays pending) until the fee decays (v4.3.3) and it
        // becomes affordable - so a flood's excess drains later instead of being
        // burned. Cumulative `remaining_balance` so a run that would overdraw
        // stops at the first tx the payer can't cover.
        loop {
            // Peek affordability (immutable borrow), then drop it before removing.
            let margin = match queue.get(&expected_nonce) {
                None => break,
                Some(tx) => {
                    let c = eff_fee
                        .saturating_mul(tx.byte_size() as u64)
                        .saturating_add(tx.message.priority_fee);
                    // Park with a one-round safety margin (+12.5%, the max the fee
                    // can rise in a single round): a tx drained this round may not
                    // execute until a slightly later, higher-fee round, so leaving
                    // this headroom stops it from being drained-then-priced-out at
                    // execution (which would drop it and gap the nonce). Purely
                    // conservative - it only ever PARKS a borderline tx one extra
                    // round, never drops one. The same margin is subtracted from
                    // the running balance so a payer's run stops before the rising
                    // execution-fee could overdraw it.
                    let margin = c.saturating_add(c / 8);
                    if margin > tx.message.fee_limit || margin > remaining_balance {
                        break;
                    }
                    margin
                }
            };
            remaining_balance = remaining_balance.saturating_sub(margin);
            run.push(queue.remove(&expected_nonce).expect("just peeked this nonce"));
            expected_nonce += 1;
        }
        if !run.is_empty() {
            let max_tip = run.iter().map(|t| t.message.priority_fee).max().unwrap_or(0);
            groups.push((max_tip, run));
        }
        if queue.is_empty() {
            empty_accounts.push(*payer);
        }
    }
    for payer in empty_accounts {
        state.mempool.remove(&payer);
    }
    // Highest tip first. Stable so equal-tip payers keep their prior relative
    // order (deterministic given the same mempool contents).
    groups.sort_by(|a, b| b.0.cmp(&a.0));

    // Per-round inclusion cap (EIP-1559 block limit, see FEE_MAX_BYTES_PER_ROUND):
    // take the highest-tip prefix that fits, defer the rest back to the mempool.
    let (selected, deferred) = select_within_cap(groups, qchain_execution::params::FEE_MAX_BYTES_PER_ROUND);
    // Re-queue the deferred txs (same admission path, so the per-payer cap and
    // dedup still apply). They were removed from their queues above; putting them
    // back keeps them for the next round instead of dropping them.
    for tx in deferred {
        admit_to_mempool(state, tx);
    }
    selected
}

/// Given tip-ordered payer groups (each a contiguous nonce run) and a byte cap,
/// split them into (selected, deferred): the highest-tip prefix of transactions
/// whose cumulative byte size fits under `cap`, and the rest. A payer's nonce
/// run is never split-with-a-gap - once one of its txs is deferred, every later
/// tx of that same payer is deferred too (including a higher nonce while
/// deferring a lower one would just fail at execution). At least one transaction
/// is always selected, so a single tx larger than the whole cap can't wedge the
/// round forever. Pure function of its inputs, so it is unit-tested directly.
/// This is what makes the priority fee buy real queue-jumping under congestion:
/// when demand exceeds `cap`, the higher-tip payers (sorted first) fill the
/// round and the lower-tip ones wait.
fn select_within_cap(
    groups: Vec<(u64, Vec<Transaction>)>,
    cap: u64,
) -> (Vec<Transaction>, Vec<Transaction>) {
    let mut selected: Vec<Transaction> = Vec::new();
    let mut deferred: Vec<Transaction> = Vec::new();
    let mut used_bytes: u64 = 0;
    for (_, run) in groups {
        let mut deferring = false;
        for tx in run {
            let sz = tx.byte_size() as u64;
            if !deferring && (selected.is_empty() || used_bytes.saturating_add(sz) <= cap) {
                used_bytes = used_bytes.saturating_add(sz);
                selected.push(tx);
            } else {
                deferring = true;
                deferred.push(tx);
            }
        }
    }
    (selected, deferred)
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

    /// Returns a fresh-enough consistent point-in-time snapshot, capturing a
    /// new one (accounts copied out and sorted by address) only when the
    /// cache is empty or older than `SNAPSHOT_CACHE_TTL`. The capture holds
    /// the snapshot-cache lock throughout so two concurrent syncing peers
    /// never both pay for a capture; the account copy is taken under the
    /// state lock and everything else runs after it is dropped.
    async fn cached_snapshot(&self) -> std::sync::Arc<CachedSnapshot> {
        let mut guard = self.snapshot_cache.lock().await;
        if let Some(cached) = guard.as_ref() {
            if cached.captured.elapsed() < SNAPSHOT_CACHE_TTL {
                return cached.clone();
            }
        }
        let (round, root, mut accounts) = {
            let state = self.state.lock().await;
            let accounts: Vec<SnapshotAccount> =
                state.ledger.store().iter().map(|(address, account)| SnapshotAccount { address, account }).collect();
            (state.next_round, state.ledger.merkle_root(), accounts)
        };
        accounts.sort_by(|a, b| a.address.to_bytes().cmp(&b.address.to_bytes()));
        let captured = std::sync::Arc::new(CachedSnapshot {
            round,
            merkle_root: hex::encode(root),
            accounts: std::sync::Arc::new(accounts),
            captured: tokio::time::Instant::now(),
        });
        *guard = Some(captured.clone());
        captured
    }

    /// Header of the current consistent snapshot - round, Merkle root, and
    /// account count. A syncing peer reads this first, then keyset-paginates
    /// `snapshot_page` against the same cached snapshot (matched by root).
    pub async fn snapshot_meta(&self) -> SnapshotMeta {
        let cached = self.cached_snapshot().await;
        SnapshotMeta { round: cached.round, merkle_root: cached.merkle_root.clone(), account_count: cached.accounts.len() }
    }

    /// One keyset page of the cached snapshot: up to `SNAPSHOT_PAGE_SIZE`
    /// accounts whose address sorts strictly after `after` (or from the start
    /// if `after` is `None`), carrying the snapshot's root so the client can
    /// tell if the cached snapshot rotated mid-download. Bounds a single
    /// response's size independent of total state size.
    pub async fn snapshot_page(&self, after: Option<Pubkey>) -> SnapshotPage {
        let _permit = SNAPSHOT_PERMITS.acquire().await.expect("snapshot semaphore is never closed");
        let cached = self.cached_snapshot().await;
        let start = match after {
            Some(a) => cached.accounts.partition_point(|x| x.address.to_bytes() <= a.to_bytes()),
            None => 0,
        };
        let end = (start + SNAPSHOT_PAGE_SIZE).min(cached.accounts.len());
        let accounts = cached.accounts[start..end].to_vec();
        SnapshotPage { round: cached.round, merkle_root: cached.merkle_root.clone(), accounts }
    }

    /// The full account set in one response, served from the same cached
    /// consistent snapshot as the paginated path. Kept for small states and
    /// simple clients / direct inspection; a far-behind peer downloading a
    /// large state should prefer `snapshot_page`. Permit-bounded, since the
    /// clone is `O(state)`.
    pub async fn snapshot(&self) -> StateSnapshot {
        let _permit = SNAPSHOT_PERMITS.acquire().await.expect("snapshot semaphore is never closed");
        let cached = self.cached_snapshot().await;
        StateSnapshot { round: cached.round, merkle_root: cached.merkle_root.clone(), accounts: (*cached.accounts).clone() }
    }

    /// The most recent `limit` captured `TransferReceipt`s (newest
    /// first), skipping `offset` from the newest end first - the real
    /// "recent activity" list a Qscan-style status page paginates
    /// through. Backed by the same in-memory, unbounded `Vec` `Ledger`
    /// already keeps for `/stark_proof` (see `qchain-execution::receipt`'s
    /// module docs on that limitation) - this endpoint doesn't add any
    /// new persistence, just a paginated read of what was already there.
    pub async fn list_transfers(&self, limit: usize, offset: usize) -> Vec<qchain_execution::TransferReceipt> {
        // Clamp the caller-supplied limit: the receipt log is unbounded and now
        // reloaded in full on restart, so an unauthenticated `?limit=<u64::MAX>`
        // would clone the ENTIRE history under the global consensus lock - a real
        // liveness DoS proportional to chain age. `MAX_ACTIVITY_LIMIT` caps one
        // response; a client paginates with `offset` for more.
        let limit = limit.min(MAX_ACTIVITY_LIMIT);
        let state = self.state.lock().await;
        let all = state.ledger.transfer_receipts();
        if offset >= all.len() {
            return Vec::new();
        }
        let end = all.len() - offset;
        let start = end.saturating_sub(limit);
        all[start..end].iter().rev().cloned().collect()
    }

    /// Captured staking activity (Delegate/Undelegate/ClaimReward), most recent
    /// first, paginated the same way as `list_transfers`. Optionally filtered to
    /// a single staker address, so the wallet can show *this* wallet's staking
    /// activity in its own activity view.
    pub async fn list_staking_events(
        &self,
        limit: usize,
        offset: usize,
        staker: Option<Pubkey>,
    ) -> Vec<qchain_execution::StakingEvent> {
        let limit = limit.min(MAX_ACTIVITY_LIMIT);
        let state = self.state.lock().await;
        let all = state.ledger.staking_events();
        match staker {
            // Unfiltered (the common dashboard poll): slice the tail directly,
            // exactly like `list_transfers` - never clone the whole unbounded,
            // ever-growing history under the global consensus lock just to
            // return `limit` rows.
            None => {
                if offset >= all.len() {
                    return Vec::new();
                }
                let end = all.len() - offset;
                let start = end.saturating_sub(limit);
                all[start..end].iter().rev().cloned().collect()
            }
            // Filtered to one staker: walk newest-first and stop once enough rows
            // are collected. The `take(MAX_ACTIVITY_SCAN)` BEFORE the filter bounds
            // the examined-item count too: without it, an address with few/zero
            // events (e.g. any never-staked address) would walk the ENTIRE
            // unbounded history before yielding nothing - the same lock-held DoS
            // the unfiltered path avoids. So a wallet sees its activity within the
            // most recent `MAX_ACTIVITY_SCAN` network staking events (ample for a
            // recent-activity view; older history needs the future real indexer).
            Some(s) => all
                .iter()
                .rev()
                .take(MAX_ACTIVITY_SCAN)
                .filter(|e| e.staker == s)
                .skip(offset)
                .take(limit)
                .cloned()
                .collect(),
        }
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

        // Bound how many of these CPU-heavy proofs run at once across the
        // whole node - see `MAX_CONCURRENT_STARK_PROOFS`. Held only around the
        // proving/verifying, after the state lock has already been dropped, so
        // it never serializes ordinary node work, only the expensive
        // unauthenticated endpoint against itself.
        let _permit = STARK_PROOF_PERMITS.acquire().await.expect("stark-proof semaphore is never closed");
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
            version: NODE_VERSION.to_string(),
            update_available: state.update_available.clone(),
            // The EFFECTIVE fee at the current round, not the stale stored value -
            // so the dashboard shows the fee decaying in real time on an idle
            // chain (matching what a transaction would actually be charged now).
            base_fee_per_byte: state.ledger.effective_base_fee_at(state.next_round),
            dust_threshold: state.ledger.current_params().dust_threshold,
            round_interval_ms: self.round_interval_ms,
            mempool_transactions: state.mempool.values().map(|q| q.len() as u64).sum(),
        }
    }

    /// Real validator economics for the dashboard's validator panel (see
    /// `EconomicsResponse`). Reads the ledger's live fee/burn/earn totals plus
    /// the current governance params, this validator's own balance, and the
    /// staking pool balance - all under one state lock.
    pub async fn economics(&self) -> EconomicsResponse {
        use qchain_execution::ids::STAKING_REWARDS_POOL_ID;
        let state = self.state.lock().await;
        let params = state.ledger.current_params();
        let validator_balance = state.ledger.store().get(&self.self_id).map(|a| a.balance).unwrap_or(0);
        let reward_pool_balance = state.ledger.store().get(&STAKING_REWARDS_POOL_ID).map(|a| a.balance).unwrap_or(0);
        EconomicsResponse {
            validator: self.self_id.to_string(),
            validator_balance,
            validator_stake: self.committee().stake_of(&self.self_id),
            total_burned: state.ledger.total_burned,
            fee_burned: state.ledger.fee_burned,
            dust_burned: state.ledger.dust_burned,
            validator_earned: state.ledger.validator_earned,
            own_commission: state.ledger.commission_of(&self.self_id),
            pool_earned: state.ledger.pool_earned,
            reward_pool_balance,
            total_emitted: state.ledger.total_emitted,
            // Effective (rolled-to-current-round) fee, matching /status.
            base_fee_per_byte: state.ledger.effective_base_fee_at(state.next_round),
            dust_threshold: params.dust_threshold,
            staking_commission_bps: params.staking_commission_bps,
            gas_price_per_fuel: params.gas_price_per_fuel,
            emission_apr_bps: params.emission_apr_bps,
            burn_pct: 50,
            next_round: state.next_round,
            executed_transactions: state.executed,
            dag_certificates: state.dag.len(),
            peer_count: self.committee().len().saturating_sub(1),
        }
    }

    /// This process's live RAM/CPU/disk/thread usage (see `ResourcesResponse`).
    /// Reads `/proc/self` and walks the `data_dir` - no consensus state lock, so
    /// a load tool can sample it at high frequency without slowing the node.
    pub fn resources(&self) -> ResourcesResponse {
        fn read_proc_status_kb(field: &str) -> u64 {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines().find(|l| l.starts_with(field)).and_then(|l| {
                        l.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok())
                    })
                })
                .unwrap_or(0)
        }
        // VmRSS / Threads live in /proc/self/status (VmRSS is in kB).
        let rss_bytes = read_proc_status_kb("VmRSS:").saturating_mul(1024);
        let num_threads = read_proc_status_kb("Threads:");
        // utime (field 14) + stime (field 15) in clock ticks; /proc/self/stat's
        // first field can contain spaces/parens (the comm), so split after the
        // trailing ')'. Assume the standard 100 ticks/sec (USER_HZ) on Linux.
        let cpu_seconds = std::fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|s| {
                let after = s.rsplit_once(')').map(|(_, rest)| rest.to_string())?;
                let f: Vec<&str> = after.split_whitespace().collect();
                // After ')', field indices shift: state is [0], so utime is [11], stime [12].
                let utime = f.get(11)?.parse::<u64>().ok()?;
                let stime = f.get(12)?.parse::<u64>().ok()?;
                Some((utime + stime) as f64 / 100.0)
            })
            .unwrap_or(0.0);
        // Disk: sum of file sizes under the data_dir (parent of the economics
        // snapshot path). 0 for an in-memory node (no data_dir).
        let disk_bytes = self
            .economics_path
            .as_ref()
            .and_then(|p| p.parent())
            .map(dir_size_bytes)
            .unwrap_or(0);
        ResourcesResponse { rss_bytes, cpu_seconds, disk_bytes, num_threads }
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
                {
                    let mut state = self.state.lock().await;
                    self.persist_batch(&batch.digest(), &batch);
                    cache_batch(&mut state, batch);
                }
                // A newly-arrived batch may be exactly the one blocking the
                // head of `pending_execution` - drain the queue now instead of
                // waiting for the next tick (no-op if nothing was blocked).
                self.try_commit().await;
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
                // Committee in effect for the proposal's round (under rotation a
                // proposer must be a member of *that round's* committee).
                let sched = self.schedule();
                let round_committee = sched.for_round(vertex.round);
                let Some(author_info) = round_committee.get(&vertex.author) else {
                    tracing::warn!("dropping vertex proposal from unknown validator {from}");
                    return;
                };
                if !qchain_crypto::verify(&author_info.pubkey_bundle, &digest[..], &author_signature) {
                    tracing::warn!("dropping vertex proposal from {from} - author_signature does not verify");
                    return;
                }
                // Structural bounds before we act on the (attacker-controlled)
                // vectors: a legitimate vertex references at most one round-(r-1)
                // certificate per validator and at most `WORKER_COUNT` worker
                // batches. Without this, a Byzantine author whose signature
                // verifies could put millions of fabricated digests in
                // `parents`/`batch_digests` and make every honest node register +
                // forever-retry a resync request per digest (unbounded memory +
                // outbound-bandwidth amplification from one message).
                //
                // The parent bound MUST use the committee of the PARENT round
                // (`vertex.round - 1`), not the current round: parents are
                // round-(r-1) certificates, one per validator of THAT round. At an
                // epoch boundary where the committee shrinks (e.g. 3 -> 2), the
                // first round of the new, smaller epoch legitimately references up
                // to `old_n` parents from the last round of the previous epoch;
                // bounding by the new (smaller) `n` would reject those honest
                // proposals and freeze the network (a real liveness bug found in a
                // live rotation test).
                //
                // Not sufficient on its own, though: the FIRST round of a shrunk
                // epoch is itself over-produced. The epoch ratchet installs the new
                // committee only after finalization crosses the boundary, which lags
                // the frontier — so the boundary round (an epoch start) is proposed
                // and certified while every node still has the OLD committee
                // installed, giving it up to `old_n` certificates even though
                // `for_round(boundary)` now returns the NEW, smaller committee. A
                // vertex at `boundary + 1` legitimately references all of them, so
                // bounding by `for_round(boundary)` alone re-froze a live 3 -> 2
                // shrink (found in a real rotation test: the withdrawal-driven drop
                // that closes the v4.1.4 audit MEDIUM now makes such shrinks happen
                // for a new reason). The sound, tight bound: a round's certificate
                // count can never exceed the LARGER of the two committees that could
                // have produced it — its own epoch's, and the previous epoch's
                // (install lag is bounded to the boundary). That is still a real,
                // finite committee size (never unbounded), so the DoS guard holds.
                let parent_round = vertex.round.saturating_sub(1);
                let prev_epoch_last_round = sched
                    .epoch_of(parent_round)
                    .saturating_mul(sched.epoch_rounds())
                    .saturating_sub(1);
                let max_parents = sched
                    .for_round(parent_round)
                    .len()
                    .max(sched.for_round(prev_epoch_last_round).len());
                if vertex.parents.len() > max_parents {
                    tracing::warn!("dropping vertex proposal from {from}: {} parents exceeds round-{} validator count {max_parents}", vertex.parents.len(), vertex.round.saturating_sub(1));
                    return;
                }
                if vertex.batch_digests.len() > WORKER_COUNT as usize {
                    tracing::warn!("dropping vertex proposal from {from}: {} batch digests exceeds WORKER_COUNT", vertex.batch_digests.len());
                    return;
                }
                self.request_missing_parents(&vertex.parents, vertex.round.saturating_sub(1), from).await;
                self.request_missing_batches(&vertex.batch_digests, from).await;
                let key = (vertex.round, vertex.author);
                {
                    let mut state = self.state.lock().await;
                    // Reject a proposal whose round is absurdly far ahead of the
                    // local frontier (see MAX_ROUND_LOOKAHEAD) - stops a Byzantine
                    // author from getting a `round = u64::MAX` vertex certified and
                    // poisoning `highest_round`/the ordering re-resolution.
                    if vertex.round > state.next_round.saturating_add(MAX_ROUND_LOOKAHEAD) {
                        tracing::warn!("dropping vertex proposal from {from}: round {} is far ahead of frontier {}", vertex.round, state.next_round);
                        return;
                    }
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
                    let vote_round = state.next_round;
                    state.pending_votes_to_send.insert(digest, (from, sig.clone(), vote_round));
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
                // A vote is only ever for THIS node's own current pending
                // proposal (current round), so the current committee is the
                // right membership set to check the voter against.
                let committee = self.committee();
                let Some(voter_info) = committee.get(&from) else {
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
                // A certificate can be for an older round than the current one
                // (resync), so verify it against *its round's* committee.
                if !verify_certificate(&cert, self.schedule().for_round(cert.vertex.round)) {
                    tracing::warn!("dropping certificate that fails quorum verification");
                    return;
                }
                let parent_round = cert.vertex.round.saturating_sub(1);
                let parents = cert.vertex.parents.clone();
                let batch_digests = cert.vertex.batch_digests.clone();
                {
                    let mut state = self.state.lock().await;
                    self.insert_certificate(&mut state, cert);
                }
                self.request_missing_parents(&parents, parent_round, from).await;
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
                if !verify_certificate(&cert, self.schedule().for_round(cert.vertex.round)) {
                    tracing::warn!("dropping certificate response that fails quorum verification");
                    return;
                }
                let parent_round = cert.vertex.round.saturating_sub(1);
                let parents = cert.vertex.parents.clone();
                let batch_digests = cert.vertex.batch_digests.clone();
                {
                    let mut state = self.state.lock().await;
                    self.insert_certificate(&mut state, cert);
                }
                self.request_missing_parents(&parents, parent_round, from).await;
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
                self.persist_batch(&batch.digest(), &batch);
                cache_batch(&mut state, batch);
            }
            NetMessage::VersionAnnounce { version } => {
                // Advisory only (see the message's doc comment). Trust it just
                // enough to nudge the operator: the sender must be a real
                // member of the validator set, and the version must parse and
                // be strictly newer than ours. Never affects consensus.
                if self.committee().get(&from).is_none() {
                    return;
                }
                if version_is_newer(&version, NODE_VERSION) {
                    let mut state = self.state.lock().await;
                    let is_new = state.update_available.as_deref().map(|cur| version_is_newer(&version, cur)).unwrap_or(true);
                    if is_new {
                        state.update_available = Some(version.clone());
                        tracing::warn!(
                            "ACTUALIZACIÓN DISPONIBLE: un validador está corriendo la versión {version} (esta corre {NODE_VERSION}). Actualizá con: sudo ./deploy/update-node.sh"
                        );
                    }
                }
            }
        }
    }

    /// Broadcasts this node's software version to its peers (see
    /// `NetMessage::VersionAnnounce`). Called on a slow cadence from the tick
    /// loop - cheap, and how the whole no-central-server update-notification
    /// mechanism propagates: as some validators upgrade, the ones still on an
    /// older build hear the newer version and raise their `update_available`.
    pub async fn announce_version(&self) {
        self.network.broadcast(&NetMessage::VersionAnnounce { version: NODE_VERSION.to_string() }).await;
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
    async fn request_missing_parents(&self, parents: &[Digest], parent_round: Round, from: ValidatorId) {
        let missing: Vec<Digest> = {
            let mut state = self.state.lock().await;
            // Never chase parents below the GC barrier: they are permanently-
            // committed history this node treats as settled (see
            // `Bullshark::gc_floor`), the peers likely pruned them anyway
            // (`DAG_RETENTION_ROUNDS`), and ordering does not need them. This
            // is what bounds a state-synced node's back-fill to the recent
            // window instead of cascading parent requests all the way down to
            // a peer's own retention floor. A no-op for a never-pruned node
            // (`gc_floor == 0`, `parent_round` never below it).
            if parent_round < state.consensus.gc_floor() {
                return;
            }
            let missing: Vec<Digest> = parents.iter().copied().filter(|d| !state.dag.contains(d)).collect();
            let req_round = state.next_round;
            for &digest in &missing {
                state.pending_cert_requests.entry(digest).or_insert((from, req_round));
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
            let req_round = state.next_round;
            for &(worker_id, digest) in &missing {
                state.pending_batch_requests.entry((worker_id, digest)).or_insert((from, req_round));
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
            let cert_retries: Vec<(Digest, ValidatorId)> = state.pending_cert_requests.iter().map(|(&d, &(from, _))| (d, from)).collect();
            let batch_retries: Vec<(WorkerId, Digest, ValidatorId)> =
                state.pending_batch_requests.iter().map(|(&(worker_id, d), &(from, _))| (worker_id, d, from)).collect();
            let vote_retries: Vec<(Digest, ValidatorId, MultiSignature)> =
                state.pending_votes_to_send.iter().map(|(&d, (from, sig, _))| (d, *from, sig.clone())).collect();
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
            match self.network.addr_of(&from) {
                Some(addr) => {
                    if let Err(e) = self.network.send_to(addr, &NetMessage::CertificateRequest { digest }).await {
                        tracing::warn!("retry: failed to request missing certificate {digest:?} from {from}: {e}");
                    }
                }
                // The peer that originally referenced this certificate is no
                // longer in our peer set - the canonical case is a validator
                // that LEFT the committee at an epoch boundary (dynamic rotation
                // shrink). Certificates are content-addressed, so any peer that
                // holds it can serve it; broadcasting the request lets a
                // surviving holder answer. Without this the request was silently
                // dropped forever (`else { continue }`), which is exactly the
                // documented freeze that forced committee changes to be grow-only:
                // a departed author's certificate, referenced as a parent by a
                // new-epoch vertex, could never be re-fetched. Only unreachable-
                // `from` requests broadcast (the rare post-departure case), so
                // this doesn't flood the common path.
                None => self.network.broadcast(&NetMessage::CertificateRequest { digest }).await,
            }
        }
        for (worker_id, digest, from) in batch_retries {
            match self.network.addr_of(&from) {
                Some(addr) => {
                    if let Err(e) = self.network.send_to(addr, &NetMessage::WorkerBatchRequest { worker_id, digest }).await {
                        tracing::warn!("retry: failed to request missing worker batch {digest:?} (worker {worker_id}) from {from}: {e}");
                    }
                }
                // Same departed-peer fallback as certificates above: broadcast so
                // a surviving holder of this content-addressed batch can serve it.
                None => self.network.broadcast(&NetMessage::WorkerBatchRequest { worker_id, digest }).await,
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
    /// `equivocation_evidence` is capped at one entry per author (a Byzantine
    /// validator can equivocate every round; one valid entry per author is
    /// enough to slash them, so the rest are dropped).
    pub async fn prune_stale_round_state(&self) {
        let mut state = self.state.lock().await;
        let round_horizon = state.next_round.saturating_sub(ROUND_STATE_RETENTION);
        if round_horizon > 0 {
            state.voted_for.retain(|(round, _), _| *round >= round_horizon);
            state.first_seen_vertex.retain(|(round, _), _| *round >= round_horizon);
            // Bound the outstanding re-sync request maps by the same round
            // window. Without this a Byzantine committee member could stream
            // `VertexProposal`s each carrying fresh random parent digests that
            // never resolve, growing these maps AND their per-tick re-send
            // bandwidth without bound (the per-message `parents.len()` cap bounds
            // one message, not the cross-message accumulation - found in a
            // proactive audit). A genuinely missing recent parent/batch/vote
            // resolves well within `ROUND_STATE_RETENTION` rounds; anything older
            // is unreachable via reactive resync anyway (that's the snapshot
            // path's job), so dropping it is safe.
            state.pending_cert_requests.retain(|_, v| v.1 >= round_horizon);
            state.pending_batch_requests.retain(|_, v| v.1 >= round_horizon);
            state.pending_votes_to_send.retain(|_, v| v.2 >= round_horizon);
        }

        // Bound `equivocation_evidence` to at most one entry per author. A
        // Byzantine validator can equivocate every round, and each round would
        // otherwise leave a new, never-collected entry forever (a slow OOM under
        // sustained misbehavior). One valid piece of evidence per author is
        // enough to slash them - slashing burns the whole self-stake once - so
        // keeping thousands of per-round entries buys nothing.
        {
            let mut seen_authors = std::collections::HashSet::new();
            state.equivocation_evidence.retain(|(_, author), _| seen_authors.insert(*author));
        }

        // Evict worker batches from the IN-MEMORY cache older than
        // `BATCH_RETENTION_ROUNDS` - the round-windowed bound on the otherwise-
        // unbounded `batches` map (fed by unauthenticated gossip). The retention
        // *tags* (`batch_seen_round`) are deliberately kept past this point (see
        // the on-disk prune below) so the disk log can be bounded on a different,
        // lower floor.
        let batch_horizon = state.next_round.saturating_sub(BATCH_RETENTION_ROUNDS);
        if batch_horizon > 0 {
            let stale: Vec<Digest> = state.batch_seen_round.iter().filter(|(_, &seen)| seen < batch_horizon).map(|(&d, _)| d).collect();
            for digest in &stale {
                state.batches.remove(digest);
            }
        }
        // Prune the ON-DISK batch log (and its retention tags) at the DAG GC
        // floor (`finalized_floor - DAG_RETENTION_ROUNDS`), the SAME window the
        // certificate log uses - NEVER at the higher `batch_horizon`. A restart
        // reloads the retained certificates and re-derives their committed order;
        // if a retained certificate's batch were already deleted from disk, a
        // solo validator (no peer to re-sync from) would re-freeze execution
        // exactly as before v3.5.1. Because `finalized_floor <= next_round`, this
        // floor is at or below `batch_horizon`, so disk batches always outlive
        // the in-memory cache and every retained cert keeps its batch on disk.
        let disk_batch_floor = state.consensus.finalized_floor().saturating_sub(DAG_RETENTION_ROUNDS);
        if disk_batch_floor > 0 {
            let expired: Vec<Digest> = state.batch_seen_round.iter().filter(|(_, &seen)| seen < disk_batch_floor).map(|(&d, _)| d).collect();
            for digest in &expired {
                state.batch_seen_round.remove(digest);
                state.batches.remove(digest);
                if let Some(db) = &self.batch_log {
                    if let Err(e) = db.remove(digest) {
                        tracing::warn!("failed to delete pruned batch {digest:?} from the batch log: {e}");
                    }
                }
            }
        }

        // Garbage-collect the certified DAG below the finalized floor minus
        // `DAG_RETENTION_ROUNDS` - the round-windowed bound on the otherwise-
        // unbounded in-memory `DagStore` *and* the on-disk cert log (#107).
        // Uses the consensus *finalized* floor, never `next_round`: only
        // rounds permanently committed/skipped and already walked into `seen`
        // are safe to drop, and the retention margin keeps them long past any
        // reactive resync. Raising `gc_floor` in lock-step is what keeps a
        // restart able to re-derive against the same barrier (see
        // `ConsensusState::set_gc_floor`); it also stops `extend_order` from
        // re-resolving the pruned rounds (which would now resolve to
        // `Undecided`, breaking the order). Best-effort on the on-disk side: a
        // failed delete just leaves a dead key to be re-pruned next tick.
        let gc_floor = state.consensus.finalized_floor().saturating_sub(DAG_RETENTION_ROUNDS);
        if gc_floor > state.consensus.gc_floor() {
            let removed = state.dag.prune_below(gc_floor);
            if !removed.is_empty() {
                if let Some(db) = &self.cert_log {
                    for digest in &removed {
                        if let Err(e) = db.remove(digest) {
                            tracing::warn!("failed to delete pruned certificate {digest:?} from the DAG log: {e}");
                        }
                    }
                }
                tracing::debug!("pruned {} certificates below round {gc_floor} from the DAG", removed.len());
            }
            state.consensus.set_gc_floor(gc_floor);
        }
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

        // The pending vertex is this validator's own current proposal, so its
        // votes are weighted by the current committee.
        let committee = self.committee();
        let stake: u64 = state.pending_votes[&vertex_digest].keys().map(|id| committee.stake_of(id)).sum();
        if stake < committee.quorum_threshold() {
            return None;
        }

        let (vertex, _) = state.own_pending_vertex.take().unwrap();
        let signatures = state.pending_votes.remove(&vertex_digest).unwrap().into_iter().collect();
        let cert = Certificate { vertex, signatures };
        self.insert_certificate(&mut state, cert.clone());
        state.own_last_certificate = Some(cert.clone());
        Some(cert)
    }

    /// Re-runs Bullshark ordering over the current DAG and executes every
    /// newly-finalized certificate's batch, crediting that certificate's
    /// author as the fee collector - the same deterministic choice every
    /// validator makes, keeping ledger state consistent across the
    /// network.
    async fn try_commit(&self) {
        // Receipts to persist are collected here and written to disk AFTER the
        // state lock is released - a `sled` insert is blocking I/O, and doing it
        // under the single global `EngineState` mutex (which every message
        // handler and RPC read contends on) needlessly serialized disk latency
        // into the consensus hot path. The write is best-effort/idempotent
        // (keyed by tx hash, re-derivable), so persisting a moment later, off
        // the lock, changes nothing about correctness (see `persist_receipt`).
        let mut to_persist: Vec<TransferReceipt> = Vec::new();
        let mut staking_to_persist: Vec<qchain_execution::StakingEvent> = Vec::new();
        let mut economics_changed = false;
        // Set inside the lock if execution blocked on a missing batch; the
        // actual re-sync send happens after the lock is released (below).
        let missing_to_request: BlockedResync;
        {
        let mut state = self.state.lock().await;
        let state = &mut *state;
        let schedule_snapshot = self.schedule();
        let newly_ordered = state.consensus.advance(&state.dag, &schedule_snapshot);
        // Append every newly-ordered certificate to the execution queue in
        // committed order. `advance` emits a digest exactly once, so a full
        // clone is buffered (not just the digest) - DAG pruning can then never
        // lose a certificate that is still waiting for its batch. Applied in
        // the vertex's own `batch_digests` order (worker-lane order at
        // proposal time), the identical certified list every validator sees.
        for digest in newly_ordered {
            let Some(cert) = state.dag.get(&digest).cloned() else { continue };
            state.pending_execution.push_back(cert);
        }
        // Drain the queue in committed order. Execution BLOCKS at the first
        // certificate whose worker batches aren't all locally available yet -
        // it is never skipped or reordered past. Skipping would drop those
        // transactions on this node forever (the digest is already consumed
        // from `advance`'s `seen` set), forking both balances AND the on-chain
        // dynamic-fee curve versus every node that did have the batch. Instead
        // the missing batches are re-synced (below) and the queue resumes
        // draining, in order, on a later `try_commit`. Batches are NOT evicted
        // on use here (that is round-windowed in `prune_stale_round_state`) so
        // a lagging peer can still fetch them.
        // Split off the executable prefix (all batches present), in order,
        // leaving the first batch-blocked certificate and everything after it
        // buffered. `blocked` names the missing batches + who to ask; the send
        // happens after the lock is released.
        let (ready, blocked) = take_executable_prefix(&mut state.pending_execution, &state.batches);
        missing_to_request = blocked;
        for cert in ready {
            for (_worker_id, batch_digest) in &cert.vertex.batch_digests {
                let batch = state
                    .batches
                    .get(batch_digest)
                    .cloned()
                    .expect("take_executable_prefix guarantees every batch of a ready certificate is cached");
                for tx in &batch.transactions {
                    let receipts_before = state.ledger.transfer_receipts().len();
                    let staking_before = state.ledger.staking_events().len();
                    match state.ledger.apply_transaction(tx, &cert.vertex.author, cert.vertex.round) {
                        Ok(_) => {
                            state.executed += 1;
                            // Persist any receipt this transaction captured, so the
                            // transfer history survives a restart (see `receipt_log`).
                            // A replay during restart re-derivation fails the nonce
                            // check above and captures nothing, so this never
                            // double-writes. Cloned out to end the immutable borrow
                            // before the next mutable `apply_transaction`.
                            to_persist.extend_from_slice(&state.ledger.transfer_receipts()[receipts_before..]);
                            // Same for staking activity (Delegate/Undelegate/Claim).
                            staking_to_persist.extend_from_slice(&state.ledger.staking_events()[staking_before..]);
                            // Any applied transaction moves the economic counters
                            // (at least a fee burn + validator credit), so flag a
                            // re-persist of the economics snapshot after the lock.
                            economics_changed = true;
                        }
                        Err(e) => tracing::warn!("transaction execution failed: {e}"),
                    }
                }
            }
        }
        // Bound the in-memory receipt/staking logs AFTER the per-transaction
        // delta above has been captured by index into `to_persist` for this
        // whole batch - draining the front now can't invalidate a live index
        // (the next commit re-reads the length fresh). Keeps RAM and boot
        // reload time bounded regardless of chain age (see `MAX_INMEM_RECEIPTS`).
        state.ledger.cap_receipt_log(MAX_INMEM_RECEIPTS);
        state.ledger.cap_staking_events(MAX_INMEM_STAKING_EVENTS);

        // ---- Phase-3.3 rotation ratchet ----
        // If this schedule rotates and the frontier epoch is now fully
        // committed, derive the NEXT epoch's committee from the committed
        // on-chain validator registry and install it, then raise the resolvable
        // frontier so consensus may proceed into that epoch. A clean ratchet
        // with no circularity: finalize epoch e-1 -> derive+install committee(e)
        // -> raise frontier to e -> the next `advance` resolves epoch e. No-op
        // for a fixed-membership (`single`) schedule, where the frontier is
        // `u64::MAX` (this whole block is skipped) — so a non-rotating node is
        // byte-for-byte unchanged. Runs under the state lock: the registry it
        // reads is committed state at the exact end of the frontier epoch,
        // identical on every honest node, so every node derives the identical
        // committee (what keeps the rotation fork-free).
        {
            let sched = self.schedule();
            let frontier = sched.frontier_epoch();
            if frontier != u64::MAX {
                let epoch_rounds = sched.epoch_rounds();
                let finalized_floor = state.consensus.finalized_floor();
                let boundary = (frontier + 1).saturating_mul(epoch_rounds);
                // AUDIT FIX (v4.1.4): the committee for the next epoch is derived
                // from the EXECUTED ledger's on-chain registry, but `finalized_floor`
                // only tracks ORDERING. If execution lags ordering — a worker-batch
                // of some round `< boundary` hasn't arrived yet, so the "block, never
                // skip" `take_executable_prefix` (v3.0.3) is still buffering that
                // round's transactions in `pending_execution` — then the registry is
                // STALE (a `RegisterValidator`/`UnregisterValidator` in that round is
                // not yet applied). Two honest nodes at different execution progress
                // would then derive DIFFERENT committees for the same epoch and fork
                // permanently (the committee is installed once and persisted). The
                // ordering-only trigger is unsafe here; also require that EXECUTION
                // has crossed the boundary: no un-executed certificate may remain
                // below `boundary`. Deterministic and self-healing — the missing
                // batch re-syncs, `pending_execution` drains, and a later tick
                // ratchets from the now-identical fully-executed registry. NO-OP for
                // a `single` (fixed-membership) schedule: this whole block is
                // `frontier == u64::MAX`-gated, so a non-rotating node is unchanged.
                let execution_crossed = state
                    .pending_execution
                    .iter()
                    .all(|c| c.vertex.round >= boundary);
                if finalized_floor >= boundary && execution_crossed {
                    let next_epoch = frontier + 1;
                    let registry = state
                        .ledger
                        .store()
                        .get(&qchain_execution::ids::VALIDATOR_REGISTRY_ACCOUNT_ID)
                        .and_then(|a| qchain_execution::validator_registry::ValidatorRegistryData::try_read(&a.data).ok())
                        .unwrap_or_default();
                    // Re-read each self-registered validator's LIVE self-stake
                    // from committed state (v4.1.4 audit MEDIUM fix): a validator
                    // that undelegated its bond is dropped from the derived set
                    // instead of coasting on its registration-time snapshot.
                    // Genesis-seeded entries (`self_stake_account == None`) keep
                    // their snapshot. Reads committed state, so every honest node
                    // computes the identical committee — fork-free.
                    let store = state.ledger.store();
                    let live_stake_of = |rv: &qchain_execution::validator_registry::RegisteredValidator| -> u64 {
                        match rv.self_stake_account {
                            None => rv.stake, // genesis bootstrap: trust snapshot
                            Some(addr) => store
                                .get(&addr)
                                .and_then(|a| <qchain_execution::staking::StakeAccountData as borsh::BorshDeserialize>::try_from_slice(&a.data).ok())
                                // A genuine self-stake: owner == validator == the entry's validator.
                                .filter(|d| d.owner == rv.validator && d.validator == rv.validator)
                                .map(|d| d.amount)
                                .unwrap_or(0), // withdrawn / missing / not a self-stake -> dropped by the min filter
                        }
                    };
                    // Fall back to the committee this epoch would otherwise
                    // inherit (the frontier epoch's) when the registry has no
                    // viable active set — so a rotation network keeps running on
                    // its genesis validators until real registrations exist.
                    let derived = active_committee_from_registry(&registry, live_stake_of);
                    // The committee this epoch inherits (the frontier epoch's) —
                    // used only as the fallback when the registry yields no set.
                    let inherited = sched.for_round(frontier.saturating_mul(epoch_rounds));
                    let committee = match &derived {
                        // Adopt the committee derived from the committed on-chain
                        // registry WHOLESALE — the real dynamic validator set: a
                        // newcomer that ranks into the top-N joins, and one that
                        // unregistered / ranked out / was slashed below the minimum
                        // is REMOVED. Automatic removal (a committee SHRINK at an
                        // epoch boundary) is now safe — the three fixes that
                        // together closed the freeze/fork that forced the earlier
                        // grow-only-only policy: (1) ordering-layer liveness of a
                        // shrinking boundary — `Bullshark::direct_status`'s unknown
                        // stake is measured over the NEXT round's committee, so a
                        // departed validator no longer holds the boundary round
                        // `Undecided` forever (v4.0.3); (2) certificate availability
                        // — `retry_pending_resync_requests` broadcasts a missing
                        // cert when the peer that referenced it has left the set, so
                        // a departed author's cert is still fetchable from a
                        // survivor (v4.0.3); (3) atomic per-leader causal-history
                        // commit — `walk_causal_history` commits a leader's whole
                        // history or none, so a late-arriving departed cert can
                        // never reorder the append-only committed prefix into a fork
                        // (v4.0.4). The registry is seeded with the genesis
                        // validators when rotation is on, so a network that never
                        // touches the registry keeps its genesis committee, and a
                        // newcomer must out-stake a seated validator (self-stakes
                        // real and slashable) to displace it — no trivial takeover.
                        Some(d) => (*d).clone(),
                        None => (*inherited).clone(),
                    };
                    {
                        let mut w = self.validator_schedule.write().expect("schedule lock not poisoned");
                        let mut new_sched = (**w).clone();
                        new_sched.install_epoch(next_epoch, committee.clone());
                        new_sched.set_frontier_epoch(next_epoch);
                        *w = std::sync::Arc::new(new_sched);
                    }
                    // The node is now entering `next_epoch` (its next proposal
                    // round is in it), so the current committee becomes this one.
                    *self.validators.write().expect("validators lock not poisoned") = std::sync::Arc::new(committee.clone());
                    // Persist it so a restart can rebuild the schedule without
                    // re-deriving from state the ledger no longer holds
                    // (best-effort; a disk error just means that epoch re-syncs
                    // from peers on the next boot, same as a lost certificate).
                    if let Some(db) = &self.committee_log {
                        match db.insert(next_epoch.to_be_bytes(), serialize_committee(&committee)) {
                            Ok(_) => {
                                let _ = db.flush();
                            }
                            Err(e) => tracing::warn!("failed to persist epoch {next_epoch} committee: {e}"),
                        }
                    }
                    // Stage 3 peer discovery: when the committee was genuinely
                    // derived from the registry (not the genesis fallback), dial
                    // its members' registered addresses — union with the config
                    // mesh so a good config peer is never dropped by a bad
                    // registry address, and a genuinely new validator (not in
                    // the config) is now reached automatically.
                    if derived.is_some() {
                        let active = qchain_execution::validator_registry::select_active_set(&registry, qchain_execution::validator_registry::MAX_ACTIVE_VALIDATORS);
                        self.network.set_peers(merge_peers(&self.config_peers, &active, &self.self_id));
                    }
                    let source = if derived.is_some() {
                        "derived from the on-chain registry"
                    } else {
                        "inherited from the genesis fallback (registry has no viable active set yet)"
                    };
                    tracing::info!("epoch {next_epoch}: committee ({} validators, {} stake) {source}; resolvable frontier raised", committee.len(), committee.total_stake());
                }
            }
        }
        } // state lock released here
        // Re-sync any batch that blocked execution, now off the state lock
        // (`request_missing_batches` re-acquires it and then sends). No-op in
        // steady state (`missing_to_request` is `None`).
        if let Some((missing, author)) = missing_to_request {
            self.request_missing_batches(&missing, author).await;
        }
        // Blocking disk writes, now off the state lock (see the note at the top).
        for r in &to_persist {
            self.persist_receipt(r);
        }
        for ev in &staking_to_persist {
            self.persist_staking_event(ev);
        }
        // Prune the on-disk logs to the same window as the in-memory ones, so
        // repeated stress runs don't grow `data/receipts` unbounded on disk and
        // boot-time reload stays fast (the reloader reads only the last
        // `MAX_INMEM_RECEIPTS`). Only touched when something was actually
        // appended this commit; drops the oldest keys (monotonic `generate_id`s,
        // so smallest = oldest). Best-effort, mirroring `persist_receipt`.
        if !to_persist.is_empty() {
            prune_log_to_last(self.receipt_log.as_ref(), MAX_INMEM_RECEIPTS);
        }
        if !staking_to_persist.is_empty() {
            prune_log_to_last(self.staking_log.as_ref(), MAX_INMEM_STAKING_EVENTS);
        }
        if economics_changed {
            self.persist_economics().await;
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
                // The gate is "did round `prev_round` certify?", weighted by the
                // committee that certified it — `for_round(prev_round)`.
                let sched = self.schedule();
                let prev_committee = sched.for_round(prev_round);
                let quorum = prev_committee.quorum_threshold();
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
                if prev_committee.stake_of(&self.self_id) < quorum {
                    let stake: u64 =
                        state.dag.certificates_in_round(prev_round).map(|c| prev_committee.stake_of(&c.vertex.author)).sum();
                    if stake < quorum {
                        return;
                    }
                }
            }

            let txs: Vec<Transaction> = drain_ready_transactions(&mut state);
            let worker_batches = partition_into_worker_batches(txs);
            let mut batch_digests: Vec<(WorkerId, Digest)> = Vec::with_capacity(worker_batches.len());
            let seen_round = state.next_round;
            for (worker_id, batch) in &worker_batches {
                let digest = batch.digest();
                self.persist_batch(&digest, batch);
                state.batches.insert(digest, batch.clone());
                // Track own batches for retention too, so both the in-memory
                // cache and the on-disk batch log are pruned by the same
                // `BATCH_RETENTION_ROUNDS` window (see `prune_stale_round_state`).
                // Without this an own batch would never be evicted - unbounded
                // growth, and for a solo validator EVERY batch is its own.
                state.batch_seen_round.entry(digest).or_insert(seen_round);
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

    #[test]
    fn active_committee_from_registry_maps_stakes_and_rejects_an_empty_registry() {
        use qchain_execution::validator_registry::{RegisteredValidator, ValidatorRegistryData, MIN_VALIDATOR_STAKE};
        // Empty registry → no viable committee (caller keeps the current one).
        assert!(active_committee_from_registry(&ValidatorRegistryData::default(), |rv| rv.stake).is_none());
        // Two registered validators → a committee carrying their exact stakes.
        let kp1 = Keypair::generate().unwrap();
        let kp2 = Keypair::generate().unwrap();
        let reg = ValidatorRegistryData {
            validators: vec![
                RegisteredValidator { validator: kp1.pubkey(), pubkey_bundle: kp1.public_key_bundle(), address: "10.0.0.1:9000".into(), stake: MIN_VALIDATOR_STAKE * 2, self_stake_account: None },
                RegisteredValidator { validator: kp2.pubkey(), pubkey_bundle: kp2.public_key_bundle(), address: "10.0.0.2:9000".into(), stake: MIN_VALIDATOR_STAKE, self_stake_account: None },
            ],
        };
        let committee = active_committee_from_registry(&reg, |rv| rv.stake).expect("a non-empty registry yields a committee");
        assert_eq!(committee.len(), 2);
        assert_eq!(committee.total_stake(), MIN_VALIDATOR_STAKE * 3);
        assert_eq!(committee.stake_of(&kp1.pubkey()), MIN_VALIDATOR_STAKE * 2);

        // The committee round-trips through the on-disk persistence format
        // (the reason a restarted rotation node can rebuild its schedule).
        let bytes = serialize_committee(&committee);
        let back = deserialize_committee(&bytes).expect("a serialized committee always deserializes");
        assert_eq!(back.len(), committee.len());
        assert_eq!(back.total_stake(), committee.total_stake());
        assert_eq!(back.ids_sorted(), committee.ids_sorted());
        assert_eq!(back.stake_of(&kp1.pubkey()), MIN_VALIDATOR_STAKE * 2);
        assert!(deserialize_committee(b"not a committee").is_none());
    }

    #[test]
    fn merge_peers_unions_config_with_registry_and_excludes_self() {
        use qchain_execution::validator_registry::RegisteredValidator;
        let self_id = Keypair::generate().unwrap().pubkey();
        let v_config = Keypair::generate().unwrap().pubkey(); // already a config peer
        let v_new = Keypair::generate().unwrap().pubkey(); // a genuinely new registrant
        let bundle = qchain_crypto::Keypair::generate().unwrap().public_key_bundle();
        let config_peers = vec![PeerInfo { id: v_config, addr: "10.0.0.2:9000".parse().unwrap() }];
        let reg = |id, addr: &str| RegisteredValidator { validator: id, pubkey_bundle: bundle.clone(), address: addr.to_string(), stake: 10_000_000, self_stake_account: None };
        let active = vec![
            reg(self_id, "10.0.0.1:9000"), // self — must be excluded
            reg(v_config, "10.0.0.2:9000"), // already a peer — no duplicate
            reg(v_new, "10.0.0.9:9000"),   // new — must be added
            reg(Keypair::generate().unwrap().pubkey(), "not-an-address"), // unparseable — skipped
        ];
        let peers = merge_peers(&config_peers, &active, &self_id);
        let ids: Vec<_> = peers.iter().map(|p| p.id).collect();
        assert!(ids.contains(&v_config), "config peer kept");
        assert!(ids.contains(&v_new), "new registrant added (stage-3 discovery)");
        assert!(!ids.contains(&self_id), "self is never a peer");
        assert_eq!(peers.iter().filter(|p| p.id == v_config).count(), 1, "no duplicate for an already-known peer");
        assert_eq!(peers.iter().find(|p| p.id == v_new).unwrap().addr.to_string(), "10.0.0.9:9000");
    }

    #[test]
    fn merge_committee_grow_only_adds_newcomers_and_never_drops_a_seated_member() {
        let a = Keypair::generate().unwrap();
        let b = Keypair::generate().unwrap();
        let c = Keypair::generate().unwrap();
        let vi = |kp: &Keypair, stake| ValidatorInfo { id: kp.pubkey(), pubkey_bundle: kp.public_key_bundle(), stake };
        let current = ValidatorSet::new(vec![vi(&a, 10), vi(&b, 10)]);
        // Derived set adds `c`, refreshes `a`'s stake, and DROPS `b` (e.g. `b`
        // unregistered). Grow-only must keep `b`, add `c`, and refresh `a`.
        let derived = ValidatorSet::new(vec![vi(&a, 25), vi(&c, 30)]);
        let merged = merge_committee_grow_only(&current, &derived);
        assert_eq!(merged.len(), 3, "b is NOT dropped; c is added");
        assert!(merged.get(&b.pubkey()).is_some(), "a seated member is never removed mid-flight");
        assert!(merged.get(&c.pubkey()).is_some(), "a newcomer is added");
        assert_eq!(merged.stake_of(&a.pubkey()), 25, "a seated member's stake is refreshed from the registry");
        assert_eq!(merged.stake_of(&b.pubkey()), 10, "a dropped-from-derived member keeps its last stake");
        // Never shrinks: for the same current, an empty-derived-overlap still
        // returns at least the current members.
        assert!(merged.len() >= current.len());
    }

    /// The real-shrink derivation the epoch ratchet now adopts wholesale (once
    /// the v4.0.3/v4.0.4 shrink-safety fixes landed): the committee derived from
    /// the on-chain registry SHRINKS when a validator unregisters. Grow-only kept
    /// the departed member forever; the ratchet now drops it at the epoch boundary
    /// (safe: ordering liveness + cert availability + atomic commit close the old
    /// freeze/fork). Determinism (stake-desc, id-asc tie-break) is what keeps
    /// every honest node deriving the byte-identical shrunk committee.
    #[test]
    fn the_derived_committee_shrinks_when_a_validator_unregisters() {
        use qchain_execution::validator_registry::{RegisteredValidator, ValidatorRegistryData};
        let kps: Vec<Keypair> = (0..3).map(|_| Keypair::generate().unwrap()).collect();
        let reg = |kp: &Keypair, stake| RegisteredValidator {
            validator: kp.pubkey(),
            pubkey_bundle: kp.public_key_bundle(),
            address: "127.0.0.1:9000".to_string(),
            stake,
            self_stake_account: None,
        };
        // Three registered validators, all above the minimum self-stake.
        let full = ValidatorRegistryData { validators: vec![reg(&kps[0], 30_000_000), reg(&kps[1], 20_000_000), reg(&kps[2], 10_000_000)] };
        let committee_before = active_committee_from_registry(&full, |rv| rv.stake).expect("three registered validators form a committee");
        assert_eq!(committee_before.len(), 3);

        // The lowest-staked validator unregisters (removed from the registry).
        let shrunk = ValidatorRegistryData { validators: vec![reg(&kps[0], 30_000_000), reg(&kps[1], 20_000_000)] };
        let committee_after = active_committee_from_registry(&shrunk, |rv| rv.stake).expect("two registered validators still form a committee");
        assert_eq!(committee_after.len(), 2, "the derived committee SHRINKS to drop the unregistered validator");
        assert!(committee_after.get(&kps[2].pubkey()).is_none(), "the departed validator is removed");
        assert!(committee_after.get(&kps[0].pubkey()).is_some() && committee_after.get(&kps[1].pubkey()).is_some(), "the survivors remain");
    }

    /// v4.1.4 audit MEDIUM fix: a self-registered validator that withdrew its
    /// self-stake (or whose bond fell below the minimum) is DROPPED from the
    /// derived committee even though its registration snapshot still records a
    /// large stake — because the committee is derived from the LIVE self-stake
    /// (`live_stake_of`), not the stale snapshot. A genesis-seeded entry
    /// (`self_stake_account == None`) keeps its snapshot (the bootstrap set).
    #[test]
    fn a_registered_validator_whose_self_stake_is_withdrawn_is_dropped_from_the_committee() {
        use qchain_execution::validator_registry::{RegisteredValidator, ValidatorRegistryData, MIN_VALIDATOR_STAKE};
        let kps: Vec<Keypair> = (0..3).map(|_| Keypair::generate().unwrap()).collect();
        // Distinct self-stake account markers so the closure can tell them apart.
        let sacc = |i: u8| { let mut b = [0u8; 32]; b[0] = 0xAA; b[1] = i; Pubkey::new(b) };
        let reg = |kp: &Keypair, stake, ssa| RegisteredValidator {
            validator: kp.pubkey(),
            pubkey_bundle: kp.public_key_bundle(),
            address: "127.0.0.1:9000".to_string(),
            stake,
            self_stake_account: ssa,
        };
        // v0: self-registered, snapshot huge; v1: self-registered, snapshot huge;
        // v2: genesis-seeded (None) with a real snapshot.
        let registry = ValidatorRegistryData {
            validators: vec![
                reg(&kps[0], MIN_VALIDATOR_STAKE * 3, Some(sacc(0))),
                reg(&kps[1], MIN_VALIDATOR_STAKE * 2, Some(sacc(1))),
                reg(&kps[2], MIN_VALIDATOR_STAKE * 2, None),
            ],
        };
        // All snapshots honored → committee of 3.
        let full = active_committee_from_registry(&registry, |rv| rv.stake).expect("committee");
        assert_eq!(full.len(), 3);

        // Now v0 withdrew its self-stake (live = 0) — the live-stake closure
        // returns 0 for its account, below the minimum, so it's dropped; v1's
        // live self-stake is still healthy; v2 (genesis, None) keeps its snapshot.
        let derived = active_committee_from_registry(&registry, |rv| match rv.self_stake_account {
            None => rv.stake,                              // genesis bootstrap keeps snapshot
            Some(a) if a == sacc(0) => 0,                  // v0 withdrew its bond
            Some(_) => MIN_VALIDATOR_STAKE * 2,            // v1 live stake healthy
        })
        .expect("two validators still form a committee");
        assert_eq!(derived.len(), 2, "the validator whose live self-stake was withdrawn is dropped");
        assert!(derived.get(&kps[0].pubkey()).is_none(), "withdrawn self-stake -> not in the active committee");
        assert!(derived.get(&kps[1].pubkey()).is_some(), "healthy live self-stake stays");
        assert!(derived.get(&kps[2].pubkey()).is_some(), "genesis-seeded entry keeps its snapshot");
    }

    fn new_state() -> EngineState {
        EngineState {
            ledger: Ledger::new(Box::new(InMemoryStore::new())).unwrap(),
            dag: DagStore::new(),
            consensus: ConsensusState::new(),
            mempool: HashMap::new(),
            batches: HashMap::new(),
            batch_seen_round: HashMap::new(),
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
            update_available: None,
            pending_execution: std::collections::VecDeque::new(),
        }
    }

    #[test]
    fn version_comparison_only_flags_a_strictly_newer_valid_version() {
        assert!(version_is_newer("1.1.0", "1.0.0"));
        assert!(version_is_newer("1.0.1", "1.0.0"));
        assert!(version_is_newer("2.0.0", "1.9.9"));
        assert!(!version_is_newer("1.0.0", "1.0.0"), "same version is not an update");
        assert!(!version_is_newer("1.0.0", "1.0.1"), "an older version must not flag an update");
        assert!(!version_is_newer("garbage", "1.0.0"), "a malformed version must never flag an update");
        assert!(!version_is_newer("1.0", "1.0.0"), "an incomplete version is treated as malformed, not an update");
    }

    fn tx(payer: &Keypair, nonce: u64) -> Transaction {
        // A realistic fee_limit (10M units, the CLI default) so the affordability
        // check in `drain_ready_transactions` treats these as payable at the
        // floor fee - the drain tests fund their payers to match.
        Transaction::new_signed(payer, nonce, [0u8; 32], 10_000_000, vec![]).unwrap()
    }

    /// A funded wallet account for the drain tests, so `drain_ready_transactions`'
    /// affordability check (which now PARKS txs a payer can't pay for at the
    /// current fee) doesn't park these at the floor fee.
    fn funded_wallet() -> Account {
        Account { balance: 1_000_000_000, ..Account::new_wallet(qchain_crypto::Pubkey::system_program_id()) }
    }

    /// The per-round inclusion cap (see `FEE_MAX_BYTES_PER_ROUND`): under
    /// congestion the highest-tip transactions fill the round and the rest wait,
    /// which is what makes the priority fee buy real queue-jumping. Also checks
    /// the two safety properties: a nonce run is never split with a gap, and at
    /// least one tx is always selected even if it alone exceeds the cap.
    #[test]
    fn inclusion_cap_takes_highest_tip_prefix_defers_rest_and_never_splits_a_nonce_run() {
        let a = Keypair::generate().unwrap();
        let b = Keypair::generate().unwrap();
        let c = Keypair::generate().unwrap();
        let ta = tx(&a, 0);
        let sz = ta.byte_size() as u64;

        // Groups already in tip-desc order (as `drain_ready_transactions` sorts
        // them): a > b > c. A cap of two tx-widths must take a and b, defer c.
        let groups = vec![
            (100u64, vec![ta.clone()]),
            (50u64, vec![tx(&b, 0)]),
            (10u64, vec![tx(&c, 0)]),
        ];
        let (sel, def) = select_within_cap(groups, sz * 2);
        assert_eq!(sel.len(), 2, "cap of two tx-widths selects the two highest-tip txs");
        assert_eq!(def.len(), 1, "the lowest-tip tx is deferred to a later round");
        assert_eq!(def[0].message.payer, c.pubkey(), "the deferred tx is the lowest-tip payer's");

        // At least one tx is always selected, even one bigger than the whole cap.
        let (sel1, def1) = select_within_cap(vec![(0u64, vec![ta.clone()])], 1);
        assert_eq!(sel1.len(), 1, "a single oversized tx is still included (no wedge)");
        assert!(def1.is_empty());

        // A payer's nonce run is never split with a gap: only the fitting prefix
        // is taken, the rest of THAT run (higher nonces) is deferred as a block.
        let run = vec![tx(&a, 0), tx(&a, 1), tx(&a, 2)];
        let (sel2, def2) = select_within_cap(vec![(0u64, run)], sz + 1);
        assert_eq!(sel2.len(), 1, "only the first nonce of the run fits under the cap");
        assert_eq!(sel2[0].message.nonce, 0);
        assert_eq!(
            def2.iter().map(|t| t.message.nonce).collect::<Vec<_>>(),
            vec![1, 2],
            "the higher nonces are deferred together, never a nonce-1-without-nonce-0 gap"
        );
    }

    /// The permanent-fork fix (see `EngineState::pending_execution`): a
    /// certificate whose batch hasn't arrived must NOT be skipped, and
    /// execution must not run any later-ordered certificate ahead of it -
    /// otherwise this node drops transactions the rest of the network applied,
    /// forking both balances and the dynamic-fee curve forever.
    #[test]
    fn take_executable_prefix_never_skips_or_reorders_past_a_missing_batch() {
        use qchain_core::{Batch, Certificate, Vertex};
        let author = Keypair::generate().unwrap().pubkey();
        let d = |n: u8| -> Digest { [n; 32] };
        let cert = |round, bds: Vec<(WorkerId, Digest)>| Certificate {
            vertex: Vertex { round, author, batch_digests: bds, parents: vec![] },
            signatures: vec![],
        };

        // Three certificates in committed order; the middle one's batch is
        // missing (even though the LAST one's batch is already present).
        let mut pending: std::collections::VecDeque<Certificate> = std::collections::VecDeque::new();
        pending.push_back(cert(0, vec![(0, d(1))]));
        pending.push_back(cert(1, vec![(0, d(2))])); // d(2) not yet cached
        pending.push_back(cert(2, vec![(0, d(3))]));

        let mut batches: HashMap<Digest, Batch> = HashMap::new();
        batches.insert(d(1), Batch { transactions: vec![] });
        batches.insert(d(3), Batch { transactions: vec![] }); // present but blocked behind d(2)

        let (ready, blocked) = take_executable_prefix(&mut pending, &batches);
        assert_eq!(ready.len(), 1, "only the first certificate is executable");
        assert_eq!(ready[0].vertex.round, 0);
        assert_eq!(pending.len(), 2, "the blocked cert and everything after it stay buffered - never skipped");
        assert_eq!(pending.front().unwrap().vertex.round, 1, "the blocked cert stays at the front (no reorder)");
        let (missing, who) = blocked.expect("the queue is blocked on a missing batch");
        assert_eq!(missing, vec![(0u8, d(2))], "the missing batch is surfaced for re-sync");
        assert_eq!(who, author);

        // The missing batch arrives: the remaining certs drain in order, none lost.
        batches.insert(d(2), Batch { transactions: vec![] });
        let (ready2, blocked2) = take_executable_prefix(&mut pending, &batches);
        assert_eq!(ready2.iter().map(|c| c.vertex.round).collect::<Vec<_>>(), vec![1, 2]);
        assert!(pending.is_empty() && blocked2.is_none(), "queue fully drains once the gap is filled");
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
        state.ledger.seed_account(alice.pubkey(), funded_wallet());

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
        state.ledger.seed_account(alice.pubkey(), funded_wallet());

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

    /// The fee-market parking fix (the real bug the 50k stress test exposed):
    /// a transaction whose fee at the CURRENT rate exceeds its signed `fee_limit`
    /// must be PARKED (left in the mempool to wait for the fee to fall), NOT
    /// drained into a batch where it would fail and be consumed - which, via the
    /// resulting nonce gap, silently strands the payer's whole backlog. When the
    /// fee later drops, the same transaction becomes ready and drains normally.
    #[test]
    fn a_tx_that_cant_afford_the_current_fee_is_parked_not_dropped() {
        let mut state = new_state();
        let alice = Keypair::generate().unwrap();
        state.ledger.seed_account(alice.pubkey(), funded_wallet());
        // Spike the on-chain base fee so a tx signed with a modest fee_limit can't
        // afford it. A tx here is ~5.4 KB; at a high base fee its byte fee blows
        // past a small fee_limit.
        let spiked = qchain_execution::params::EconomicParams {
            base_fee_per_byte: 10_000_000,
            ..qchain_execution::params::EconomicParams::default()
        };
        state.ledger.seed_account(
            qchain_execution::ids::PARAMS_ACCOUNT_ID,
            Account { data: borsh::to_vec(&spiked).unwrap(), ..Account::new_wallet(qchain_crypto::Pubkey::system_program_id()) },
        );
        // fee_limit 10M, but the fee at 10M/byte over ~5.4KB is ~54 BILLION >> limit.
        state.mempool.entry(alice.pubkey()).or_default().insert(0, tx(&alice, 0));

        let ready = drain_ready_transactions(&mut state);
        assert!(ready.is_empty(), "an unaffordable tx must be PARKED, not drained into a failing batch");
        assert_eq!(state.mempool.get(&alice.pubkey()).map(|q| q.len()), Some(1), "it must stay in the mempool, waiting");

        // Drop the fee back to the floor: the same tx now affords it and drains.
        let cheap = qchain_execution::params::EconomicParams::default();
        state.ledger.seed_account(
            qchain_execution::ids::PARAMS_ACCOUNT_ID,
            Account { data: borsh::to_vec(&cheap).unwrap(), ..Account::new_wallet(qchain_crypto::Pubkey::system_program_id()) },
        );
        let ready = drain_ready_transactions(&mut state);
        assert_eq!(ready.len(), 1, "once the fee falls, the parked tx drains normally");
        assert_eq!(ready[0].message.nonce, 0);
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
            Account { nonce: 2, balance: 1_000_000_000, ..Account::new_wallet(qchain_crypto::Pubkey::system_program_id()) },
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
        state.ledger.seed_account(alice.pubkey(), funded_wallet());
        state.ledger.seed_account(bob.pubkey(), funded_wallet());

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
