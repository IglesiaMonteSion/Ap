//! Deterministic simulation testing (DST) for `qchain-consensus`'s
//! Narwhal-Bullshark core (design: `ARCHITECTURE.md`'s phase-2 roadmap -
//! "Testing de simulación determinista para el consenso"). A single
//! seeded PRNG drives every non-deterministic choice (message drop/delay,
//! fault scheduling) in an otherwise synchronous, single-threaded event
//! loop - no real time, no threads, no real network - so a failing
//! scenario is reproducible by re-running the same seed.
//!
//! What this proves, precisely: given the *same* replicated set of
//! certificates each honest validator ends up holding (subject to
//! whatever drops/delays/partitions/Byzantine behavior the scenario
//! injects), do all honest validators' committed total orders stay
//! prefix-consistent with each other (safety), and does progress resume
//! once faults end (liveness)? It reuses the real `qchain-consensus`
//! crate (`DagStore`, `ConsensusState`/Bullshark, `ValidatorSet`,
//! `verify_certificate`) and a synchronous re-implementation of
//! `qchain-node`'s protocol logic (`validator.rs`) - not a model of the
//! protocol, the actual ordering algorithm.
//!
//! Determinism, precisely — and honestly (this is the load-bearing property; a
//! test that "sometimes" fails and is shrugged off as noise is worthless). The
//! run is driven only by logical ticks (no wall clock) on a single thread (no
//! thread ever needs to "get CPU in time" — that was never the cause), and
//! every fault choice comes from one seeded `StdRng`. The one thing that is
//! *not* seeded is the raw key material: validator keypairs come from the OS
//! CSPRNG (`qchain_crypto::Keypair::generate`) because liboqs's `oqs` bindings
//! expose no pluggable RNG hook and no seeded ML-DSA keygen (see
//! `pqc-cryptography`; the `pure`/RustCrypto backend *is* seedable but can't be
//! feature-unified with the node's `liboqs` backend in one workspace build, so
//! bit-for-bit key determinism isn't reachable here). The rotation flake ("max
//! committed round was 4") had **two** now-fixed causes rooted in that:
//!   1. **Leader schedule (primary).** Leader election is
//!      `ids_sorted()[SHA3(round) % n]`, and `ids_sorted()` orders validators
//!      by pubkey bytes — so random pubkeys shuffled the *leader schedule* every
//!      process run, and the same seed crossed the epoch boundary on some runs,
//!      stalled the round before it on others. Fixed at the source:
//!      `run_simulation` sorts the generated keypairs into pubkey order so
//!      **index order == `ids_sorted()` order**, making the leader for any round
//!      a pure function of `(round, committee index-set)`, independent of the
//!      random key *values*. Behavior/membership are assigned by the post-sort
//!      index, so the scenario's index semantics are unchanged.
//!   2. **Re-sync emission order (secondary).** The per-tick retry of
//!      outstanding `CertificateRequest`s iterated a `HashMap`, whose
//!      `RandomState`/digest-value order leaked into which request got which
//!      sequence number, i.e. into delivery timing. Fixed by making that set
//!      insertion-ordered (a `Vec`) — see `validator.rs`.
//!
//! What remains, stated plainly: the protocol legitimately sorts by digest in a
//! few places (a vertex's `parents`, `walk_causal_history`), and digests hash
//! the run's random author keys, so the *exact tick* a given round commits is
//! not bit-identical across process runs. That residual is **timing only**. It
//! cannot affect **safety** — prefix-consistency between honest validators in a
//! single run is independent of digest order and delivery timing — which is why
//! the rotation tests assert `safety_violation.is_none()` *strictly, over a
//! large seed sweep*: that is the real #194 guarantee and it holds every time.
//! For **liveness** (crossing the epoch boundary), the tests use a tick/loss
//! budget generous enough that every seed in the sweep crosses; a run that
//! doesn't is never dismissed — `SimReport::progress_note` +
//! `max_round_with_quorum` say whether it was a genuine liveness limit under the
//! injected loss or a leader that formed quorum yet failed to commit. The flake
//! is therefore explained and removed, not reclassified as noise.

pub mod validator;

use qchain_consensus::{ValidatorInfo, ValidatorSet};
use qchain_core::{Digest, ValidatorId};
use qchain_crypto::Keypair;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{BTreeMap, HashMap, HashSet};
pub use validator::{ByzantineBehavior, SimMessage, SimValidator};

#[derive(Clone, Debug, Default)]
pub struct FaultPolicy {
    /// Probability (0.0-1.0) any single message is dropped outright.
    pub drop_rate: f64,
    /// If set, overrides `drop_rate` specifically for
    /// `CertificateBroadcast` messages - lets a scenario isolate
    /// certificate-broadcast loss from vote/proposal loss (which
    /// `VertexProposal`'s retry-while-pending logic already recovers from
    /// indirectly, see `project-lessons-learned`), to test whether a
    /// dropped certificate broadcast - which nothing currently retries -
    /// is a real safety/liveness problem on its own.
    pub cert_drop_rate: Option<f64>,
    /// Extra ticks (0..=max) a surviving message may be delayed, chosen
    /// uniformly per message.
    pub max_delay_ticks: u64,
    /// Two validator-index groups and the tick until which any message
    /// crossing between them is dropped, modeling a network partition
    /// that heals at that tick.
    pub partition: Option<(Vec<usize>, Vec<usize>, u64)>,
}

/// A validator-set membership change at an epoch boundary — `#194`, the
/// membership-change / rotation DST. `None` on a `Scenario` means fixed
/// membership (a `single` schedule: every round resolves to the one committee,
/// byte-identical to the phase-1/2 behavior the 9 base scenarios exercise).
///
/// When set, the driver builds a rotating `ValidatorSchedule`: epoch 0 is the
/// committee of `epoch0` indices, epoch 1+ the committee of `epoch1` indices,
/// with both installed and the resolvable frontier raised to epoch 1 (in a DST
/// every node knows the whole rotation up front and identically — the exact
/// "all honest nodes install byte-identical committees" premise the schedule's
/// safety argument rests on). A small `epoch_rounds` makes the sim cross the
/// boundary quickly. This is what exercises, end-to-end and under certificate
/// loss, the two rotation fixes that were only ever verified live: v4.0.3
/// (`direct_status` weighs round `r+1` support under `for_round(r+1)`, so a
/// shrunk/rotated committee stays live across the boundary) and v4.0.4
/// (`walk_causal_history` commits a leader atomically, so a *departed*
/// validator's late-arriving epoch-boundary certificate can never reorder an
/// already-committed prefix).
#[derive(Clone, Debug)]
pub struct Rotation {
    /// Rounds per epoch — the boundary granularity. Keep small so the run
    /// crosses at least one boundary within `ticks`.
    pub epoch_rounds: u64,
    /// Validator indices forming the epoch-0 (bootstrap) committee.
    pub epoch0: Vec<usize>,
    /// Validator indices forming the epoch-1-onward committee (the change): a
    /// join is an index in `epoch1` but not `epoch0`; a departure is the
    /// reverse. Overlap ≥ quorum keeps liveness across the boundary.
    pub epoch1: Vec<usize>,
}

pub struct Scenario {
    pub validator_count: usize,
    /// Validator index -> non-default behavior. Absent indices are
    /// `ByzantineBehavior::Honest`.
    pub byzantine: HashMap<usize, ByzantineBehavior>,
    pub fault: FaultPolicy,
    pub ticks: u64,
    /// Optional epoch-boundary committee change (`#194`). `None` = fixed
    /// membership (a `single` schedule), the shape the 9 base scenarios use.
    pub rotation: Option<Rotation>,
}

#[derive(Debug)]
pub struct SimReport {
    /// `Some(description)` the moment two honest validators' committed
    /// orders are found to diverge (one isn't a prefix of the other).
    pub safety_violation: Option<String>,
    /// `Some(description)` if more than one distinct certificate was ever
    /// formed for the same (round, author) - the precise "did
    /// equivocation succeed" check, independent of whether it happened to
    /// also show up as a prefix divergence.
    pub equivocation_succeeded: Option<String>,
    pub honest_committed_counts: Vec<usize>,
    pub made_progress: bool,
    /// Full committed order per validator index (honest and Byzantine
    /// alike) - kept for debugging a reported `safety_violation` digest by
    /// digest, not just knowing that one occurred.
    pub committed_orders: Vec<Vec<Digest>>,
    /// True if any honest validator captured a real, independently
    /// verifiable `EquivocationEvidence` during the run - the DST-side
    /// proof that `SimValidator::handle_message`'s evidence-capture logic
    /// (mirroring `qchain-node::engine`) actually fires against a real
    /// `ByzantineBehavior::Equivocator`, not just that the equivocation
    /// lock kept it from succeeding.
    pub equivocation_evidence_captured: bool,
    /// The highest consensus round any honest validator has *committed* (the
    /// max round among its committed certificates). Lets a membership-change
    /// scenario (`#194`) assert its run genuinely crossed the epoch boundary
    /// (committed a round `>= epoch_rounds`, i.e. under the *new* committee) —
    /// so a "stayed safe" result isn't vacuously true because the sim never
    /// actually rotated.
    pub max_committed_round: u64,
    /// Highest round for which a quorum of that round's committee actually
    /// formed (and broadcast) a certificate — the "was quorum available at this
    /// round" signal, using the epoch's committee threshold. Detects *temporary
    /// absence of quorum*: if a rotation run fails to cross its boundary,
    /// comparing this to `max_committed_round` explains WHY — quorum never
    /// formed at the boundary round (a liveness limit under the injected loss
    /// budget) vs. quorum formed but a leader wasn't committed (a real bug to
    /// surface, not swallow).
    pub max_round_with_quorum: u64,
    /// Human-readable explanation of the progress outcome, populated whenever a
    /// rotation run does *not* cross its epoch boundary. The point (per the #2
    /// requirement) is that a blocked run is never opaque: the report says which
    /// round it reached, whether quorum was even available there, and therefore
    /// whether the block is a liveness limit or a bug.
    pub progress_note: Option<String>,
}

fn is_prefix_consistent(a: &[Digest], b: &[Digest]) -> bool {
    let n = a.len().min(b.len());
    a[..n] == b[..n]
}

/// Runs `scenario` to completion and reports the safety/liveness outcome.
/// `seed` controls the entire fault-injection schedule - same scenario +
/// same seed always reproduces the same run (see module docs for the
/// one exception, key material).
pub fn run_simulation(scenario: &Scenario, seed: u64) -> SimReport {
    let mut rng = StdRng::seed_from_u64(seed);

    // Generate every keypair, then SORT by pubkey bytes so that index order ==
    // `ValidatorSet::ids_sorted()` order. This is what pins the leader schedule
    // to `(round, committee index-set)` and removes the process-run leader
    // shuffle (see the module docs on determinism). Behavior + committee
    // membership are assigned by the POST-sort index below, so the scenario's
    // index-based semantics are unchanged.
    let mut keypairs: Vec<Keypair> =
        (0..scenario.validator_count).map(|_| Keypair::generate().expect("keypair generation should not fail")).collect();
    keypairs.sort_by_key(|kp| kp.pubkey().to_bytes());

    let mut ids: Vec<ValidatorId> = Vec::new();
    let mut sims: Vec<SimValidator> = Vec::new();
    let mut infos: Vec<ValidatorInfo> = Vec::new();
    for (i, kp) in keypairs.into_iter().enumerate() {
        let id = kp.pubkey();
        let behavior = scenario.byzantine.get(&i).copied().unwrap_or(ByzantineBehavior::Honest);
        infos.push(ValidatorInfo { id, pubkey_bundle: kp.public_key_bundle(), stake: 1 });
        ids.push(id);
        sims.push(SimValidator::new(id, kp, behavior));
    }
    // Build the validator schedule (the per-round committee resolver). Fixed
    // membership => a `single` schedule (every round -> the one committee,
    // byte-identical to the phase-1/2 single-`ValidatorSet` consensus, which is
    // why the 9 base scenarios stay 9/9). A `rotation` scenario => a real
    // rotating schedule with epoch 0 and epoch 1 committees installed and the
    // frontier raised, so consensus resolves each round under its epoch's
    // committee across a genuine boundary (#194).
    let committee_of = |indices: &[usize]| -> ValidatorSet {
        ValidatorSet::new(indices.iter().map(|&i| infos[i].clone()).collect())
    };
    let schedule = match &scenario.rotation {
        None => qchain_consensus::ValidatorSchedule::single(ValidatorSet::new(infos.clone())),
        Some(rot) => {
            let mut s = qchain_consensus::ValidatorSchedule::new(rot.epoch_rounds, committee_of(&rot.epoch0));
            s.install_epoch(1, committee_of(&rot.epoch1));
            // Every node knows the whole (deterministic) rotation up front and
            // identically, so both epochs are resolvable from the start.
            s.set_frontier_epoch(1);
            s
        }
    };

    // (deliver_tick, seq) -> (from_idx, to_idx, message). BTreeMap keeps
    // events ordered for deterministic delivery given a fixed seed.
    let mut queue: BTreeMap<(u64, u64), (usize, usize, SimMessage)> = BTreeMap::new();
    let mut seq: u64 = 0;
    // (round, author) -> every distinct certificate digest ever formed
    // for it - the precise equivocation-success check.
    let mut certified: HashMap<(u64, ValidatorId), HashSet<Digest>> = HashMap::new();

    let enqueue =
        |queue: &mut BTreeMap<(u64, u64), (usize, usize, SimMessage)>, seq: &mut u64, tick: u64, from: usize, to: usize, msg: SimMessage, rng: &mut StdRng| {
            if let Some((group_a, group_b, until)) = &scenario.fault.partition {
                if tick < *until {
                    let crosses = (group_a.contains(&from) && group_b.contains(&to)) || (group_b.contains(&from) && group_a.contains(&to));
                    if crosses {
                        return;
                    }
                }
            }
            let drop_rate = match (&msg, scenario.fault.cert_drop_rate) {
                (SimMessage::CertificateBroadcast(_), Some(rate)) => rate,
                _ => scenario.fault.drop_rate,
            };
            if drop_rate > 0.0 && rng.gen::<f64>() < drop_rate {
                return;
            }
            let delay = if scenario.fault.max_delay_ticks > 0 { rng.gen_range(0..=scenario.fault.max_delay_ticks) } else { 0 };
            queue.insert((tick + 1 + delay, *seq), (from, to, msg));
            *seq += 1;
        };

    for tick in 0..scenario.ticks {
        // `i` cross-references three parallel collections (sims, ids, and
        // the peer-filter below), not just `sims` - an iterator/enumerate
        // rewrite wouldn't be clearer here.
        #[allow(clippy::needless_range_loop)]
        for i in 0..scenario.validator_count {
            let peers: Vec<ValidatorId> = (0..scenario.validator_count).filter(|&j| j != i).map(|j| ids[j]).collect();
            let outgoing = sims[i].maybe_propose(&schedule, &peers);
            for (to_id, msg) in outgoing {
                let to_idx = ids.iter().position(|x| *x == to_id).unwrap();
                if let SimMessage::CertificateBroadcast(cert) = &msg {
                    certified.entry((cert.vertex.round, cert.vertex.author)).or_default().insert(cert.vertex.digest());
                }
                enqueue(&mut queue, &mut seq, tick, i, to_idx, msg, &mut rng);
            }
            for (to_id, msg) in sims[i].retry_pending_cert_requests() {
                let to_idx = ids.iter().position(|x| *x == to_id).unwrap();
                enqueue(&mut queue, &mut seq, tick, i, to_idx, msg, &mut rng);
            }
        }

        let due_keys: Vec<(u64, u64)> = queue.range(..=(tick, u64::MAX)).map(|(k, _)| *k).collect();
        for key in due_keys {
            let Some((from, to, msg)) = queue.remove(&key) else { continue };
            let peers: Vec<ValidatorId> = (0..scenario.validator_count).filter(|&j| j != to).map(|j| ids[j]).collect();
            let outgoing = sims[to].handle_message(ids[from], msg, &schedule, &peers);
            for (to_id, out_msg) in outgoing {
                let to_idx = ids.iter().position(|x| *x == to_id).unwrap();
                if let SimMessage::CertificateBroadcast(cert) = &out_msg {
                    certified.entry((cert.vertex.round, cert.vertex.author)).or_default().insert(cert.vertex.digest());
                }
                enqueue(&mut queue, &mut seq, tick, to, to_idx, out_msg, &mut rng);
            }
            sims[to].try_commit(&schedule);
        }
    }

    let honest_indices: Vec<usize> = (0..scenario.validator_count)
        .filter(|i| scenario.byzantine.get(i).map(|b| *b == ByzantineBehavior::Honest).unwrap_or(true))
        .collect();

    let mut safety_violation = None;
    'outer: for (a_pos, &i) in honest_indices.iter().enumerate() {
        for &j in &honest_indices[a_pos + 1..] {
            if !is_prefix_consistent(&sims[i].committed_order, &sims[j].committed_order) {
                safety_violation = Some(format!("honest validators at index {i} and {j} disagree on committed order"));
                break 'outer;
            }
        }
    }

    let mut equivocation_succeeded = None;
    for ((round, author), digests) in &certified {
        if digests.len() > 1 {
            equivocation_succeeded = Some(format!("{} distinct certificates formed for round {round}, author {author}", digests.len()));
            break;
        }
    }

    let honest_committed_counts: Vec<usize> = honest_indices.iter().map(|&i| sims[i].committed_order.len()).collect();
    let made_progress = honest_committed_counts.iter().any(|&c| c > 0);
    let committed_orders: Vec<Vec<Digest>> = sims.iter().map(|s| s.committed_order.clone()).collect();
    let equivocation_evidence_captured = honest_indices.iter().any(|&i| !sims[i].equivocation_evidence.is_empty());
    // Highest round any honest validator committed (the max round among its
    // committed certificates, resolved through its DAG). A committed digest is
    // never pruned in this harness, so it's always still resolvable.
    let max_committed_round = honest_indices
        .iter()
        .map(|&i| sims[i].committed_order.iter().filter_map(|d| sims[i].dag.get(d).map(|c| c.vertex.round)).max().unwrap_or(0))
        .max()
        .unwrap_or(0);

    // "Was quorum available at each round?" — group the certificates formed for
    // each round by distinct author, and check that count against the round's
    // committee threshold. This is the temporary-quorum-absence detector: the
    // highest round that reached a quorum of certs, using the epoch's committee.
    let mut round_authors: BTreeMap<u64, HashSet<ValidatorId>> = BTreeMap::new();
    for (round, author) in certified.keys() {
        round_authors.entry(*round).or_default().insert(*author);
    }
    let max_round_with_quorum = round_authors
        .iter()
        .filter(|(round, authors)| (authors.len() as u64) >= schedule.for_round(**round).quorum_threshold())
        .map(|(round, _)| *round)
        .max()
        .unwrap_or(0);

    // A blocked rotation run must never be opaque (the #2 requirement): say
    // which round it reached and whether quorum was even available past it. A
    // non-crossing under injected certificate loss is the *documented* liveness
    // limit — `Bullshark::extend_order` stops at the first Undecided round, and
    // a leader that never gathers direct round+1 support (its support certs kept
    // getting dropped) leaves that round Undecided forever, so later rounds
    // can't commit even though their certs exist (`max_round_with_quorum` past
    // the stall shows exactly that). It is NOT a safety issue (safety is checked
    // separately and always holds) and NOT a per-run fluke: with the
    // deterministic leader schedule it is reproducible for a given seed's drop
    // schedule (e.g. seed 5 at 0.2 loss stalls at round 2 no matter the tick
    // budget — verified to 2400 ticks). The fix for it would be the
    // indirect/fallback commit rule (deferred, see the `certificate_broadcast_
    // loss_alone...` test). That is why the crossing/liveness assertion runs at
    // a MILD loss where the boundary reliably crosses, and safety is what's
    // asserted strictly under harsh loss.
    let progress_note = scenario.rotation.as_ref().and_then(|rot| {
        if max_committed_round >= rot.epoch_rounds {
            return None;
        }
        Some(format!(
            "did not cross epoch boundary: max_committed_round={max_committed_round} < epoch_rounds={} \
             (committed counts {honest_committed_counts:?}); max_round_with_quorum={max_round_with_quorum}. \
             This is the documented leader-starvation liveness limit under the injected certificate loss \
             (extend_order stops at the first Undecided round; the indirect commit rule is deferred), NOT a \
             safety issue and NOT noise — it is deterministic for this seed's drop schedule.",
            rot.epoch_rounds
        ))
    });

    SimReport {
        safety_violation,
        equivocation_succeeded,
        honest_committed_counts,
        made_progress,
        committed_orders,
        equivocation_evidence_captured,
        max_committed_round,
        max_round_with_quorum,
        progress_note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Shared drivers for the rotation/shrink DSTs (#194, #2) ===
    //
    // Empirically-chosen budgets (from the crossing-rate sweep, documented in
    // the CLAUDE.md #2 entry): every seed crosses the epoch boundary at
    // `LIVENESS_LOSS`/`LIVENESS_TICKS` (measured 40/40 with a round-2 margin),
    // while `HARSH_LOSS` is high enough that some seeds legitimately can't cross
    // (leader starvation — a documented liveness limit) yet SAFETY must still
    // hold. Certificate loss + a small delay is what makes a departed
    // validator's boundary certificate arrive late/out of order — the exact
    // condition that exercises v4.0.4 (atomic leader commit) and v4.0.3 (r+1
    // support weighed under the next round's committee).
    const LIVENESS_LOSS: f64 = 0.1;
    const LIVENESS_TICKS: u64 = 600;
    const HARSH_LOSS: f64 = 0.35;
    const HARSH_TICKS: u64 = 300;

    /// Sweeps `seeds` seeds and asserts the two RUN-INDEPENDENT rotation
    /// guarantees at the mild liveness budget: SAFETY holds for every seed
    /// (strict — digest/timing-independent), and every seed CROSSES the epoch
    /// boundary (commits a round `>= epoch_rounds`, i.e. under the NEW
    /// committee), so "stayed safe" is never vacuously true. A non-crossing is
    /// reported with its `progress_note`, never dismissed as noise.
    fn rotation_liveness_sweep(rotation: Rotation, validator_count: usize, seeds: u64) {
        for seed in 0..seeds {
            let fault = FaultPolicy { drop_rate: 0.0, cert_drop_rate: Some(LIVENESS_LOSS), max_delay_ticks: 2, partition: None };
            let scenario = Scenario { validator_count, byzantine: HashMap::new(), fault, ticks: LIVENESS_TICKS, rotation: Some(rotation.clone()) };
            let report = run_simulation(&scenario, seed);
            assert!(report.safety_violation.is_none(), "seed {seed}: SAFETY VIOLATION {:?}\norders {:?}", report.safety_violation, report.committed_orders);
            assert!(report.made_progress, "seed {seed}: no progress at all, counts {:?}", report.honest_committed_counts);
            assert!(
                report.max_committed_round >= rotation.epoch_rounds,
                "seed {seed}: did not cross the epoch boundary within {LIVENESS_TICKS} ticks at {LIVENESS_LOSS} cert loss. {}",
                report.progress_note.clone().unwrap_or_default()
            );
        }
    }

    /// Sweeps `seeds` seeds under HARSH certificate loss and asserts SAFETY only
    /// — honest validators never diverge — the one property that must hold on
    /// every single run regardless of the injected loss or the non-seeded key
    /// material (module docs). Liveness is deliberately NOT asserted here:
    /// under heavy ongoing loss a leader can be permanently starved (the
    /// documented limit), which is a liveness gap, never a safety one. This is
    /// the hundreds-of-runs stress the #2 requirement asks for.
    fn rotation_safety_sweep(rotation: Rotation, validator_count: usize, seeds: u64) {
        for seed in 0..seeds {
            let fault = FaultPolicy { drop_rate: 0.0, cert_drop_rate: Some(HARSH_LOSS), max_delay_ticks: 3, partition: None };
            let scenario = Scenario { validator_count, byzantine: HashMap::new(), fault, ticks: HARSH_TICKS, rotation: Some(rotation.clone()) };
            let report = run_simulation(&scenario, seed);
            assert!(
                report.safety_violation.is_none(),
                "seed {seed}: SAFETY VIOLATION under harsh loss {:?}\norders {:?}",
                report.safety_violation, report.committed_orders
            );
        }
    }

    fn rotation_scenario() -> Rotation {
        // v0 leaves, v4 joins: {0,1,2,3} -> {1,2,3,4}, three overlap.
        Rotation { epoch_rounds: 5, epoch0: vec![0, 1, 2, 3], epoch1: vec![1, 2, 3, 4] }
    }
    fn shrink_scenario() -> Rotation {
        // v0 leaves, committee shrinks: {0,1,2,3} -> {1,2,3}, quorum 3 -> 2.
        Rotation { epoch_rounds: 5, epoch0: vec![0, 1, 2, 3], epoch1: vec![1, 2, 3] }
    }

    #[test]
    fn honest_network_no_faults_converges_safely_and_makes_progress() {
        let scenario = Scenario { validator_count: 4, byzantine: HashMap::new(), fault: FaultPolicy::default(), ticks: 60, rotation: None };
        let report = run_simulation(&scenario, 1);
        assert!(report.safety_violation.is_none(), "{:?}", report.safety_violation);
        assert!(report.made_progress);
    }

    #[test]
    fn honest_network_under_message_loss_and_delay_stays_safe() {
        let fault = FaultPolicy { drop_rate: 0.2, max_delay_ticks: 3, ..Default::default() };
        let scenario = Scenario { validator_count: 4, byzantine: HashMap::new(), fault, ticks: 150, rotation: None };
        for seed in 0..3 {
            let report = run_simulation(&scenario, seed);
            assert!(report.safety_violation.is_none(), "seed {seed}: {:?}", report.safety_violation);
        }
    }

    #[test]
    fn one_silent_validator_below_the_fault_bound_still_makes_progress() {
        // n=4, f=1 (f < n/3): one crashed/censoring validator must not
        // stop the other three from reaching quorum (2f+1 = 3, exactly
        // the three honest validators).
        let mut byzantine = HashMap::new();
        byzantine.insert(3, ByzantineBehavior::Silent);
        let scenario = Scenario { validator_count: 4, byzantine, fault: FaultPolicy::default(), ticks: 80, rotation: None };
        let report = run_simulation(&scenario, 7);
        assert!(report.safety_violation.is_none());
        assert!(report.made_progress, "3 honest validators (2f+1 for f=1) must still reach quorum without the 4th");
    }

    #[test]
    fn equivocating_author_never_gets_two_certificates_for_the_same_round() {
        // Real ML-DSA-65 signing dominates runtime here (see
        // `pqc-cryptography`) - kept to a handful of seeds rather than a
        // large sweep so the suite stays fast; each seed still drives a
        // fully independent fault-injection schedule.
        let mut byzantine = HashMap::new();
        byzantine.insert(0, ByzantineBehavior::Equivocator);
        let scenario = Scenario { validator_count: 4, byzantine, fault: FaultPolicy::default(), ticks: 80, rotation: None };
        for seed in 0..3 {
            let report = run_simulation(&scenario, seed);
            assert!(report.equivocation_succeeded.is_none(), "seed {seed}: {:?}", report.equivocation_succeeded);
            assert!(report.safety_violation.is_none(), "seed {seed}: {:?}", report.safety_violation);
            // Not just "the equivocation lock kept it from succeeding" -
            // real, independently-verifiable evidence must have actually
            // been captured, since honest validators inevitably split on
            // which of the equivocator's two vertices they saw first (the
            // evil vertex only reaches half the peers - see
            // `SimValidator::maybe_propose`).
            assert!(report.equivocation_evidence_captured, "seed {seed}: no honest validator captured equivocation evidence");
        }
    }

    #[test]
    fn a_healing_partition_still_reaches_safety_and_resumes_progress() {
        // Split 4 validators 2-2 for the first 30 ticks (neither side has
        // quorum alone - 2 < quorum_threshold of 3), then heal.
        let fault = FaultPolicy { drop_rate: 0.0, max_delay_ticks: 0, partition: Some((vec![0, 1], vec![2, 3], 30)), ..Default::default() };
        let scenario = Scenario { validator_count: 4, byzantine: HashMap::new(), fault, ticks: 100, rotation: None };
        let report = run_simulation(&scenario, 3);
        assert!(report.safety_violation.is_none());
        assert!(report.made_progress, "progress must resume once the partition heals");
    }

    /// Isolates *only* `CertificateBroadcast` loss (zero proposal/vote
    /// loss, via `drop_rate: 0.0` alongside `cert_drop_rate`) - the one
    /// message type nothing retried before `CertificateRequest`/
    /// `CertificateResponse` re-sync existed (see `project-lessons-learned`
    /// and the module docs on `cert_drop_rate`).
    ///
    /// This scenario, run while building the re-sync mechanism, found two
    /// real, distinct bugs in sequence, both documented in
    /// `project-lessons-learned`: (1) before re-sync existed, a dropped
    /// certificate broadcast was simply unrecoverable - complete permanent
    /// stall, zero commits ever, confirmed empirically before any fix
    /// existed. (2) once re-sync started letting certificates arrive late
    /// and out of order, `Bullshark::extend_order` turned out to have a
    /// real safety bug: it skipped past a round whose leader hadn't yet
    /// independently satisfied its own commit condition to check *later*
    /// rounds, so two validators could walk the same later leader through
    /// different locally-known ancestor sets and disagree on relative
    /// order - fixed by making `extend_order` stop, not skip, at the first
    /// uncommitted round (see `bullshark.rs`).
    ///
    /// That safety fix is asserted here unconditionally - it must never
    /// regress. What it does *not* fully restore is *sustained* liveness
    /// under heavy, ongoing certificate loss: stopping (rather than
    /// skipping) at a round whose leader lacks direct round+1 support is
    /// exactly the scenario the module's own docs already name as
    /// deferred to phase 2 ("the indirect/fallback commit rule for a
    /// leader that never gathers direct support"). Only `made_progress`
    /// (weak - at least one commit) is asserted for now; a real
    /// stronger bar (sustained progress despite ongoing loss) is the
    /// concrete, empirically-motivated reason the indirect commit rule
    /// is next, not a hypothetical roadmap item.
    #[test]
    fn certificate_broadcast_loss_alone_stays_safe_but_liveness_needs_the_indirect_commit_rule() {
        let fault = FaultPolicy { drop_rate: 0.0, cert_drop_rate: Some(0.35), max_delay_ticks: 0, partition: None };
        let scenario = Scenario { validator_count: 4, byzantine: HashMap::new(), fault, ticks: 300, rotation: None };
        for seed in 0..5 {
            let report = run_simulation(&scenario, seed);
            assert!(report.safety_violation.is_none(), "seed {seed}: {:?}", report.safety_violation);
            assert!(report.made_progress, "seed {seed}: expected at least some progress, got counts {:?}", report.honest_committed_counts);
        }
    }

    /// Documentation test, not a guarantee: beyond the f < n/3 bound
    /// (here, 2 of 4 Byzantine - f=2 when the bound only tolerates f=1),
    /// safety is explicitly *not* claimed by this protocol family (see
    /// `ARCHITECTURE.md` §1 and `blockchain-security-audit`). This test
    /// only asserts the harness can express such a scenario, not that it
    /// stays safe - if it happens to stay safe for a given seed, that's
    /// not a property to rely on.
    #[test]
    fn beyond_the_fault_bound_is_out_of_scope_for_the_safety_guarantee() {
        let mut byzantine = HashMap::new();
        byzantine.insert(0, ByzantineBehavior::Equivocator);
        byzantine.insert(1, ByzantineBehavior::Equivocator);
        let scenario = Scenario { validator_count: 4, byzantine, fault: FaultPolicy::default(), ticks: 50, rotation: None };
        // No safety assertion here on purpose - f=2 of n=4 exceeds f<n/3.
        let _report = run_simulation(&scenario, 42);
    }

    /// **`#194` — membership-change / rotation DST under certificate loss.**
    ///
    /// The whole propose/vote/certify/commit state machine crosses a real
    /// epoch boundary where the committee *rotates* — validator 0 leaves and
    /// validator 4 joins (indices {0,1,2,3} → {1,2,3,4}, three overlap) — all
    /// while certificate broadcasts are being dropped and delayed. This is the
    /// assurance the audit (`#194`) asked for: the phase-3.3 rotation was only
    /// ever verified *live* (v4.1.0/v4.2.2), never in the DST, because the
    /// harness modeled a single fixed committee. It now threads a real
    /// `ValidatorSchedule` (see `validator.rs`), so this exercises end-to-end,
    /// under adversarial message loss, the two consensus fixes that make
    /// rotation safe and were themselves found the hard way:
    ///   - **v4.0.3** (`direct_status` weighs round `r+1` support under
    ///     `for_round(r+1)`): a departed validator can never certify `r+1`, so
    ///     counting its stake as "possible future support" would freeze the
    ///     boundary leader forever. Liveness across the boundary depends on it.
    ///   - **v4.0.4** (`walk_causal_history` commits a leader *atomically*): the
    ///     departed validator's last-round certificate can arrive late via
    ///     re-sync (exactly what `cert_drop_rate` + delay produce here); without
    ///     the atomic commit it could reorder a prefix two honest nodes already
    ///     committed → a fork. Asserted absent across a seed sweep.
    ///
    /// Non-vacuous: `rotation_liveness_sweep` asserts every seed actually
    /// committed a round `>= epoch_rounds` (i.e. under the *new* committee), so
    /// "stayed safe" is never true only because the sim never rotated. This runs
    /// a real seed sweep at the mild liveness budget where the boundary reliably
    /// crosses (the leader schedule is now deterministic, so this is stable, not
    /// flaky — see the module determinism note and the #2 CLAUDE.md entry). The
    /// harsh-loss SAFETY guarantee is a separate, larger sweep below.
    #[test]
    fn a_committee_rotation_across_an_epoch_boundary_under_cert_loss_stays_safe() {
        rotation_liveness_sweep(rotation_scenario(), 5, 32);
    }

    /// **`#194` — committee SHRINK across an epoch boundary under cert loss.**
    ///
    /// The harder rotation case and the one v4.0.3/v4.0.4 were specifically
    /// found for: the committee *shrinks* at the boundary (validator 0 leaves,
    /// {0,1,2,3} → {1,2,3}, quorum 3 → 2). A shrink is where "a departed
    /// validator's late certificate reorders an already-committed prefix" and
    /// "the boundary leader is held Undecided forever by a departed validator's
    /// phantom future support" actually bite. Seed sweep; safety holds and every
    /// seed crosses the boundary.
    #[test]
    fn a_committee_shrink_across_an_epoch_boundary_under_cert_loss_stays_safe() {
        rotation_liveness_sweep(shrink_scenario(), 4, 32);
    }

    /// **`#194`/#2 — SAFETY under HARSH certificate loss, hundreds of runs.**
    ///
    /// The mandatory-CI safety stress the #2 requirement asks for. Both the
    /// rotation and shrink shapes are swept over a large seed set at a harsh
    /// cert-loss rate (0.35) where liveness is *not* guaranteed — a leader can
    /// be permanently starved (the documented limit) — but SAFETY must hold on
    /// every single run: no two honest validators ever diverge. Because the
    /// leader schedule is now deterministic per `(round, committee)` and the
    /// re-sync emission order is insertion-ordered, a failure here is a real,
    /// reproducible protocol bug, never process-run noise. (The deep
    /// thousands-of-seeds version is `zzz_deep_rotation_safety_sweep`, `#[ignore]`d
    /// so normal CI stays fast; run it with `--ignored` for a soak.)
    #[test]
    fn rotation_and_shrink_stay_safe_under_harsh_cert_loss_over_a_large_seed_sweep() {
        rotation_safety_sweep(rotation_scenario(), 5, 64);
        rotation_safety_sweep(shrink_scenario(), 4, 64);
    }

    /// Opt-in soak (thousands of seeds) — the "cientos o miles de veces" deep
    /// run. `#[ignore]`d so it never slows normal CI; run explicitly with
    /// `cargo test -p qchain-simulation --release -- --ignored`. Asserts the
    /// same strict SAFETY guarantee over a much larger sweep, plus that the mild
    /// liveness budget crosses the boundary every time over hundreds of seeds.
    #[test]
    #[ignore]
    fn zzz_deep_rotation_safety_sweep() {
        rotation_safety_sweep(rotation_scenario(), 5, 1000);
        rotation_safety_sweep(shrink_scenario(), 4, 1000);
        rotation_liveness_sweep(rotation_scenario(), 5, 300);
        rotation_liveness_sweep(shrink_scenario(), 4, 300);
    }
}
