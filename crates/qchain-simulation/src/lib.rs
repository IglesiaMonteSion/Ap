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
//! Honest scope note: validator keypairs come from the OS CSPRNG (via
//! `qchain_crypto::Keypair::generate`), not the scenario's seed - liboqs's
//! `oqs` bindings don't expose a pluggable RNG hook (see
//! `pqc-cryptography`), so full determinism down to key material isn't
//! achievable without patching that binding. What *is* fully seeded and
//! reproducible is everything the safety/liveness properties actually
//! depend on: the fault-injection schedule (which messages drop, delay,
//! or get partitioned) and the resulting event interleaving. A scenario
//! that fails is a structural protocol failure, not a key-dependent
//! fluke - rerunning it (even with fresh keys) reproduces the same
//! outcome.

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
    /// Extra ticks (0..=max) a surviving message may be delayed, chosen
    /// uniformly per message.
    pub max_delay_ticks: u64,
    /// Two validator-index groups and the tick until which any message
    /// crossing between them is dropped, modeling a network partition
    /// that heals at that tick.
    pub partition: Option<(Vec<usize>, Vec<usize>, u64)>,
}

pub struct Scenario {
    pub validator_count: usize,
    /// Validator index -> non-default behavior. Absent indices are
    /// `ByzantineBehavior::Honest`.
    pub byzantine: HashMap<usize, ByzantineBehavior>,
    pub fault: FaultPolicy,
    pub ticks: u64,
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

    let mut ids: Vec<ValidatorId> = Vec::new();
    let mut sims: Vec<SimValidator> = Vec::new();
    let mut infos: Vec<ValidatorInfo> = Vec::new();
    for i in 0..scenario.validator_count {
        let kp = Keypair::generate().expect("keypair generation should not fail");
        let id = kp.pubkey();
        let behavior = scenario.byzantine.get(&i).copied().unwrap_or(ByzantineBehavior::Honest);
        infos.push(ValidatorInfo { id, pubkey_bundle: kp.public_key_bundle(), stake: 1 });
        ids.push(id);
        sims.push(SimValidator::new(id, kp, behavior));
    }
    let validators = ValidatorSet::new(infos);

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
            if scenario.fault.drop_rate > 0.0 && rng.gen::<f64>() < scenario.fault.drop_rate {
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
            let outgoing = sims[i].maybe_propose(&validators, &peers);
            for (to_id, msg) in outgoing {
                let to_idx = ids.iter().position(|x| *x == to_id).unwrap();
                if let SimMessage::CertificateBroadcast(cert) = &msg {
                    certified.entry((cert.vertex.round, cert.vertex.author)).or_default().insert(cert.vertex.digest());
                }
                enqueue(&mut queue, &mut seq, tick, i, to_idx, msg, &mut rng);
            }
        }

        let due_keys: Vec<(u64, u64)> = queue.range(..=(tick, u64::MAX)).map(|(k, _)| *k).collect();
        for key in due_keys {
            let Some((from, to, msg)) = queue.remove(&key) else { continue };
            let peers: Vec<ValidatorId> = (0..scenario.validator_count).filter(|&j| j != to).map(|j| ids[j]).collect();
            let outgoing = sims[to].handle_message(ids[from], msg, &validators, &peers);
            for (to_id, out_msg) in outgoing {
                let to_idx = ids.iter().position(|x| *x == to_id).unwrap();
                if let SimMessage::CertificateBroadcast(cert) = &out_msg {
                    certified.entry((cert.vertex.round, cert.vertex.author)).or_default().insert(cert.vertex.digest());
                }
                enqueue(&mut queue, &mut seq, tick, to, to_idx, out_msg, &mut rng);
            }
            sims[to].try_commit(&validators);
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

    SimReport { safety_violation, equivocation_succeeded, honest_committed_counts, made_progress }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_network_no_faults_converges_safely_and_makes_progress() {
        let scenario = Scenario { validator_count: 4, byzantine: HashMap::new(), fault: FaultPolicy::default(), ticks: 60 };
        let report = run_simulation(&scenario, 1);
        assert!(report.safety_violation.is_none(), "{:?}", report.safety_violation);
        assert!(report.made_progress);
    }

    #[test]
    fn honest_network_under_message_loss_and_delay_stays_safe() {
        let fault = FaultPolicy { drop_rate: 0.2, max_delay_ticks: 3, partition: None };
        let scenario = Scenario { validator_count: 4, byzantine: HashMap::new(), fault, ticks: 150 };
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
        let scenario = Scenario { validator_count: 4, byzantine, fault: FaultPolicy::default(), ticks: 80 };
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
        let scenario = Scenario { validator_count: 4, byzantine, fault: FaultPolicy::default(), ticks: 80 };
        for seed in 0..3 {
            let report = run_simulation(&scenario, seed);
            assert!(report.equivocation_succeeded.is_none(), "seed {seed}: {:?}", report.equivocation_succeeded);
            assert!(report.safety_violation.is_none(), "seed {seed}: {:?}", report.safety_violation);
        }
    }

    #[test]
    fn a_healing_partition_still_reaches_safety_and_resumes_progress() {
        // Split 4 validators 2-2 for the first 30 ticks (neither side has
        // quorum alone - 2 < quorum_threshold of 3), then heal.
        let fault = FaultPolicy { drop_rate: 0.0, max_delay_ticks: 0, partition: Some((vec![0, 1], vec![2, 3], 30)) };
        let scenario = Scenario { validator_count: 4, byzantine: HashMap::new(), fault, ticks: 100 };
        let report = run_simulation(&scenario, 3);
        assert!(report.safety_violation.is_none());
        assert!(report.made_progress, "progress must resume once the partition heals");
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
        let scenario = Scenario { validator_count: 4, byzantine, fault: FaultPolicy::default(), ticks: 50 };
        // No safety assertion here on purpose - f=2 of n=4 exceeds f<n/3.
        let _report = run_simulation(&scenario, 42);
    }
}
