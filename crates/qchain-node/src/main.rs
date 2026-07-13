//! Phase-1 testnet validator binary: loads a `NodeConfig`, joins the fixed
//! validator set over real TCP, and runs the Narwhal-Bullshark
//! propose/vote/certify/commit loop (`engine.rs`) alongside a JSON-RPC
//! server (`rpc.rs`) for wallet traffic. See `ARCHITECTURE.md` §1/§4 and
//! the `blockchain-core-rust` skill.

use clap::Parser;
use qchain_consensus::{ConsensusState, DagStore, ValidatorInfo, ValidatorSet};
use qchain_execution::{
    genesis_params_account_data, genesis_registry_account_data, GovernanceProgram, Ledger, Program, RewardPoolData, StakingProgram, SystemProgram,
    GOVERNANCE_PROGRAM_ID, PARAMS_ACCOUNT_ID, REGISTRY_ACCOUNT_ID, STAKING_PROGRAM_ID, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID,
};
use qchain_network::{Network, PeerInfo};
use qchain_node::config::NodeConfig;
use qchain_node::engine::{Engine, EngineState};
use qchain_node::rpc;
use qchain_storage::{InMemoryStore, SledStore, StateStore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(about = "qchain phase-1 testnet validator")]
struct Cli {
    #[arg(short, long)]
    config: PathBuf,
}

/// Caps how many `handle_message` tasks may run concurrently - see the
/// real, live-confirmed unbounded-memory bug this closes where it's used,
/// below. Generous enough that legitimate concurrent traffic (this
/// session measured real throughput up to ~110 tx/s across 10 validators)
/// is never the limiting factor, while still bounding worst-case memory
/// under a real retry storm to a fixed, small multiple of one message's
/// size instead of "however large the pending backlog happens to grow."
const MAX_CONCURRENT_MESSAGE_HANDLERS: usize = 256;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let config = NodeConfig::load(&cli.config)?;

    let keypair = qchain_crypto::read_keypair_file(&config.keypair_path)?;
    let self_id = keypair.pubkey();

    let mut validator_infos = Vec::new();
    let mut peers = Vec::new();
    for v in &config.validators {
        let id = v.pubkey_bundle.to_address();
        validator_infos.push(ValidatorInfo { id, pubkey_bundle: v.pubkey_bundle.clone(), stake: v.stake });
        if id != self_id {
            peers.push(PeerInfo { id, addr: v.addr });
        }
    }
    if !validator_infos.iter().any(|v| v.id == self_id) {
        anyhow::bail!("this node's keypair ({self_id}) is not present in the configured validator set");
    }
    let validators = ValidatorSet::new(validator_infos);

    let (network, mut rx) = Network::start(self_id, config.listen_addr, peers).await?;
    let network = Arc::new(network);

    // A `SledStore` reopened at a path from a previous run already holds
    // real state (balances, registry, params, staking stats) - re-running
    // genesis seeding against it would double-credit `config.genesis`
    // allocations via `credit`'s additive balance update, and would
    // silently reset the registry/params/staking-stats accounts back to
    // their genesis contents via `seed_account`'s unconditional overwrite,
    // discarding any governance decisions made in a prior run. `is_fresh`
    // (empty store) is what actually distinguishes "first boot" from
    // "restart" - `InMemoryStore` is always fresh by construction.
    let store: Box<dyn StateStore> = match &config.data_dir {
        Some(dir) => Box::new(SledStore::open(dir)?),
        None => Box::new(InMemoryStore::new()),
    };
    let is_fresh = store.iter().next().is_none();

    // Real bug found while live-auditing the persistence work (see
    // `engine.rs`'s `propose_round` doc comment for the full story): the
    // account store isn't the only thing that needs to survive a restart.
    // A restarted node's own `next_round` must resume past every round
    // number it has ever used, or its first new proposal collides with
    // what its peers already remember voting for it - permanently, via the
    // equivocation lock, freezing not just this validator but (since
    // quorum needs support from all but a small Byzantine minority) the
    // whole network. `round_checkpoint_path` is `None` for an in-memory
    // node - nothing to restore, since it's always fresh next process
    // start anyway.
    let (round_checkpoint_path, next_round) = match &config.data_dir {
        Some(dir) => {
            let path = dir.join("round_checkpoint");
            let resumed = std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(0);
            (Some(path), resumed)
        }
        None => (None, 0),
    };

    let mut ledger = Ledger::new(store)?;
    ledger.register_program(qchain_crypto::Pubkey::system_program_id(), Program::Native(Box::new(SystemProgram)));
    ledger.register_program(STAKING_PROGRAM_ID, Program::Native(Box::new(StakingProgram)));
    ledger.register_program(GOVERNANCE_PROGRAM_ID, Program::Native(Box::new(GovernanceProgram)));
    if is_fresh {
        for alloc in &config.genesis {
            ledger.credit(alloc.address, alloc.balance);
        }
        // Phase-2 governance prerequisites (§6/§5 - see `qchain-execution`'s
        // `staking`/`governance` module docs): the staking-stats counter starts
        // at zero, and the algorithm registry starts at its genesis contents
        // (Ed25519 + ML-DSA-65, both Active).
        ledger.seed_account(
            STAKING_STATS_ID,
            qchain_core::Account { data: borsh::to_vec(&0u64)?, ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID) },
        );
        ledger.seed_account(
            REGISTRY_ACCOUNT_ID,
            qchain_core::Account { data: genesis_registry_account_data(), ..qchain_core::Account::new_wallet(GOVERNANCE_PROGRAM_ID) },
        );
        // Economic parameters (base fee, dust threshold, gas price) start at
        // their compiled-in defaults and become governable (Low-tier
        // proposals, no time-lock) from here - see `qchain-execution`'s
        // `params`/`governance` module docs.
        ledger.seed_account(
            PARAMS_ACCOUNT_ID,
            qchain_core::Account { data: genesis_params_account_data(), ..qchain_core::Account::new_wallet(GOVERNANCE_PROGRAM_ID) },
        );
        // Shared delegator staking-reward pool (`ARCHITECTURE.md` §5's
        // staking-rewards paragraph, `qchain-execution::staking`'s module
        // docs for the reward-per-share accrual mechanism): starts empty,
        // `balance` accrues from every transaction's fee split from here.
        ledger.seed_account(
            STAKING_REWARDS_POOL_ID,
            qchain_core::Account { data: borsh::to_vec(&RewardPoolData::default())?, ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID) },
        );
    } else {
        tracing::info!("reusing persisted state from a prior run; skipping genesis seeding");
    }

    // Real bug found live building this exact fix, one layer deeper than
    // the `propose_round` gate it pairs with: `ConsensusState::
    // resuming_from` is only safe to use when this validator's own stake
    // alone already meets quorum (the same condition `propose_round`
    // guards its fast path on) - in that case, and only that case, nobody
    // else could have certified anything while it was down, so whatever
    // it proposes after resuming genuinely has no real ancestor history
    // to walk. For a validator that is *not* dominant, its peers kept
    // producing real certificates the whole time, each carrying REAL
    // parent links reaching all the way back past this validator's
    // checkpoint round - `walk_causal_history` follows those parent links
    // regardless of where `extend_order`'s outer loop starts, so
    // `resuming_from(next_round)` doesn't skip that walk, it just makes
    // `seen` start empty right before the walk needs to redo it - and
    // unlike the round-by-round outer loop (which caches each round's
    // walk in `seen` incrementally, safe against `ConsensusState::new()`),
    // a `walk_causal_history` call that fails partway (an ancestor still
    // being resynced) caches *nothing*, so the whole multi-round walk
    // gets redone from scratch on every single incoming message during
    // resync - confirmed live: a real 3-validator testnet, stakes spread
    // evenly (no validator dominant), one validator restarted after a
    // real gap - CPU pinned at 200%+ and RSS climbing into the hundreds
    // of MB within seconds, RPC completely unresponsive, while the exact
    // same scenario with `ConsensusState::new()` recovered in under a
    // second. Falling back to `ConsensusState::new()` for the non-dominant
    // case costs nothing here - it's exactly what already worked before
    // this fix existed, and that path never even reaches `resuming_from`'s
    // added behavior in the first place.
    let consensus =
        if validators.stake_of(&self_id) >= validators.quorum_threshold() { ConsensusState::resuming_from(next_round) } else { ConsensusState::new() };

    // Task #107 - DAG persistence. Reload every certificate this validator
    // previously certified from local disk (`data_dir/dag`, a `sled` tree)
    // instead of re-fetching the whole chain from peers one certificate at a
    // time after a restart - the slow path a restart otherwise takes, since
    // `round_checkpoint` deliberately persists only `next_round`, not the
    // DAG (see `Engine::cert_log`). `None` for an in-memory node - nothing
    // to persist or reload. Re-execution of the transactions these
    // certificates carry is idempotent: `Ledger::apply_transaction`'s nonce
    // check rejects an already-applied transaction before charging any fee
    // or touching state, exactly as the pre-existing network-refetch restart
    // already relied on. A cert that fails to decode (corrupt on disk) is
    // skipped, not fatal - it is simply re-fetched from peers, exactly as
    // every cert was before DAG persistence existed.
    let cert_log: Option<sled::Db> = match &config.data_dir {
        Some(dir) => Some(sled::open(dir.join("dag"))?),
        None => None,
    };
    let mut dag = DagStore::new();
    if let Some(db) = &cert_log {
        let mut loaded = 0usize;
        for entry in db.iter() {
            let (_digest, bytes) = entry?;
            match borsh::from_slice::<qchain_core::Certificate>(&bytes) {
                Ok(cert) => {
                    dag.insert(cert);
                    loaded += 1;
                }
                Err(e) => tracing::warn!("skipping a corrupt certificate in the on-disk DAG log: {e}"),
            }
        }
        if loaded > 0 {
            tracing::info!("reloaded {loaded} certificates from the on-disk DAG log");
        }
    }

    let engine = Arc::new(Engine {
        self_id,
        keypair,
        validators,
        network,
        chain_id: config.chain_id(),
        cert_log,
        state: tokio::sync::Mutex::new(EngineState {
            ledger,
            dag,
            consensus,
            mempool: HashMap::new(),
            batches: HashMap::new(),
            batch_seen_round: HashMap::new(),
            pending_votes: HashMap::new(),
            own_pending_vertex: None,
            next_round,
            round_checkpoint_path,
            executed: 0,
            voted_for: HashMap::new(),
            pending_cert_requests: HashMap::new(),
            pending_batch_requests: HashMap::new(),
            pending_votes_to_send: HashMap::new(),
            own_last_certificate: None,
            first_seen_vertex: HashMap::new(),
            equivocation_evidence: HashMap::new(),
        }),
    });

    {
        let engine = engine.clone();
        // Real, live-confirmed unbounded-memory bug closed here: every
        // incoming message used to get its own `tokio::spawn`'d
        // `handle_message` task with no cap at all on how many could be
        // in flight concurrently. That's harmless at the tiny message
        // rates every earlier live test in this session exercised, but a
        // validator resyncing after a real gap of even a couple hundred
        // rounds (found investigating a *different* validator - one that
        // never restarted at all - spiking to multiple GB of RAM) drives
        // `retry_pending_resync_requests` to resend every still-pending
        // certificate/batch request on every single tick, unconditionally,
        // for as long as the backlog takes to resolve - and a backlog that
        // large takes many ticks. Each retry round adds another wave of
        // spawned tasks before the previous wave has finished (each one
        // contends on the same `state` mutex and does real ML-DSA-65
        // signature verification), so the number of simultaneously
        // in-flight tasks - each holding its own message payload - grows
        // without bound. Confirmed live with a counter: 300,000+ in-flight
        // tasks and climbing within seconds, matching the multi-GB RSS
        // observed independently. `MAX_CONCURRENT_MESSAGE_HANDLERS` caps
        // this directly; requests beyond the cap simply wait for a permit
        // instead of piling up as unbounded spawned tasks. This also
        // reduces read pressure on the bounded (4096) channel from
        // `Network::start`, which back-pressures the TCP read loop, which
        // back-pressures the sender's writes (`write_all().await` blocks
        // once the OS socket buffer fills) - the retry storm's own send
        // rate slows down for free once its peer stops draining fast
        // enough, no change needed to the retry logic itself.
        let message_handler_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_MESSAGE_HANDLERS));
        tokio::spawn(async move {
            while let Some((from, msg)) = rx.recv().await {
                let engine = engine.clone();
                let permit = message_handler_slots.clone().acquire_owned().await.expect("semaphore is never closed");
                tokio::spawn(async move {
                    engine.handle_message(from, msg).await;
                    drop(permit);
                });
            }
        });
    }

    {
        let engine = engine.clone();
        let interval = std::time::Duration::from_millis(config.round_interval_ms);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                engine.propose_round().await;
                engine.retry_pending_resync_requests().await;
                engine.prune_stale_round_state().await;
            }
        });
    }

    tracing::info!("qchain-node {self_id} up: p2p={}, rpc={}", config.listen_addr, config.rpc_addr);
    let app = rpc::router(engine);
    let listener = tokio::net::TcpListener::bind(config.rpc_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
