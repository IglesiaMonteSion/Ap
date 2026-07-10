//! Phase-1 testnet validator binary: loads a `NodeConfig`, joins the fixed
//! validator set over real TCP, and runs the Narwhal-Bullshark
//! propose/vote/certify/commit loop (`engine.rs`) alongside a JSON-RPC
//! server (`rpc.rs`) for wallet traffic. See `ARCHITECTURE.md` §1/§4 and
//! the `blockchain-core-rust` skill.

mod config;
mod engine;
mod rpc;

use clap::Parser;
use config::NodeConfig;
use engine::{Engine, EngineState};
use qchain_consensus::{ConsensusState, DagStore, ValidatorInfo, ValidatorSet};
use qchain_execution::{
    genesis_params_account_data, genesis_registry_account_data, GovernanceProgram, Ledger, Program, StakingProgram, SystemProgram,
    GOVERNANCE_PROGRAM_ID, PARAMS_ACCOUNT_ID, REGISTRY_ACCOUNT_ID, STAKING_PROGRAM_ID, STAKING_STATS_ID,
};
use qchain_network::{Network, PeerInfo};
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
    } else {
        tracing::info!("reusing persisted state from a prior run; skipping genesis seeding");
    }

    let engine = Arc::new(Engine {
        self_id,
        keypair,
        validators,
        network,
        state: tokio::sync::Mutex::new(EngineState {
            ledger,
            dag: DagStore::new(),
            consensus: ConsensusState::new(),
            mempool: HashMap::new(),
            batches: HashMap::new(),
            pending_votes: HashMap::new(),
            own_pending_vertex: None,
            next_round,
            round_checkpoint_path,
            executed: 0,
            voted_for: HashMap::new(),
        }),
    });

    {
        let engine = engine.clone();
        tokio::spawn(async move {
            while let Some((from, msg)) = rx.recv().await {
                let engine = engine.clone();
                tokio::spawn(async move { engine.handle_message(from, msg).await });
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
            }
        });
    }

    tracing::info!("qchain-node {self_id} up: p2p={}, rpc={}", config.listen_addr, config.rpc_addr);
    let app = rpc::router(engine);
    let listener = tokio::net::TcpListener::bind(config.rpc_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
