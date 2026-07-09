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
    genesis_registry_account_data, GovernanceProgram, Ledger, Program, StakingProgram, SystemProgram, GOVERNANCE_PROGRAM_ID,
    REGISTRY_ACCOUNT_ID, STAKING_PROGRAM_ID, STAKING_STATS_ID,
};
use qchain_network::{Network, PeerInfo};
use qchain_storage::InMemoryStore;
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

    let mut ledger = Ledger::new(Box::new(InMemoryStore::new()))?;
    ledger.register_program(qchain_crypto::Pubkey::system_program_id(), Program::Native(Box::new(SystemProgram)));
    ledger.register_program(STAKING_PROGRAM_ID, Program::Native(Box::new(StakingProgram)));
    ledger.register_program(GOVERNANCE_PROGRAM_ID, Program::Native(Box::new(GovernanceProgram)));
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

    let engine = Arc::new(Engine {
        self_id,
        keypair,
        validators,
        network,
        state: tokio::sync::Mutex::new(EngineState {
            ledger,
            dag: DagStore::new(),
            consensus: ConsensusState::new(),
            mempool: Vec::new(),
            batches: HashMap::new(),
            pending_votes: HashMap::new(),
            own_pending_vertex: None,
            next_round: 0,
            executed: 0,
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
