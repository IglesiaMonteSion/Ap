mod genesis;
mod rpc;
mod state;

use clap::Parser;
use genesis::Genesis;
use supersol_core::{Block, Ledger, Poh, BASE_FEE_UNITS, UNITS_PER_SSOL};
use supersol_crypto::Keypair;
use state::AppState;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// SuperSol validator node: ticks a Proof of History clock, applies
/// transactions to an in-memory account ledger, and serves a Solana-style
/// JSON-RPC API over HTTP.
#[derive(Parser)]
struct Args {
    /// Port to serve JSON-RPC on.
    #[arg(long, default_value_t = 8899)]
    rpc_port: u16,

    /// Directory holding this node's genesis record and ledger snapshot.
    #[arg(long, default_value = "./supersol-ledger")]
    ledger_dir: PathBuf,

    /// Milliseconds between Proof of History ticks.
    #[arg(long, default_value_t = 50)]
    tick_ms: u64,

    /// Number of ticks per slot (block production interval = tick_ms * ticks_per_slot).
    #[arg(long, default_value_t = 20)]
    ticks_per_slot: u64,

    /// Keypair file identifying this validator. If omitted, an ephemeral
    /// identity is generated for this run only (fine for local testing, not
    /// for a persistent node).
    #[arg(long)]
    identity: Option<PathBuf>,

    /// Enable the devnet faucet's `requestAirdrop` RPC method. Never enable
    /// this on a network meant to hold real value.
    #[arg(long)]
    enable_faucet: bool,

    /// Maximum units a single requestAirdrop call may mint.
    #[arg(long, default_value_t = 10 * UNITS_PER_SSOL)]
    faucet_max_units: u64,

    /// Flat fee (in base units) charged per transaction, paid to this
    /// validator. Defaults to a value about 10x lower than Solana's typical
    /// per-signature fee.
    #[arg(long, default_value_t = BASE_FEE_UNITS)]
    fee_units: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    std::fs::create_dir_all(&args.ledger_dir)?;
    let genesis_path = args.ledger_dir.join("genesis.json");
    let ledger_path = args.ledger_dir.join("ledger.json");

    let genesis = Genesis::load_or_create(&genesis_path)?;

    let identity_keypair = match &args.identity {
        Some(path) if path.exists() => supersol_crypto::read_keypair_file(path)?,
        Some(path) => {
            let kp = Keypair::generate();
            supersol_crypto::write_keypair_file(&kp, path)?;
            println!("Generated new validator identity at {}", path.display());
            kp
        }
        None => {
            println!("No --identity given: using an ephemeral validator identity for this run only.");
            Keypair::generate()
        }
    };
    let identity = identity_keypair.pubkey();

    let ledger: Ledger = if ledger_path.exists() {
        let bytes = std::fs::read(&ledger_path)?;
        serde_json::from_slice(&bytes)?
    } else {
        Ledger::new()
    };
    let resumed_slot = ledger.blocks.last().map(|b| b.slot).unwrap_or(0);

    let poh = Poh::new(genesis.poh_seed);

    let app_state = Arc::new(AppState {
        ledger: Mutex::new(ledger),
        poh: Mutex::new(poh),
        programs: supersol_runtime::default_program_registry(),
        pending_txs: Mutex::new(Vec::new()),
        pending_airdrops: Mutex::new(Vec::new()),
        pending_poh_entries: Mutex::new(Vec::new()),
        slot: Mutex::new(resumed_slot),
        genesis_seed: genesis.poh_seed,
        identity,
        faucet_enabled: args.enable_faucet,
        faucet_max_units: args.faucet_max_units,
        fee_units: args.fee_units,
        ledger_path: ledger_path.clone(),
    });

    println!("SuperSol validator starting");
    println!("  identity:      {identity}");
    println!("  ledger dir:    {}", args.ledger_dir.display());
    println!("  resumed slot:  {resumed_slot}");
    println!("  faucet:        {}", if args.enable_faucet { "enabled" } else { "disabled" });
    println!("  fee/tx:        {} photon", args.fee_units);
    println!("  rpc endpoint:  http://127.0.0.1:{}", args.rpc_port);

    spawn_poh_ticker(app_state.clone(), args.tick_ms);
    spawn_block_producer(app_state.clone(), args.tick_ms * args.ticks_per_slot);

    let app = rpc::router(app_state);
    let addr = SocketAddr::from(([0, 0, 0, 0], args.rpc_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Background thread producing the steady heartbeat of Proof of History
/// ticks, independent of whether any transactions arrive - this is what
/// lets the chain order events in time even during otherwise-idle periods.
fn spawn_poh_ticker(state: Arc<AppState>, tick_ms: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(tick_ms));
        let entry = {
            let mut poh = state.poh.lock().unwrap();
            poh.tick()
        };
        state.pending_poh_entries.lock().unwrap().push(entry);
    });
}

/// Background thread that periodically packages everything that happened
/// since the last slot boundary (ticks, applied transactions, airdrops) into
/// an immutable, auditable Block and persists a ledger snapshot to disk.
fn spawn_block_producer(state: Arc<AppState>, slot_ms: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(slot_ms.max(1)));

        let entries = std::mem::take(&mut *state.pending_poh_entries.lock().unwrap());
        let transactions = std::mem::take(&mut *state.pending_txs.lock().unwrap());
        let airdrops = std::mem::take(&mut *state.pending_airdrops.lock().unwrap());

        if entries.is_empty() && transactions.is_empty() && airdrops.is_empty() {
            continue;
        }

        let previous_blockhash = state.latest_blockhash();
        let blockhash = entries.last().map(|e| e.hash).unwrap_or(previous_blockhash);

        let mut slot_guard = state.slot.lock().unwrap();
        *slot_guard += 1;
        let slot = *slot_guard;
        drop(slot_guard);

        let block = Block {
            slot,
            leader: state.identity,
            previous_blockhash,
            blockhash,
            poh_entries: entries,
            transactions,
            airdrops,
        };

        state.ledger.lock().unwrap().push_block(block);

        if let Err(e) = state.persist() {
            eprintln!("warning: failed to persist ledger snapshot: {e}");
        }
    });
}
