mod genesis;
mod rpc;
mod state;

use clap::Parser;
use genesis::Genesis;
use state::{AppState, MetaFile};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use supersol_core::{
    Account, Block, Ledger, Poh, BASE_FEE_UNITS, MAX_RECENT_BLOCKS, STAKING_RESERVE_UNITS, TOTAL_SUPPLY_UNITS,
    TREASURY_ALLOCATION_UNITS, UNITS_PER_SSOL,
};
use supersol_crypto::{Keypair, Pubkey};

/// SuperSol validator node: ticks a Proof of History clock, applies
/// transactions to an in-memory account ledger, and serves a Solana-style
/// JSON-RPC API over HTTP. Deliberately lightweight to run: Proof of History
/// here is a single SHA-256 per tick (negligible CPU even on very modest
/// hardware), and persistence is O(1) per block rather than rewriting the
/// whole chain history every slot - see the README for real hardware
/// expectations.
#[derive(Parser)]
struct Args {
    /// Port to serve JSON-RPC on.
    #[arg(long, default_value_t = 8899)]
    rpc_port: u16,

    /// Directory holding this node's genesis record and ledger snapshot.
    #[arg(long, default_value = "./supersol-ledger")]
    ledger_dir: PathBuf,

    /// Milliseconds between Proof of History ticks. Each tick is one
    /// SHA-256 hash - cheap enough that this rarely needs tuning even on
    /// low-power hardware.
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

    /// Maximum units a single requestAirdrop call may disburse from the
    /// fixed-supply treasury.
    #[arg(long, default_value_t = 10 * UNITS_PER_SSOL)]
    faucet_max_units: u64,

    /// Flat fee (in base units) charged per transaction, paid to this
    /// validator. Defaults to a value about 10x lower than Solana's typical
    /// per-signature fee.
    #[arg(long, default_value_t = BASE_FEE_UNITS)]
    fee_units: u64,

    /// How many recent blocks to keep resident in memory (older blocks stay
    /// on disk in the append-only block log, just not cached in RAM). Lower
    /// this on very memory-constrained hardware.
    #[arg(long, default_value_t = MAX_RECENT_BLOCKS)]
    recent_blocks_window: usize,

    /// Number of slots per staking-reward epoch: every this many slots, the
    /// staking rewards reserve pays out to active stake accounts, pro-rata
    /// by stake. A placeholder cadence for this MVP - real calibration is a
    /// tokenomics decision, not something to trust a default for.
    #[arg(long, default_value_t = 200)]
    epoch_slots: u64,

    /// Units distributed from the staking rewards reserve per epoch (split
    /// pro-rata across active stakes), capped by the reserve's remaining
    /// balance. 0 disables staking rewards entirely.
    #[arg(long, default_value_t = 1_000 * UNITS_PER_SSOL)]
    reward_units_per_epoch: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    std::fs::create_dir_all(&args.ledger_dir)?;
    let genesis_path = args.ledger_dir.join("genesis.json");
    let accounts_path = args.ledger_dir.join("accounts.json");
    let meta_path = args.ledger_dir.join("meta.json");
    let blocks_log_path = args.ledger_dir.join("blocks.log");

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

    // Resuming an existing ledger only ever needs two small files - the
    // current account balances and a chain-tip checkpoint - never the full
    // block history, however long the chain has grown.
    let mut ledger = Ledger::new(genesis.poh_seed).with_recent_blocks_window(args.recent_blocks_window);
    let is_fresh_ledger = !meta_path.exists();
    if is_fresh_ledger {
        // The one and only place the fixed 700,000,000 SSOL supply is ever
        // created, and only on the very first boot of a brand new ledger:
        // split between the faucet-disbursable treasury and the staking
        // rewards reserve. Together they always sum to exactly
        // TOTAL_SUPPLY_UNITS.
        ledger.genesis_mint(Pubkey::treasury(), TREASURY_ALLOCATION_UNITS);
        ledger.genesis_mint(Pubkey::staking_rewards_pool(), STAKING_RESERVE_UNITS);
    } else {
        if accounts_path.exists() {
            let bytes = std::fs::read(&accounts_path)?;
            ledger.accounts = serde_json::from_slice::<HashMap<Pubkey, Account>>(&bytes)?;
        }
        let meta: MetaFile = serde_json::from_slice(&std::fs::read(&meta_path)?)?;
        ledger.slot = meta.slot;
        ledger.last_blockhash = meta.last_blockhash;
    }
    let resumed_slot = ledger.slot;

    let poh = Poh::new(genesis.poh_seed);

    let app_state = Arc::new(AppState {
        ledger: Mutex::new(ledger),
        poh: Mutex::new(poh),
        programs: supersol_runtime::default_program_registry(),
        pending_txs: Mutex::new(Vec::new()),
        pending_airdrops: Mutex::new(Vec::new()),
        pending_poh_entries: Mutex::new(Vec::new()),
        identity,
        faucet_enabled: args.enable_faucet,
        faucet_max_units: args.faucet_max_units,
        fee_units: args.fee_units,
        accounts_path,
        meta_path,
        blocks_log_path,
    });

    println!("SuperSol validator starting");
    println!("  identity:      {identity}");
    println!("  ledger dir:    {}", args.ledger_dir.display());
    println!("  resumed slot:  {resumed_slot}");
    {
        let ledger = app_state.ledger.lock().unwrap();
        println!(
            "  total supply:  {} SSOL (treasury: {} SSOL, staking pool: {} SSOL, burned: {} SSOL)",
            TOTAL_SUPPLY_UNITS / UNITS_PER_SSOL,
            ledger.get_balance(&Pubkey::treasury()) / UNITS_PER_SSOL,
            ledger.get_balance(&Pubkey::staking_rewards_pool()) / UNITS_PER_SSOL,
            ledger.total_burned / UNITS_PER_SSOL
        );
    }
    println!("  faucet:        {}", if args.enable_faucet { "enabled" } else { "disabled" });
    println!("  fee/tx:        {} photon (burned)", args.fee_units);
    println!(
        "  staking:       {} SSOL/epoch, every {} slots",
        args.reward_units_per_epoch / UNITS_PER_SSOL,
        args.epoch_slots
    );
    println!("  rpc endpoint:  http://127.0.0.1:{}", args.rpc_port);

    spawn_poh_ticker(app_state.clone(), args.tick_ms);
    spawn_block_producer(
        app_state.clone(),
        args.tick_ms * args.ticks_per_slot,
        args.epoch_slots,
        args.reward_units_per_epoch,
    );

    let app = rpc::router(app_state);
    let addr = SocketAddr::from(([0, 0, 0, 0], args.rpc_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Background thread producing the steady heartbeat of Proof of History
/// ticks, independent of whether any transactions arrive - this is what
/// lets the chain order events in time even during otherwise-idle periods.
/// Each tick is a single SHA-256 hash, so this thread's CPU footprint stays
/// negligible regardless of hardware.
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
/// an immutable, auditable Block and durably records it. Disk and memory
/// cost per iteration stay flat as the chain grows - see `AppState::persist_block`.
/// Also triggers staking-reward distribution once per epoch boundary.
fn spawn_block_producer(state: Arc<AppState>, slot_ms: u64, epoch_slots: u64, reward_units_per_epoch: u64) {
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
        let slot = state.slot() + 1;

        let block = Block {
            slot,
            leader: state.identity,
            previous_blockhash,
            blockhash,
            poh_entries: entries,
            transactions,
            airdrops,
        };

        {
            let mut ledger = state.ledger.lock().unwrap();
            ledger.push_block(block.clone());
            if epoch_slots > 0 && slot % epoch_slots == 0 {
                let distributed =
                    ledger.distribute_staking_rewards(supersol_crypto::Pubkey::staking_rewards_pool(), reward_units_per_epoch);
                if distributed > 0 {
                    println!(
                        "epoch at slot {slot}: distributed {} SSOL in staking rewards",
                        distributed / UNITS_PER_SSOL
                    );
                }
            }
        }

        if let Err(e) = state.persist_block(&block) {
            eprintln!("warning: failed to persist block/ledger snapshot: {e}");
        }
    });
}
