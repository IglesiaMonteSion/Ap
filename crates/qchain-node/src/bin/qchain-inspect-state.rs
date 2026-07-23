//! `qchain-inspect-state` — read-only pre-upgrade state inspector (pre-mainnet #8).
//!
//! Opens a node's on-disk state WITHOUT modifying it and reports what an upgrade
//! would find: the chain id / fingerprint, the format+decodability of every
//! critical singleton (especially the validator registry — V2 / migratable-V1 /
//! corrupt), the live supply and pool balances, the treasury configuration, and a
//! final verdict on whether the next binary would START or HALT. The point is to
//! catch an incompatibility BEFORE restarting a live network, so an operator
//! never bricks a chain by discovering a format problem only at boot.
//!
//! Usage: `qchain-inspect-state --config node.json`

use borsh::BorshDeserialize;
use qchain_crypto::{Pubkey, RegistryEntry};
use qchain_execution::ids;
use qchain_node::config::NodeConfig;
use qchain_storage::{RedbStore, SledStore, StateStore};

fn open_ro(dir: &std::path::Path, engine: &str) -> anyhow::Result<Box<dyn StateStore>> {
    match engine {
        "redb" => {
            let redb_path = dir.join("state.redb");
            if redb_path.exists() {
                Ok(Box::new(RedbStore::open(&redb_path)?))
            } else if dir.join("db").exists() {
                // A network configured for redb but still holding legacy sled state
                // (an upgrade would migrate it). Read the sled state for the report.
                println!("  NOTE: storage_engine=redb but state is still in legacy sled (an upgrade migrates sled->redb).");
                Ok(Box::new(SledStore::open(dir)?))
            } else {
                anyhow::bail!("no state found under {} (neither state.redb nor sled db)", dir.display());
            }
        }
        _ => Ok(Box::new(SledStore::open(dir)?)),
    }
}

fn main() -> anyhow::Result<()> {
    let mut config_path: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-c" => config_path = args.next(),
            "-h" | "--help" => {
                println!("Usage: qchain-inspect-state --config <node.json>\n\nRead-only inspection of a node's on-disk state before an upgrade. Never modifies state.");
                return Ok(());
            }
            other => anyhow::bail!("unexpected argument {other:?} (use --config <node.json>)"),
        }
    }
    let config_path = config_path.ok_or_else(|| anyhow::anyhow!("missing --config <node.json>"))?;
    let config: NodeConfig = serde_json::from_slice(&std::fs::read(&config_path)?)?;

    println!("== qchain-inspect-state (READ-ONLY) ==");
    println!("config: {config_path}");
    println!("chain_id: {}", hex::encode(config.chain_id()));
    println!("network_fingerprint: {}", hex::encode(config.network_fingerprint()));
    println!("network_profile: {:?}", config.network_profile);
    println!("economics_v7: {}   hard_cap_supply: {}", config.economics_v7, config.hard_cap_supply);

    let dir = match &config.data_dir {
        Some(d) => d.clone(),
        None => {
            println!("\ndata_dir is not set (in-memory store) — nothing persisted to inspect.");
            return Ok(());
        }
    };
    let store = open_ro(&dir, &config.storage_engine)?;

    let get = |id: Pubkey| store.get(&id);
    let mut problems: Vec<String> = Vec::new();

    println!("\n-- critical singletons --");
    // A present-but-undecodable money/authority singleton would HALT the node.
    let mut check = |id: Pubkey, name: &str, ok: &dyn Fn(&[u8]) -> bool, required: bool| {
        match get(id) {
            None => {
                if required {
                    println!("  {name:<22} MISSING (required)  -> WOULD HALT");
                    problems.push(format!("{name} missing"));
                } else {
                    println!("  {name:<22} absent (ok — feature not enabled)");
                }
            }
            Some(a) if ok(&a.data) => println!("  {name:<22} present, decodes OK ({} bytes)", a.data.len()),
            Some(a) => {
                println!("  {name:<22} present but DOES NOT DECODE ({} bytes)  -> WOULD HALT", a.data.len());
                problems.push(format!("{name} corrupt"));
            }
        }
    };
    check(ids::PARAMS_ACCOUNT_ID, "PARAMS", &|d| qchain_execution::EconomicParams::read_or_legacy(d).is_some(), true);
    check(ids::REGISTRY_ACCOUNT_ID, "CRYPTO_REGISTRY", &|d| Vec::<RegistryEntry>::try_from_slice(d).is_ok(), true);
    if config.economics_v7 {
        check(ids::STAKING_GLOBAL_ID, "STAKING_GLOBAL", &|d| qchain_execution::staking_v7::GlobalStakingState::try_from_slice(d).is_ok(), true);
        check(ids::TREASURY_ACCOUNT_ID, "TREASURY", &|d| qchain_execution::treasury_v7::TreasuryState::try_from_slice(d).is_ok() || (d.len() == 32 && Pubkey::try_from_slice(d).is_ok()), false);
    }

    // The validator registry: report its FORMAT via the real production decoder.
    println!("\n-- validator registry (versioned) --");
    match get(ids::VALIDATOR_REGISTRY_ACCOUNT_ID) {
        None => {
            if config.economics_v7 {
                println!("  MISSING (required on a v7 network)  -> WOULD HALT");
                problems.push("validator registry missing".into());
            } else {
                println!("  absent (v6 network — ok)");
            }
        }
        Some(a) => {
            match qchain_execution::validator_v7::decode_registry(&a.data) {
                Some(reg) => {
                    // Distinguish V2 (decodes as current) from migratable V1.
                    let is_v2 = qchain_execution::validator_v7::ValidatorV7Registry::try_from_slice(&a.data).is_ok();
                    let fmt = if is_v2 { "V2 (current)" } else { "V1 legacy -> MIGRATES to V2 on read" };
                    println!("  format: {fmt} ({} bytes, {} validators)", a.data.len(), reg.validators.len());
                    for v in reg.validators.iter().take(20) {
                        println!("    - {} moniker={:?} state={:?} bond={}", v.address, v.moniker, v.state, v.bond);
                    }
                }
                None => {
                    println!("  format: UNRECOGNIZED / CORRUPT ({} bytes)  -> WOULD HALT (fail-loud)", a.data.len());
                    problems.push("validator registry corrupt/unknown-format".into());
                }
            }
        }
    }

    // Supply + pools (informational; the invariant is Σ balances vs the cap).
    println!("\n-- supply & pools --");
    let mut total: u128 = 0;
    let mut accounts = 0u64;
    for (_k, acc) in store.iter() {
        total = total.saturating_add(acc.balance as u128);
        accounts += 1;
    }
    println!("  accounts: {accounts}");
    println!("  Σ balances: {total} atoms ({} QCH)", total / 1_000_000_000);
    if config.hard_cap_supply {
        let cap = config.supply_cap_qch.unwrap_or(qchain_execution::economics_v7::MAX_SUPPLY_QCH) as u128 * 1_000_000_000u128;
        let within = total <= cap;
        println!("  hard cap: {} QCH — Σ balances {} the cap", cap / 1_000_000_000, if within { "<=" } else { "EXCEEDS" });
        if !within {
            problems.push("supply exceeds hard cap".into());
        }
    }
    for (id, name) in [
        (ids::TREASURY_ACCOUNT_ID, "treasury"),
        (ids::STAKING_RESERVE_ID, "staking_reserve"),
        (ids::VALIDATOR_FEE_POOL_ID, "validator_fee_pool"),
        (ids::VALIDATOR_BOND_ESCROW_ID, "bond_escrow"),
    ] {
        if let Some(a) = get(id) {
            println!("  {name:<20} {} QCH", a.balance / 1_000_000_000);
        }
    }

    // Treasury configuration from state (if a multisig is set up).
    if let Some(a) = get(ids::TREASURY_ACCOUNT_ID) {
        if let Ok(t) = qchain_execution::treasury_v7::TreasuryState::try_from_slice(&a.data) {
            println!("\n-- treasury multisig --");
            println!("  {}-of-{}  timelock={} rounds  max_per_release={} QCH  max_per_window={} QCH / {} rounds  pending_ops={}",
                t.threshold, t.signers.len(), t.timelock_rounds,
                t.max_per_release / 1_000_000_000, t.max_per_window / 1_000_000_000, t.window_rounds, t.pending.len());
            if t.threshold < 2 {
                println!("  WARNING: threshold < 2 (single point of control) — not mainnet-grade");
            }
        }
    }

    println!("\n== VERDICT ==");
    if problems.is_empty() {
        println!("  OK — the next binary would START on this state (all critical singletons decode or migrate).");
    } else {
        println!("  WOULD HALT — {} problem(s):", problems.len());
        for p in &problems {
            println!("    - {p}");
        }
        println!("  Do NOT upgrade until these are resolved (restore from backup / re-sync, or add the needed migration).");
        std::process::exit(2);
    }
    Ok(())
}
