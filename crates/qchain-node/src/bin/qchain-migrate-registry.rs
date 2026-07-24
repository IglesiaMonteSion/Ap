//! `qchain-migrate-registry` — offline, atomic, reversible migration of the
//! validator registry to the current (V2) schema (pre-mainnet #3).
//!
//! Background: the running node migrates a legacy V1 registry to V2 ON READ
//! (`validator_v7::decode_registry`) and only PERSISTS the V2 form when the next
//! registry-mutating instruction (bond/exit/…) commits. A network with no
//! registry churn — e.g. a single validator — therefore re-migrates on every
//! read forever and never cleans up its on-disk bytes. This tool performs that
//! persistence explicitly, safely, and reversibly, with a dry-run preview, a
//! backup, and a rollback.
//!
//! FORK SAFETY — READ THIS FIRST. Rewriting the registry V1→V2 changes the
//! registry account's bytes, hence its Merkle leaf, hence the state root. On a
//! SINGLE-VALIDATOR network this is safe at any time (no peer to diverge from).
//! On a MULTI-NODE network it MUST be coordinated: STOP every node, run
//! `--apply` on every node, RESTART every node — otherwise a migrated node forks
//! from un-migrated peers. The migration is deterministic (every node writes
//! byte-identical V2), so a coordinated cutover converges. The node must be
//! STOPPED in all cases (the store needs exclusive access).
//!
//! Usage:
//!   qchain-migrate-registry --config node.json                 # dry-run (default), read-only
//!   qchain-migrate-registry --config node.json --apply --yes   # migrate (backs up first)
//!   qchain-migrate-registry --config node.json --rollback <backup.bak>

use borsh::BorshDeserialize;
use qchain_core::Account;
use qchain_execution::ids;
use qchain_execution::validator_v7::{decode_registry, detect_registry_schema, plan_registry_migration, RegistryMigration};
use qchain_node::config::NodeConfig;
use qchain_storage::{RedbStore, SledStore, StateStore};
use sha3::{Digest, Sha3_256};

fn open_store(dir: &std::path::Path, engine: &str) -> anyhow::Result<Box<dyn StateStore>> {
    match engine {
        "redb" => {
            let redb_path = dir.join("state.redb");
            if redb_path.exists() {
                Ok(Box::new(RedbStore::open(&redb_path)?))
            } else if dir.join("db").exists() {
                println!("  NOTE: storage_engine=redb but state is still in legacy sled (migrating the sled registry; the node's sled->redb migration carries it forward).");
                Ok(Box::new(SledStore::open(dir)?))
            } else {
                anyhow::bail!("no state found under {} (neither state.redb nor sled db)", dir.display());
            }
        }
        _ => Ok(Box::new(SledStore::open(dir)?)),
    }
}

fn short_hash(bytes: &[u8]) -> String {
    let h: [u8; 32] = Sha3_256::digest(bytes).into();
    hex::encode(&h[..8])
}

struct Args {
    config: String,
    apply: bool,
    yes: bool,
    backup: Option<String>,
    rollback: Option<String>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut config = None;
    let mut apply = false;
    let mut yes = false;
    let mut backup = None;
    let mut rollback = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-c" => config = args.next(),
            "--apply" => apply = true,
            "--yes" | "-y" => yes = true,
            "--backup" => backup = args.next(),
            "--rollback" => rollback = args.next(),
            "-h" | "--help" => {
                println!(
                    "Usage: qchain-migrate-registry --config <node.json> [--apply --yes] [--backup <file>] [--rollback <file>]\n\n\
                     Offline, reversible migration of the validator registry to the current (V2) schema.\n\
                     Default is a READ-ONLY dry-run. STOP the node first (the store needs exclusive access).\n\n\
                     FORK SAFETY: rewriting V1->V2 changes the registry account bytes -> the state root.\n\
                     Single-validator: safe any time. Multi-node: coordinated only (stop all, apply all, restart all)."
                );
                std::process::exit(0);
            }
            other => anyhow::bail!("unexpected argument {other:?} (use --help)"),
        }
    }
    Ok(Args {
        config: config.ok_or_else(|| anyhow::anyhow!("missing --config <node.json>"))?,
        apply,
        yes,
        backup,
        rollback,
    })
}

fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    let config: NodeConfig = serde_json::from_slice(&std::fs::read(&args.config)?)?;

    println!("== qchain-migrate-registry ==");
    println!("config: {}", args.config);
    let chain_id_hex = hex::encode(config.chain_id());
    println!("chain_id: {chain_id_hex}");

    let dir = match &config.data_dir {
        Some(d) => d.clone(),
        None => {
            println!("\ndata_dir is not set (in-memory store) — nothing persisted to migrate.");
            return Ok(());
        }
    };
    let reg_id = ids::VALIDATOR_REGISTRY_ACCOUNT_ID;

    // --- rollback path ---
    if let Some(backup_path) = &args.rollback {
        let bytes = std::fs::read(backup_path)?;
        let acct = Account::try_from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("backup file {backup_path} is not a valid Account: {e}"))?;
        if decode_registry(&acct.data).is_none() {
            anyhow::bail!("backup {backup_path} does not hold a decodable registry — refusing to restore corrupt state");
        }
        println!("\n-- rollback --");
        println!("  restoring registry account from {backup_path} ({} bytes, data hash {})", acct.data.len(), short_hash(&acct.data));
        {
            let mut store = open_store(&dir, &config.storage_engine)?;
            store.set(reg_id, acct.clone());
            store.flush()?;
        }
        // Verify the restore is durable + decodable.
        let store = open_store(&dir, &config.storage_engine)?;
        let restored = store.get(&reg_id).ok_or_else(|| anyhow::anyhow!("registry account vanished after rollback"))?;
        if restored.data != acct.data || decode_registry(&restored.data).is_none() {
            anyhow::bail!("rollback verification FAILED — the store does not hold the backed-up registry");
        }
        println!("  OK — rolled back and verified ({} bytes, hash {}).", restored.data.len(), short_hash(&restored.data));
        return Ok(());
    }

    // --- read the current registry + plan ---
    let store = open_store(&dir, &config.storage_engine)?;
    let acct = match store.get(&reg_id) {
        Some(a) => a,
        None => {
            if config.economics_v7 {
                println!("\nVALIDATOR_REGISTRY is MISSING on a v7 network — that is a fail-loud HALT condition, not something to migrate.");
                println!("Restore from a good backup / re-sync a fresh data_dir before starting the node.");
                std::process::exit(2);
            }
            println!("\nVALIDATOR_REGISTRY is absent (this is a v6 network) — nothing to migrate.");
            return Ok(());
        }
    };
    let old_data = acct.data.clone();
    println!("\n-- current registry --");
    match detect_registry_schema(&old_data) {
        Some(s) => println!("  schema_version: {} ({})", s.version(), s),
        None => println!("  schema_version: UNKNOWN (corrupt)"),
    }
    println!("  size: {} bytes   data hash: {}", old_data.len(), short_hash(&old_data));

    let plan = plan_registry_migration(&old_data);
    let new_bytes = match plan {
        RegistryMigration::AlreadyCurrent { validators } => {
            println!("\n== ALREADY CURRENT (V2) — {validators} validator(s). Nothing to migrate. ==");
            return Ok(());
        }
        RegistryMigration::Corrupt => {
            println!("\n== CORRUPT — the registry bytes match no known schema. ==");
            println!("Refusing to migrate (fail-loud). Restore from a good backup / re-sync a fresh data_dir.");
            std::process::exit(2);
        }
        RegistryMigration::Migrated { validators, new_bytes } => {
            println!("\n-- migration plan: V1 (legacy) -> V2 (current) --");
            println!("  {validators} validator(s); operator = withdrawal = the consensus address (pre-role-separation).");
            println!("  new size: {} bytes   new data hash: {}", new_bytes.len(), short_hash(&new_bytes));
            new_bytes
        }
    };

    // Fork-safety reminder, always printed before any write is even considered.
    println!("\n  ⚠ This REWRITES the registry account on disk (V1->V2) → changes the registry account");
    println!("    hash → the state root. Single-validator: safe. MULTI-NODE: coordinated only");
    println!("    (stop ALL nodes, --apply on ALL, restart ALL) or a migrated node forks from its peers.");

    if !args.apply {
        println!("\n== DRY-RUN (no changes written). Re-run with `--apply --yes` to persist the migration. ==");
        return Ok(());
    }
    if !args.yes {
        println!("\n--apply requires --yes (this changes on-disk state). Aborting without writing anything.");
        std::process::exit(1);
    }
    drop(store); // release the read handle before reopening read-write

    // --- backup the OLD registry account (for rollback) ---
    let backup_path = args
        .backup
        .clone()
        .unwrap_or_else(|| dir.join(format!("registry-backup-{}-{}.bak", &chain_id_hex[..8], short_hash(&old_data))).to_string_lossy().into_owned());
    if std::path::Path::new(&backup_path).exists() {
        anyhow::bail!("backup file {backup_path} already exists — refusing to overwrite; pass a different --backup or remove it");
    }
    let backup_blob = borsh::to_vec(&acct)?;
    std::fs::write(&backup_path, &backup_blob)?;
    println!("\n  backup of the current registry account written to {backup_path} ({} bytes)", backup_blob.len());

    // --- apply: write V2, flush, drop, then reopen and VERIFY ---
    {
        let mut store = open_store(&dir, &config.storage_engine)?;
        let mut new_acct = acct.clone();
        new_acct.data = new_bytes.clone();
        store.set(reg_id, new_acct);
        store.flush()?; // atomic + durable (single-account commit)
    }
    let store = open_store(&dir, &config.storage_engine)?;
    let after = store.get(&reg_id).ok_or_else(|| anyhow::anyhow!("registry account vanished after write"))?;
    let ok = after.data == new_bytes
        && matches!(detect_registry_schema(&after.data), Some(qchain_execution::validator_v7::RegistrySchema::V3Current))
        && decode_registry(&after.data).is_some();
    if !ok {
        drop(store);
        eprintln!("\n  VERIFY FAILED — restoring from backup {backup_path}");
        let mut store = open_store(&dir, &config.storage_engine)?;
        store.set(reg_id, acct.clone());
        store.flush()?;
        anyhow::bail!("migration verification failed; the store was restored from the backup. No change persisted.");
    }

    println!("\n== MIGRATED — persisted V2 registry ({} validators, {} bytes, hash {}). ==",
        decode_registry(&after.data).map(|r| r.validators.len()).unwrap_or(0),
        after.data.len(),
        short_hash(&after.data));
    println!("  Rollback if needed:  qchain-migrate-registry --config {} --rollback {backup_path}", args.config);
    println!("  MULTI-NODE: do this on every node while ALL are stopped, then restart them together.");
    Ok(())
}
