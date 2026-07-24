//! End-to-end test of the `qchain-migrate-registry` binary (pre-mainnet #3):
//! seed a real sled store with a genuinely legacy V1 registry, then drive the
//! ACTUAL built tool through dry-run → apply → rollback → re-apply, asserting
//! the on-disk schema at each step. Exercises the full store plumbing (open /
//! set / flush / reopen), the backup, and the reversibility.

use borsh::BorshDeserialize;
use qchain_core::Account;
use qchain_crypto::Keypair;
use qchain_execution::ids;
use qchain_execution::validator_v7::{detect_registry_schema, legacy_v1_registry_bytes, RegistrySchema};
use qchain_storage::{SledStore, StateStore};
use std::process::Command;

const TOOL: &str = env!("CARGO_BIN_EXE_qchain-migrate-registry");

/// Read the registry account's schema from the store, releasing the sled lock
/// before returning (so the tool can open it next). Retries the open briefly:
/// sled holds an advisory file lock that the just-exited tool subprocess may not
/// have released the instant `.output()` returned.
fn registry_schema(data_dir: &std::path::Path) -> Option<RegistrySchema> {
    let mut last_err = None;
    for _ in 0..50 {
        match SledStore::open(data_dir) {
            Ok(store) => {
                let acct = store.get(&ids::VALIDATOR_REGISTRY_ACCOUNT_ID).expect("registry present");
                return detect_registry_schema(&acct.data);
            }
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
    panic!("could not open store after retries: {last_err:?}");
}

fn run(cfg: &str, args: &[&str]) -> std::process::Output {
    Command::new(TOOL).arg("--config").arg(cfg).args(args).output().expect("tool runs")
}

#[test]
fn migrate_registry_tool_migrates_v1_to_v2_and_rolls_back() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let backup = tmp.path().join("reg.bak");

    // Seed a genuinely legacy V1 registry into a real sled store.
    let v = Keypair::generate().unwrap();
    let v1_bytes = legacy_v1_registry_bytes(v.pubkey(), "legacy", v.public_key_bundle(), "1.2.3.4:9000");
    {
        let mut store = SledStore::open(&data_dir).unwrap();
        let mut acct = Account::new_wallet(ids::STAKING_PROGRAM_ID);
        acct.data = v1_bytes.clone();
        store.set(ids::VALIDATOR_REGISTRY_ACCOUNT_ID, acct);
        store.flush().unwrap();
    }
    assert_eq!(registry_schema(&data_dir), Some(RegistrySchema::V1Legacy), "seeded as V1");

    // Minimal config the tool can deserialize (only data_dir/storage_engine/
    // economics_v7 matter here; keypair_path need not exist).
    let cfg_path = tmp.path().join("node.json");
    let cfg = serde_json::json!({
        "keypair_path": tmp.path().join("kp.json"),
        "listen_addr": "127.0.0.1:9101",
        "rpc_addr": "127.0.0.1:8080",
        "validators": [],
        "data_dir": data_dir,
        "storage_engine": "sled",
        "economics_v7": true,
    });
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    let cfg_str = cfg_path.to_str().unwrap();

    // 1) Dry-run (default): reports V1 + plan, writes NOTHING.
    let out = run(cfg_str, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "dry-run exits 0: {stdout}");
    assert!(stdout.contains("schema_version: 1"), "dry-run reports V1: {stdout}");
    assert!(stdout.contains("DRY-RUN"), "dry-run says so: {stdout}");
    assert_eq!(registry_schema(&data_dir), Some(RegistrySchema::V1Legacy), "dry-run changed nothing");

    // 2) --apply WITHOUT --yes: refuses, writes nothing (exit 1).
    let out = run(cfg_str, &["--apply", "--backup", backup.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "apply without --yes aborts");
    assert!(!backup.exists(), "no backup written on abort");
    assert_eq!(registry_schema(&data_dir), Some(RegistrySchema::V1Legacy), "abort changed nothing");

    // 3) --apply --yes: backs up, migrates to V4, verifies.
    let out = run(cfg_str, &["--apply", "--yes", "--backup", backup.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "apply exits 0: {stdout}");
    assert!(stdout.contains("MIGRATED"), "apply reports success: {stdout}");
    assert!(backup.exists(), "backup written");
    assert_eq!(registry_schema(&data_dir), Some(RegistrySchema::V4Current), "persisted V4");

    // The backup holds the original V1 account (rollback source).
    let backup_acct = Account::try_from_slice(&std::fs::read(&backup).unwrap()).unwrap();
    assert_eq!(backup_acct.data, v1_bytes, "backup is the original V1 registry");

    // 4) Re-apply is a safe no-op (already V4).
    let out = run(cfg_str, &["--apply", "--yes", "--backup", tmp.path().join("reg2.bak").to_str().unwrap()]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("ALREADY CURRENT"), "re-apply is a no-op");

    // 5) Rollback restores V1.
    let out = run(cfg_str, &["--rollback", backup.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "rollback exits 0: {stdout}");
    assert!(stdout.contains("rolled back"), "rollback reports success: {stdout}");
    assert_eq!(registry_schema(&data_dir), Some(RegistrySchema::V1Legacy), "rolled back to V1");
}

#[test]
fn migrate_registry_tool_refuses_corrupt_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    {
        let mut store = SledStore::open(&data_dir).unwrap();
        let mut acct = Account::new_wallet(ids::STAKING_PROGRAM_ID);
        acct.data = vec![0xFFu8; 9]; // matches no known schema
        store.set(ids::VALIDATOR_REGISTRY_ACCOUNT_ID, acct);
        store.flush().unwrap();
    }
    let cfg_path = tmp.path().join("node.json");
    let cfg = serde_json::json!({
        "keypair_path": tmp.path().join("kp.json"),
        "listen_addr": "127.0.0.1:9101",
        "rpc_addr": "127.0.0.1:8080",
        "validators": [],
        "data_dir": data_dir,
        "storage_engine": "sled",
        "economics_v7": true,
    });
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

    // Corrupt → fail-loud (exit 2), never guesses/migrates.
    let out = run(cfg_path.to_str().unwrap(), &["--apply", "--yes"]);
    assert_eq!(out.status.code(), Some(2), "corrupt registry is fail-loud");
    assert!(String::from_utf8_lossy(&out.stdout).contains("CORRUPT"));
}
