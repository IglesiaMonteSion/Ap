//! Coordinator tool for standing up a real multi-machine testnet: takes one
//! JSON "manifest" per participating validator (their public key bundle,
//! their own reachable `listen_addr`/`rpc_addr`, and their stake - nothing
//! secret, since a manifest never contains a private key) and merges them
//! into one shared validator set, then writes out one `NodeConfig` per
//! participant. Each participant still supplies their own `keypair.json`
//! locally (see `qchain keygen`) - the coordinator never sees or needs
//! private key material, only the public bundle each participant already
//! prints via `qchain bundle`.
//!
//! A manifest file looks like:
//! ```json
//! { "pubkey_bundle": { ... from `qchain bundle` ... },
//!   "listen_addr": "203.0.113.10:9000",
//!   "rpc_addr": "203.0.113.10:8080",
//!   "stake": 1000000,
//!   "name": "Validador Buenos Aires" }
//! ```
//! `name` is optional (a human-readable moniker wallets show when picking a
//! delegation target); omit it for a nameless validator.

use clap::Parser;
use qchain_node::config::{GenesisAllocation, NodeConfig, ValidatorConfig};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Merge per-validator manifests into a shared NodeConfig set for a real multi-machine testnet")]
struct Cli {
    /// Directory of manifest `*.json` files, one per validator - read in
    /// sorted filename order, which also determines `node1.json`,
    /// `node2.json`, ... output naming.
    #[arg(long)]
    manifests_dir: PathBuf,
    /// Optional JSON array of `{ "address": ..., "balance": ... }` genesis
    /// allocations (e.g. a faucet wallet, or pre-funded demo accounts).
    /// Omit for a genesis with no allocations at all.
    #[arg(long)]
    genesis: Option<PathBuf>,
    /// Directory to write `node1.json`, `node2.json`, ... into.
    #[arg(long)]
    out_dir: PathBuf,
    /// Milliseconds between round-advancement attempts. A real
    /// multi-region deployment has meaningfully more network latency than
    /// a single-host testnet - the default here is deliberately higher
    /// than `qchain-node`'s own same-host default (500ms) to leave real
    /// margin.
    #[arg(long, default_value_t = 1_000)]
    round_interval_ms: u64,
    /// Relative filename every output config expects its own keypair at -
    /// each participant places their own `keypair.json` (never generated
    /// or seen by this tool) next to the config file this tool hands them.
    #[arg(long, default_value = "keypair.json")]
    keypair_name: String,
    /// Relative directory every output config points `data_dir` at, for
    /// real on-disk persistence (`SledStore`) across restarts.
    #[arg(long, default_value = "data")]
    data_dir_name: String,
}

#[derive(Deserialize)]
struct ValidatorManifest {
    pubkey_bundle: qchain_crypto::PublicKeyBundle,
    listen_addr: SocketAddr,
    rpc_addr: SocketAddr,
    stake: u64,
    /// Optional human-readable moniker for this validator, carried into the
    /// shared config so wallets can show a named list. Absent = no name.
    #[serde(default)]
    name: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let mut manifest_paths: Vec<PathBuf> = std::fs::read_dir(&cli.manifests_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    manifest_paths.sort();
    if manifest_paths.is_empty() {
        anyhow::bail!("no *.json manifest files found in {}", cli.manifests_dir.display());
    }

    let manifests: Vec<ValidatorManifest> = manifest_paths
        .iter()
        .map(|p| -> anyhow::Result<ValidatorManifest> { Ok(serde_json::from_slice(&std::fs::read(p)?)?) })
        .collect::<anyhow::Result<_>>()?;

    // A real, live-confirmed permanent-freeze bug this closes (see
    // `qchain_consensus::quorum::ValidatorSet::new`'s doc comment and
    // `project-lessons-learned`): two manifests naming the same validator
    // identity - an honest copy-paste mistake between contributors, or a
    // malicious contributor duplicating someone else's already-public
    // bundle - inflates the quorum threshold past what real, unique-
    // validator votes could ever reach, freezing the whole network from
    // genesis. `ValidatorSet::new` itself no longer double-counts a
    // duplicate's stake, but catching it here, before any node ever
    // starts, gives a human-actionable error pointing at the exact
    // colliding manifest files instead of a silent, confusing freeze.
    let mut seen_addresses: std::collections::HashMap<qchain_crypto::Pubkey, &std::path::Path> = std::collections::HashMap::new();
    for (manifest, path) in manifests.iter().zip(manifest_paths.iter()) {
        let address = manifest.pubkey_bundle.to_address();
        if let Some(first_path) = seen_addresses.insert(address, path) {
            anyhow::bail!(
                "duplicate validator identity {address} in both {} and {} - each manifest must be a distinct validator, or this genesis would freeze the network at launch (see qchain_consensus::quorum::ValidatorSet)",
                first_path.display(),
                path.display()
            );
        }
    }

    let validators: Vec<ValidatorConfig> =
        manifests.iter().map(|m| ValidatorConfig { pubkey_bundle: m.pubkey_bundle.clone(), addr: m.listen_addr, stake: m.stake, name: m.name.clone() }).collect();

    let genesis: Vec<GenesisAllocation> = match &cli.genesis {
        Some(path) => serde_json::from_slice(&std::fs::read(path)?)?,
        None => Vec::new(),
    };

    std::fs::create_dir_all(&cli.out_dir)?;
    for (i, manifest) in manifests.iter().enumerate() {
        let config = NodeConfig {
            keypair_path: PathBuf::from(&cli.keypair_name),
            listen_addr: manifest.listen_addr,
            rpc_addr: manifest.rpc_addr,
            validators: validators.clone(),
            genesis: genesis.clone(),
            round_interval_ms: cli.round_interval_ms,
            data_dir: Some(PathBuf::from(&cli.data_dir_name)),
            state_sync_peers: Vec::new(),
            state_sync_trusted_root: None,
            state_sync_trusted_round: None,
            validator_rotation: false,
            epoch_rounds: None,
            compressed_state_tree: false,
        };
        let out_path = cli.out_dir.join(format!("node{}.json", i + 1));
        std::fs::write(&out_path, serde_json::to_string_pretty(&config)?)?;
        println!("{} -> validator {} (listen {}, rpc {}) [from {}]", out_path.display(), manifest.pubkey_bundle.to_address(), manifest.listen_addr, manifest.rpc_addr, manifest_paths[i].display());
    }

    println!(
        "\nWrote {} node config(s) to {}. Send each nodeN.json to the matching participant - they place it next to their own {} and a {}/ directory, then run: qchain-node --config nodeN.json",
        manifests.len(),
        cli.out_dir.display(),
        cli.keypair_name,
        cli.data_dir_name
    );
    Ok(())
}
