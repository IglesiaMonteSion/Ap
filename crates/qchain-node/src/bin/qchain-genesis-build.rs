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
    /// Start the network with the COMPRESSED state tree (`compressed_state_tree:
    /// true`) instead of the legacy 256-deep tree. This is a network-wide,
    /// genesis-level hard-fork choice folded into the `chain_id`: EVERY node must
    /// use the same value, and it can only be chosen when a network is FIRST
    /// created (you cannot convert a running chain - the state root changes).
    /// ~6x higher apply throughput and lower RAM/disk under load; see the
    /// compressed-tree notes. Off by default (the legacy tree).
    #[arg(long, default_value_t = false)]
    compressed_state_tree: bool,
    /// Run the AUTHENTICATED P2P transport (`authenticated_transport: true`): a
    /// per-connection mutual ML-DSA handshake so only real validators of this
    /// network can connect and no one can spoof a validator at the transport
    /// layer. Unlike the two flags above this is NOT folded into `chain_id`
    /// (it's a network-layer choice, not consensus/state), but it IS
    /// wire-breaking, so every node must use the same value and turning it on
    /// is a coordinated cutover. Off by default.
    #[arg(long, default_value_t = false)]
    authenticated_transport: bool,
    /// Also ENCRYPT the authenticated P2P transport (`encrypted_transport: true`):
    /// an ML-KEM-768 exchange inside the handshake so every message is AEAD-
    /// encrypted and the channel is bound into the signed transcript (closes the
    /// on-path relay gap). Requires `--authenticated-transport`. Like it, NOT
    /// folded into `chain_id` but wire-breaking → coordinated cutover, same value
    /// on every node. Off by default.
    #[arg(long, default_value_t = false)]
    encrypted_transport: bool,
    /// Start the network with the v7 ECONOMICS (`economics_v7: true`): shares+index
    /// staking, per-quanto emission, the 45/45/10 fee split, the 500 QCH validator
    /// bond. Like `--compressed-state-tree` this is a network-wide, genesis-level
    /// hard-fork choice folded into the `chain_id`: EVERY node must use the same
    /// value, and it can only be chosen when a network is FIRST created. Off by
    /// default (the v6 economics).
    #[arg(long, default_value_t = false)]
    economics_v7: bool,
    /// Rounds per reward quanto for a v7 network (`rounds_per_quanto`). Omitted
    /// uses the standard default; exposed so a test network can use a small value
    /// to cross a quanto boundary quickly. Only meaningful with `--economics-v7`.
    #[arg(long)]
    rounds_per_quanto: Option<u64>,
    /// The per-quanto compounding rate (fixed-point, scale 1e18), for a v7
    /// network. Omitted (the default) BAKES the value computed ONCE on this build
    /// machine into every config — the critical mitigation for the f64 derivation
    /// (`(1+apy)^(1/quantos_per_year)`), which is NOT bit-identical across
    /// platforms (glibc/musl/x86/aarch64). If it were left unbaked, two validators
    /// of the same network on different architectures would each re-derive it and
    /// get a different value → a different `chain_id` and a diverging on-chain
    /// staking index → fork. Override only to pin an exact integer. Only meaningful
    /// with `--economics-v7`.
    #[arg(long)]
    quanto_rate_fp: Option<u128>,
    /// (v7) base58 address allowed to release the genesis-locked treasury. With
    /// `--treasury-qch`, mints that many QCH LOCKED into the treasury account at
    /// genesis; only a `Release` signed by this authority moves them. Folded into
    /// the `chain_id`. Only meaningful with `--economics-v7`.
    #[arg(long)]
    treasury_authority: Option<String>,
    /// (v7) how much QCH to lock in the genesis treasury (converted to units:
    /// 1 QCH = 1e9). Requires `--treasury-authority`. Max 9223372036 QCH.
    #[arg(long)]
    treasury_qch: Option<u64>,
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

    if cli.encrypted_transport && !cli.authenticated_transport {
        anyhow::bail!("--encrypted-transport requires --authenticated-transport (encryption without authentication is meaningless)");
    }

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

    // Validate the genesis allocations before anyone launches (audit hardening):
    // a DUPLICATE address would be silently SUMMED by `ledger.credit` (additive),
    // and an address equal to a reserved singleton (System Program, the v7 pool
    // ids, the phase-3 governance/staking singletons) would be credited and then
    // OVERWRITTEN by the singleton seeding — its funds vanishing. Reject both with
    // an actionable error, same spirit as the duplicate-manifest check.
    {
        use std::collections::HashSet;
        let reserved: Vec<(qchain_crypto::Pubkey, &str)> = vec![
            (qchain_crypto::Pubkey::system_program_id(), "System Program"),
            (qchain_execution::STAKING_PROGRAM_ID, "STAKING_PROGRAM"),
            (qchain_execution::STAKING_STATS_ID, "STAKING_STATS"),
            (qchain_execution::GOVERNANCE_PROGRAM_ID, "GOVERNANCE_PROGRAM"),
            (qchain_execution::REGISTRY_ACCOUNT_ID, "REGISTRY"),
            (qchain_execution::PARAMS_ACCOUNT_ID, "PARAMS"),
            (qchain_execution::STAKING_REWARDS_POOL_ID, "STAKING_REWARDS_POOL"),
            (qchain_execution::VALIDATOR_REGISTRY_ACCOUNT_ID, "VALIDATOR_REGISTRY"),
            (qchain_execution::ids::VALIDATOR_BOND_ESCROW_ID, "VALIDATOR_BOND_ESCROW"),
            (qchain_execution::ids::STAKING_RESERVE_ID, "STAKING_RESERVE"),
            (qchain_execution::ids::VALIDATOR_FEE_POOL_ID, "VALIDATOR_FEE_POOL"),
            (qchain_execution::ids::STAKING_UNBONDING_POOL_ID, "STAKING_UNBONDING_POOL"),
            (qchain_execution::ids::VALIDATOR_UNBONDING_POOL_ID, "VALIDATOR_UNBONDING_POOL"),
            (qchain_execution::ids::STAKING_GLOBAL_ID, "STAKING_GLOBAL"),
            (qchain_execution::ids::ADMIN_FEE_WALLET, "ADMIN_FEE_WALLET"),
        ];
        let mut seen: HashSet<qchain_crypto::Pubkey> = HashSet::new();
        for a in &genesis {
            if !seen.insert(a.address) {
                anyhow::bail!("duplicate genesis allocation for {} — two entries for the same address would be silently summed", a.address);
            }
            if let Some((_, name)) = reserved.iter().find(|(id, _)| *id == a.address) {
                anyhow::bail!("genesis allocation to the reserved singleton {name} ({}) — it would be overwritten by seeding and the funds lost; remove it", a.address);
            }
        }
    }

    // Bake the per-quanto rate ONCE on this machine (audit fix for the cross-arch
    // f64 fork): resolve it here and write `Some(...)` into every config, so every
    // node — whatever its platform — reads the SAME integer instead of each
    // re-deriving it via non-bit-identical `f64::powf`.
    let baked_rate_fp: Option<u128> = if cli.economics_v7 {
        Some(cli.quanto_rate_fp.unwrap_or_else(|| {
            qchain_execution::economics_v7::derive_quanto_rate_fp(
                qchain_execution::economics_v7::STAKING_TARGET_APY_BPS,
                qchain_execution::economics_v7::DEFAULT_QUANTOS_PER_YEAR,
            )
        }))
    } else {
        None
    };

    // Resolve the genesis treasury (v7): validate the authority is a real address
    // and the QCH amount is present + in range, then convert QCH → units (1e9).
    let (treasury_authority, treasury_amount): (Option<String>, Option<u64>) = match (&cli.treasury_authority, cli.treasury_qch) {
        (Some(auth), Some(qch)) => {
            if !cli.economics_v7 {
                anyhow::bail!("--treasury-authority/--treasury-qch require --economics-v7");
            }
            auth.parse::<qchain_crypto::Pubkey>()
                .map_err(|e| anyhow::anyhow!("--treasury-authority is not a valid base58 address: {e}"))?;
            if qch > 9_223_372_036 {
                anyhow::bail!("--treasury-qch too large (max 9223372036 QCH)");
            }
            (Some(auth.clone()), Some(qch.saturating_mul(1_000_000_000)))
        }
        (None, None) => (None, None),
        _ => anyhow::bail!("--treasury-authority and --treasury-qch must be given together"),
    };

    std::fs::create_dir_all(&cli.out_dir)?;
    let mut shared_chain_id: Option<[u8; 32]> = None;
    for (i, manifest) in manifests.iter().enumerate() {
        let config = NodeConfig {
            keypair_path: PathBuf::from(&cli.keypair_name),
            listen_addr: manifest.listen_addr,
            rpc_addr: manifest.rpc_addr,
            validators: validators.clone(),
            genesis: genesis.clone(),
            round_interval_ms: cli.round_interval_ms,
            // Network-wide genesis choice (folded into chain_id) - same for every node.
            compressed_state_tree: cli.compressed_state_tree,
            data_dir: Some(PathBuf::from(&cli.data_dir_name)),
            state_sync_peers: Vec::new(),
            state_sync_trusted_root: None,
            state_sync_trusted_round: None,
            validator_rotation: false,
            epoch_rounds: None,
            storage_engine: "sled".to_string(),
            authenticated_transport: cli.authenticated_transport,
            encrypted_transport: cli.encrypted_transport,
            economics_v7: cli.economics_v7,
            quanto_rate_fp: baked_rate_fp,
            rounds_per_quanto: cli.rounds_per_quanto,
            treasury_authority: treasury_authority.clone(),
            treasury_amount,
            rpc_rate_limit_per_10s: None,
            remote_signer: None,
        };
        // Every output config shares the same validators+genesis (+ folded genesis
        // flags), so they all resolve to the identical chain_id — the network's
        // identity. Compute it once and confirm it never differs between configs.
        let cid = config.chain_id();
        match shared_chain_id {
            None => shared_chain_id = Some(cid),
            Some(prev) => assert_eq!(prev, cid, "all configs must share one chain_id"),
        }
        let out_path = cli.out_dir.join(format!("node{}.json", i + 1));
        std::fs::write(&out_path, serde_json::to_string_pretty(&config)?)?;
        println!("{} -> validator {} (listen {}, rpc {}) [from {}]", out_path.display(), manifest.pubkey_bundle.to_address(), manifest.listen_addr, manifest.rpc_addr, manifest_paths[i].display());
    }

    let cid_hex = hex::encode(shared_chain_id.unwrap_or([0u8; 32]));
    println!(
        "\nWrote {} node config(s) to {}. Send each nodeN.json to the matching participant - they place it next to their own {} and a {}/ directory, then run: qchain-node --config nodeN.json",
        manifests.len(),
        cli.out_dir.display(),
        cli.keypair_name,
        cli.data_dir_name
    );
    // The network's identity. In a COORDINATED relaunch every operator must build
    // from the SAME manifests+genesis+flags and confirm this exact value — a
    // mismatch means two operators built different networks that will not
    // interoperate (they would fork). Cross-check it against every running node's
    // `GET /chain_id` after launch.
    println!("\nchain_id: {cid_hex}");
    if cli.economics_v7 {
        println!("economics: v7 ENABLED (rounds_per_quanto={}) — a hard-forked network, distinct from any v6 chain.", cli.rounds_per_quanto.map(|r| r.to_string()).unwrap_or_else(|| "default".into()));
        println!("quanto_rate_fp: {} (BAKED into every config — identical on every platform, no f64 re-derivation)", baked_rate_fp.unwrap_or(0));
        if let (Some(auth), Some(units)) = (&treasury_authority, treasury_amount) {
            println!("treasury: {} QCH ({units} units) LOCKED in genesis, release authority {auth} (only a signed Release moves it) — folded into the chain_id.", units / 1_000_000_000);
        }
    }
    if cli.compressed_state_tree {
        println!("state tree: COMPRESSED — folded into the chain_id above.");
    }
    println!("EVERY validator of this network must build from the same manifests + genesis + flags and see this SAME chain_id, or the network will fork.");
    Ok(())
}
