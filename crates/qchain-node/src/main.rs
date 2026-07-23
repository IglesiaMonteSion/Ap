//! Phase-1 testnet validator binary: loads a `NodeConfig`, joins the fixed
//! validator set over real TCP, and runs the Narwhal-Bullshark
//! propose/vote/certify/commit loop (`engine.rs`) alongside a JSON-RPC
//! server (`rpc.rs`) for wallet traffic. See `ARCHITECTURE.md` §1/§4 and
//! the `blockchain-core-rust` skill.

use anyhow::Context;
use clap::Parser;
use qchain_consensus::{ConsensusState, DagStore, ValidatorInfo, ValidatorSchedule, ValidatorSet};
use qchain_execution::{
    genesis_params_account_data, genesis_registry_account_data, Ledger, RewardPoolData,
    GOVERNANCE_PROGRAM_ID, PARAMS_ACCOUNT_ID, REGISTRY_ACCOUNT_ID, STAKING_PROGRAM_ID, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, VALIDATOR_REGISTRY_ACCOUNT_ID,
};
use qchain_network::{Network, PeerInfo};
use qchain_node::config::NodeConfig;
use qchain_node::engine::{Engine, EngineState};
use qchain_node::rpc;
use qchain_storage::{InMemoryStore, RedbStore, SledStore, StateStore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

mod state_sync;

/// Opens the account state store for the configured engine. `"sled"` (default)
/// is the original path, completely unchanged. `"redb"` opens the modern
/// `RedbStore` at `data_dir/state.redb`; if the `data_dir` still holds a legacy
/// sled state (its `db` marker file present) and no redb file exists yet, the
/// sled state is migrated into redb once, with a verification that the migrated
/// account set is byte-for-byte identical - the sled files are kept as a backup.
fn open_state_store(dir: &std::path::Path, engine: &str) -> anyhow::Result<Box<dyn StateStore>> {
    match engine {
        "redb" => {
            std::fs::create_dir_all(dir)?;
            let redb_path = dir.join("state.redb");
            let legacy_sled_present = dir.join("db").exists();
            if !redb_path.exists() && legacy_sled_present {
                migrate_sled_to_redb(dir, &redb_path)?;
            }
            Ok(Box::new(RedbStore::open(&redb_path)?))
        }
        // Default (and any unrecognized value, defensively) is the original sled.
        other => {
            if other != "sled" {
                tracing::warn!("unknown storage_engine {other:?}, falling back to sled");
            }
            Ok(Box::new(SledStore::open(dir)?))
        }
    }
}

/// One-time migration of a legacy `sled` account state into a fresh `redb` file,
/// verified: every account is copied and the resulting redb account set must be
/// identical to the sled one, or the migration aborts (the node refuses to start
/// rather than run on a partially-migrated state). The sled files are left in
/// place as a backup - nothing is deleted.
fn migrate_sled_to_redb(dir: &std::path::Path, redb_path: &std::path::Path) -> anyhow::Result<()> {
    tracing::info!("migrating legacy sled state at {} into redb...", dir.display());
    let sled = SledStore::open(dir)?;
    let sled_accounts: Vec<_> = sled.iter().collect();
    {
        let mut redb = RedbStore::open(redb_path)?;
        for (k, v) in &sled_accounts {
            redb.set(*k, v.clone());
        }
        redb.flush().map_err(|e| anyhow::anyhow!("migration flush into redb failed: {e}"))?;
    }
    // Verify: reopen the redb file fresh and compare its account set to sled's.
    let redb = RedbStore::open(redb_path)?;
    let mut s = sled_accounts;
    let mut r: Vec<_> = redb.iter().collect();
    s.sort_by_key(|(k, _)| k.to_bytes());
    r.sort_by_key(|(k, _)| k.to_bytes());
    if s != r {
        anyhow::bail!(
            "sled->redb migration mismatch at {}: migrated {} accounts but the verified redb set differs - refusing to start on a bad migration (the sled state is untouched)",
            dir.display(),
            r.len()
        );
    }
    tracing::info!("migrated {} accounts from sled to redb (verified identical); sled files kept as backup", r.len());
    Ok(())
}

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

/// QCH-3.1 / S10 (tarea #188): endurecer el proceso ANTES de leer la clave del
/// validador — deshabilitar core dumps (para que un crash/OOM no vuelque la
/// clave privada a un archivo), y best-effort `mlockall` para que las páginas
/// con secretos no vayan a swap. Linux-only; best-effort (loguea si no puede,
/// no aborta — p.ej. `mlockall` suele fallar bajo `RLIMIT_MEMLOCK` bajo).
#[cfg(target_os = "linux")]
fn harden_process() {
    // Deshabilitar core dumps: RLIMIT_CORE = 0 + PR_SET_DUMPABLE = 0.
    unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) != 0 {
            tracing::warn!("no se pudo deshabilitar core dumps (RLIMIT_CORE)");
        }
        // PR_SET_DUMPABLE=0: el proceso no es volcable (ni ptrace de otro usuario).
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            tracing::warn!("no se pudo setear PR_SET_DUMPABLE=0");
        }
        // Best-effort: fijar todas las páginas en RAM (evita swap de secretos).
        // Falla común bajo RLIMIT_MEMLOCK bajo → solo se loguea.
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            tracing::info!("mlockall no disponible (RLIMIT_MEMLOCK); core dumps sí deshabilitados");
        } else {
            tracing::info!("process hardening: core dumps OFF + páginas fijadas en RAM (mlockall)");
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn harden_process() {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    harden_process();
    let cli = Cli::parse();
    let config = NodeConfig::load(&cli.config)?;

    // Consensus signer (tarea #193). `remote_signer` in the config selects an
    // out-of-process remote/HSM signer that holds the block-signing key, so it
    // never lives in this (internet-facing) process; `None` (the default) reads
    // the key in-process from `keypair_path`, byte-identical to before. Either
    // way the identity (self_id) is the SAME validator key — a local↔remote
    // migration needs no re-registration and does not change `chain_id`.
    let signer: Arc<dyn qchain_crypto::Signer> = match &config.remote_signer {
        Some(endpoint) => {
            let rs = qchain_remote_signer::RemoteSigner::connect(endpoint)
                .with_context(|| format!("cannot connect to the remote signer at {endpoint}"))?;
            tracing::info!(
                "consensus signer: REMOTE at {endpoint} — the block-signing key is NOT in this node process (#193)"
            );
            Arc::new(rs) as Arc<dyn qchain_crypto::Signer>
        }
        None => {
            let kp = qchain_crypto::read_keypair_file(&config.keypair_path)?;
            Arc::new(kp) as Arc<dyn qchain_crypto::Signer>
        }
    };
    let self_id = signer.bundle().to_address();

    let mut validator_infos = Vec::new();
    let mut peers = Vec::new();
    let mut validator_directory = Vec::new();
    // #193-B: consensus-id → cold withdrawal address, derived from the config
    // (folded into chain_id when any is set → all nodes build the same map → no
    // fork). A validator's fee commission is credited to its withdrawal address
    // instead of its consensus id, so a compromised consensus key can't spend it.
    let mut withdrawal_map: std::collections::HashMap<qchain_core::ValidatorId, qchain_crypto::Pubkey> = std::collections::HashMap::new();
    for v in &config.validators {
        let id = v.pubkey_bundle.to_address();
        validator_infos.push(ValidatorInfo { id, pubkey_bundle: v.pubkey_bundle.clone(), stake: v.stake });
        validator_directory.push(qchain_node::engine::ValidatorDirEntry { address: id, name: v.name.clone(), stake: v.stake });
        if let Some(w) = v.withdrawal_address {
            withdrawal_map.insert(id, w);
        }
        if id != self_id {
            peers.push(PeerInfo { id, addr: v.addr });
        }
    }
    // Where THIS node's own fee earnings land (its withdrawal address if set,
    // else its consensus id) — used to report its own balance/commission.
    let self_fee_dest = withdrawal_map.get(&self_id).copied().unwrap_or(self_id);
    // A fixed-membership node MUST be in its own configured validator set. A
    // rotation node need not be: a genuine newcomer joins by staking and
    // registering on-chain, so it runs with the *genesis* validators as its
    // config (to bootstrap P2P connectivity + the epoch-0 committee, identical
    // to everyone else's) without being one of them, and enters the active
    // committee once the registry-derived set includes it (stage-3 discovery).
    if !config.validator_rotation && !validator_infos.iter().any(|v| v.id == self_id) {
        anyhow::bail!("this node's keypair ({self_id}) is not present in the configured validator set");
    }
    let validators = ValidatorSet::new(validator_infos);

    // Keep the config mesh so the phase-3.3 rotation ratchet can union it with
    // the current committee's registry addresses (stage-3 peer discovery).
    let config_peers = peers.clone();
    // Authenticated transport (task #176), opt-in via `authenticated_transport`.
    // The authorized set starts as every configured validator id; a rotation
    // node's ratchet later widens it to the registry committee (kept in
    // lock-step with `set_peers` — see the epoch ratchet in `engine`). Binds
    // `chain_id`, so a validator from a different network can't even connect.
    // Encryption requires authentication (there is no verified peer to bind an
    // encrypted channel to otherwise). Reject a misconfiguration loudly rather
    // than silently ignoring the flag.
    // MAINNET posture (task #208): auth + encryption are MANDATORY. Fail-stop at
    // startup (never silently run a mainnet with a plaintext/unauthenticated P2P
    // transport). No-op for a testnet (`mainnet` false, the default).
    config.validate_mainnet_transport()?;

    // MANDATORY MAINNET PROFILE (task #211): when `network_profile: "mainnet"`
    // (or the legacy `mainnet: true`), REFUSE TO START unless every hard
    // production protection is present — data_dir, redb, auth+encrypted P2P,
    // remote signer, a private validator RPC, a state-sync trust anchor, explicit
    // RPC limits, and explicit v7 economics. Accumulates ALL missing pieces into
    // one clear error. No-op for a testnet (the default). Log the network
    // fingerprint so an operator can confirm every node shares the SAME config.
    config.validate_network_profile()?;
    if config.is_mainnet_profile() {
        tracing::info!(
            "network_profile: MAINNET — all hard protections satisfied. network fingerprint: {} (MUST be identical on every node)",
            hex::encode(config.network_fingerprint())
        );
    }
    if config.encrypted_transport && !config.authenticated_transport {
        anyhow::bail!("encrypted_transport requires authenticated_transport (encryption without authentication is meaningless)");
    }
    let auth = if config.authenticated_transport {
        let authorized: std::collections::HashSet<_> =
            config.validators.iter().map(|v| v.pubkey_bundle.to_address()).collect();
        if config.encrypted_transport {
            tracing::info!("authenticated + ENCRYPTED P2P transport: ENABLED (ML-DSA handshake + ML-KEM-768 channel, ChaCha20-Poly1305)");
        } else {
            tracing::info!("authenticated P2P transport: ENABLED (per-connection ML-DSA handshake)");
        }
        Some(Arc::new(qchain_network::AuthState::new_with_encryption(signer.clone(), config.chain_id(), authorized, config.encrypted_transport)))
    } else {
        None
    };
    let (network, mut rx) = Network::start_with_auth(self_id, config.listen_addr, peers, auth).await?;
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
    let mut store: Box<dyn StateStore> = match &config.data_dir {
        Some(dir) => open_state_store(dir, &config.storage_engine)?,
        None => Box::new(InMemoryStore::new()),
    };
    let mut is_fresh = store.iter().next().is_none();

    // State-sync bootstrap (see `NodeConfig::state_sync_peers`): the real
    // catch-up path for a validator that fell further behind than
    // `engine::DAG_RETENTION_ROUNDS` - its peers pruned the old certificates
    // it would otherwise replay from round 0, so there is nothing to fetch
    // per-digest. Instead, on an empty local store with state-sync peers
    // configured, pull a *verified* account-state snapshot and install it,
    // then resume consensus from the snapshot's round. Only runs on a fresh
    // store: a node with existing state resumes normally (an operator
    // recovers a hopelessly-behind validator by wiping `data_dir` and
    // restarting, exactly the Cosmos state-sync recovery flow).
    let mut synced_round: Option<u64> = None;
    if is_fresh && !config.state_sync_peers.is_empty() {
        let snapshot = state_sync::fetch_verified_snapshot(&config).await?;
        for acc in &snapshot.accounts {
            store.set(acc.address, acc.account.clone());
        }
        tracing::info!(
            "state-synced {} accounts at round {} (verified root {})",
            snapshot.accounts.len(),
            snapshot.round,
            snapshot.merkle_root
        );
        synced_round = Some(snapshot.round);
        // The snapshot already contains every account, including the genesis
        // program singletons - genesis seeding must be skipped or it would
        // overwrite real state with genesis defaults.
        is_fresh = false;
    }

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
    let (round_checkpoint_path, mut next_round) = match &config.data_dir {
        Some(dir) => {
            let path = dir.join("round_checkpoint");
            // ATOMIC engine (redb): read the round from the store's committed
            // metadata FIRST — it was committed in the SAME transaction as the
            // account state, so it is ALWAYS consistent with it (both durable
            // together or neither). Fall back to the legacy checkpoint file for a
            // pre-atomic redb DB or the sled/in-memory path.
            let from_meta = store
                .get_meta("next_round")
                .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
                .map(u64::from_le_bytes);
            let resumed = from_meta
                .or_else(|| std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse::<u64>().ok()))
                .unwrap_or(0);
            (Some(path), resumed)
        }
        None => (None, 0),
    };
    // A just-installed snapshot fixes the round to resume consensus from -
    // ahead of both a fresh node's `0` and any (necessarily older) round
    // checkpoint. Persist it so a later ordinary restart resumes correctly.
    if let Some(round) = synced_round {
        next_round = round;
        if store.supports_atomic_meta() {
            // Commit the just-installed snapshot accounts AND the resume round in
            // ONE atomic transaction, so a crash right after sync leaves a
            // consistent (state, round) pair on disk — never a round ahead of an
            // empty account set. Refuse to start if it can't be made durable.
            store.put_meta("next_round", round.to_le_bytes().to_vec());
            if let Err(e) = store.flush() {
                anyhow::bail!("failed to durably commit the state-sync snapshot: {e}");
            }
        } else if let Some(path) = &round_checkpoint_path {
            let _ = std::fs::write(path, round.to_string());
        }
    }

    // `compressed_state_tree` is a genesis-level, network-wide choice (folded
    // into chain_id); default false = the legacy 256-deep tree, byte-identical
    // to every existing network.
    // `economics_v7` and `compressed_state_tree` are both genesis-level,
    // network-wide choices folded into `chain_id`; both default false = the v6
    // economics + legacy tree, byte-identical to every existing network.
    let mut ledger = Ledger::new_with_config(
        store,
        config.compressed_state_tree,
        config.economics_v7,
        config.quanto_rate_fp(),
        config.rounds_per_quanto(),
    )?;
    if config.compressed_state_tree {
        tracing::info!("state tree: COMPRESSED (O(log n)) - a hard-forked network; /stark_proof light-client serves compressed bindings");
    }
    if config.economics_v7 {
        tracing::info!(
            "economics: v7 ENABLED (shares+index staking, per-quanto emission, 45/45/10 fee split, 500 QCH bond) - a hard-forked network; rounds_per_quanto={}",
            config.rounds_per_quanto()
        );
    }
    // Register the standard native programs (chosen by economics_v7). Shared
    // with `Ledger::simulate` so a dry-run dispatches exactly like the live node.
    qchain_execution::register_standard_programs(&mut ledger, config.economics_v7);
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
        // Emergency governance guardian multisig (task #213). Seeded with the
        // configured guardian set (empty by default = the pause feature is
        // inert). Folded into `chain_id` only when set (see `NodeConfig::
        // chain_id`), so a network without guardians is byte-identical.
        {
            let guardians = config.guardian_pubkeys()?;
            let threshold = config.governance_guardian_threshold;
            ledger.seed_account(
                qchain_execution::EMERGENCY_ACCOUNT_ID,
                qchain_core::Account {
                    data: qchain_execution::genesis_emergency_account_data(guardians, threshold),
                    ..qchain_core::Account::new_wallet(GOVERNANCE_PROGRAM_ID)
                },
            );
        }
        // Shared delegator staking-reward pool (`ARCHITECTURE.md` §5's
        // staking-rewards paragraph, `qchain-execution::staking`'s module
        // docs for the reward-per-share accrual mechanism): starts empty,
        // `balance` accrues from every transaction's fee split from here.
        ledger.seed_account(
            STAKING_REWARDS_POOL_ID,
            qchain_core::Account { data: borsh::to_vec(&RewardPoolData::default())?, ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID) },
        );
        // On-chain validator registry (phase 3 - `qchain-execution::
        // validator_registry`): starts empty and is populated live by
        // `RegisterValidator`. Inert this increment (nothing reads it for
        // consensus yet), but seeded at genesis the same way every other
        // program singleton is so the account exists for the first
        // registration to mutate.
        // With rotation ON, pre-seed the registry with the genesis validators
        // so the per-epoch committee derived from it starts out equal to the
        // genesis committee (nobody dropped; a newcomer is *added* by stake
        // rank). With rotation OFF, seed the EMPTY registry exactly as before,
        // so the genesis state root is byte-identical for existing networks
        // (`genesis_validator_registry_with` vs `..._account_data`).
        let validator_registry_data = if config.validator_rotation {
            qchain_execution::validator_registry::genesis_validator_registry_with(
                config
                    .validators
                    .iter()
                    .map(|v| (v.pubkey_bundle.clone(), v.addr.to_string(), v.stake)),
            )
        } else {
            qchain_execution::validator_registry::genesis_validator_registry_account_data()
        };
        ledger.seed_account(
            VALIDATOR_REGISTRY_ACCOUNT_ID,
            qchain_core::Account {
                data: validator_registry_data,
                ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
            },
        );
        // v7 genesis (SPEC §15 + §12 strict pool separation): the six separate
        // economic pools start empty (or at their genesis state for the global
        // staking singleton), and the admin-fee wallet is a real system-owned
        // wallet ready to receive the 10% admin share once fee routing is wired.
        // The founder's 10M allocation is a normal `genesis` entry the operator
        // sets (handled by the credit loop above), not hardcoded here. Seeded only
        // for a v7 network, so a v6 genesis state root is byte-identical.
        if config.economics_v7 {
            use qchain_execution::ids::{
                ADMIN_FEE_WALLET, STAKING_GLOBAL_ID, STAKING_RESERVE_ID, STAKING_UNBONDING_POOL_ID, VALIDATOR_BOND_ESCROW_ID, VALIDATOR_FEE_POOL_ID, VALIDATOR_UNBONDING_POOL_ID,
            };
            // Global staking singleton: MUST seed with `genesis_with_rate` (index =
            // 1.0, carrying the per-quanto rate), never `Default` (index = 0) — the
            // per-quanto close reads this, and `stake()` reads `rate_fp` to price a
            // fresh deposit's shares at the NEXT quanto's index (epoch-aligned
            // activation: a deposit earns from the next quanto, not the partial one
            // it joined during).
            ledger.seed_account(
                STAKING_GLOBAL_ID,
                qchain_core::Account {
                    data: borsh::to_vec(&qchain_execution::staking_v7::GlobalStakingState::genesis_with_rate(config.quanto_rate_fp()))?,
                    ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
                },
            );
            // The fund pools start empty; each is program-owned so the dust
            // sweep never touches it and no source subsidizes another (§12). The
            // bond escrow is seeded below with the founder validators' bonds.
            for pool in [STAKING_RESERVE_ID, VALIDATOR_FEE_POOL_ID, STAKING_UNBONDING_POOL_ID, VALIDATOR_UNBONDING_POOL_ID] {
                ledger.seed_account(pool, qchain_core::Account::new_wallet(STAKING_PROGRAM_ID));
            }
            // Admin-fee wallet: a REAL system-owned wallet (the operator spends it
            // with a normal signed transfer). Seeded empty; the 10% admin share
            // credits here once v7 fee routing is wired.
            ledger.seed_account(ADMIN_FEE_WALLET, qchain_core::Account::new_wallet(qchain_crypto::Pubkey::system_program_id()));
            // The validator registry account ([9;32]) was seeded above in the
            // phase-3 (`validator_registry`) format; a v7 network instead uses the
            // `validator_v7::ValidatorV7Registry` format at the SAME id (SPEC §7).
            // Seed it with the FOUNDER validators (the genesis `validators` set) as
            // Active from quanto 0, so a fresh v7 network has an eligible committee
            // for the fee distribution from the first quanto (instead of pooling
            // fees with nobody to pay until someone `v7-bond-register`s). Each
            // founder's 500 QCH bond is MINTED into the escrow at genesis (operator
            // decision), so the §13 invariant holds: escrow balance == Σ bonds and
            // every bond == VALIDATOR_BOND_ATOMS. Deterministic (config order), so
            // every node of the network seeds the identical registry + escrow → same
            // genesis state root, no fork. Monikers: the config `name` if it's a
            // valid, unique moniker, else a deterministic `founder-<i>` fallback.
            use qchain_execution::economics_v7::{moniker_is_valid, normalize_moniker, VALIDATOR_BOND_ATOMS};
            use qchain_execution::validator_v7::{ValidatorV7Entry, ValidatorV7Registry, ValidatorV7State};
            let mut used_monikers = std::collections::HashSet::new();
            let mut founders = Vec::with_capacity(config.validators.len());
            for (i, v) in config.validators.iter().enumerate() {
                let named = v.name.as_deref().map(normalize_moniker).filter(|m| moniker_is_valid(m));
                let mut moniker = match named {
                    Some(m) if !used_monikers.contains(&m) => m,
                    _ => format!("founder-{i}"),
                };
                let mut k = 0u32;
                while used_monikers.contains(&moniker) {
                    k += 1;
                    moniker = format!("founder-{i}-{k}");
                }
                used_monikers.insert(moniker.clone());
                let consensus_addr = v.pubkey_bundle.to_address();
                founders.push(ValidatorV7Entry {
                    address: consensus_addr,
                    // At genesis a founder controls its own consensus key (no cold
                    // operator was posted), so the operator defaults to the consensus
                    // address; the WITHDRAWAL address routes bond + fee earnings to the
                    // configured cold address (#193-B) when set, else the consensus key
                    // (byte-identical to a network that doesn't separate the funds key).
                    operator_address: consensus_addr,
                    withdrawal_address: v.withdrawal_address.unwrap_or(consensus_addr),
                    moniker,
                    pubkey_bundle: v.pubkey_bundle.clone(),
                    p2p_address: v.addr.to_string(),
                    bond: VALIDATOR_BOND_ATOMS,
                    state: ValidatorV7State::Active,
                    registered_quanto: 0,
                    activation_quanto: 0,
                    exit_requested_quanto: 0,
                    bond_release_quanto: 0,
                    participation_credits: 0,
                    participation_opportunities: 0,
                });
            }
            let escrow_total = VALIDATOR_BOND_ATOMS.saturating_mul(founders.len() as u64);
            ledger.seed_account(
                VALIDATOR_REGISTRY_ACCOUNT_ID,
                qchain_core::Account {
                    data: borsh::to_vec(&ValidatorV7Registry { validators: founders })?,
                    ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
                },
            );
            ledger.seed_account(
                VALIDATOR_BOND_ESCROW_ID,
                qchain_core::Account { balance: escrow_total, ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID) },
            );
            // Genesis treasury (optional): mint the initial circulating supply
            // LOCKED into the treasury account, releasable only by the configured
            // authority (SPEC: v7 treasury). Deterministic (same authority+amount on
            // every node → identical genesis root). Absent when no treasury is
            // configured, so a v7 network without one is unchanged.
            if let (Some(auth_b58), Some(amount)) = (config.treasury_authority.as_deref(), config.treasury_amount) {
                let authority = auth_b58
                    .parse::<qchain_crypto::Pubkey>()
                    .map_err(|e| anyhow::anyhow!("treasury_authority is not a valid address: {e}"))?;
                ledger.seed_account(
                    qchain_execution::ids::TREASURY_ACCOUNT_ID,
                    qchain_execution::treasury_v7::genesis_treasury_account(authority, amount),
                );
                tracing::info!(
                    "treasury: seeded {} units ({} QCH) LOCKED, release authority {}",
                    amount,
                    amount / 1_000_000_000,
                    auth_b58
                );
            }
        }
    } else {
        tracing::info!("reusing persisted state from a prior run; skipping genesis seeding");
    }

    // Phase-3.3: build the committee schedule (rotating when enabled, else a
    // single fixed committee = the exact phase-1/2 behavior) and — for a
    // rotation node with a `data_dir` — reload the per-epoch committees prior
    // runs persisted, so a restart re-resolves the retained DAG window under the
    // right committees (each was derived from the on-chain registry as of a past
    // epoch boundary, state the current ledger no longer holds and so cannot
    // re-derive). `committee_log` is `None` (no persistence, no reload) unless
    // both rotation is on and a `data_dir` is configured.
    let committee_log: Option<sled::Db> = match (&config.data_dir, config.validator_rotation) {
        (Some(dir), true) => Some(sled::open(dir.join("committees"))?),
        _ => None,
    };
    let mut validator_schedule = if config.validator_rotation {
        tracing::info!("validator rotation ENABLED (epoch_rounds={}) - the active committee is re-derived from the on-chain registry each epoch", config.epoch_rounds());
        ValidatorSchedule::new(config.epoch_rounds(), validators.clone())
    } else {
        ValidatorSchedule::single(validators.clone())
    };
    if let Some(db) = &committee_log {
        let mut loaded = 0u64;
        let mut max_epoch = 0u64;
        for kv in db.iter() {
            let (k, v) = kv?;
            // A malformed (non-8-byte) key would otherwise map to epoch 0 and
            // clobber the genesis committee - skip it loudly instead.
            let Ok(epoch_bytes) = <[u8; 8]>::try_from(k.as_ref()) else {
                tracing::warn!("skipping a committee-log entry with a malformed {}-byte key (expected 8)", k.len());
                continue;
            };
            let epoch = u64::from_be_bytes(epoch_bytes);
            match qchain_node::engine::deserialize_committee(&v) {
                Some(committee) => {
                    validator_schedule.install_epoch(epoch, committee);
                    max_epoch = max_epoch.max(epoch);
                    loaded += 1;
                }
                None => tracing::warn!("skipping corrupt persisted committee for epoch {epoch}"),
            }
        }
        if loaded > 0 {
            // Everything up to the highest reloaded epoch is known, so the
            // resolvable frontier resumes there; the ratchet derives further
            // epochs from here as the chain advances past them.
            validator_schedule.set_frontier_epoch(max_epoch);
            tracing::info!("reloaded {loaded} epoch committees from disk; resolvable frontier at epoch {max_epoch}");
        }
    }
    // The committee in effect for the round this node resumes at (under rotation)
    // or the single fixed set (no rotation) — used for the resume decision below.
    let current_committee = validator_schedule.for_round(next_round).clone();

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
    let mut consensus =
        if current_committee.stake_of(&self_id) >= current_committee.quorum_threshold() { ConsensusState::resuming_from(next_round) } else { ConsensusState::new() };

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
    // Worker batches (the transaction payloads the reloaded certificates only
    // reference by digest). Reloaded into the initial `batches` cache so a
    // restarted validator can EXECUTE the transactions those certificates carry
    // instead of blocking `take_executable_prefix` on a batch it can no longer
    // fetch (a single validator has no peer to re-sync from) - see
    // `Engine::batch_log`. `None`/empty for an in-memory node, exactly the prior
    // behavior. Their retention round is unknown after a restart, so they are
    // tagged with the current resume round; the next prune tick re-windows them.
    let batch_log: Option<sled::Db> = match &config.data_dir {
        Some(dir) => Some(sled::open(dir.join("batches"))?),
        None => None,
    };
    let mut reloaded_batches: HashMap<qchain_core::Digest, qchain_core::Batch> = HashMap::new();
    let mut reloaded_batch_rounds: HashMap<qchain_core::Digest, u64> = HashMap::new();
    if let Some(db) = &batch_log {
        let mut loaded = 0usize;
        for entry in db.iter() {
            let (digest_bytes, bytes) = entry?;
            match borsh::from_slice::<qchain_core::Batch>(&bytes) {
                Ok(batch) => {
                    if digest_bytes.len() == 32 {
                        let mut digest = [0u8; 32];
                        digest.copy_from_slice(&digest_bytes);
                        reloaded_batches.insert(digest, batch);
                        reloaded_batch_rounds.insert(digest, next_round);
                        loaded += 1;
                    } else {
                        tracing::warn!("skipping a batch-log entry with a malformed {}-byte key (expected 32)", digest_bytes.len());
                    }
                }
                Err(e) => tracing::warn!("skipping a corrupt batch in the on-disk batch log: {e}"),
            }
        }
        if loaded > 0 {
            tracing::info!("reloaded {loaded} worker batches from the on-disk batch log");
        }
    }
    // If this node persisted a *pruned* DAG (a long-lived validator that
    // garbage-collected old rounds - see `engine::DAG_RETENTION_ROUNDS`), its
    // reloaded DAG starts at some round > 0. Set the consensus GC barrier to
    // that real bottom so the re-derivation (whose `seen` set didn't survive
    // the restart) stops cleanly at the pruned boundary instead of trying to
    // walk a retained-window leader's ancestry off into the dropped region.
    // A never-pruned DAG has `lowest_round == 0`, making this a no-op that
    // preserves the existing restart behavior exactly.
    if !dag.is_empty() {
        consensus.set_gc_floor(dag.lowest_round());
    }
    // After a state-sync the DAG is empty but consensus must not try to
    // resolve or walk anything below the snapshot round - there are no
    // certificates for that pruned history, and the account effects are
    // already installed. Set the barrier (and start watermark) to the
    // snapshot round, the same role `round_checkpoint` plays for an ordinary
    // restart; peers supply certificates from here forward via normal resync.
    if let Some(round) = synced_round {
        consensus.set_gc_floor(round);
    }

    // Reload the transfer-history log (a `sled` tree at `data_dir/receipts`)
    // so the dashboard's recent-activity list survives a restart/update -
    // without this the receipts live only in memory and every boot shows an
    // empty history even though balances (in `SledStore`) are intact. Loaded
    // before the engine replays committed transactions: a replay hits the
    // nonce check in `apply_transaction` and captures nothing, so the restored
    // history stays exact (no duplicates). Corrupt entries are skipped, not
    // fatal - history is a convenience view, not consensus state.
    let receipt_log: Option<sled::Db> = match &config.data_dir {
        Some(dir) => Some(sled::open(dir.join("receipts"))?),
        None => None,
    };
    if let Some(db) = &receipt_log {
        // Load only the most recent `MAX_INMEM_RECEIPTS` (newest-first via a
        // reverse scan, then flipped back to chronological order). Each receipt
        // is ~32 KB, so loading the full log made boot take ~18 s on a real node
        // with only ~11.6k receipts (and RPC binds only after this) - which the
        // updater's health check misread as a "possible freeze". The on-disk log
        // is pruned to the same bound, so in steady state the reverse scan sees
        // at most `MAX_INMEM_RECEIPTS` entries anyway; the `.take` is the belt to
        // that suspenders for a log written by an older, unpruned binary.
        let mut newest_first = Vec::new();
        for entry in db.iter().rev().take(qchain_node::engine::MAX_INMEM_RECEIPTS) {
            let (_seq, bytes) = entry?;
            match serde_json::from_slice::<qchain_execution::TransferReceipt>(&bytes) {
                Ok(r) => newest_first.push(r),
                Err(e) => tracing::warn!("skipping a corrupt transfer receipt in the on-disk log: {e}"),
            }
        }
        if !newest_first.is_empty() {
            newest_first.reverse(); // back to oldest-first, as the chain requires
            tracing::info!("reloaded {} transfer receipts from the on-disk log", newest_first.len());
            ledger.restore_receipts(newest_first);
        }
    }

    // The full-proof log (`data_dir/receipts_full`) holds the most recent
    // receipts WITH their Merkle proofs, so `/stark_proof` survives a restart.
    // Overlay each full receipt's proofs onto the matching (by tx_hash) light
    // receipt just reloaded above - restoring the two-tier state (recent = full,
    // older = light) exactly as it was before the restart.
    let receipt_full_log: Option<sled::Db> = match &config.data_dir {
        Some(dir) => Some(sled::open(dir.join("receipts_full"))?),
        None => None,
    };
    if let Some(db) = &receipt_full_log {
        let mut full: std::collections::HashMap<[u8; 32], qchain_execution::TransferReceipt> = std::collections::HashMap::new();
        for entry in db.iter().rev().take(qchain_node::engine::N_FULL_PROOF_RECEIPTS) {
            let (_seq, bytes) = entry?;
            // Full receipts are now Borsh (compact); an older node wrote serde_json.
            // Try Borsh first, fall back to serde_json so a pre-upgrade full log
            // still loads (no /stark_proof gap on the user's upgrade restart).
            let decoded = borsh::from_slice::<qchain_execution::TransferReceipt>(&bytes)
                .ok()
                .or_else(|| serde_json::from_slice::<qchain_execution::TransferReceipt>(&bytes).ok());
            if let Some(r) = decoded {
                full.insert(r.tx_hash, r);
            }
        }
        if !full.is_empty() {
            let overlaid = ledger.overlay_receipt_proofs(&full);
            tracing::info!("reloaded {} full-proof receipts (overlaid onto {overlaid} history entries)", full.len());
        }
    }

    // Same for staking activity (a `sled` tree at `data_dir/staking`) so the
    // dashboard's and wallet's staking history survives a restart.
    let staking_log: Option<sled::Db> = match &config.data_dir {
        Some(dir) => Some(sled::open(dir.join("staking"))?),
        None => None,
    };
    if let Some(db) = &staking_log {
        // Bounded reverse reload, same as receipts (see above).
        let mut newest_first = Vec::new();
        for entry in db.iter().rev().take(qchain_node::engine::MAX_INMEM_STAKING_EVENTS) {
            let (_seq, bytes) = entry?;
            match serde_json::from_slice::<qchain_execution::StakingEvent>(&bytes) {
                Ok(e) => newest_first.push(e),
                Err(e) => tracing::warn!("skipping a corrupt staking event in the on-disk log: {e}"),
            }
        }
        if !newest_first.is_empty() {
            newest_first.reverse();
            tracing::info!("reloaded {} staking events from the on-disk log", newest_first.len());
            ledger.restore_staking_events(newest_first);
        }
    }

    // Restore the persisted economics snapshot (lifetime burn/earnings counters)
    // so they don't reset to zero on every restart. A missing/corrupt file just
    // starts the counters at zero (the pre-persistence behavior).
    let economics_path: Option<std::path::PathBuf> = config.data_dir.as_ref().map(|dir| dir.join("economics"));
    // ATOMIC engine (redb): the economics counters were committed IN the per-round
    // state transaction, so read them from the store metadata FIRST — consistent
    // with the account state. Fall back to the legacy file (sled path / a
    // pre-atomic redb DB).
    let econ_bytes: Option<Vec<u8>> = ledger
        .get_meta("economics")
        .or_else(|| economics_path.as_ref().and_then(|p| std::fs::read(p).ok()));
    if let Some(bytes) = econ_bytes {
        match borsh::BorshDeserialize::try_from_slice(&bytes) {
            Ok(snap) => {
                ledger.import_economics(snap);
                tracing::info!("restored persisted economics counters");
            }
            Err(e) => tracing::warn!("ignoring a corrupt economics snapshot ({e}); starting counters at zero"),
        }
    }

    // v7 participation pipeline (#209): restore the accumulator + next-quanto +
    // fed-but-unconsumed tallies committed atomically with the round state, so
    // the participation gating resumes fork-safely instead of re-deriving from a
    // pruned DAG. Only present on a v7 network with the atomic store; absent (a
    // v6 network / fresh genesis) → start empty, identical to before.
    let mut participation_credits: std::collections::BTreeMap<u64, HashMap<qchain_core::ValidatorId, u64>> = std::collections::BTreeMap::new();
    let mut participation_next_quanto: u64 = 0;
    if let Some(bytes) = ledger.get_meta("v7_participation") {
        match <qchain_node::engine::PersistedParticipation as borsh::BorshDeserialize>::try_from_slice(&bytes) {
            Ok(blob) => {
                participation_next_quanto = blob.next_quanto;
                for (q, m) in blob.credits {
                    participation_credits.insert(q, m.into_iter().collect());
                }
                ledger.import_participation(blob.tallies);
                tracing::info!("restored v7 participation pipeline (next_quanto={participation_next_quanto}, {} accrued quanto(s))", participation_credits.len());
            }
            Err(e) => tracing::warn!("ignoring a corrupt v7 participation blob ({e}); participation resumes empty"),
        }
    }

    // STARTUP GATE (#217): after genesis-seeding (fresh) or loading persisted
    // state, the critical singletons must be valid. Refuse to start on a corrupt
    // (present-but-undecodable) or missing-required one — never run degraded on
    // silent defaults. Brick-safe: absent optional/version-dependent accounts
    // (EMERGENCY / v7 set on a v6 network) are tolerated.
    if let Err(e) = ledger.validate_critical_singletons(config.economics_v7) {
        anyhow::bail!("FATAL: {e}. Restore from a good backup / re-sync a fresh data_dir before restarting.");
    }

    // The committee schedule was built (and, for a rotation node, reloaded from
    // disk) above, before the consensus-resume decision. `current_committee` is
    // the set in effect for the resume round; the schedule carries the full
    // per-epoch map + resolvable frontier.
    let engine = Arc::new(Engine {
        self_id,
        signer,
        withdrawal_map,
        self_fee_dest,
        validators: std::sync::RwLock::new(std::sync::Arc::new(current_committee)),
        validator_schedule: std::sync::RwLock::new(std::sync::Arc::new(validator_schedule)),
        validator_directory,
        network,
        chain_id: config.chain_id(),
        cert_log,
        batch_log,
        committee_log,
        state_checkpoints: config.state_checkpoints(),
        config_peers,
        receipt_log,
        receipt_full_log,
        staking_log,
        economics_path,
        round_interval_ms: config.round_interval_ms,
        disk_size_cache: std::sync::Mutex::new(None),
        sig_cache: std::sync::Mutex::new(qchain_node::engine::SigVerifyCache::new(qchain_node::engine::MAX_SIG_CACHE)),
        admission_quota: std::sync::Mutex::new(qchain_node::engine::AdmissionQuota::default()),
        snapshot_cache: tokio::sync::Mutex::new(None),
        state: tokio::sync::Mutex::new(EngineState {
            ledger,
            dag,
            consensus,
            mempool: HashMap::new(),
            pipeline_next: HashMap::new(),
            batches: reloaded_batches,
            batch_seen_round: reloaded_batch_rounds,
            wanted_batches: HashMap::new(),
            speculative_batches: HashMap::new(),
            pending_votes: HashMap::new(),
            own_pending_vertex: None,
            next_round,
            round_checkpoint_path,
            executed: 0,
            round_committed: HashMap::new(),
            voted_for: HashMap::new(),
            pending_cert_requests: HashMap::new(),
            pending_batch_requests: HashMap::new(),
            pending_votes_to_send: HashMap::new(),
            own_last_certificate: None,
            first_seen_vertex: HashMap::new(),
            equivocation_evidence: HashMap::new(),
            update_available: None,
            pending_execution: std::collections::VecDeque::new(),
            pending_availability_votes: HashMap::new(),
            participation_credits,
            participation_next_quanto,
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
                // Backstop: cast any deferred availability-gated votes whose
                // batches have since arrived (the batch handlers drive this
                // directly; this catches any missed path). No-op when idle.
                engine.try_cast_available_votes().await;
                engine.prune_stale_round_state().await;
            }
        });
    }

    {
        // Slow, separate cadence for the version announcement (see
        // `Engine::announce_version` / `NetMessage::VersionAnnounce`): the
        // whole no-central-server update-notification mechanism. Every 30s is
        // plenty - a peer that upgrades is noticed within one interval, and it
        // adds negligible traffic (one tiny message per peer per interval).
        let engine = engine.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                ticker.tick().await;
                engine.announce_version().await;
            }
        });
    }

    tracing::info!("qchain-node {self_id} up: p2p={}, rpc={}", config.listen_addr, config.rpc_addr);
    // QCH-RPC-001: the JSON-RPC has no authentication, so a PUBLIC bind
    // (non-loopback `rpc_addr`) with no per-IP rate limit lets anyone flood it
    // (submit txs, hammer read endpoints) unbounded. Warn loudly when exposed
    // without a limit so an operator doesn't ship an open, unmetered RPC by
    // accident. We warn rather than refuse to start, so a legitimate setup that
    // fronts the RPC with its own rate limiting (nginx/Cloudflare) isn't broken;
    // the actionable fix is `rpc_rate_limit_per_10s` in the config (see #196).
    // "Reachable by remote clients" = a non-loopback bind OR a loopback bind the
    // operator declared to sit behind a trusted same-host proxy (the Cloudflare
    // tunnel / local nginx case): in both, the real clients are remote.
    let rpc_public = !config.rpc_addr.ip().is_loopback() || config.rpc_behind_trusted_proxy;
    if rpc_public && config.rpc_rate_limit_per_10s.filter(|&n| n > 0).is_none() {
        tracing::warn!(
            "SECURITY: rpc_addr {} is reachable by remote clients (public bind or rpc_behind_trusted_proxy) but no GENERAL per-IP rate limit is set - the unauthenticated read/submit RPC is exposed unmetered (POST /simulate IS protected mandatorily; this is about the other endpoints). Set `rpc_rate_limit_per_10s` in the config, or front the RPC with your own rate limiting, or bind rpc_addr to 127.0.0.1 and reach it via a tunnel.",
            config.rpc_addr
        );
    }
    // The `/simulate` limiter is MANDATORY whenever the RPC is reachable by remote
    // clients (never None/0) — its own per-IP + per-txid gate on the most expensive
    // unauthenticated endpoint. On a genuinely private loopback bind it stays opt-in
    // (`simulate_rate_limit_per_10s`). With a trusted proxy the per-IP gate keys on
    // the real client via X-Forwarded-For (see `SimRateLimiter::for_rpc`).
    let sim_limiter = rpc::SimRateLimiter::for_rpc(config.rpc_addr, config.simulate_rate_limit_per_10s, config.rpc_behind_trusted_proxy);
    if sim_limiter.is_some() && rpc_public {
        tracing::info!(
            "POST /simulate: mandatory per-IP + per-txid rate limit ACTIVE ({})",
            if config.rpc_behind_trusted_proxy { "loopback behind trusted proxy - per-IP keyed on X-Forwarded-For" } else { "public RPC" }
        );
    }
    // The `/tx` limiter (task #210): same mandatory-when-public policy — it
    // protects the SIGNED-transaction submission endpoint (per-IP + per-txid),
    // complementing the always-on engine-side verify-concurrency cap + global/
    // per-payer admission quota. On a private loopback RPC it's opt-in
    // (`tx_rate_limit_per_10s`).
    let tx_limiter = rpc::TxRateLimiter::for_rpc(config.rpc_addr, config.tx_rate_limit_per_10s, config.rpc_behind_trusted_proxy);
    if tx_limiter.is_some() && rpc_public {
        tracing::info!(
            "POST /tx: mandatory per-IP + per-txid rate limit ACTIVE ({}); global/per-payer admission quota + concurrent-verify cap always on",
            if config.rpc_behind_trusted_proxy { "loopback behind trusted proxy - per-IP keyed on X-Forwarded-For" } else { "public RPC" }
        );
    }
    let flush_engine = engine.clone();
    let app = rpc::router(engine, config.rpc_rate_limit_per_10s, sim_limiter, tx_limiter);
    // `into_make_service_with_connect_info` so the (opt-in) per-IP rate limiter
    // can read each client's address (task #196). Harmless when the limiter is
    // off — no layer consults it.
    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    let listener = tokio::net::TcpListener::bind(config.rpc_addr).await?;
    // Serve until a shutdown signal arrives; on SIGTERM/SIGINT flush every sled
    // store to disk BEFORE exiting, so the durable `round_checkpoint` is never
    // ahead of the persisted state (the restart-durability fix - see
    // `Engine::flush_all`). `flush_all` takes the state lock, so any in-flight
    // commit finishes first and a consistent point-in-time is flushed.
    tokio::select! {
        r = axum::serve(listener, app) => { r?; }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received; flushing state to disk before exit");
            flush_engine.flush_all().await;
        }
    }
    Ok(())
}

/// Resolves on the first SIGTERM (systemd stop/restart) or SIGINT (Ctrl-C).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
