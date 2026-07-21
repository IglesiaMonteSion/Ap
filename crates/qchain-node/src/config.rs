//! Node configuration: everything needed to join the phase-1 testnet as one
//! validator - own keypair, the full (fixed, phase-1) validator set with
//! its stake and network addresses, and genesis allocations. JSON, loaded
//! once at startup; there is no dynamic validator-set membership yet (see
//! `ARCHITECTURE.md`'s phase-1 out-of-scope list - that's a governance
//! feature for a later phase).

use qchain_crypto::{Pubkey, PublicKeyBundle};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub pubkey_bundle: PublicKeyBundle,
    pub addr: SocketAddr,
    pub stake: u64,
    /// Optional human-readable moniker so wallets can show a named list of
    /// validators to delegate to, instead of asking the user to paste a raw
    /// address. Set in the shared genesis config (every node with the same
    /// genesis sees the same name). `skip_serializing_if` keeps the field OUT
    /// of the JSON entirely when absent, so a config written before names
    /// existed serializes byte-for-byte identically - which means `chain_id`
    /// (a hash over `validators`+`genesis`) is UNCHANGED for existing
    /// networks. A network that does set names folds them into its chain_id,
    /// which is fine: setting names is a genesis-level decision for that
    /// network, made once up front.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GenesisAllocation {
    pub address: Pubkey,
    pub balance: u64,
}

#[derive(Serialize, Deserialize)]
pub struct NodeConfig {
    /// Path to this validator's own keypair file (see
    /// `qchain_crypto::write_keypair_file` / the `qchain keygen` CLI
    /// command).
    pub keypair_path: PathBuf,
    /// P2P listen address - must match this validator's `addr` entry in
    /// `validators` below.
    pub listen_addr: SocketAddr,
    /// JSON-RPC listen address for wallet/client traffic.
    pub rpc_addr: SocketAddr,
    /// The full validator set, self included.
    pub validators: Vec<ValidatorConfig>,
    #[serde(default)]
    pub genesis: Vec<GenesisAllocation>,
    /// Milliseconds between round-advancement attempts.
    #[serde(default = "default_round_interval_ms")]
    pub round_interval_ms: u64,
    /// Directory for a real, disk-persistent `SledStore` (see
    /// `qchain-storage`'s `store.rs` module docs for why `sled` rather
    /// than RocksDB). Omitted (the default) keeps the phase-1 behavior of
    /// an `InMemoryStore` that starts empty on every restart - existing
    /// configs from earlier live tests in this session keep working
    /// unchanged.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    /// RPC URLs of peers this node may state-sync from when it starts with
    /// an empty local store (a fresh join, or an operator recovering a
    /// validator that fell further behind than `DAG_RETENTION_ROUNDS` by
    /// wiping `data_dir` and restarting). Empty (the default) keeps the
    /// original behavior exactly: a fresh node seeds genesis and replays
    /// from round 0. When set, the node fetches a verified account-state
    /// snapshot (`GET /snapshot`) instead of replaying pruned history it
    /// could never fetch. See `main.rs`'s state-sync path.
    #[serde(default)]
    pub state_sync_peers: Vec<String>,
    /// Optional out-of-band trust anchor for state-sync (Cosmos-style
    /// `trust_height`/`trust_hash`): if set, a fetched snapshot is accepted
    /// only if its `(round, merkle_root)` matches this exactly - turning
    /// state-sync from "trust the source peer" (weak subjectivity) into a
    /// fully verified catch-up against a value the operator obtained
    /// independently. Hex-encoded 32-byte root.
    #[serde(default)]
    pub state_sync_trusted_root: Option<String>,
    #[serde(default)]
    pub state_sync_trusted_round: Option<u64>,
    /// **Opt-in dynamic validator rotation (phase 3.3).** When `false` (the
    /// default, and what every existing config resolves to), the validator set
    /// is fixed for the life of the network — exactly the phase-1/2 behavior,
    /// zero change. When `true`, the *active* consensus committee is re-derived
    /// each epoch from the on-chain validator registry (who has staked and
    /// called `register-validator`): a newcomer with enough self-stake enters
    /// the committee automatically at the next epoch boundary, and one that
    /// unregisters or falls below the minimum leaves — no coordinated redeploy.
    ///
    /// **Hard requirement: every node in a network must set this identically.**
    /// It changes how consensus resolves each round's committee, so a mismatch
    /// would fork the network. It is a genesis-level, network-wide decision.
    /// The `validators` list still seeds epoch 0 (the bootstrap committee) and
    /// governs until/unless a viable active set exists on-chain, so a rotation
    /// network still starts exactly from its genesis validators.
    #[serde(default)]
    pub validator_rotation: bool,
    /// Rounds per epoch — only meaningful when `validator_rotation` is `true`.
    /// The granularity at which the active committee may change. Omitted (the
    /// default) uses the standard `EPOCH_ROUNDS` (1024). Exposed mainly so a
    /// test network can use a small value to cross an epoch boundary quickly;
    /// like `validator_rotation`, it must match across all nodes.
    #[serde(default)]
    pub epoch_rounds: Option<u64>,
    /// State-commitment tree. `false` (default, every existing network) is the
    /// legacy 256-deep sparse Merkle tree - byte-identical to phase-1/2, zero
    /// change. `true` selects the O(log n) path-compressed tree (measured ~34x
    /// faster per account write / ~4x higher apply throughput). It changes the
    /// STATE ROOT, so it is a genesis-level HARD FORK: a network choosing it
    /// needs a fresh genesis and CANNOT be an in-place upgrade of an existing
    /// chain. Like `validator_rotation`, every node in a network must set this
    /// identically (it is folded into `chain_id` below, so a mismatched node
    /// computes a different chain_id and its transactions are rejected rather
    /// than silently forking). The STARK light-client (`/stark_proof` +
    /// `light-client-verify`) works in compressed mode too (v5.1.0): a
    /// compressed node captures receipts carrying O(log n) `CompressedProof`s and
    /// serves `compressed_bindings` verified with
    /// `qchain-stark::verify_batch_bound_to_compressed_state`.
    #[serde(default)]
    pub compressed_state_tree: bool,
    /// On-disk storage engine for the account state (only meaningful with a
    /// `data_dir`). `"sled"` (the default, and what every existing config
    /// resolves to) is the original `sled` 0.34 store - unchanged, byte-identical
    /// behavior. `"redb"` selects the modern pure-Rust `RedbStore` (mmap'd, ACID),
    /// whose in-RAM mirror + per-round flush keeps memory flat under a write burst
    /// (fixing sled 0.34's measured multi-GB flood RSS). This is a NODE-LOCAL
    /// storage choice - it does NOT change the state root, wire, consensus, or
    /// `chain_id`, so it is NOT a hard fork and nodes on different engines
    /// interoperate. A node set to `"redb"` whose `data_dir` still holds a legacy
    /// sled state auto-migrates it once on startup (verified: the migrated account
    /// set must be identical), keeping the sled files as a backup.
    #[serde(default = "default_storage_engine")]
    pub storage_engine: String,
    /// Authenticated P2P transport (task #176). `false` (the default, every
    /// existing network) is the phase-1 unauthenticated transport, byte-
    /// identical to before this field existed. `true` runs a per-connection
    /// mutual ML-DSA handshake (reusing the validator key) before any message
    /// flows, so a non-member can't spoof a validator at the transport layer
    /// and only real validators of THIS network can even connect. It is a
    /// NETWORK-LAYER choice, NOT consensus/state: it is deliberately NOT folded
    /// into `chain_id` (two nodes differing only on this flag have the same
    /// chain_id). But it IS wire-breaking — an auth-on node and an auth-off
    /// node cannot complete a connection — so every node in a network must set
    /// it identically, and turning it on is a COORDINATED cutover (all nodes
    /// together). No genesis change and no state change: an existing chain can
    /// flip it on with a coordinated restart, no fresh genesis needed.
    #[serde(default)]
    pub authenticated_transport: bool,
    /// Opt-in **encrypted** transport, on top of `authenticated_transport`.
    /// `false` (default) is the auth-only handshake (v6.4.x): P2P traffic is
    /// public data and flows in the clear. `true` runs an ML-KEM-768 exchange
    /// inside the same handshake, so every message is AEAD-encrypted
    /// (ChaCha20-Poly1305) and the channel is cryptographically bound into the
    /// signed transcript — adding confidentiality and closing the on-path relay
    /// gap the auth-only handshake documents as its honest limit. Requires
    /// `authenticated_transport` (encryption without authentication is
    /// meaningless — there is no verified peer to bind the channel to). Like the
    /// auth flag it is a NETWORK-LAYER choice, NOT consensus/state: NOT folded
    /// into `chain_id`, but wire-breaking (an encrypting node and a non-
    /// encrypting node can't complete a connection), so it is a COORDINATED
    /// cutover — every node sets it identically. No genesis/state change.
    #[serde(default)]
    pub encrypted_transport: bool,
    /// v7 economics (shares+index staking, per-quanto emission, the 45/45/10 fee
    /// split, the 500 QCH validator bond). `false` (default, every existing
    /// network) is the v6 economics — byte-identical, zero change. `true` is a
    /// genesis-level, network-wide HARD FORK (folded into `chain_id` below): a v7
    /// network needs a fresh genesis and every node must set this identically (a
    /// mismatched node computes a different `chain_id` and its transactions are
    /// rejected rather than silently forking). See `docs/ECONOMIC-REDESIGN.md` and
    /// `qchain-execution`'s `economics_v7`/`staking_v7`/`fees_v7`/`validator_v7`.
    #[serde(default)]
    pub economics_v7: bool,
    /// Per-quanto compounding rate in `QUANTO_RATE_SCALE` (1e18) fixed point,
    /// baked at genesis. Only read when `economics_v7` is on; part of the network
    /// config hash. When omitted the node derives it from the compiled-in
    /// `STAKING_TARGET_APY_BPS`/`DEFAULT_QUANTOS_PER_YEAR` — fine for a
    /// same-platform test network, but a production genesis should bake the exact
    /// integer here (via genesis-build), because the derivation uses f64 (`powf`)
    /// which is not bit-identical across platforms, and the chain only ever runs
    /// the integer `advance_staking_index`.
    #[serde(default)]
    pub quanto_rate_fp: Option<u128>,
    /// Rounds per reward quanto (`economics_v7::DEFAULT_ROUNDS_PER_QUANTO` when
    /// omitted). Only read when `economics_v7` is on; part of the network config
    /// hash. Exposed so a test network can use a small value to cross a quanto
    /// boundary quickly.
    #[serde(default)]
    pub rounds_per_quanto: Option<u64>,
    /// v7 genesis treasury authority — base58 pubkey allowed to sign `Release`
    /// (unlock+send) / `SetAuthority` on the locked treasury account. Only read
    /// when `economics_v7` is on AND `treasury_amount` is set. Part of the network
    /// config hash (a different authority is a different genesis → different chain).
    #[serde(default)]
    pub treasury_authority: Option<String>,
    /// v7 genesis treasury amount, in QCH-units (1 QCH = 1e9). Minted LOCKED into
    /// `TREASURY_ACCOUNT_ID` at genesis (owned by the treasury program; only a
    /// `Release` signed by `treasury_authority` moves it). Only meaningful with
    /// `economics_v7` + `treasury_authority`; part of the network config hash.
    #[serde(default)]
    pub treasury_amount: Option<u64>,
    /// Per-IP RPC rate limit (task #196, QCH-S6): max requests any single client
    /// IP may make in a 10-second window before it's temporarily banned (60 s).
    /// `None`/`0` (the default, and what every existing config resolves to)
    /// disables it entirely — zero overhead, byte-identical behavior, no
    /// interference with a loopback-private RPC or the operator's own tools. Set
    /// it only when EXPOSING the RPC publicly (`--rpc-public`), where a per-IP
    /// cap + temp ban blunts an unauthenticated request flood. It is a
    /// node-LOCAL policy: not folded into `chain_id`, no consensus/wire impact.
    #[serde(default)]
    pub rpc_rate_limit_per_10s: Option<u32>,
}

fn default_storage_engine() -> String {
    "sled".to_string()
}

fn default_round_interval_ms() -> u64 {
    500
}

impl NodeConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        let cfg: NodeConfig = serde_json::from_slice(&bytes)?;
        // Reject a self-inflicted misconfig early with a clear message instead of
        // a cryptic panic later: `tokio::time::interval(Duration::from_millis(0))`
        // panics ("interval period must be non-zero") at node startup.
        if cfg.round_interval_ms == 0 {
            anyhow::bail!("round_interval_ms must be greater than 0");
        }
        Ok(cfg)
    }

    /// A real, live-confirmed cross-network replay gap this closes (see
    /// `project-lessons-learned` and `qchain_core::Message::chain_id`'s doc
    /// comment): the hash of this network's own genesis data - only
    /// `validators`/`genesis`, deliberately excluding per-validator fields
    /// like `listen_addr`/`rpc_addr`/`keypair_path`/`round_interval_ms`/
    /// `data_dir` that legitimately differ between validators of the exact
    /// same network. Every validator loading the same genesis config
    /// computes the identical `chain_id` independently - no coordination
    /// round-trip needed, same principle `qchain-genesis-build` already
    /// relies on for producing per-validator configs from one shared
    /// manifest.
    pub fn chain_id(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut bytes = serde_json::to_vec(&(&self.validators, &self.genesis)).expect("genesis data always serializes");
        // Fold the compressed-state-tree choice in ONLY when it is enabled, so an
        // existing (legacy, `false`) network's chain_id is byte-identical to
        // before this field existed - its live transactions keep verifying. A
        // compressed network gets a distinct chain_id (it is a genuinely
        // separate, hard-forked network, and a legacy node must not accept its
        // transactions or vice versa).
        if self.compressed_state_tree {
            bytes.extend_from_slice(b"compressed-state-tree-v1");
        }
        // Same "fold in only when enabled" discipline: a v6 (default, `false`)
        // network's chain_id is byte-identical to before this field existed. A v7
        // network gets a distinct chain_id — it is a genuinely separate,
        // hard-forked network (fresh genesis, §15), and a v6 node must not accept
        // its transactions or vice versa. The resolved rate + rounds are folded in
        // too (SPEC §17: the economic parameters are part of the network config
        // hash), so a 12%-APY network and an 8%-APY one are distinct chains.
        if self.economics_v7 {
            bytes.extend_from_slice(b"economics-v7-45-45-10");
            bytes.extend_from_slice(&self.quanto_rate_fp().to_le_bytes());
            bytes.extend_from_slice(&self.rounds_per_quanto().to_le_bytes());
            // The genesis treasury (locked supply + its release authority) is part
            // of the genesis state, so it folds into the network identity: a
            // different authority or amount is a genuinely different genesis. Only
            // when a treasury is actually configured, so a v7 network without one
            // keeps its chain_id unchanged.
            if let (Some(auth), Some(amt)) = (&self.treasury_authority, self.treasury_amount) {
                bytes.extend_from_slice(b"treasury-v7");
                bytes.extend_from_slice(auth.as_bytes());
                bytes.extend_from_slice(&amt.to_le_bytes());
            }
        }
        Sha3_256::digest(bytes).into()
    }

    /// The resolved per-quanto compounding rate: the genesis-baked config value,
    /// or (when omitted) derived from the compiled-in APY target. The derivation
    /// is off-chain (f64); see `quanto_rate_fp`'s field doc for the determinism
    /// caveat. Only meaningful when `economics_v7` is on.
    pub fn quanto_rate_fp(&self) -> u128 {
        self.quanto_rate_fp.unwrap_or_else(|| {
            qchain_execution::economics_v7::derive_quanto_rate_fp(
                qchain_execution::economics_v7::STAKING_TARGET_APY_BPS,
                qchain_execution::economics_v7::DEFAULT_QUANTOS_PER_YEAR,
            )
        })
    }

    /// The resolved rounds-per-quanto (config override or the standard default).
    /// Only meaningful when `economics_v7` is on.
    pub fn rounds_per_quanto(&self) -> u64 {
        self.rounds_per_quanto.unwrap_or(qchain_execution::economics_v7::DEFAULT_ROUNDS_PER_QUANTO)
    }

    /// Rounds per epoch for validator rotation (the config override, or the
    /// standard `EPOCH_ROUNDS` default). Only meaningful when
    /// `validator_rotation` is set.
    pub fn epoch_rounds(&self) -> u64 {
        self.epoch_rounds.unwrap_or(qchain_consensus::schedule::DEFAULT_EPOCH_ROUNDS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_crypto::Keypair;

    fn config_with(validators: Vec<ValidatorConfig>, genesis: Vec<GenesisAllocation>) -> NodeConfig {
        NodeConfig {
            keypair_path: PathBuf::from("keypair.json"),
            listen_addr: "127.0.0.1:35001".parse().unwrap(),
            rpc_addr: "127.0.0.1:28001".parse().unwrap(),
            validators,
            genesis,
            round_interval_ms: 500,
            data_dir: None,
            state_sync_peers: Vec::new(),
            state_sync_trusted_root: None,
            state_sync_trusted_round: None,
            validator_rotation: false,
            epoch_rounds: None,
            compressed_state_tree: false,
            storage_engine: "sled".to_string(),
            authenticated_transport: false,
            encrypted_transport: false,
            economics_v7: false,
            quanto_rate_fp: None,
            rounds_per_quanto: None,
            treasury_authority: None,
            treasury_amount: None,
            rpc_rate_limit_per_10s: None,
        }
    }

    /// Every validator of the same real network loads the same
    /// `validators`/`genesis` data but has its own `listen_addr`/
    /// `rpc_addr`/`keypair_path` - `chain_id` must depend only on the
    /// former, or validators of the exact same network would each compute
    /// a different chain_id and reject every real transaction.
    #[test]
    fn chain_id_is_identical_across_validators_of_the_same_network_despite_differing_per_validator_fields() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None }];
        let genesis = vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 5_000_000 }];

        let mut a = config_with(validators.clone(), genesis.clone());
        let mut b = config_with(validators, genesis);
        a.rpc_addr = "127.0.0.1:28001".parse().unwrap();
        b.rpc_addr = "127.0.0.1:28002".parse().unwrap();
        a.listen_addr = "127.0.0.1:35001".parse().unwrap();
        b.listen_addr = "127.0.0.1:35009".parse().unwrap();

        assert_eq!(a.chain_id(), b.chain_id(), "same genesis data must produce the same chain_id regardless of per-validator network config");
    }

    /// `economics_v7` folds into `chain_id` ONLY when enabled, so a v6 (default,
    /// `false`) network's chain_id is byte-identical to before the field existed —
    /// its live transactions keep verifying. A v7 network gets a distinct chain_id
    /// (a genuinely separate, hard-forked network), and two v7 networks with
    /// different reward rates are distinct chains too.
    #[test]
    fn economics_v7_folds_into_chain_id_only_when_enabled() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None }];
        let genesis = vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 5_000_000 }];

        let v6 = config_with(validators.clone(), genesis.clone());
        let mut v7 = config_with(validators.clone(), genesis.clone());
        v7.economics_v7 = true;
        // v6 default is byte-identical to a config from before the field existed.
        assert_eq!(v6.chain_id(), config_with(validators.clone(), genesis.clone()).chain_id(), "v6 default unchanged");
        // v7 is a distinct network.
        assert_ne!(v6.chain_id(), v7.chain_id(), "a v7 network has a distinct chain_id");
        // Two v7 networks with different rounds_per_quanto are distinct chains.
        let mut v7_fast = config_with(validators, genesis);
        v7_fast.economics_v7 = true;
        v7_fast.rounds_per_quanto = Some(8);
        assert_ne!(v7.chain_id(), v7_fast.chain_id(), "economic params are part of the config hash");
    }

    /// The real, live-confirmed gap this closes (see
    /// `project-lessons-learned`): two genuinely independent networks -
    /// different genesis allocations - must get different chain_ids, or a
    /// transaction signed for one would still validate on the other.
    #[test]
    fn chain_id_differs_across_genuinely_different_networks() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None }];

        let network_a = config_with(validators.clone(), vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 1 }]);
        let network_b = config_with(validators, vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 2 }]);

        assert_ne!(network_a.chain_id(), network_b.chain_id(), "genuinely different genesis data must produce different chain_ids");
    }

    /// The whole point of `skip_serializing_if` on `name`: an existing network
    /// (validators with no name) must compute the EXACT same chain_id it did
    /// before the field existed, so adding this feature never breaks a live
    /// deployment. We prove it by checking the serialized bytes carry no
    /// `name` key when name is `None` (byte-identical to the old struct), and
    /// that setting a name does change the bytes (so it folds into chain_id).
    #[test]
    fn name_none_is_omitted_from_serialization_so_chain_id_is_unchanged() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let nameless = ValidatorConfig { pubkey_bundle: bundle.clone(), addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None };
        let named = ValidatorConfig { name: Some("Alice".into()), ..nameless.clone() };

        let nameless_json = serde_json::to_string(&nameless).unwrap();
        assert!(!nameless_json.contains("name"), "a nameless validator must serialize with no `name` key (byte-identical to pre-name configs, preserving chain_id)");

        let c_nameless = config_with(vec![nameless], vec![]);
        let c_named = config_with(vec![named], vec![]);
        assert_ne!(c_nameless.chain_id(), c_named.chain_id(), "setting a name folds it into the network's own chain_id");
    }
}
