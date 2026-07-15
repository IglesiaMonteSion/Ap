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
}

fn default_round_interval_ms() -> u64 {
    500
}

impl NodeConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
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
        let bytes = serde_json::to_vec(&(&self.validators, &self.genesis)).expect("genesis data always serializes");
        Sha3_256::digest(bytes).into()
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
