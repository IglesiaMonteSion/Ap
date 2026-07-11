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
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000 }];
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
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000 }];

        let network_a = config_with(validators.clone(), vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 1 }]);
        let network_b = config_with(validators, vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 2 }]);

        assert_ne!(network_a.chain_id(), network_b.chain_id(), "genuinely different genesis data must produce different chain_ids");
    }
}
