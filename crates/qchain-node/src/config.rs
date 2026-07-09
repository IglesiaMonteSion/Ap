//! Node configuration: everything needed to join the phase-1 testnet as one
//! validator - own keypair, the full (fixed, phase-1) validator set with
//! its stake and network addresses, and genesis allocations. JSON, loaded
//! once at startup; there is no dynamic validator-set membership yet (see
//! `ARCHITECTURE.md`'s phase-1 out-of-scope list - that's a governance
//! feature for a later phase).

use qchain_crypto::{Pubkey, PublicKeyBundle};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

#[derive(Clone, Deserialize)]
pub struct ValidatorConfig {
    pub pubkey_bundle: PublicKeyBundle,
    pub addr: SocketAddr,
    pub stake: u64,
}

#[derive(Clone, Deserialize)]
pub struct GenesisAllocation {
    pub address: Pubkey,
    pub balance: u64,
}

#[derive(Deserialize)]
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
}

fn default_round_interval_ms() -> u64 {
    500
}

impl NodeConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}
