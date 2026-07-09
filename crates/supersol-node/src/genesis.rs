use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The genesis record for a SuperSol ledger: just a random seed for the
/// Proof of History chain. Deliberately empty of any pre-funded "foundation"
/// accounts - every unit of supply in this network is minted later, on
/// request, through the devnet faucet or (in a future phase) validator
/// rewards, rather than pre-allocated to insiders at network creation.
#[derive(Serialize, Deserialize)]
pub struct Genesis {
    pub poh_seed: [u8; 32],
}

impl Genesis {
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            Ok(serde_json::from_slice(&bytes)?)
        } else {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            let genesis = Genesis { poh_seed: seed };
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, serde_json::to_vec_pretty(&genesis)?)?;
            Ok(genesis)
        }
    }
}
