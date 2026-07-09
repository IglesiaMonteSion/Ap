use supersol_core::{Ledger, Poh, PohEntry, ProgramRegistry, Transaction};
use supersol_crypto::Pubkey;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct AppState {
    pub ledger: Mutex<Ledger>,
    pub poh: Mutex<Poh>,
    pub programs: ProgramRegistry,
    pub pending_txs: Mutex<Vec<Transaction>>,
    pub pending_airdrops: Mutex<Vec<(Pubkey, u64)>>,
    pub pending_poh_entries: Mutex<Vec<PohEntry>>,
    pub slot: Mutex<u64>,
    pub genesis_seed: [u8; 32],
    pub identity: Pubkey,
    pub faucet_enabled: bool,
    pub faucet_max_units: u64,
    pub fee_units: u64,
    pub ledger_path: PathBuf,
}

impl AppState {
    /// The blockhash a client should attach to a new transaction: the most
    /// recently finalized block's hash, or the genesis seed before the first
    /// block has been produced.
    pub fn latest_blockhash(&self) -> [u8; 32] {
        let ledger = self.ledger.lock().unwrap();
        ledger.latest_block().map(|b| b.blockhash).unwrap_or(self.genesis_seed)
    }

    pub fn persist(&self) -> anyhow::Result<()> {
        let ledger = self.ledger.lock().unwrap();
        let bytes = serde_json::to_vec(&*ledger)?;
        let tmp_path = self.ledger_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, bytes)?;
        std::fs::rename(&tmp_path, &self.ledger_path)?;
        Ok(())
    }
}
