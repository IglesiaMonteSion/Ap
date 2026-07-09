use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use supersol_core::{Block, Ledger, Poh, PohEntry, ProgramRegistry, Transaction};
use supersol_crypto::Pubkey;

/// Small, resumable checkpoint of the chain tip - just enough to resume in
/// O(1) without replaying or re-reading the whole block history.
#[derive(Serialize, Deserialize)]
pub struct MetaFile {
    pub slot: u64,
    #[serde(with = "supersol_core::hex32")]
    pub last_blockhash: [u8; 32],
}

pub struct AppState {
    pub ledger: Mutex<Ledger>,
    pub poh: Mutex<Poh>,
    pub programs: ProgramRegistry,
    pub pending_txs: Mutex<Vec<Transaction>>,
    pub pending_airdrops: Mutex<Vec<(Pubkey, u64)>>,
    pub pending_poh_entries: Mutex<Vec<PohEntry>>,
    pub identity: Pubkey,
    pub faucet_enabled: bool,
    pub faucet_max_units: u64,
    pub fee_units: u64,
    pub accounts_path: PathBuf,
    pub meta_path: PathBuf,
    pub blocks_log_path: PathBuf,
}

impl AppState {
    /// The blockhash a client should attach to a new transaction: the most
    /// recently finalized block's hash, or the genesis seed before the first
    /// block has been produced.
    pub fn latest_blockhash(&self) -> [u8; 32] {
        self.ledger.lock().unwrap().latest_blockhash()
    }

    pub fn slot(&self) -> u64 {
        self.ledger.lock().unwrap().slot
    }

    /// Durably record a newly produced block and refresh the resumable
    /// checkpoint. Deliberately cheap regardless of how long the chain has
    /// grown: the block is only *appended* to `blocks.log` (never rewritten),
    /// and the two snapshot files only ever contain current-state-sized data
    /// (the account map, and a few bytes of chain-tip metadata) - never the
    /// full history. This is what keeps disk I/O per block flat instead of
    /// growing with the chain, so running a validator stays cheap even after
    /// millions of blocks.
    pub fn persist_block(&self, block: &Block) -> anyhow::Result<()> {
        let mut line = serde_json::to_vec(block)?;
        line.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.blocks_log_path)?;
        file.write_all(&line)?;

        let (accounts_bytes, meta) = {
            let ledger = self.ledger.lock().unwrap();
            (
                serde_json::to_vec(&ledger.accounts)?,
                MetaFile {
                    slot: ledger.slot,
                    last_blockhash: ledger.last_blockhash,
                },
            )
        };
        atomic_write(&self.accounts_path, &accounts_bytes)?;
        atomic_write(&self.meta_path, &serde_json::to_vec(&meta)?)?;
        Ok(())
    }

    /// Look up a block by slot: check the in-memory recent-blocks window
    /// first, and only fall back to scanning the append-only log (an O(n)
    /// operation, but only paid per *query* for old history, never per
    /// block produced) if it has already been evicted from memory.
    pub fn get_block(&self, slot: u64) -> anyhow::Result<Option<Block>> {
        if let Some(block) = self.ledger.lock().unwrap().get_recent_block(slot) {
            return Ok(Some(block.clone()));
        }
        scan_blocks_log_for_slot(&self.blocks_log_path, slot)
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, bytes)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn scan_blocks_log_for_slot(path: &Path, slot: u64) -> anyhow::Result<Option<Block>> {
    use std::io::{BufRead, BufReader};

    if !path.exists() {
        return Ok(None);
    }
    let file = std::fs::File::open(path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let block: Block = serde_json::from_str(&line)?;
        if block.slot == slot {
            return Ok(Some(block));
        }
    }
    Ok(None)
}
