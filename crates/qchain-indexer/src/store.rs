//! Persistent index built from the node's RPC, on `sled`.
//!
//! The whole point of the indexer is DURABILITY of full history: a validator
//! only keeps a rolling window of transfer receipts (~5000) in memory/disk, and
//! nothing at all lets you query "every transaction of address X" or "block
//! (round) N and its transactions". This store polls the node and writes every
//! transaction it sees into its own database, keyed so the QScan frontend can
//! answer the same questions Etherscan does: latest blocks/txs, a tx by hash, an
//! address page with its full history, blocks and their contents, and search.
//!
//! Trees:
//! - `tx`       : `be(seq)`            -> JSON `TxRecord`   (the global tx log; reverse-iterate for newest-first)
//! - `hash2seq` : `hash_hex` (utf8)    -> `be(seq)`        (dedup on ingest + lookup a tx by hash)
//! - `addr`     : `addr32 ++ be(seq)`  -> `[]`             (prefix-scan for one address's txs)
//! - `blocks`   : `be(round)`          -> JSON `BlockRecord`
//! - `meta`     : small key/value (cursor, chain_id, cached node snapshots)
//!
//! `seq` is a monotonic insertion counter the indexer owns; because new txs are
//! inserted oldest-first within each poll batch, a higher `seq` always means a
//! more-recently-produced transaction, so reverse iteration is "newest first".

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// One transaction as the explorer shows it - the union of a transfer and a
/// staking action, with a `kind` the UI switches on (Etherscan-style single
/// list rather than separate tabs). `from`/`to` are base58 address strings as
/// the node serialized them; `ts` is the Unix time the indexer FIRST saw it
/// (0 for rows back-filled from before the indexer ran - the UI falls back to
/// round-based age for those).
#[derive(Serialize, Deserialize, Clone)]
pub struct TxRecord {
    pub seq: u64,
    pub hash: String,
    /// "transfer" | "delegate" | "undelegate" | "unbonding_started" | "claim_reward"
    pub kind: String,
    pub from: String,
    /// For a transfer: the recipient. For staking: the validator delegated to.
    pub to: String,
    /// For staking only: the stake account address ("" for a transfer).
    #[serde(default)]
    pub stake_account: String,
    pub amount: u64,
    pub fee: u64,
    pub round: u64,
    pub ts: u64,
}

/// One block = one consensus round. `bytes`/`tx_count` are authoritative from
/// the node's `/rounds` (they count contract-call txs the transfer log never
/// sees); `fees`/`burned` are aggregated from the transfers the indexer stored
/// for that round (honest limitation: staking fee is 0 and contract fees vary,
/// same caveat the node dashboard documents).
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct BlockRecord {
    pub round: u64,
    pub tx_count: u32,
    pub bytes: u64,
    pub fill_pct: u32,
    pub cap_bytes: u64,
    pub target_bytes: u64,
    pub fees: u64,
    pub burned: u64,
    pub ts: u64,
}

#[derive(Clone)]
pub struct Store {
    /// Kept to hold the database open for the process lifetime (the trees are
    /// handles into it).
    #[allow(dead_code)]
    db: sled::Db,
    tx: sled::Tree,
    hash2seq: sled::Tree,
    addr: sled::Tree,
    blocks: sled::Tree,
    meta: sled::Tree,
}

fn be(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Self {
            tx: db.open_tree("tx")?,
            hash2seq: db.open_tree("hash2seq")?,
            addr: db.open_tree("addr")?,
            blocks: db.open_tree("blocks")?,
            meta: db.open_tree("meta")?,
            db,
        })
    }

    // ---- cursor / small meta ----

    pub fn last_seq(&self) -> u64 {
        self.meta
            .get("last_seq")
            .ok()
            .flatten()
            .and_then(|v| v.as_ref().try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0)
    }

    fn set_last_seq(&self, seq: u64) {
        let _ = self.meta.insert("last_seq", &be(seq));
    }

    pub fn total_txs(&self) -> u64 {
        self.tx.len() as u64
    }

    pub fn total_blocks(&self) -> u64 {
        self.blocks.len() as u64
    }

    pub fn set_meta_json(&self, key: &str, value: &serde_json::Value) {
        if let Ok(bytes) = serde_json::to_vec(value) {
            let _ = self.meta.insert(key.as_bytes(), bytes);
        }
    }

    pub fn get_meta_json(&self, key: &str) -> Option<serde_json::Value> {
        self.meta
            .get(key.as_bytes())
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
    }

    // ---- transactions ----

    pub fn has_hash(&self, hash: &str) -> bool {
        self.hash2seq.get(hash.as_bytes()).ok().flatten().is_some()
    }

    /// Insert a new transaction (caller has already checked it's unseen). Assigns
    /// the next `seq`, writes the global log + hash index + an address index for
    /// every party of the record (from, to, and the stake account if any).
    /// Returns the assigned seq.
    pub fn insert_tx(&self, mut rec: TxRecord) -> Result<u64> {
        let seq = self.last_seq() + 1;
        rec.seq = seq;
        for p in [rec.from.as_str(), rec.to.as_str(), rec.stake_account.as_str()] {
            if p.is_empty() {
                continue;
            }
            if let Some(a32) = decode_addr(p) {
                let mut key = [0u8; 40];
                key[..32].copy_from_slice(&a32);
                key[32..].copy_from_slice(&be(seq));
                self.addr.insert(key, &[])?;
            }
        }
        self.hash2seq.insert(rec.hash.as_bytes(), &be(seq))?;
        let body = serde_json::to_vec(&rec)?;
        self.tx.insert(be(seq), body)?;
        self.set_last_seq(seq);
        Ok(seq)
    }

    pub fn get_tx_by_hash(&self, hash: &str) -> Option<TxRecord> {
        let seq = self.hash2seq.get(hash.as_bytes()).ok().flatten()?;
        let raw = self.tx.get(seq).ok().flatten()?;
        serde_json::from_slice(&raw).ok()
    }

    /// Newest-first page of the global tx list, optionally filtered by `kind`.
    /// `kind == None` returns everything.
    pub fn list_txs(&self, page: usize, size: usize, kind: Option<&str>) -> Vec<TxRecord> {
        let mut out = Vec::with_capacity(size);
        let mut skipped = 0usize;
        let skip = page.saturating_mul(size);
        for item in self.tx.iter().rev() {
            let Ok((_, v)) = item else { continue };
            let Ok(rec) = serde_json::from_slice::<TxRecord>(&v) else { continue };
            if let Some(k) = kind {
                if rec.kind != k {
                    continue;
                }
            }
            if skipped < skip {
                skipped += 1;
                continue;
            }
            out.push(rec);
            if out.len() >= size {
                break;
            }
        }
        out
    }

    /// Every seq for an address, newest-first, capped. Used to page an address's
    /// transaction history.
    pub fn address_txs(&self, addr: &str, page: usize, size: usize, cap: usize) -> (Vec<TxRecord>, usize) {
        let Some(a32) = decode_addr(addr) else { return (vec![], 0) };
        let mut seqs: Vec<u64> = Vec::new();
        for (k, _) in self.addr.scan_prefix(a32).take(cap).flatten() {
            if k.len() == 40 {
                if let Ok(s) = k[32..].try_into() {
                    seqs.push(u64::from_be_bytes(s));
                }
            }
        }
        let total = seqs.len();
        seqs.sort_unstable();
        seqs.reverse();
        let skip = page.saturating_mul(size);
        let mut out = Vec::with_capacity(size);
        for s in seqs.into_iter().skip(skip).take(size) {
            if let Some(raw) = self.tx.get(be(s)).ok().flatten() {
                if let Ok(rec) = serde_json::from_slice::<TxRecord>(&raw) {
                    out.push(rec);
                }
            }
        }
        (out, total)
    }

    // ---- blocks (rounds) ----

    pub fn upsert_block(&self, rec: BlockRecord) -> Result<()> {
        // Preserve the first-seen ts if the block already exists.
        let existing = self.get_block(rec.round);
        let mut rec = rec;
        if let Some(prev) = existing {
            if prev.ts != 0 {
                rec.ts = prev.ts;
            }
        }
        self.blocks.insert(be(rec.round), serde_json::to_vec(&rec)?)?;
        Ok(())
    }

    pub fn get_block(&self, round: u64) -> Option<BlockRecord> {
        let raw = self.blocks.get(be(round)).ok().flatten()?;
        serde_json::from_slice(&raw).ok()
    }

    pub fn list_blocks(&self, page: usize, size: usize) -> Vec<BlockRecord> {
        let mut out = Vec::with_capacity(size);
        let skip = page.saturating_mul(size);
        for (_, v) in self.blocks.iter().rev().skip(skip).take(size).flatten() {
            if let Ok(rec) = serde_json::from_slice::<BlockRecord>(&v) {
                out.push(rec);
            }
        }
        out
    }

    pub fn txs_in_round(&self, round: u64) -> Vec<TxRecord> {
        // Scan the tail of the tx log (rounds are near-monotonic with seq, so
        // the newest few hundred entries cover any recent round); fall back to a
        // bounded scan. For a specific round we walk from newest and collect
        // matches until we pass below the round.
        let mut out = Vec::new();
        let mut scanned = 0usize;
        for item in self.tx.iter().rev() {
            if scanned > 200_000 {
                break;
            }
            scanned += 1;
            let Ok((_, v)) = item else { continue };
            let Ok(rec) = serde_json::from_slice::<TxRecord>(&v) else { continue };
            if rec.round == round {
                out.push(rec);
            } else if rec.round < round && scanned > 50 {
                // We've walked past the target round's window; stop.
                break;
            }
        }
        out.reverse();
        out
    }
}

/// Decode a base58 address to its 32 raw bytes, or `None` if it isn't a
/// well-formed 32-byte address.
pub fn decode_addr(s: &str) -> Option<[u8; 32]> {
    let v = bs58::decode(s).into_vec().ok()?;
    v.try_into().ok()
}

/// Current Unix time in seconds (real wall clock - this is an ordinary service
/// process, unlike a workflow script).
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
