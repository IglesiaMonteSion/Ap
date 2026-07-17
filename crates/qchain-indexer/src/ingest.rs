//! Polls a validator's RPC and writes new transactions/blocks into the index.
//!
//! The node serves a rolling window, newest-first. Each tick we page back
//! through `/transfers` and `/staking_activity` until we hit a page that is
//! entirely already-indexed (dedup by tx hash), so as long as we poll faster
//! than the node's window churns (~5000 txs) we lose nothing. New rows are
//! inserted OLDEST-first so `seq` increases with chain order. `/rounds` gives
//! the authoritative per-round byte/tx counts for block records; `/status`,
//! `/holders`, `/economics`, `/validators`, `/validator_registry`,
//! `/active_validators` are cached for the home/rich-list/validators pages.

use crate::store::{now_unix, BlockRecord, Store, TxRecord};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

#[derive(Deserialize)]
struct TransferSummary {
    tx_hash: String,
    from: String,
    to: String,
    amount: u64,
    fee: u64,
    round: u64,
}

#[derive(Deserialize)]
struct StakingSummary {
    tx_hash: String,
    kind: String,
    staker: String,
    validator: String,
    stake_account: String,
    amount: u64,
    round: u64,
}

#[derive(Deserialize)]
struct RoundFill {
    round: u64,
    bytes: u64,
    tx_count: u32,
    fill_pct: u32,
    cap_bytes: u64,
    target_bytes: u64,
}

#[derive(Deserialize)]
struct StatusPartial {
    next_round: u64,
}

/// How far back to page through the node's rolling window in one tick before
/// giving up (the node keeps ~5000 receipts; we cap generously above that).
const MAX_PAGES: usize = 40;
const PAGE: usize = 500;

pub struct Ingestor {
    pub node: String,
    pub store: Arc<Store>,
    pub http: reqwest::Client,
    /// Ticks between refreshes of the cached node snapshots (holders/economics/
    /// validators) - those are heavier and don't need per-tick freshness.
    tick: u64,
}

impl Ingestor {
    pub fn new(node: String, store: Arc<Store>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { node, store, http, tick: 0 }
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Option<T> {
        let url = format!("{}{}", self.node.trim_end_matches('/'), path);
        let resp = self.http.get(&url).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json::<T>().await.ok()
    }

    async fn get_raw(&self, path: &str) -> Option<serde_json::Value> {
        self.get_json::<serde_json::Value>(path).await
    }

    /// One ingestion pass. Best-effort: any failed fetch just means this tick
    /// indexes less; the next tick catches up.
    pub async fn tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        let ts = now_unix();

        // Chain height (also confirms the node is reachable).
        let synced_round = self
            .get_json::<StatusPartial>("/status")
            .await
            .map(|s| s.next_round.saturating_sub(1));

        self.ingest_transfers(ts).await;
        self.ingest_staking(ts).await;
        self.ingest_rounds(ts).await;

        // Cache the heavier node snapshots for the frontend, less often.
        if self.tick % 5 == 1 {
            for (path, key) in [
                ("/status", "status"),
                ("/economics", "economics"),
                ("/holders?limit=100", "holders"),
                ("/validators", "validators"),
                ("/validator_registry", "validator_registry"),
                ("/active_validators", "active_validators"),
                ("/chain_id", "chain_id"),
            ] {
                if let Some(v) = self.get_raw(path).await {
                    self.store.set_meta_json(key, &v);
                }
            }
        }

        if let Some(r) = synced_round {
            self.store.set_meta_json("synced_round", &serde_json::json!(r));
        }
        self.store.set_meta_json("last_ingest_unix", &serde_json::json!(ts));
    }

    async fn ingest_transfers(&self, ts: u64) {
        let mut fresh: Vec<TxRecord> = Vec::new();
        'paging: for p in 0..MAX_PAGES {
            let path = format!("/transfers?limit={}&offset={}", PAGE, p * PAGE);
            let Some(rows) = self.get_json::<Vec<TransferSummary>>(&path).await else { break };
            if rows.is_empty() {
                break;
            }
            let mut all_seen = true;
            for r in &rows {
                if self.store.has_hash(&r.tx_hash) {
                    continue;
                }
                all_seen = false;
                fresh.push(TxRecord {
                    seq: 0,
                    hash: r.tx_hash.clone(),
                    kind: "transfer".into(),
                    from: r.from.clone(),
                    to: r.to.clone(),
                    stake_account: String::new(),
                    amount: r.amount,
                    fee: r.fee,
                    round: r.round,
                    ts,
                });
            }
            // A full page that was entirely already-indexed means we've caught
            // up with what we had - nothing older can be new.
            if all_seen {
                break 'paging;
            }
        }
        // Insert oldest-first so seq tracks chain order.
        for rec in fresh.into_iter().rev() {
            let _ = self.store.insert_tx(rec);
        }
    }

    async fn ingest_staking(&self, ts: u64) {
        let mut fresh: Vec<TxRecord> = Vec::new();
        for p in 0..MAX_PAGES {
            let path = format!("/staking_activity?limit={}&offset={}", PAGE, p * PAGE);
            let Some(rows) = self.get_json::<Vec<StakingSummary>>(&path).await else { break };
            if rows.is_empty() {
                break;
            }
            let mut all_seen = true;
            for r in &rows {
                if self.store.has_hash(&r.tx_hash) {
                    continue;
                }
                all_seen = false;
                fresh.push(TxRecord {
                    seq: 0,
                    hash: r.tx_hash.clone(),
                    kind: r.kind.clone(),
                    from: r.staker.clone(),
                    to: r.validator.clone(),
                    stake_account: r.stake_account.clone(),
                    amount: r.amount,
                    fee: 0,
                    round: r.round,
                    ts,
                });
            }
            if all_seen {
                break;
            }
        }
        for rec in fresh.into_iter().rev() {
            let _ = self.store.insert_tx(rec);
        }
    }

    async fn ingest_rounds(&self, ts: u64) {
        let Some(rows) = self.get_json::<Vec<RoundFill>>("/rounds?limit=300").await else { return };
        for r in rows {
            // Aggregate fees/burn from the transfers we stored for this round.
            let txs = self.store.txs_in_round(r.round);
            let fees: u64 = txs.iter().map(|t| t.fee).sum();
            let burned = fees / 2;
            let rec = BlockRecord {
                round: r.round,
                tx_count: r.tx_count,
                bytes: r.bytes,
                fill_pct: r.fill_pct,
                cap_bytes: r.cap_bytes,
                target_bytes: r.target_bytes,
                fees,
                burned,
                ts,
            };
            let _ = self.store.upsert_block(rec);
        }
    }
}

/// Spawn the polling loop; runs until the process exits.
pub async fn run(node: String, store: Arc<Store>, poll_ms: u64) {
    let mut ing = Ingestor::new(node, store);
    let mut interval = tokio::time::interval(Duration::from_millis(poll_ms.max(200)));
    loop {
        interval.tick().await;
        ing.tick().await;
    }
}
