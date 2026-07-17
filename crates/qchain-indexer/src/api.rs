//! The QScan HTTP API + embedded frontend.
//!
//! Everything here is READ-ONLY over the index the ingestor built. The frontend
//! (an Etherscan-style single-page app) is served at `/`; the data it needs is
//! under `/api/*`. No endpoint touches the node or any keys - the indexer is a
//! pure read replica, so exposing it publicly can never affect consensus.

use crate::store::{decode_addr, Store};
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Store>,
    pub node: String,
    pub http: reqwest::Client,
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(index_html))
        .route("/qscan.js", get(js_asset))
        .route("/favicon.svg", get(favicon))
        .route("/api/stats", get(stats))
        .route("/api/txs", get(txs))
        .route("/api/tx/:hash", get(tx_detail))
        .route("/api/blocks", get(blocks))
        .route("/api/block/:round", get(block_detail))
        .route("/api/address/:addr", get(address))
        .route("/api/validators", get(validators))
        .route("/api/holders", get(holders))
        .route("/api/search", get(search))
        .route("/api/health", get(health))
        .with_state(state)
}

// ---- frontend assets ----

async fn index_html() -> Html<&'static str> {
    Html(include_str!("qscan.html"))
}

async fn js_asset() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8")], include_str!("qscan.js"))
}

async fn favicon() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/svg+xml")], include_str!("favicon.svg"))
}

// ---- query params ----

#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    page: usize,
    #[serde(default = "def_size")]
    size: usize,
    #[serde(default)]
    kind: Option<String>,
}
fn def_size() -> usize {
    25
}

const MAX_SIZE: usize = 100;

// ---- handlers ----

async fn health() -> Json<Value> {
    Json(json!({"ok": true}))
}

/// Home-page stat cards: chain height, totals the indexer owns, plus the
/// cached node figures (supply, burned, fee, validator count).
async fn stats(State(st): State<ApiState>) -> Json<Value> {
    let store = &st.store;
    let synced = store.get_meta_json("synced_round").and_then(|v| v.as_u64()).unwrap_or(0);
    let status = store.get_meta_json("status").unwrap_or(json!({}));
    let holders = store.get_meta_json("holders").unwrap_or(json!({}));
    let econ = store.get_meta_json("economics").unwrap_or(json!({}));
    let validators = store.get_meta_json("validators").unwrap_or(json!([]));
    // The node's /chain_id is an object {"chain_id":"…"}; surface the inner string.
    let chain_id = store
        .get_meta_json("chain_id")
        .and_then(|v| v.get("chain_id").cloned().or(Some(v)))
        .unwrap_or(json!(null));
    let val_count = validators.as_array().map(|a| a.len()).unwrap_or(0);
    Json(json!({
        "height": synced,
        "indexed_txs": store.total_txs(),
        "indexed_blocks": store.total_blocks(),
        "last_ingest_unix": store.get_meta_json("last_ingest_unix").and_then(|v| v.as_u64()).unwrap_or(0),
        "circulating": holders.get("total_balance"),
        "held_in_wallets": holders.get("held_in_wallets"),
        "held_in_programs": holders.get("held_in_programs"),
        "total_accounts": holders.get("total_accounts"),
        "wallet_accounts": holders.get("wallet_accounts"),
        "total_burned": econ.get("total_burned").or_else(|| holders.get("total_burned")),
        "total_emitted": econ.get("total_emitted"),
        "base_fee_per_byte": status.get("base_fee_per_byte"),
        "mempool_transactions": status.get("mempool_transactions"),
        "round_interval_ms": status.get("round_interval_ms"),
        "executed_transactions": status.get("executed_transactions"),
        "version": status.get("version"),
        "validators": val_count,
        "chain_id": chain_id,
    }))
}

async fn txs(State(st): State<ApiState>, Query(q): Query<Page>) -> Json<Value> {
    let size = q.size.clamp(1, MAX_SIZE);
    let kind = q.kind.as_deref().filter(|k| !k.is_empty() && *k != "all");
    let rows = st.store.list_txs(q.page, size, kind);
    Json(json!({"txs": rows, "page": q.page, "size": size, "total": st.store.total_txs()}))
}

/// A transaction's detail. We return the indexed summary and, best-effort, the
/// node's full receipt (`/transfers/:hash`) with before/after balances + Merkle
/// proofs when it's still in the node's window.
async fn tx_detail(State(st): State<ApiState>, Path(hash): Path<String>) -> Result<Json<Value>, (StatusCode, String)> {
    let hash = hash.trim().to_lowercase();
    // Only a real 64-hex tx hash is ever a valid lookup; reject anything else
    // before it reaches the store or is interpolated into the node URL (avoids
    // path/query injection via a crafted :hash segment).
    if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((StatusCode::BAD_REQUEST, "not a valid transaction hash".into()));
    }
    let rec = st.store.get_tx_by_hash(&hash);
    let full = {
        let url = format!("{}/transfers/{}", st.node.trim_end_matches('/'), hash);
        st.http.get(&url).send().await.ok().and_then(|r| if r.status().is_success() { Some(r) } else { None })
    };
    let full_json: Option<Value> = match full {
        Some(r) => r.json().await.ok(),
        None => None,
    };
    if rec.is_none() && full_json.is_none() {
        return Err((StatusCode::NOT_FOUND, "transaction not found in index".into()));
    }
    Ok(Json(json!({"tx": rec, "receipt": full_json})))
}

async fn blocks(State(st): State<ApiState>, Query(q): Query<Page>) -> Json<Value> {
    let size = q.size.clamp(1, MAX_SIZE);
    let rows = st.store.list_blocks(q.page, size);
    Json(json!({"blocks": rows, "page": q.page, "size": size, "total": st.store.total_blocks()}))
}

async fn block_detail(State(st): State<ApiState>, Path(round): Path<u64>) -> Result<Json<Value>, (StatusCode, String)> {
    let block = st.store.get_block(round);
    let txs = st.store.txs_in_round(round);
    if block.is_none() && txs.is_empty() {
        return Err((StatusCode::NOT_FOUND, "block (round) not indexed".into()));
    }
    Ok(Json(json!({"block": block, "txs": txs})))
}

/// Address page: the account state (fetched live from the node), plus the full
/// indexed transaction history of that address (paginated), plus a live stake
/// lookup if the address is a stake account.
async fn address(State(st): State<ApiState>, Path(addr): Path<String>, Query(q): Query<Page>) -> Result<Json<Value>, (StatusCode, String)> {
    let addr = addr.trim().to_string();
    if decode_addr(&addr).is_none() {
        return Err((StatusCode::BAD_REQUEST, "not a valid address".into()));
    }
    let size = q.size.clamp(1, MAX_SIZE);
    let (rows, total) = st.store.address_txs(&addr, q.page, size, 100_000);
    let account = fetch_node(&st, &format!("/account/{}", addr)).await;
    let stake = fetch_node(&st, &format!("/stake/{}", addr)).await;
    Ok(Json(json!({
        "address": addr,
        "account": account,
        "stake": stake,
        "txs": rows,
        "tx_total": total,
        "page": q.page,
        "size": size,
    })))
}

async fn validators(State(st): State<ApiState>) -> Json<Value> {
    Json(json!({
        "validators": st.store.get_meta_json("validators").unwrap_or(json!([])),
        "registry": st.store.get_meta_json("validator_registry").unwrap_or(json!(null)),
        "active": st.store.get_meta_json("active_validators").unwrap_or(json!(null)),
        "economics": st.store.get_meta_json("economics").unwrap_or(json!(null)),
    }))
}

async fn holders(State(st): State<ApiState>) -> Json<Value> {
    Json(st.store.get_meta_json("holders").unwrap_or(json!({"top": []})))
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
}

/// Classify a search string the way Etherscan's one box does: a 64-hex string
/// is a transaction hash; an all-digits string is a block (round) number; a
/// valid base58 32-byte string is an address.
async fn search(State(st): State<ApiState>, Query(sq): Query<SearchQ>) -> Json<Value> {
    let q = sq.q.trim();
    if q.is_empty() {
        return Json(json!({"type": "none"}));
    }
    // Transaction hash (64 hex chars).
    if q.len() == 64 && q.chars().all(|c| c.is_ascii_hexdigit()) {
        let low = q.to_lowercase();
        if st.store.get_tx_by_hash(&low).is_some() {
            return Json(json!({"type": "tx", "target": low}));
        }
        // Might still be in the node's window even if not indexed yet.
        return Json(json!({"type": "tx", "target": low}));
    }
    // Block / round number.
    if q.chars().all(|c| c.is_ascii_digit()) {
        if let Ok(r) = q.parse::<u64>() {
            return Json(json!({"type": "block", "target": r}));
        }
    }
    // Address.
    if decode_addr(q).is_some() {
        return Json(json!({"type": "address", "target": q}));
    }
    Json(json!({"type": "unknown"}))
}

/// Fetch a JSON value from the node, `null` on any failure (used for the live
/// account/stake lookups an address page shows).
async fn fetch_node(st: &ApiState, path: &str) -> Value {
    let url = format!("{}{}", st.node.trim_end_matches('/'), path);
    match st.http.get(&url).send().await {
        Ok(r) if r.status().is_success() => r.json::<Value>().await.unwrap_or(Value::Null),
        _ => Value::Null,
    }
}
