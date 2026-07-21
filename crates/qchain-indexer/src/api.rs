//! The QScan HTTP API + embedded frontend.
//!
//! Everything here is READ-ONLY over the index the ingestor built. The frontend
//! (an Etherscan-style single-page app) is served at `/`; the data it needs is
//! under `/api/*`. No endpoint touches the node or any keys - the indexer is a
//! pure read replica, so exposing it publicly can never affect consensus.

use crate::store::{decode_addr, Store};
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Short read-through TTL for live node lookups. The node RPC (127.0.0.1) is
/// reachable only through this public read replica, so an unauthenticated flood
/// of `/api/address`/`/api/tx` would otherwise amplify onto the validator's
/// consensus `state` lock (each node hit takes it). Caching collapses a flood
/// to at most one node hit per key per TTL.
const NODE_CACHE_TTL: Duration = Duration::from_millis(1500);
/// Bound the distinct-key growth of the node cache (addresses are attacker-
/// chosen); cleared wholesale past this size rather than tracking per-entry LRU.
const NODE_CACHE_MAX: usize = 20_000;
/// Cap on concurrent UPSTREAM fetches to the node across ALL requests
/// (QCH-QSCAN-001): a flood of DISTINCT cold keys would otherwise open one node
/// connection per request and amplify onto the validator's consensus lock. With
/// the singleflight below, in practice only cold-key misses reach here.
pub const MAX_UPSTREAM_FETCHES: usize = 16;
/// Bound the in-flight singleflight map so a flood of distinct cold keys can't
/// grow it without bound; past this we skip coalescing (still semaphore-bounded).
const MAX_INFLIGHT_KEYS: usize = 4_096;

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Store>,
    pub node: String,
    pub http: reqwest::Client,
    pub node_cache: Arc<Mutex<HashMap<String, (Instant, Value)>>>,
    /// Singleflight (QCH-QSCAN-001): one per-key async lock coalesces a
    /// cache-miss STAMPEDE — N concurrent requests for the same cold key make a
    /// SINGLE upstream node fetch, not N. The first request holds the key's lock
    /// while it fetches+caches; the rest wait, then find the fresh cache entry.
    pub inflight: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// Global cap on concurrent upstream node fetches (`MAX_UPSTREAM_FETCHES`).
    pub node_sem: Arc<tokio::sync::Semaphore>,
    /// Public URL of the non-custodial wallet to open for signing (deploy /
    /// interact). None = the deploy/interact UI is hidden (read-only contracts).
    pub wallet_url: Option<String>,
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
        .route("/api/programs", get(programs))
        .route("/api/search", get(search))
        .route("/api/config", get(config))
        .route("/api/health", get(health))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

/// Security headers on the internet-facing explorer (parity with the wallet).
/// The SPA loads only same-origin external JS (`/qscan.js`, no inline scripts or
/// event handlers) and talks only to `/api/*`, so a strict CSP fits; inline
/// styles need `style-src 'unsafe-inline'`. Defense-in-depth backstop under the
/// per-value `esc()` escaping, plus anti-framing/anti-sniff.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; \
             frame-ancestors 'none'; form-action 'self'",
        ),
    );
    h.insert(header::X_FRAME_OPTIONS, header::HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, header::HeaderValue::from_static("no-referrer"));
    resp
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

/// Frontend config: the wallet URL to open for signing (deploy/interact), when
/// the operator configured `--wallet-url`. Absent = the deploy/interact UI stays
/// hidden and QScan is read-only. QScan never receives any key; signing happens
/// entirely in the wallet popup over the postMessage bridge.
async fn config(State(st): State<ApiState>) -> Json<Value> {
    Json(json!({ "wallet_url": st.wallet_url }))
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
    // Route through the cached fetch (same amplification protection as the
    // address page); a Null result means the node had no such receipt.
    let full = fetch_node(&st, &format!("/transfers/{}", hash)).await;
    let full_json: Option<Value> = if full.is_null() { None } else { Some(full) };
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

/// Deployed smart contracts (read-only), for QScan's "Contratos" section.
/// Proxied live from the node's `/programs` (short-TTL cached) — metadata only
/// (address, code-hash, entry point, size), never keys or bytecode.
async fn programs(State(st): State<ApiState>) -> Json<Value> {
    Json(fetch_node(&st, "/programs?limit=500").await)
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
    // Fast path: serve from the short-TTL cache if fresh (never hold the std
    // Mutex across an `.await`).
    if let Some(v) = cache_get_fresh(st, path) {
        return v;
    }

    // SINGLEFLIGHT (QCH-QSCAN-001): take a per-key async lock so a cache-miss
    // stampede for the same cold key collapses to ONE upstream fetch. Bounded:
    // past `MAX_INFLIGHT_KEYS` we skip coalescing (still semaphore-bounded).
    let key_lock: Option<Arc<tokio::sync::Mutex<()>>> = {
        let mut inflight = st.inflight.lock().unwrap();
        if inflight.len() >= MAX_INFLIGHT_KEYS {
            None
        } else {
            Some(inflight.entry(path.to_string()).or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))).clone())
        }
    };
    let _guard = match &key_lock {
        Some(l) => Some(l.lock().await),
        None => None,
    };
    // Re-check the cache: the request that held this lock before us may have
    // just populated it, so we return without a second upstream fetch.
    if key_lock.is_some() {
        if let Some(v) = cache_get_fresh(st, path) {
            drop(_guard);
            st.inflight.lock().unwrap().remove(path);
            return v;
        }
    }

    // Global cap on concurrent upstream fetches. If the semaphore is closed
    // (never, in practice) treat as a miss.
    let val = match st.node_sem.acquire().await {
        Ok(_permit) => {
            let url = format!("{}{}", st.node.trim_end_matches('/'), path);
            match st.http.get(&url).send().await {
                Ok(r) if r.status().is_success() => r.json::<Value>().await.unwrap_or(Value::Null),
                _ => Value::Null,
            }
        }
        Err(_) => Value::Null,
    };
    // Cache only successful lookups (don't pin a transient failure).
    if !val.is_null() {
        let mut cache = st.node_cache.lock().unwrap();
        if cache.len() >= NODE_CACHE_MAX {
            cache.clear();
        }
        cache.insert(path.to_string(), (Instant::now(), val.clone()));
    }
    drop(_guard);
    if key_lock.is_some() {
        st.inflight.lock().unwrap().remove(path);
    }
    val
}

/// Return the cached value for `path` if present and within the TTL.
fn cache_get_fresh(st: &ApiState, path: &str) -> Option<Value> {
    let cache = st.node_cache.lock().unwrap();
    cache.get(path).filter(|(t, _)| t.elapsed() < NODE_CACHE_TTL).map(|(_, v)| v.clone())
}
