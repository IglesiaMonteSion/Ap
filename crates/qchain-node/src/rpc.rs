//! JSON-RPC (plain HTTP+JSON, not a JSON-RPC-2.0-envelope) surface for
//! wallet/client traffic - what `qchain-cli` talks to. Deliberately small:
//! submit a transaction, read an account, read node status.

use crate::engine::{Engine, EconomicsResponse, HoldersResponse, SnapshotMeta, SnapshotPage, StarkProofError, StarkProofResponse, StateSnapshot, StatusResponse};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use qchain_core::{Account, Transaction};
use qchain_crypto::Pubkey;
use qchain_execution::TransferReceipt;
use serde_json::json;
use std::sync::Arc;

/// Per-IP RPC rate limiter with a temporary ban (task #196, QCH-S6). A sliding
/// 10-second window per client IP; once a single IP exceeds `limit` requests in
/// a window it is banned for `BAN`. Opt-in via `NodeConfig::rpc_rate_limit_per_10s`
/// (default off, zero overhead) — meant for a publicly exposed RPC, not the
/// loopback-private default. The tracked-IP map is bounded (`MAX_TRACKED_IPS`)
/// so the limiter can't itself be turned into an OOM by a spray of source IPs.
#[derive(Clone)]
struct RateLimiter {
    inner: Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, IpState>>>,
    limit: u32,
}

struct IpState {
    window_start: std::time::Instant,
    count: u32,
    banned_until: Option<std::time::Instant>,
}

const RL_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
const RL_BAN: std::time::Duration = std::time::Duration::from_secs(60);
const MAX_TRACKED_IPS: usize = 100_000;

impl RateLimiter {
    fn new(limit: u32) -> Self {
        Self { inner: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())), limit }
    }
    /// `true` = allowed, `false` = throttled (429). Pure per-IP token counting.
    fn allow(&self, ip: std::net::IpAddr) -> bool {
        let now = std::time::Instant::now();
        let mut m = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        // Bound the map: if it's full and this is a new IP, drop entries whose
        // window has elapsed and that aren't actively banned (cheap GC).
        if m.len() >= MAX_TRACKED_IPS && !m.contains_key(&ip) {
            m.retain(|_, s| s.banned_until.map(|b| now < b).unwrap_or(false) || now.duration_since(s.window_start) < RL_WINDOW);
        }
        let st = m.entry(ip).or_insert(IpState { window_start: now, count: 0, banned_until: None });
        if let Some(b) = st.banned_until {
            if now < b {
                return false;
            }
            st.banned_until = None;
            st.window_start = now;
            st.count = 0;
        }
        if now.duration_since(st.window_start) >= RL_WINDOW {
            st.window_start = now;
            st.count = 0;
        }
        st.count = st.count.saturating_add(1);
        if st.count > self.limit {
            st.banned_until = Some(now + RL_BAN);
            return false;
        }
        true
    }
}

async fn rate_limit_mw(
    State(rl): State<RateLimiter>,
    conn: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // Without ConnectInfo (shouldn't happen once wired) fail open — never break
    // the RPC because we couldn't read the peer address.
    if let Some(axum::extract::ConnectInfo(addr)) = conn {
        if !rl.allow(addr.ip()) {
            return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded - try again shortly").into_response();
        }
    }
    next.run(req).await
}

// ————————————————————————————————————————————————————————————————————————
// Dedicated, MANDATORY-when-public rate limiter for `POST /simulate`
// ————————————————————————————————————————————————————————————————————————
// `/simulate` is the single most expensive UNAUTHENTICATED endpoint: each call
// runs a hybrid PQC signature verify and can compile+run WASM, and only a small
// pool of concurrent simulations exists (`MAX_CONCURRENT_SIMULATIONS`). The
// singleflight (`SIM_INFLIGHT`, keyed by txid+round+state_root) already coalesces
// IDENTICAL concurrent requests, but a flood of DISTINCT signed txs — or a
// distributed replay of ONE signed tx (whose PQC verify runs BEFORE the result
// cache is consulted) — can still occupy every slot and burn CPU. So this limiter
// is not optional: whenever the RPC is reachable by remote clients it is forced
// on and never honours `None`/`0`. It caps two dimensions in a 10 s sliding
// window, both WINDOW-ONLY (no ban):
//   * PER IP  — the request source. Window-only, deliberately NOT a ban: a ban
//     would lock out every legitimate user who shares one address — e.g. all
//     clients behind a reverse proxy that doesn't forward the real IP — for the
//     whole ban period.
//   * PER TXID — how often ONE transaction is simulated node-wide (kills the
//     distributed single-tx replay that per-IP alone can't, since each botnet IP
//     stays under its own cap). Window-only so an attacker can't get a victim's
//     txid banned by pre-flooding it.
// A "max one ACTIVE simulation per txid+state_root" is the existing singleflight,
// and "max N concurrent WASM executions" is `MAX_CONCURRENT_SIMULATIONS` — both
// unchanged; this adds the missing per-IP/per-txid admission gate in front.
//
// Honest residual (bounded, not closed): a large BOTNET of distinct IPs each
// simulating DISTINCT signed txs stays under both caps, so it can still keep the
// WASM pool busy. That flood is bounded by the `MAX_CONCURRENT_SIMULATIONS`
// semaphore (it never exhausts memory or spawns unbounded work — excess requests
// get an immediate 429 from `try_acquire`) and is answered operationally by
// horizontal scaling: run the public simulation RPC on read-only replicas,
// separate from the consensus validator (see `docs/DEPLOY.md`).

/// Default per-IP `/simulate` cap (10 s window) when the RPC is public and the
/// operator didn't set one — mid-range of the recommended 5–10.
pub const DEFAULT_SIM_PER_IP_10S: u32 = 8;
/// Floor a public `/simulate` per-IP cap can never go below (so a config of 0 /
/// an absurdly low value can't neuter the protection on a public bind).
pub const MIN_SIM_PER_IP_10S: u32 = 5;
/// Per-txid `/simulate` cap (10 s window), node-wide. Generous — a legitimate
/// wallet simulates a given tx once or twice before sending, never near this — so
/// it only ever trips on abusive replay of one signed tx.
pub const SIM_PER_TXID_10S: u32 = 20;

/// A bounded per-key sliding-window counter. Window-only (no ban): the excess in
/// a window gets a 429 and the key recovers automatically on the next window.
/// Used for BOTH the per-IP and per-txid `/simulate` gates.
struct WindowMap<K> {
    map: std::collections::HashMap<K, Window>,
    last_gc: std::time::Instant,
}

struct Window {
    start: std::time::Instant,
    count: u32,
}

impl<K: std::hash::Hash + Eq> WindowMap<K> {
    fn new() -> Self {
        Self { map: std::collections::HashMap::new(), last_gc: std::time::Instant::now() }
    }

    /// `true` = within `limit` for the current window. Bounded and GC-THROTTLED:
    /// the expired-entry sweep runs at most once per second, so a spray of
    /// distinct keys can't force an `O(n)` `retain` on every request (the
    /// amplification a naive "GC whenever full" invites — the sweep would find
    /// nothing to drop yet still rescan the whole map per request). When the map
    /// is full of still-live entries a brand-new key is rejected (fail closed)
    /// rather than growing the map or rescanning; that's only reachable under an
    /// active distinct-key flood and self-heals as elapsed windows are GC'd.
    fn allow(&mut self, key: K, limit: u32, now: std::time::Instant) -> bool {
        if self.map.len() >= MAX_TRACKED_IPS && now.duration_since(self.last_gc) >= std::time::Duration::from_secs(1) {
            self.map.retain(|_, w| now.duration_since(w.start) < RL_WINDOW);
            self.last_gc = now;
        }
        if self.map.len() >= MAX_TRACKED_IPS && !self.map.contains_key(&key) {
            return false;
        }
        let w = self.map.entry(key).or_insert(Window { start: now, count: 0 });
        if now.duration_since(w.start) >= RL_WINDOW {
            w.start = now;
            w.count = 0;
        }
        w.count = w.count.saturating_add(1);
        w.count <= limit
    }
}

/// Per-IP + per-txid sliding-window limiter for `/simulate`. Cheap `O(1)` counters
/// under a plain mutex; both maps are bounded and GC-throttled so the limiter
/// can't itself be an OOM or a CPU-amplification vector.
#[derive(Clone)]
pub struct SimRateLimiter {
    per_ip: Arc<std::sync::Mutex<WindowMap<std::net::IpAddr>>>,
    per_txid: Arc<std::sync::Mutex<WindowMap<[u8; 32]>>>,
    ip_limit: u32,
    txid_limit: u32,
    /// Resolve the client IP from `X-Forwarded-For` — but ONLY when the direct TCP
    /// peer is loopback (our trusted same-host proxy). See
    /// `NodeConfig::rpc_behind_trusted_proxy`.
    trust_proxy: bool,
}

impl SimRateLimiter {
    fn new(ip_limit: u32, txid_limit: u32, trust_proxy: bool) -> Self {
        Self {
            per_ip: Arc::new(std::sync::Mutex::new(WindowMap::new())),
            per_txid: Arc::new(std::sync::Mutex::new(WindowMap::new())),
            ip_limit,
            txid_limit,
            trust_proxy,
        }
    }

    /// Build the `/simulate` limiter for a given RPC bind. **Mandatory when the
    /// RPC is reachable by remote clients** — either a non-loopback `rpc_addr`, OR
    /// a loopback bind the operator declared to sit behind a trusted same-host
    /// proxy (`trust_proxy`, the Cloudflare-tunnel / local-nginx case where the
    /// real clients are remote even though the TCP peer is loopback). In that case
    /// it is always `Some`, with the per-IP cap forced to at least
    /// `MIN_SIM_PER_IP_10S` (a `None`/`0`/too-low config is raised to a safe
    /// value). On a genuinely private loopback RPC (no trusted proxy) it is opt-in:
    /// `Some` only if the operator set a positive value, else `None` (the
    /// operator's own box; local dev/tests aren't throttled).
    pub fn for_rpc(rpc_addr: std::net::SocketAddr, configured_per_ip: Option<u32>, trust_proxy: bool) -> Option<Self> {
        let public = !rpc_addr.ip().is_loopback() || trust_proxy;
        let configured = configured_per_ip.filter(|&n| n > 0);
        let ip_limit = if public {
            configured.unwrap_or(DEFAULT_SIM_PER_IP_10S).max(MIN_SIM_PER_IP_10S)
        } else {
            // Genuinely private loopback: opt-in only.
            configured?
        };
        Some(Self::new(ip_limit, SIM_PER_TXID_10S, trust_proxy))
    }

    /// `true` = allowed. Per-IP sliding window, window-only (no ban).
    fn allow_ip(&self, ip: std::net::IpAddr) -> bool {
        let now = std::time::Instant::now();
        let mut m = self.per_ip.lock().unwrap_or_else(|e| e.into_inner());
        m.allow(ip, self.ip_limit, now)
    }

    /// `true` = allowed. Per-txid sliding window, window-only (a ban keyed by an
    /// attacker-suppliable txid would let one flooder lock out a victim's tx).
    fn allow_txid(&self, txid: [u8; 32]) -> bool {
        let now = std::time::Instant::now();
        let mut m = self.per_txid.lock().unwrap_or_else(|e| e.into_inner());
        m.allow(txid, self.txid_limit, now)
    }
}

/// The client IP the per-IP gate keys on. Normally the direct TCP peer. When the
/// node is declared behind a trusted SAME-HOST proxy (`trust_proxy`) AND the
/// direct peer is loopback (that proxy), use the RIGHTMOST `X-Forwarded-For` hop
/// — the address the trusted proxy actually saw the client on. The rightmost is
/// the value our immediate proxy appended, so a client that injects its own
/// `X-Forwarded-For` can't spoof past it (its forgery ends up to the LEFT). This
/// assumes a SINGLE trusted hop (the documented cloudflared / local-nginx setup);
/// a missing or unparseable header falls back to the peer (fail safe, no panic).
/// `trust_proxy` is never honoured for a non-loopback peer — an unauthenticated
/// header from a direct remote is ignored.
fn client_ip(trust_proxy: bool, peer: std::net::IpAddr, headers: &axum::http::HeaderMap) -> std::net::IpAddr {
    if trust_proxy && peer.is_loopback() {
        if let Some(last) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|xff| xff.rsplit(',').next())
        {
            if let Ok(ip) = last.trim().parse::<std::net::IpAddr>() {
                return ip;
            }
        }
    }
    peer
}

/// Per-route middleware for `/simulate`: the PER-IP gate, run BEFORE the body is
/// even parsed so a flood (well-formed or not) is rejected with 429 immediately,
/// before any permit/verify/WASM. The per-TXID gate runs inside `simulate_tx`
/// (it needs the parsed tx's txid).
async fn simulate_ip_rate_limit_mw(
    State(rl): State<SimRateLimiter>,
    conn: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if let Some(axum::extract::ConnectInfo(addr)) = conn {
        let ip = client_ip(rl.trust_proxy, addr.ip(), req.headers());
        if !rl.allow_ip(ip) {
            return (StatusCode::TOO_MANY_REQUESTS, "simulate rate limit exceeded for your IP - slow down").into_response();
        }
    }
    next.run(req).await
}

pub fn router(engine: Arc<Engine>, rpc_rate_limit_per_10s: Option<u32>, sim_limiter: Option<SimRateLimiter>) -> Router {
    // Opt-in per-IP rate limiter (task #196). `None`/`0` → not layered at all.
    let base = base_router(engine, sim_limiter);
    match rpc_rate_limit_per_10s.filter(|&n| n > 0) {
        Some(limit) => base.layer(axum::middleware::from_fn_with_state(RateLimiter::new(limit), rate_limit_mw)),
        None => base,
    }
}

fn base_router(engine: Arc<Engine>, sim_limiter: Option<SimRateLimiter>) -> Router {
    // `/simulate` gets its dedicated per-IP middleware (when present) AND the
    // limiter is threaded to the handler as an `Extension` for the per-txid gate.
    let simulate = match &sim_limiter {
        Some(rl) => post(simulate_tx).layer(axum::middleware::from_fn_with_state(rl.clone(), simulate_ip_rate_limit_mw)),
        None => post(simulate_tx),
    };
    let router = Router::new()
        .route("/", get(explorer))
        .route("/tx", post(submit_tx))
        .route("/simulate", simulate)
        .route("/account/:address", get(get_account))
        .route("/stake/:address", get(get_stake))
        .route("/stake_v7/:address", get(get_stake_v7))
        .route("/status", get(status))
        .route("/economics", get(economics))
        .route("/holders", get(holders))
        .route("/programs", get(programs))
        .route("/program/:address", get(program))
        .route("/resources", get(resources))
        .route("/root", get(root))
        .route("/stark_proof", get(stark_proof))
        .route("/transfers", get(list_transfers))
        .route("/transfers/:hash", get(get_transfer))
        .route("/staking_activity", get(staking_activity))
        .route("/rounds", get(rounds))
        .route("/validators", get(validators))
        .route("/validator_registry", get(validator_registry))
        .route("/validator_v7_registry", get(validator_v7_registry))
        .route("/active_validators", get(active_validators))
        .route("/equivocation_evidence", get(equivocation_evidence))
        .route("/chain_id", get(chain_id))
        .route("/version", get(version))
        .route("/snapshot/meta", get(snapshot_meta))
        .route("/snapshot", get(snapshot))
        .route("/snapshot/page", get(snapshot_page))
        .with_state(engine);
    // Thread the `/simulate` limiter to the handler (per-txid gate). An Extension
    // layer is a no-op for every other route; `simulate_tx` reads it via an
    // `Option<Extension<..>>` so it simply skips the per-txid gate when absent.
    match sim_limiter {
        Some(rl) => router.layer(axum::Extension(rl)),
        None => router,
    }
}

#[derive(serde::Deserialize)]
struct SnapshotPageQuery {
    /// Keyset cursor: return accounts whose address sorts strictly after this
    /// (the address string as it appears in a prior page's last entry).
    /// Omitted for the first page.
    after: Option<String>,
}

/// One keyset page of the cached consistent snapshot - see
/// `Engine::snapshot_page`. The client pages with `after=<last address>`
/// until it gets a short page, checking every page carries the same
/// `merkle_root` (else the server's snapshot rotated and it restarts).
async fn snapshot_page(State(engine): State<Arc<Engine>>, Query(query): Query<SnapshotPageQuery>) -> Result<Json<SnapshotPage>, (StatusCode, String)> {
    let after = match query.after {
        Some(hex_addr) => Some(hex_addr.parse::<Pubkey>().map_err(|e: anyhow::Error| (StatusCode::BAD_REQUEST, e.to_string()))?),
        None => None,
    };
    Ok(Json(engine.snapshot_page(after).await))
}

/// Header of this validator's account-state snapshot - round, Merkle root,
/// and account count. A far-behind peer reads this before pulling the full
/// snapshot (see `GET /snapshot`), and it doubles as the value a cross-check
/// or an operator trust anchor compares against.
async fn snapshot_meta(State(engine): State<Arc<Engine>>) -> Json<SnapshotMeta> {
    Json(engine.snapshot_meta().await)
}

/// Full account-state snapshot - the real catch-up path for a validator that
/// fell further behind than the DAG retention window (its peers pruned the
/// old certificates it would otherwise replay). The receiver rebuilds the
/// Merkle tree and verifies the root before trusting any of it; see
/// `qchain_node::engine::StateSnapshot` for the trust model.
async fn snapshot(State(engine): State<Arc<Engine>>) -> Json<StateSnapshot> {
    Json(engine.snapshot().await)
}

/// This network's genesis-derived identity (`NodeConfig::chain_id`'s doc
/// comment) - a client fetches this before signing so its transactions
/// are bound to the network it actually intends, closing the
/// cross-network replay gap documented on `qchain_core::Message::chain_id`.
async fn chain_id(State(engine): State<Arc<Engine>>) -> Json<serde_json::Value> {
    Json(json!({ "chain_id": hex::encode(engine.chain_id) }))
}

/// This node's software version, plus a newer version if one has been heard
/// from a validator-set peer ("there is an update available"). Backs both a
/// direct check and the dashboard's update banner. See
/// `qchain_node::engine::NODE_VERSION` and the version-announce mechanism.
async fn version(State(engine): State<Arc<Engine>>) -> Json<serde_json::Value> {
    let status = engine.status().await;
    Json(json!({ "version": status.version, "update_available": status.update_available }))
}

/// A minimal, self-contained status page - not a real block explorer (no
/// transaction history browsing, no search across the network), just
/// enough for a public-testnet participant to sanity-check a validator
/// from a browser without installing `qchain-cli`: this validator's own
/// status, its live Merkle root, and a one-off account balance lookup.
/// Plain `fetch()` against this same origin's `/status`/`/root`/
/// `/account/:address` - no build step, no dependency, works from the
/// bare HTML file.
async fn explorer() -> impl axum::response::IntoResponse {
    // Security headers on the operator dashboard (task #196, QCH-S9), matching
    // what the public QScan indexer already sets: a strict CSP that keeps the
    // page same-origin only (no external script/style/img/connect, so a stored
    // value can't exfiltrate or load a third-party payload), plus clickjacking
    // (frame-ancestors/X-Frame-Options), MIME-sniffing (nosniff) and referrer
    // hardening. `'unsafe-inline'` is required because the dashboard is a single
    // self-contained HTML with inline <script>/<style> and no build step; the
    // real protections here are `connect-src 'self'` (no exfil), `object-src` /
    // `base-uri` / `frame-ancestors` = none.
    const CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
    (
        [
            ("Content-Security-Policy", CSP),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ],
        Html(include_str!("explorer.html")),
    )
}

async fn submit_tx(State(engine): State<Arc<Engine>>, Json(tx): Json<Transaction>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let hash = engine.submit_transaction(tx).await.map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(json!({ "hash": hex::encode(hash) })))
}

/// The protocol singletons + admin wallet whose `data`/state the LEDGER ITSELF
/// rewrites as part of normal execution (dynamic-fee epoch tick, quanto close,
/// reward accrual). A WASM contract cannot take one over (the boundary forbids
/// writing an account it neither signs for nor owns), so their churn appearing in
/// a sim diff is mechanics, not an attack — the wallet must NOT red-flag them.
fn is_protocol_singleton(pk: &Pubkey) -> bool {
    use qchain_execution::ids::*;
    const PROTOCOL: [Pubkey; 19] = [
        STAKING_PROGRAM_ID, STAKING_STATS_ID, GOVERNANCE_PROGRAM_ID, REGISTRY_ACCOUNT_ID,
        PARAMS_ACCOUNT_ID, STAKING_REWARDS_POOL_ID, LOADER_PROGRAM_ID, FEE_STATE_ACCOUNT_ID,
        VALIDATOR_REGISTRY_ACCOUNT_ID, VALIDATOR_BOND_ESCROW_ID, STAKING_RESERVE_ID,
        VALIDATOR_FEE_POOL_ID, STAKING_UNBONDING_POOL_ID, VALIDATOR_UNBONDING_POOL_ID,
        STAKING_GLOBAL_ID, VALIDATOR_V7_PROGRAM_ID, ADMIN_FEE_WALLET, TREASURY_V7_PROGRAM_ID,
        TREASURY_ACCOUNT_ID,
    ];
    PROTOCOL.contains(pk)
}

/// Classify one simulated account change → `(sensitive, is_protocol)`. The wallet
/// renders `sensitive` in red and demands a second confirmation. Computed on the
/// NODE (not the wallet) because it needs the singleton IDs + account semantics the
/// wallet can't see. A change is SENSITIVE when it is NOT a protocol singleton AND
/// one of: the account is DELETED; a PRE-EXISTING account's owner/data/code moved
/// (a takeover); or a freshly-CREATED, program-owned account gains non-empty data
/// (a lazily-created allowance/operator/admin record — the approve-phishing vector).
/// A plain new wallet (system-owned, no data) and protocol-singleton churn are NOT
/// sensitive, which avoids alert fatigue on ordinary transfers/contract calls.
fn classify_sim_change(c: &qchain_execution::SimAccountChange) -> (bool, bool) {
    let sys = Pubkey::system_program_id();
    let empty_hash: [u8; 32] = <sha3::Sha3_256 as sha3::Digest>::digest([]).into();
    let owner_changed = c.owner_before != c.owner_after;
    let data_changed = c.data_hash_before != c.data_hash_after;
    let code_changed = c.code_hash_before != c.code_hash_after;
    let created = !c.existed_before && c.exists_after;
    let deleted = c.existed_before && !c.exists_after;
    let is_protocol = is_protocol_singleton(&c.address);
    let program_owned_after = c.owner_after != sys;
    let data_nonempty_after = c.data_hash_after != empty_hash;
    let sensitive = !is_protocol
        && (deleted
            || (c.existed_before && (owner_changed || data_changed || code_changed))
            || (created && program_owned_after && data_nonempty_after));
    (sensitive, is_protocol)
}

/// DRY-RUN a transaction and report its predicted outcome WITHOUT committing
/// (QCH-WALLET-001): a wallet POSTs the (signed) tx here before broadcasting so
/// it can show the user the real fee + resulting balances + whether it would
/// succeed — instead of signing/broadcasting blind. Read-only: runs on a scratch
/// ledger, never touches consensus/state (see `Ledger::simulate`).
async fn simulate_tx(
    State(engine): State<Arc<Engine>>,
    sim_rl: Option<axum::Extension<SimRateLimiter>>,
    Json(tx): Json<Transaction>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // PER-TXID rate gate (mandatory when the RPC is public; absent Extension =
    // loopback with no limiter). Runs BEFORE `simulate_transaction`, so an abusive
    // replay of ONE signed tx is rejected with 429 IMMEDIATELY — before the PQC
    // verify (which happens ahead of the result-cache lookup) and before any WASM.
    // The per-IP gate already ran in the route middleware; this catches a
    // distributed single-tx replay that stays under each IP's cap.
    if let Some(axum::Extension(rl)) = &sim_rl {
        if !rl.allow_txid(tx.txid()) {
            return Err((StatusCode::TOO_MANY_REQUESTS, "this transaction is being simulated too frequently - retry shortly".to_string()));
        }
    }
    // `None` = the node is at its simulation-concurrency cap. Respond 429 (Too
    // Many Requests) so the caller backs off instead of the node queueing an
    // unbounded backlog of expensive dry-runs (re-audit QCH-SIMULATE DoS).
    let Some(sim) = engine.simulate_transaction(&tx).await else {
        return Err((StatusCode::TOO_MANY_REQUESTS, "simulation server busy - retry shortly".to_string()));
    };
    // Rich per-account state diff (re-audit QCH-SIMULATE #2): balance AND
    // owner/nonce/data-hash/code-hash before+after, plus `data_changed`/
    // `owner_changed`/etc. booleans so the wallet can warn "this changes the
    // contract's data/admin" even when no balance moves. `before`/`after` (the
    // balance) are kept for backward compatibility with older wallet builds.
    //
    // The node ALSO computes, authoritatively, `sensitive` (should the wallet
    // red-flag + demand a second confirmation) and `protocol` (is this a
    // protocol singleton whose data churn is ledger mechanics, not a takeover).
    // Doing it here — not in the wallet — is the fix for a real review finding:
    // (1) an authority GRANT that lazily CREATES its record (approve/setOperator/
    // admin-PDA writing `{spender, amount}` into a fresh program-owned account)
    // must count as sensitive even though the account is "new" — the wallet alone
    // can't tell a benign new wallet from a new authority record, but the node
    // knows the resulting owner + whether `data` is non-empty; (2) the sim diff
    // window includes protocol singletons ([1..=18] + ADMIN_FEE_WALLET) whose
    // `data` the LEDGER itself rewrites every call (dynamic-fee epoch tick) or
    // quanto close — flagging those as "sensitive" would train users to reflexively
    // tick the confirmation on ordinary calls, dulling the real alert. A contract
    // cannot take over a protocol singleton (the WASM boundary forbids writing an
    // account it neither signs for nor owns), so their churn is never sensitive.
    let hx = |b: &[u8; 32]| hex::encode(b);
    let changes: Vec<serde_json::Value> = sim
        .changes
        .iter()
        .map(|c| {
            let owner_changed = c.owner_before != c.owner_after;
            let data_changed = c.data_hash_before != c.data_hash_after;
            let code_changed = c.code_hash_before != c.code_hash_after;
            let (sensitive, is_protocol) = classify_sim_change(c);
            json!({
                "address": c.address.to_string(),
                "existed_before": c.existed_before,
                "exists_after": c.exists_after,
                "before": c.balance_before.to_string(),
                "after": c.balance_after.to_string(),
                "balance_before": c.balance_before.to_string(),
                "balance_after": c.balance_after.to_string(),
                "owner_before": c.owner_before.to_string(),
                "owner_after": c.owner_after.to_string(),
                "owner_changed": owner_changed,
                "nonce_before": c.nonce_before,
                "nonce_after": c.nonce_after,
                "data_hash_before": hx(&c.data_hash_before),
                "data_hash_after": hx(&c.data_hash_after),
                "data_changed": data_changed,
                "code_hash_before": hx(&c.code_hash_before),
                "code_hash_after": hx(&c.code_hash_after),
                "code_changed": code_changed,
                // Authoritative node verdict (see the block comment above).
                "sensitive": sensitive,
                "protocol": is_protocol,
            })
        })
        .collect();
    Ok(Json(json!({
        "ok": sim.ok,
        // "ok" | "rejected_before_charge" | "execution_failed_after_charge"
        // (re-audit QCH-SIMULATE): a failed tx is NOT necessarily free — this
        // tells the wallet whether the shown `fee` would actually be lost.
        "status": sim.status.as_str(),
        "error": sim.error,
        "fee": sim.fee.to_string(),
        "payer_before": sim.payer_before.to_string(),
        "payer_after": sim.payer_after.to_string(),
        "changes": changes,
        "round": sim.round,
    })))
}

async fn get_account(State(engine): State<Arc<Engine>>, Path(address): Path<String>) -> Result<Json<Account>, (StatusCode, String)> {
    let pk: Pubkey = address.parse().map_err(|e: anyhow::Error| (StatusCode::BAD_REQUEST, e.to_string()))?;
    engine.get_account(&pk).await.map(Json).ok_or((StatusCode::NOT_FOUND, "account not found".to_string()))
}

/// `/stake/:address` - live state of a stake account, so the wallet can show
/// the real pending reward and pre-check whether an Undelegate would be
/// accepted (bonding/lock periods) instead of submitting a tx that execution
/// would reject. Returns `{exists:false}` for an address that isn't a stake
/// account, so the caller can distinguish "not staked" from an error.
async fn get_stake(State(engine): State<Arc<Engine>>, Path(address): Path<String>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use borsh::BorshDeserialize;
    use qchain_execution::ids::{STAKING_PROGRAM_ID, STAKING_REWARDS_POOL_ID};
    use qchain_execution::staking::{pending_reward, RewardPoolData, StakeAccountData};
    let pk: Pubkey = address.parse().map_err(|e: anyhow::Error| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let Some(acct) = engine.get_account(&pk).await else {
        return Ok(Json(json!({ "exists": false })));
    };
    if acct.owner != STAKING_PROGRAM_ID || acct.data.is_empty() {
        return Ok(Json(json!({ "exists": false })));
    }
    let sad = StakeAccountData::try_from_slice(&acct.data).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("stake account decode: {e}")))?;
    // Pool's running accumulator (0 if the pool was never seeded/accrued).
    let acc_per_share = match engine.get_account(&STAKING_REWARDS_POOL_ID).await {
        Some(pool) if !pool.data.is_empty() => RewardPoolData::try_from_slice(&pool.data).map(|p| p.acc_reward_per_share).unwrap_or(0),
        _ => 0,
    };
    let pending = pending_reward(sad.amount, sad.reward_debt, acc_per_share);
    // `next_round` is the round consensus is working on now - close enough for a
    // UX pre-check of the 100-round bonding/lock windows.
    let current_round = engine.status().await.next_round;
    Ok(Json(json!({
        "exists": true,
        "owner": sad.owner.to_string(),
        "validator": sad.validator.to_string(),
        "amount": sad.amount,
        "pending_reward": pending,
        "locked_until_round": sad.locked_until_round,
        "bonding_until_round": sad.bonding_until_round,
        "unbonding_requested_at_round": sad.unbonding_requested_at_round,
        "current_round": current_round,
    })))
}

/// `/stake_v7/:address` - live state of a v7 staking position (economics_v7
/// networks). The v6 `/stake/:address` decodes `StakeAccountData`; a v7 position
/// is a `StakePositionV7` (shares+index), a different format, so the wallet's v7
/// staking UI reads this instead. Returns the index-accrued `value` (what the
/// position is worth NOW = shares × the live global index), the net deposited,
/// the lifecycle `state`, and the pending unbonding chunk with whether it's
/// withdrawable yet (`current_quanto >= unbonding_ready_quanto`). `value`,
/// `active_shares`, and amounts are strings (u128 / can exceed 2^53). Returns
/// `{exists:false}` for an address that isn't a v7 position.
async fn get_stake_v7(State(engine): State<Arc<Engine>>, Path(address): Path<String>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use borsh::BorshDeserialize;
    use qchain_execution::ids::{STAKING_GLOBAL_ID, STAKING_PROGRAM_ID};
    use qchain_execution::staking_v7::{GlobalStakingState, StakePositionV7};
    let pk: Pubkey = address.parse().map_err(|e: anyhow::Error| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let Some(acct) = engine.get_account(&pk).await else {
        return Ok(Json(json!({ "exists": false })));
    };
    if acct.owner != STAKING_PROGRAM_ID || acct.data.is_empty() {
        return Ok(Json(json!({ "exists": false })));
    }
    // A v6 stake account also lives under STAKING_PROGRAM_ID; only a genuine
    // StakePositionV7 decodes here, so a v6 account cleanly reports not-a-v7.
    let Ok(pos) = StakePositionV7::try_from_slice(&acct.data) else {
        return Ok(Json(json!({ "exists": false })));
    };
    let global = engine
        .get_account(&STAKING_GLOBAL_ID)
        .await
        .and_then(|a| GlobalStakingState::try_from_slice(&a.data).ok())
        .unwrap_or_else(GlobalStakingState::genesis);
    // The position's real worth includes any deposit still activating (shown at
    // face while in its join quanto), so a just-staked position never displays
    // below what was put in.
    let value = qchain_execution::staking_v7::position_current_value(&pos, &global);
    let activating = qchain_execution::staking_v7::is_activating(&pos, &global);
    let withdrawable = pos.unbonding_amount > 0 && global.current_quanto >= pos.unbonding_ready_quanto;
    // Cadence for the wallet's reward/unbonding progress bars: with these the
    // wallet draws "next reward in ~Xh" (progress within the current quanto) and
    // the unbonding countdown, from real on-chain timing rather than guesses.
    let (current_round, rounds_per_quanto, round_interval_ms) = engine.quanto_timing().await;
    Ok(Json(json!({
        "exists": true,
        "owner": pos.owner.to_string(),
        "active_shares": pos.active_shares.to_string(),
        "value": value.to_string(),
        "net_deposited": pos.net_deposited,
        "state": format!("{:?}", pos.state),
        "activating": activating,
        "pending_amount": pos.pending_amount,
        "activation_quanto": pos.pending_activation_quanto,
        "created_quanto": pos.created_quanto,
        "last_modified_quanto": pos.last_modified_quanto,
        "unbonding_amount": pos.unbonding_amount,
        "unbonding_ready_quanto": pos.unbonding_ready_quanto,
        "withdrawable": withdrawable,
        "current_quanto": global.current_quanto,
        "current_round": current_round,
        "rounds_per_quanto": rounds_per_quanto,
        "round_interval_ms": round_interval_ms,
        "unbonding_quantos": qchain_execution::economics_v7::STAKING_UNBONDING_QUANTOS,
    })))
}

async fn status(State(engine): State<Arc<Engine>>) -> Json<StatusResponse> {
    Json(engine.status().await)
}

/// `/economics` - real validator economics for the dashboard's validator
/// panel: live burn (fees + dust), validator earnings, staking pool, and the
/// current governance parameters. See `EconomicsResponse`.
async fn economics(State(engine): State<Arc<Engine>>) -> Json<EconomicsResponse> {
    Json(engine.economics().await)
}

#[derive(serde::Deserialize)]
struct HoldersQuery {
    #[serde(default = "default_holders_limit")]
    limit: usize,
}
fn default_holders_limit() -> usize {
    50
}

/// `/holders?limit=N` - QCH distribution and the top-holding wallets (rich
/// list) for the dashboard's "distribución" panel. See `HoldersResponse`.
/// Read-only; built from the TTL-cached snapshot, so it doesn't slow consensus.
async fn holders(State(engine): State<Arc<Engine>>, Query(query): Query<HoldersQuery>) -> Json<HoldersResponse> {
    Json(engine.holders(query.limit).await)
}

#[derive(serde::Deserialize)]
struct ProgramsQuery {
    #[serde(default = "default_holders_limit")]
    limit: usize,
}

/// `/programs?limit=N` - the deployed smart contracts (loader-owned WASM program
/// accounts), read-only, for QScan's "Contratos" section. Metadata only
/// (address, code-hash, entry point, size) - never keys, never bytecode. Built
/// from the TTL-cached snapshot, so it doesn't slow consensus. See
/// `ProgramsResponse`.
async fn programs(State(engine): State<Arc<Engine>>, Query(query): Query<ProgramsQuery>) -> Json<crate::engine::ProgramsResponse> {
    Json(engine.programs(query.limit).await)
}

/// `/program/:address` - a SINGLE deployed contract's metadata (address,
/// code_hash, entry point, size, deployer). Re-audit #4: what `qchain
/// verify-program` fetches to compare a deployed contract's `code_hash` against a
/// locally-compiled `.wasm` (reproducible-build verification). Metadata only,
/// never the bytecode/keys. 404 if no WASM program lives at the address.
async fn program(State(engine): State<Arc<Engine>>, Path(address): Path<String>) -> Result<Json<crate::engine::ProgramEntry>, (StatusCode, String)> {
    let pk: Pubkey = address.parse().map_err(|e: anyhow::Error| (StatusCode::BAD_REQUEST, e.to_string()))?;
    engine.program(&pk).await.map(Json).ok_or((StatusCode::NOT_FOUND, "no deployed program at this address".to_string()))
}

/// `/resources` - the node's own live RAM/CPU/disk/thread usage, so a load tool
/// can sample and report peaks without shell access to the node. See
/// `ResourcesResponse`. Not behind the state lock (reads `/proc/self` + data_dir).
async fn resources(State(engine): State<Arc<Engine>>) -> Json<crate::engine::ResourcesResponse> {
    Json(engine.resources())
}

async fn root(State(engine): State<Arc<Engine>>) -> Json<serde_json::Value> {
    let (root, receipt_count) = engine.merkle_root().await;
    Json(json!({ "root": hex::encode(root), "receipt_count": receipt_count }))
}

#[derive(serde::Deserialize)]
struct StarkProofQuery {
    /// Prove only the most recent `limit` captured transfer receipts
    /// instead of every one ever captured - bounds proving cost for a
    /// caller that only wants recent history. Omit for "all of them".
    limit: Option<usize>,
}

async fn stark_proof(
    State(engine): State<Arc<Engine>>,
    Query(query): Query<StarkProofQuery>,
) -> Result<Json<StarkProofResponse>, (StatusCode, String)> {
    engine.stark_proof(query.limit).await.map(Json).map_err(|e| match e {
        StarkProofError::NoReceipts => (StatusCode::NOT_FOUND, e.to_string()),
        StarkProofError::Prove(_) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        StarkProofError::ChainBroken(_) => (StatusCode::CONFLICT, e.to_string()),
    })
}

/// The light, list-view shape of a captured transfer - just enough to
/// render a real "recent activity" table (Qscan's whole reason to exist
/// over the older single-screen status page). Full before/after
/// balances and Merkle proofs are only served per-transaction, by hash,
/// via `GET /transfers/:hash` - a list of dozens of those would be most
/// of a light client's proof payload repeated for no reason.
#[derive(serde::Serialize)]
struct TransferSummary {
    tx_hash: String,
    from: Pubkey,
    to: Pubkey,
    amount: u64,
    fee: u64,
    round: u64,
}

impl From<&crate::engine::TransferSummaryLite> for TransferSummary {
    fn from(r: &crate::engine::TransferSummaryLite) -> Self {
        TransferSummary { tx_hash: hex::encode(r.tx_hash), from: r.from, to: r.to, amount: r.amount, fee: r.fee, round: r.round }
    }
}

#[derive(serde::Deserialize)]
struct ListTransfersQuery {
    #[serde(default = "default_transfers_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

fn default_transfers_limit() -> usize {
    20
}

/// Real recent-activity list, newest first - see `Engine::list_transfers`
/// for what backs it (the same in-memory receipt log `/stark_proof`
/// already reads, not a new indexer).
async fn list_transfers(State(engine): State<Arc<Engine>>, Query(query): Query<ListTransfersQuery>) -> Json<Vec<TransferSummary>> {
    let receipts = engine.list_transfers(query.limit, query.offset).await;
    Json(receipts.iter().map(TransferSummary::from).collect())
}

/// Real committed size of the most recent rounds (newest first) - the honest
/// "how full is each round" data, counting every committed tx (including
/// contract calls that never appear in `/transfers`). See `Engine::RoundFill`.
async fn rounds(State(engine): State<Arc<Engine>>, Query(query): Query<RoundsQuery>) -> Json<Vec<crate::engine::RoundFill>> {
    Json(engine.recent_round_fill(query.limit).await)
}

#[derive(serde::Deserialize)]
struct RoundsQuery {
    #[serde(default = "default_rounds_limit")]
    limit: usize,
}

fn default_rounds_limit() -> usize {
    30
}

/// Full detail for one transfer by its transaction hash (hex) - the
/// before/after balances and Merkle proofs a light client would want to
/// inspect for that specific transaction, without fetching (and
/// re-verifying) a whole STARK batch just to look at one row.
async fn get_transfer(State(engine): State<Arc<Engine>>, Path(hash): Path<String>) -> Result<Json<TransferReceipt>, (StatusCode, String)> {
    let bytes = hex::decode(&hash).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let tx_hash: [u8; 32] = bytes.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "transaction hash must be 32 bytes".to_string()))?;
    engine.get_transfer(tx_hash).await.map(Json).ok_or((StatusCode::NOT_FOUND, "no receipt captured for that transaction hash".to_string()))
}

/// Wire shape of a captured staking action, with hex hashes and string
/// addresses (the `StakingEvent`'s raw `[u8;32]`/`Pubkey` fields rendered for
/// JSON), plus a lower-case `kind` string the UI can switch on.
#[derive(serde::Serialize)]
struct StakingSummary {
    tx_hash: String,
    kind: String,
    staker: Pubkey,
    validator: Pubkey,
    stake_account: Pubkey,
    amount: u64,
    round: u64,
}

impl From<&qchain_execution::StakingEvent> for StakingSummary {
    fn from(e: &qchain_execution::StakingEvent) -> Self {
        let kind = match e.kind {
            qchain_execution::StakingEventKind::Delegate => "delegate",
            qchain_execution::StakingEventKind::Undelegate => "undelegate",
            qchain_execution::StakingEventKind::UnbondingStarted => "unbonding_started",
            qchain_execution::StakingEventKind::ClaimReward => "claim_reward",
        };
        StakingSummary {
            tx_hash: hex::encode(e.tx_hash),
            kind: kind.to_string(),
            staker: e.staker,
            validator: e.validator,
            stake_account: e.stake_account,
            amount: e.amount,
            round: e.round,
        }
    }
}

#[derive(serde::Deserialize)]
struct StakingActivityQuery {
    #[serde(default = "default_transfers_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    /// Optional filter: only this staker's activity (base58 address). Used by
    /// the wallet to show a single wallet's staking history.
    staker: Option<String>,
}

/// Real staking activity (Delegate/Undelegate/ClaimReward), newest first -
/// what the transfer list can't show, since staking never produces a
/// `TransferReceipt`. Optionally filtered by `?staker=<address>`.
async fn staking_activity(State(engine): State<Arc<Engine>>, Query(query): Query<StakingActivityQuery>) -> Result<Json<Vec<StakingSummary>>, (StatusCode, String)> {
    let staker = match &query.staker {
        Some(s) if !s.trim().is_empty() => Some(s.trim().parse::<Pubkey>().map_err(|e: anyhow::Error| (StatusCode::BAD_REQUEST, e.to_string()))?),
        _ => None,
    };
    let events = engine.list_staking_events(query.limit, query.offset, staker).await;
    Ok(Json(events.iter().map(StakingSummary::from).collect()))
}

/// The validator directory: address, optional name, and BFT stake for every
/// validator in this network's set. Lets a wallet render a named list to pick a
/// delegation target instead of asking the user to paste a raw address. Static
/// config data (from the shared genesis), read-only.
async fn validators(State(engine): State<Arc<Engine>>) -> Json<Vec<crate::engine::ValidatorDirEntry>> {
    Json(engine.validator_directory.clone())
}

/// `/validator_registry` - the live, on-chain validator registry (phase 3):
/// every identity that has registered itself by locking self-stake
/// (`StakingInstruction::RegisterValidator`), with its address, consensus
/// key bundle, and self-stake. Read straight from
/// `VALIDATOR_REGISTRY_ACCOUNT_ID`'s on-chain `data`, so it reflects real
/// state, not static config (unlike `/validators`, which is the config's
/// fixed set). Inert this increment - nothing consumes it for consensus yet,
/// but it's the discovery surface a future joining node/wallet reads. Each
/// entry's `stake` is a snapshot from registration time.
async fn validator_registry(State(engine): State<Arc<Engine>>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use qchain_execution::validator_registry::ValidatorRegistryData;
    use qchain_execution::ids::VALIDATOR_REGISTRY_ACCOUNT_ID;
    let Some(acct) = engine.get_account(&VALIDATOR_REGISTRY_ACCOUNT_ID).await else {
        // Not seeded (e.g. a pre-phase-3 persisted store) - report empty rather
        // than error, so callers can treat "no registry" as "no registrations."
        return Ok(Json(json!({ "validators": [] })));
    };
    let registry = ValidatorRegistryData::try_read(&acct.data).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("validator registry decode: {e}")))?;
    let validators: Vec<serde_json::Value> = registry
        .validators
        .iter()
        .map(|v| {
            // `pubkey_bundle` is included so a coordinator tool (`qchain
            // gen-validators`) can rebuild a node `validators` config array
            // straight from on-chain registrations - no hand-collecting each
            // newcomer's bundle. It's public key material, safe to expose.
            json!({
                "validator": v.validator.to_string(),
                "address": v.address,
                "stake": v.stake,
                "pubkey_bundle": v.pubkey_bundle,
            })
        })
        .collect();
    Ok(Json(json!({ "validators": validators })))
}

/// `/validator_v7_registry` - the v7 validator registry (economics_v7 networks).
/// The v7 registry lives at the SAME account id as the phase-3 v6 registry but
/// in the v7 `ValidatorV7Registry` format, so `/validator_registry` (a v6
/// reader) can't decode it - this endpoint decodes the v7 shape and reports each
/// validator's moniker, address, bond, lifecycle state, activation/exit/release
/// quanto, live participation, and whether it's eligible for the current
/// quanto's fee distribution (Active, past activation, min participation). On a
/// v6 network (or a not-yet-seeded store) it returns an empty list rather than
/// erroring. Read-only; nothing here changes state.
async fn validator_v7_registry(State(engine): State<Arc<Engine>>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use borsh::BorshDeserialize;
    use qchain_execution::ids::{STAKING_GLOBAL_ID, VALIDATOR_REGISTRY_ACCOUNT_ID};
    use qchain_execution::staking_v7::GlobalStakingState;
    use qchain_execution::validator_v7::ValidatorV7Registry;
    let Some(acct) = engine.get_account(&VALIDATOR_REGISTRY_ACCOUNT_ID).await else {
        return Ok(Json(json!({ "current_quanto": 0, "validators": [] })));
    };
    // Decode the v7 format; a v6-format registry (or empty) → empty list, so a
    // caller hitting this on a v6 network gets a clean answer, not a 500.
    let Ok(registry) = ValidatorV7Registry::try_from_slice(&acct.data) else {
        return Ok(Json(json!({ "current_quanto": 0, "validators": [] })));
    };
    let current_quanto = engine
        .get_account(&STAKING_GLOBAL_ID)
        .await
        .and_then(|a| GlobalStakingState::try_from_slice(&a.data).ok())
        .map(|g| g.current_quanto)
        .unwrap_or(0);
    let validators: Vec<serde_json::Value> = registry
        .validators
        .iter()
        .map(|v| {
            json!({
                "moniker": v.moniker,
                "address": v.address.to_string(),
                "operator_address": v.operator_address.to_string(),
                "withdrawal_address": v.withdrawal_address.to_string(),
                "p2p_address": v.p2p_address,
                "bond": v.bond,
                "state": format!("{:?}", v.state),
                "registered_quanto": v.registered_quanto,
                "activation_quanto": v.activation_quanto,
                "exit_requested_quanto": v.exit_requested_quanto,
                "bond_release_quanto": v.bond_release_quanto,
                "participation_bps": v.participation_bps(),
                "eligible_now": qchain_execution::fees_v7::is_eligible(v, current_quanto),
            })
        })
        .collect();
    Ok(Json(json!({ "current_quanto": current_quanto, "validators": validators })))
}

/// `/active_validators` - the ACTIVE validator set for the current epoch,
/// selected deterministically from the on-chain registry: the top
/// `MAX_ACTIVE_VALIDATORS` by stake (ties broken by address), the same pure
/// function every node computes identically (phase 3.2 - see
/// `validator_registry::select_active_set`). Inert this increment: consensus
/// still uses the static config set; this endpoint just previews what the
/// stake-ranked active set *would* be, so the selection can be inspected on a
/// live network before phase 3.3 wires it into `qchain-consensus`. `epoch` is
/// derived from the node's current round.
async fn active_validators(State(engine): State<Arc<Engine>>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use qchain_execution::validator_registry::{active_set_for_epoch, epoch_of, ValidatorRegistryData, MAX_ACTIVE_VALIDATORS};
    use qchain_execution::ids::VALIDATOR_REGISTRY_ACCOUNT_ID;
    let current_round = engine.status().await.next_round;
    let epoch = epoch_of(current_round);
    let registry = match engine.get_account(&VALIDATOR_REGISTRY_ACCOUNT_ID).await {
        Some(acct) => ValidatorRegistryData::try_read(&acct.data).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("validator registry decode: {e}")))?,
        None => ValidatorRegistryData::default(),
    };
    let active = active_set_for_epoch(&registry, epoch, MAX_ACTIVE_VALIDATORS);
    let validators: Vec<serde_json::Value> = active
        .validators
        .iter()
        .map(|v| json!({ "validator": v.validator.to_string(), "address": v.address, "stake": v.stake }))
        .collect();
    Ok(Json(json!({ "epoch": active.epoch, "current_round": current_round, "epoch_rounds": qchain_execution::validator_registry::EPOCH_ROUNDS, "max_active": MAX_ACTIVE_VALIDATORS, "validators": validators })))
}

/// Every equivocation this validator has independently witnessed and
/// verified (see `Engine::handle_message`'s `VertexProposal` arm) - each
/// entry is fully self-verifying (`qchain_core::EquivocationEvidence`), so
/// `qchain-cli report-equivocation` trusts nothing this endpoint says
/// beyond the raw signed vertices, the same "don't trust the node, verify
/// the bytes" posture `/stark_proof` already established.
async fn equivocation_evidence(State(engine): State<Arc<Engine>>) -> Json<Vec<qchain_core::EquivocationEvidence>> {
    Json(engine.equivocation_evidence().await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_execution::SimAccountChange;
    use sha3::{Digest, Sha3_256};
    use std::net::{IpAddr, Ipv4Addr};

    fn mk_change(addr: Pubkey) -> SimAccountChange {
        // A no-op change: existed before and after, nothing moved. Callers mutate
        // the fields for the case under test.
        let empty: [u8; 32] = Sha3_256::digest([]).into();
        SimAccountChange {
            address: addr,
            existed_before: true,
            exists_after: true,
            balance_before: 100,
            balance_after: 100,
            owner_before: Pubkey::system_program_id(),
            owner_after: Pubkey::system_program_id(),
            nonce_before: 0,
            nonce_after: 0,
            data_hash_before: empty,
            data_hash_after: empty,
            code_hash_before: [0u8; 32],
            code_hash_after: [0u8; 32],
        }
    }

    /// "Mostrar cambios completos de estado" — the NODE authoritatively classifies
    /// each simulated change so the wallet knows what to red-flag + gate behind a
    /// second confirmation. Covers the two real review findings: an authority GRANT
    /// (fresh program-owned account with data = approve-phishing) MUST be sensitive
    /// even though it's "new", and protocol-singleton data churn (the ledger's own
    /// fee/quanto mechanics) must NOT be, to avoid alert fatigue.
    #[test]
    fn sim_change_sensitivity_classification() {
        use qchain_execution::ids::{FEE_STATE_ACCOUNT_ID, LOADER_PROGRAM_ID, STAKING_GLOBAL_ID};
        let nonempty: [u8; 32] = Sha3_256::digest(b"grant").into();
        let user = Pubkey::new([99u8; 32]); // a non-protocol address (1..=18 are singletons)
        let contract = Pubkey::new([200u8; 32]); // a program (non-system) owner

        // Plain transfer: the recipient is a NEW system-owned wallet with NO data.
        // Not sensitive (the created-account carve-out is safe HERE, unlike a grant).
        let mut newpay = mk_change(user);
        newpay.existed_before = false;
        newpay.owner_after = Pubkey::system_program_id();
        newpay.balance_before = 0;
        newpay.balance_after = 5;
        assert_eq!(classify_sim_change(&newpay), (false, false), "new plain wallet is not sensitive");

        // GRANT (Finding 1): a freshly CREATED, program-owned account gains data =
        // a lazily-created allowance/operator/admin record. MUST be sensitive.
        let mut grant = mk_change(user);
        grant.existed_before = false;
        grant.owner_after = contract;
        grant.data_hash_after = nonempty;
        assert_eq!(classify_sim_change(&grant), (true, false), "a new program-owned account with data (a grant) IS sensitive");

        // A new program-owned account with EMPTY data (e.g. a claimed-but-unwritten
        // PDA) is not a grant yet → not sensitive.
        let mut empty_pda = mk_change(user);
        empty_pda.existed_before = false;
        empty_pda.owner_after = contract;
        assert_eq!(classify_sim_change(&empty_pda), (false, false), "a new program-owned account with no data is not sensitive");

        // TAKEOVER: a PRE-EXISTING account's data moves (admin/allowance change).
        let mut takeover = mk_change(user);
        takeover.data_hash_after = nonempty;
        assert_eq!(classify_sim_change(&takeover), (true, false), "data change on a pre-existing account is sensitive");

        // OWNER takeover of a pre-existing account.
        let mut owner_to = mk_change(user);
        owner_to.owner_after = contract;
        assert_eq!(classify_sim_change(&owner_to), (true, false), "owner change on a pre-existing account is sensitive");

        // DELETION of a pre-existing account.
        let mut del = mk_change(user);
        del.exists_after = false;
        assert_eq!(classify_sim_change(&del), (true, false), "deletion is sensitive");

        // PROTOCOL singleton churn (Finding 2): FEE_STATE / STAKING_GLOBAL data is
        // rewritten by the ledger every call/quanto — flagged `protocol`, NEVER
        // sensitive (a contract cannot take a singleton over).
        for id in [FEE_STATE_ACCOUNT_ID, STAKING_GLOBAL_ID, LOADER_PROGRAM_ID] {
            let mut proto = mk_change(id);
            proto.data_hash_after = nonempty; // its data churned
            assert_eq!(classify_sim_change(&proto), (false, true), "protocol singleton churn is not sensitive, but is flagged protocol");
        }

        // A pure balance change on a normal account (a received transfer) is not
        // sensitive.
        let mut balonly = mk_change(user);
        balonly.balance_after = 999;
        assert_eq!(classify_sim_change(&balonly), (false, false), "a pure balance change is not sensitive");
    }

    /// #196: the per-IP limiter allows up to `limit` requests, then bans the IP
    /// (subsequent requests are throttled), and a DIFFERENT IP is unaffected.
    #[test]
    fn rate_limiter_allows_up_to_limit_then_bans_per_ip() {
        let rl = RateLimiter::new(3);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(rl.allow(a), "1st allowed");
        assert!(rl.allow(a), "2nd allowed");
        assert!(rl.allow(a), "3rd allowed");
        assert!(!rl.allow(a), "4th over the limit -> throttled");
        assert!(!rl.allow(a), "still banned");
        // A different IP has its own independent bucket.
        assert!(rl.allow(b), "a separate IP is unaffected");
    }

    /// The dedicated `/simulate` limiter is MANDATORY whenever the RPC is reachable
    /// by remote clients — a public (non-loopback) bind, OR a loopback bind behind a
    /// trusted proxy: `for_rpc` returns `Some` there and never a per-IP cap below the
    /// floor, even if the operator set `None`, `0`, or a too-low value. On a
    /// genuinely private loopback bind (no trusted proxy) it is opt-in.
    #[test]
    fn simulate_limiter_is_mandatory_on_a_public_bind() {
        let public: std::net::SocketAddr = "203.0.113.7:8080".parse().unwrap();
        let loopback: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Public + unset -> forced on at the default.
        let rl = SimRateLimiter::for_rpc(public, None, false).expect("public bind must always have a /simulate limiter");
        assert_eq!(rl.ip_limit, DEFAULT_SIM_PER_IP_10S);
        // Public + 0/None-ish -> forced to the floor, never disabled.
        assert_eq!(SimRateLimiter::for_rpc(public, Some(0), false).unwrap().ip_limit, DEFAULT_SIM_PER_IP_10S, "0 is treated as unset -> default");
        assert_eq!(SimRateLimiter::for_rpc(public, Some(2), false).unwrap().ip_limit, MIN_SIM_PER_IP_10S, "a too-low value is raised to the floor");
        assert_eq!(SimRateLimiter::for_rpc(public, Some(9), false).unwrap().ip_limit, 9, "a value at/above the floor is honoured");
        assert_eq!(rl.txid_limit, SIM_PER_TXID_10S, "per-txid cap is always set");

        // Genuinely private loopback (no trusted proxy) + unset -> off; + positive -> opt-in on.
        assert!(SimRateLimiter::for_rpc(loopback, None, false).is_none(), "loopback unset -> no limiter");
        assert!(SimRateLimiter::for_rpc(loopback, Some(0), false).is_none(), "loopback 0 -> no limiter");
        assert_eq!(SimRateLimiter::for_rpc(loopback, Some(3), false).unwrap().ip_limit, 3, "loopback honours an explicit opt-in value verbatim");

        // Loopback BEHIND A TRUSTED PROXY -> treated as public: mandatory, floored,
        // and `trust_proxy` is recorded so the middleware reads X-Forwarded-For.
        let proxied = SimRateLimiter::for_rpc(loopback, None, true).expect("loopback+trusted-proxy must have a /simulate limiter");
        assert_eq!(proxied.ip_limit, DEFAULT_SIM_PER_IP_10S, "trusted-proxy loopback is forced on at the default");
        assert!(proxied.trust_proxy, "trust_proxy flag is recorded");
        assert_eq!(SimRateLimiter::for_rpc(loopback, Some(2), true).unwrap().ip_limit, MIN_SIM_PER_IP_10S, "trusted-proxy floors a too-low value too");
    }

    /// The `/simulate` per-IP and per-txid gates are BOTH window-only (no ban): the
    /// excess in a window is rejected but a fresh window lets the key through again,
    /// and a different key has its own independent bucket. Window-only per-IP avoids
    /// locking out every user sharing one address (behind a proxy); window-only
    /// per-txid stops one flooder from banning a victim's tx.
    #[test]
    fn simulate_limiter_per_ip_and_per_txid_are_window_only() {
        let rl = SimRateLimiter::new(3, 2, false);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        // Per-IP: up to the cap, then rejected while the window stands.
        assert!(rl.allow_ip(a) && rl.allow_ip(a) && rl.allow_ip(a), "up to the cap allowed");
        assert!(!rl.allow_ip(a), "over the cap -> rejected");
        assert!(!rl.allow_ip(a), "still over the cap in this window");
        assert!(rl.allow_ip(b), "a separate IP is unaffected");
        // Per-txid: up to the cap, then throttled, and a different txid is unaffected.
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        assert!(rl.allow_txid(t1) && rl.allow_txid(t1), "up to the txid cap allowed");
        assert!(!rl.allow_txid(t1), "over the txid cap -> throttled");
        assert!(rl.allow_txid(t2), "a different txid is unaffected");
    }

    /// `client_ip` reads `X-Forwarded-For` ONLY when trusted AND the direct peer is
    /// loopback (our same-host proxy), uses the RIGHTMOST hop (spoof-resistant), and
    /// falls back to the peer on a missing/garbage header. It never trusts the
    /// header from a direct remote peer or when trust is off.
    #[test]
    fn client_ip_resolves_xff_only_from_a_trusted_loopback_proxy() {
        let loop_peer: IpAddr = "127.0.0.1".parse().unwrap();
        let remote_peer: IpAddr = "198.51.100.2".parse().unwrap();
        let client: IpAddr = "203.0.113.9".parse().unwrap();

        let mut h = axum::http::HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.9".parse().unwrap());
        // Trusted proxy + loopback peer -> use XFF.
        assert_eq!(client_ip(true, loop_peer, &h), client);
        // Trust off -> ignore the (unauthenticated) header, use the peer.
        assert_eq!(client_ip(false, loop_peer, &h), loop_peer);
        // Trusted but the direct peer is NOT loopback -> not our proxy, ignore XFF.
        assert_eq!(client_ip(true, remote_peer, &h), remote_peer);

        // Multiple hops: the RIGHTMOST value (what our trusted proxy appended) wins,
        // so a client-injected leftmost value is ignored (spoof-resistant).
        let mut h2 = axum::http::HeaderMap::new();
        h2.insert("x-forwarded-for", "1.2.3.4, 203.0.113.9".parse().unwrap());
        assert_eq!(client_ip(true, loop_peer, &h2), client);

        // Garbage header -> fall back to the peer, never panic.
        let mut h3 = axum::http::HeaderMap::new();
        h3.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(client_ip(true, loop_peer, &h3), loop_peer);
    }
}
