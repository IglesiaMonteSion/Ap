//! Minimal faucet service for a qchain public testnet: holds a single
//! funded wallet keypair and, on request, submits a real signed `Transfer`
//! from it to whatever address asks - the payout is a real transaction
//! that goes through the same consensus path as any other client
//! transaction (no direct ledger mutation on one node, which would
//! diverge state across the network instead of replicating it).
//! Rate-limited per requested address by a simple in-memory cooldown -
//! not persisted across restarts, and not meant to run more than one
//! instance against the same keypair at once (the single global lock
//! below also serializes nonce lookups, since this wallet has exactly
//! one signer and concurrent requests would otherwise race for the same
//! nonce).

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use qchain_core::{Instruction, Transaction};
use qchain_crypto::{Keypair, Pubkey};
use qchain_execution::SystemInstruction;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(about = "qchain testnet faucet: funds requested addresses from a pre-funded wallet")]
struct Cli {
    /// The validator RPC this faucet submits transactions to and reads
    /// its own nonce from.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    rpc: String,
    /// Path to the faucet's own funded keypair (see `qchain keygen`) -
    /// must already hold real balance, e.g. via a genesis allocation.
    #[arg(long)]
    keypair: PathBuf,
    /// Address to bind the faucet's own HTTP server on.
    #[arg(long, default_value = "0.0.0.0:9090")]
    listen: SocketAddr,
    /// Units paid out per successful request. Fixed by the operator, not
    /// client-supplied - a request only ever names the recipient address,
    /// never an amount, so nobody can drain the faucet in one call.
    #[arg(long, default_value_t = 10_000_000)]
    amount: u64,
    #[arg(long, default_value_t = 10_000_000)]
    fee_limit: u64,
    /// Minimum seconds between payouts to the same address.
    #[arg(long, default_value_t = 60)]
    cooldown_secs: u64,
    /// Global cap: the maximum number of payouts the faucet will make in any
    /// rolling `rate_window_secs` window, across ALL addresses. The per-address
    /// cooldown alone gives no Sybil resistance — an attacker naming a fresh
    /// random address every request never trips it and can slowly drain the
    /// faucet wallet — so this bounds the total outflow regardless of how many
    /// distinct addresses ask. Default 200/hour.
    #[arg(long, default_value_t = 200)]
    max_payouts_per_window: usize,
    /// The rolling window (seconds) for `max_payouts_per_window`. Default 1h.
    #[arg(long, default_value_t = 3600)]
    rate_window_secs: u64,
}

struct FaucetState {
    rpc: String,
    keypair: Keypair,
    amount: u64,
    fee_limit: u64,
    cooldown: Duration,
    last_claim: HashMap<Pubkey, Instant>,
    /// Global rate limit (across all addresses) — the timestamps of recent
    /// confirmed payouts, pruned to the rolling window. Bounds total outflow
    /// against a Sybil that rotates its recipient address to evade the
    /// per-address cooldown.
    recent_payouts: Vec<Instant>,
    rate_window: Duration,
    max_payouts_per_window: usize,
    /// The faucet wallet's own nonce, tracked locally instead of re-fetched
    /// from the network on every request - a real, live-confirmed bug this
    /// closes (see `project-lessons-learned`): re-fetching raced the
    /// network's own settlement latency (`round_interval_ms` plus gossip/
    /// consensus), so a second request arriving before the first request's
    /// transaction had actually executed read the same stale nonce and
    /// collided with it - confirmed live via real `nonce mismatch`
    /// execution failures under nothing more adversarial than plain
    /// sequential requests. The mutex held across this whole handler (see
    /// `faucet`'s own comment) makes a single local counter authoritative
    /// under the "single signer, serialize everything" model. IMPORTANT:
    /// the counter is only advanced AFTER the payout is confirmed executed
    /// on chain, and is reset to `None` (forcing a re-fetch) on any
    /// admission failure or confirmation timeout. This matters because
    /// admission does NOT guarantee the nonce is consumed: a transaction
    /// admitted at a low dynamic fee can hit `FeeExceedsLimit`/
    /// `InsufficientFunds` when it later executes at a risen fee and return
    /// BEFORE the on-chain nonce bump - so a naive "advance on admission"
    /// counter would desync and permanently brick the faucet (signing
    /// nonces the chain never reaches). `None` until the first request,
    /// which fetches the real starting value once.
    next_nonce: Option<u64>,
}

#[derive(serde::Deserialize)]
struct FaucetRequest {
    address: String,
}

async fn fetch_nonce(client: &reqwest::Client, rpc: &str, pk: &Pubkey) -> anyhow::Result<u64> {
    let resp = client.get(format!("{rpc}/account/{pk}")).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(0);
    }
    let account: qchain_core::Account = resp.error_for_status()?.json().await?;
    Ok(account.nonce)
}

async fn fetch_balance(client: &reqwest::Client, rpc: &str, pk: &Pubkey) -> anyhow::Result<u64> {
    let resp = client.get(format!("{rpc}/account/{pk}")).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(0);
    }
    let account: qchain_core::Account = resp.error_for_status()?.json().await?;
    Ok(account.balance)
}

/// How long to wait for a submitted payout to actually land before giving
/// up and reporting an honest failure - a real, live-confirmed bug this
/// closes (see `project-lessons-learned`): the old code returned success
/// the moment `POST /tx` was merely *admitted* to the mempool, which is not
/// the same claim as "the recipient was funded" - a transaction can still
/// fail at real execution (the exact nonce-race above, or the faucet
/// wallet genuinely running dry) with the client none the wiser, believing
/// funds arrived when they never did. Bounded, not indefinite - a real
/// operator needs a faucet request to eventually fail loudly rather than
/// hang forever if the network stalls.
const CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(10);
const CONFIRMATION_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Real, live-confirmed cross-network replay gap this closes (see
/// `qchain_core::Message::chain_id`'s doc comment) - fetched fresh per
/// request, same as `fetch_nonce`, so the faucet always signs for whatever
/// network `--rpc` actually points at.
async fn fetch_chain_id(client: &reqwest::Client, rpc: &str) -> anyhow::Result<[u8; 32]> {
    let resp: serde_json::Value = client.get(format!("{rpc}/chain_id")).send().await?.error_for_status()?.json().await?;
    let hex_str = resp["chain_id"].as_str().ok_or_else(|| anyhow::anyhow!("malformed /chain_id response"))?;
    let bytes = hex::decode(hex_str)?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("chain_id must be 32 bytes"))
}

async fn faucet(State(state): State<Arc<Mutex<FaucetState>>>, Json(req): Json<FaucetRequest>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let to: Pubkey = req.address.parse().map_err(|e: anyhow::Error| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Held across the whole request, not just the cooldown check - this
    // is also what keeps two concurrent requests from fetching the same
    // nonce and racing each other's submission (see module docs).
    let mut state = state.lock().await;
    if let Some(last) = state.last_claim.get(&to) {
        let elapsed = last.elapsed();
        if elapsed < state.cooldown {
            let wait = (state.cooldown - elapsed).as_secs();
            return Err((StatusCode::TOO_MANY_REQUESTS, format!("already funded recently - try again in {wait}s")));
        }
    }
    // Global rate cap across ALL addresses — the per-address cooldown above
    // gives no Sybil resistance (a fresh recipient address per request never
    // trips it), so this bounds total outflow regardless of how many distinct
    // addresses ask. Prune the rolling window, then reject if the cap is hit.
    let now = Instant::now();
    let window = state.rate_window;
    state.recent_payouts.retain(|t| now.duration_since(*t) < window);
    if state.recent_payouts.len() >= state.max_payouts_per_window {
        return Err((StatusCode::TOO_MANY_REQUESTS, format!("faucet global rate limit reached ({} payouts per {}s) - try again later", state.max_payouts_per_window, window.as_secs())));
    }

    let client = reqwest::Client::new();
    let from = state.keypair.pubkey();
    let nonce = match state.next_nonce {
        Some(n) => n,
        None => fetch_nonce(&client, &state.rpc, &from).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?,
    };
    let chain_id = fetch_chain_id(&client, &state.rpc).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let balance_before = fetch_balance(&client, &state.rpc, &to).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let ix = Instruction {
        program_id: Pubkey::system_program_id(),
        accounts: vec![from, to],
        data: borsh::to_vec(&SystemInstruction::Transfer { amount: state.amount }).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    };
    let tx = Transaction::new_signed(&state.keypair, nonce, chain_id, state.fee_limit, vec![ix])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = client.post(format!("{}/tx", state.rpc)).json(&tx).send().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    if !resp.status().is_success() {
        // Admission failed: this nonce was NOT consumed on chain. Reset the
        // tracked nonce so the next request re-fetches the true value instead
        // of carrying a stale local counter forward.
        state.next_nonce = None;
        let body = resp.text().await.unwrap_or_default();
        return Err((StatusCode::BAD_GATEWAY, format!("node rejected the faucet transaction: {body}")));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    // Don't report success until the payout is actually confirmed on
    // chain - see `CONFIRMATION_TIMEOUT`'s doc comment for the real bug
    // this closes.
    let deadline = std::time::Instant::now() + CONFIRMATION_TIMEOUT;
    loop {
        let balance_now = fetch_balance(&client, &state.rpc, &to).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
        if balance_now >= balance_before + state.amount {
            break;
        }
        if std::time::Instant::now() >= deadline {
            // Admitted but never executed. Admission does NOT guarantee the
            // nonce is consumed: under a risen dynamic fee (EIP-1559) the tx can
            // hit FeeExceedsLimit/InsufficientFunds and return BEFORE the
            // on-chain nonce bump, leaving the chain at `nonce`. If we trusted an
            // advanced local counter the faucet would sign nonce+1, nonce+2, ...
            // forever (all NonceTooHigh, never executing) and be permanently
            // bricked until restart. Reset so the next request re-syncs.
            state.next_nonce = None;
            return Err((
                StatusCode::GATEWAY_TIMEOUT,
                format!("submitted but never confirmed executing within {CONFIRMATION_TIMEOUT:?} - the faucet wallet may be out of funds, or the network may be stalled"),
            ));
        }
        tokio::time::sleep(CONFIRMATION_POLL_INTERVAL).await;
    }

    // Confirmed executed on chain -> the on-chain nonce really did bump, so it
    // is now safe to advance the tracked nonce for the next request.
    state.next_nonce = Some(nonce + 1);
    // Bound the cooldown map: drop entries older than the cooldown window
    // (they can no longer rate-limit anything) so a Sybil stream of fresh
    // addresses can't grow it without bound.
    let now = Instant::now();
    let cooldown = state.cooldown; // copy out before the &mut borrow in retain
    state.last_claim.retain(|_, t| now.duration_since(*t) < cooldown);
    state.last_claim.insert(to, now);
    // Record this confirmed payout against the global rolling-window cap.
    state.recent_payouts.push(now);
    Ok(Json(json!({ "funded": req.address, "amount": state.amount, "tx": body })))
}

async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let keypair = qchain_crypto::read_keypair_file(&cli.keypair)?;
    tracing::info!("faucet wallet: {}", keypair.pubkey());

    let state = Arc::new(Mutex::new(FaucetState {
        rpc: cli.rpc,
        keypair,
        amount: cli.amount,
        fee_limit: cli.fee_limit,
        cooldown: Duration::from_secs(cli.cooldown_secs),
        last_claim: HashMap::new(),
        recent_payouts: Vec::new(),
        rate_window: Duration::from_secs(cli.rate_window_secs),
        max_payouts_per_window: cli.max_payouts_per_window,
        next_nonce: None,
    }));

    let app = Router::new().route("/health", get(health)).route("/faucet", post(faucet)).with_state(state);

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    tracing::info!("faucet listening on {}", cli.listen);
    axum::serve(listener, app).await?;
    Ok(())
}
