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
    #[arg(long, default_value_t = 1_000_000)]
    fee_limit: u64,
    /// Minimum seconds between payouts to the same address.
    #[arg(long, default_value_t = 60)]
    cooldown_secs: u64,
}

struct FaucetState {
    rpc: String,
    keypair: Keypair,
    amount: u64,
    fee_limit: u64,
    cooldown: Duration,
    last_claim: HashMap<Pubkey, Instant>,
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

    let client = reqwest::Client::new();
    let from = state.keypair.pubkey();
    let nonce = fetch_nonce(&client, &state.rpc, &from).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    let ix = Instruction {
        program_id: Pubkey::system_program_id(),
        accounts: vec![from, to],
        data: borsh::to_vec(&SystemInstruction::Transfer { amount: state.amount }).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    };
    let tx = Transaction::new_signed(&state.keypair, nonce, [0u8; 32], state.fee_limit, vec![ix])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let resp = client.post(format!("{}/tx", state.rpc)).json(&tx).send().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err((StatusCode::BAD_GATEWAY, format!("node rejected the faucet transaction: {body}")));
    }
    let body: serde_json::Value = resp.json().await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    state.last_claim.insert(to, Instant::now());
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
    }));

    let app = Router::new().route("/health", get(health)).route("/faucet", post(faucet)).with_state(state);

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    tracing::info!("faucet listening on {}", cli.listen);
    axum::serve(listener, app).await?;
    Ok(())
}
