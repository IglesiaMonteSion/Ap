//! JSON-RPC (plain HTTP+JSON, not a JSON-RPC-2.0-envelope) surface for
//! wallet/client traffic - what `qchain-cli` talks to. Deliberately small:
//! submit a transaction, read an account, read node status.

use crate::engine::{Engine, StarkProofError, StarkProofResponse, StatusResponse};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use qchain_core::{Account, Transaction};
use qchain_crypto::Pubkey;
use serde_json::json;
use std::sync::Arc;

pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/", get(explorer))
        .route("/tx", post(submit_tx))
        .route("/account/:address", get(get_account))
        .route("/status", get(status))
        .route("/root", get(root))
        .route("/stark_proof", get(stark_proof))
        .with_state(engine)
}

/// A minimal, self-contained status page - not a real block explorer (no
/// transaction history browsing, no search across the network), just
/// enough for a public-testnet participant to sanity-check a validator
/// from a browser without installing `qchain-cli`: this validator's own
/// status, its live Merkle root, and a one-off account balance lookup.
/// Plain `fetch()` against this same origin's `/status`/`/root`/
/// `/account/:address` - no build step, no dependency, works from the
/// bare HTML file.
async fn explorer() -> Html<&'static str> {
    Html(include_str!("explorer.html"))
}

async fn submit_tx(State(engine): State<Arc<Engine>>, Json(tx): Json<Transaction>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let hash = engine.submit_transaction(tx).await.map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(json!({ "hash": hex::encode(hash) })))
}

async fn get_account(State(engine): State<Arc<Engine>>, Path(address): Path<String>) -> Result<Json<Account>, (StatusCode, String)> {
    let pk: Pubkey = address.parse().map_err(|e: anyhow::Error| (StatusCode::BAD_REQUEST, e.to_string()))?;
    engine.get_account(&pk).await.map(Json).ok_or((StatusCode::NOT_FOUND, "account not found".to_string()))
}

async fn status(State(engine): State<Arc<Engine>>) -> Json<StatusResponse> {
    Json(engine.status().await)
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
