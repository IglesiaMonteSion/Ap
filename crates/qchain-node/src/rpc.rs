//! JSON-RPC (plain HTTP+JSON, not a JSON-RPC-2.0-envelope) surface for
//! wallet/client traffic - what `qchain-cli` talks to. Deliberately small:
//! submit a transaction, read an account, read node status.

use crate::engine::{Engine, StatusResponse};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use qchain_core::{Account, Transaction};
use qchain_crypto::Pubkey;
use serde_json::json;
use std::sync::Arc;

pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/tx", post(submit_tx))
        .route("/account/:address", get(get_account))
        .route("/status", get(status))
        .with_state(engine)
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
