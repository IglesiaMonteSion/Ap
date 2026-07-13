//! JSON-RPC (plain HTTP+JSON, not a JSON-RPC-2.0-envelope) surface for
//! wallet/client traffic - what `qchain-cli` talks to. Deliberately small:
//! submit a transaction, read an account, read node status.

use crate::engine::{Engine, SnapshotMeta, StarkProofError, StarkProofResponse, StateSnapshot, StatusResponse};
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

pub fn router(engine: Arc<Engine>) -> Router {
    Router::new()
        .route("/", get(explorer))
        .route("/tx", post(submit_tx))
        .route("/account/:address", get(get_account))
        .route("/status", get(status))
        .route("/root", get(root))
        .route("/stark_proof", get(stark_proof))
        .route("/transfers", get(list_transfers))
        .route("/transfers/:hash", get(get_transfer))
        .route("/equivocation_evidence", get(equivocation_evidence))
        .route("/chain_id", get(chain_id))
        .route("/snapshot/meta", get(snapshot_meta))
        .route("/snapshot", get(snapshot))
        .with_state(engine)
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
}

impl From<&TransferReceipt> for TransferSummary {
    fn from(r: &TransferReceipt) -> Self {
        TransferSummary { tx_hash: hex::encode(r.tx_hash), from: r.from, to: r.to, amount: r.amount, fee: r.fee }
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

/// Full detail for one transfer by its transaction hash (hex) - the
/// before/after balances and Merkle proofs a light client would want to
/// inspect for that specific transaction, without fetching (and
/// re-verifying) a whole STARK batch just to look at one row.
async fn get_transfer(State(engine): State<Arc<Engine>>, Path(hash): Path<String>) -> Result<Json<TransferReceipt>, (StatusCode, String)> {
    let bytes = hex::decode(&hash).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let tx_hash: [u8; 32] = bytes.try_into().map_err(|_| (StatusCode::BAD_REQUEST, "transaction hash must be 32 bytes".to_string()))?;
    engine.get_transfer(tx_hash).await.map(Json).ok_or((StatusCode::NOT_FOUND, "no receipt captured for that transaction hash".to_string()))
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
