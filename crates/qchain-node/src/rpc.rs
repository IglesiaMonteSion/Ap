//! JSON-RPC (plain HTTP+JSON, not a JSON-RPC-2.0-envelope) surface for
//! wallet/client traffic - what `qchain-cli` talks to. Deliberately small:
//! submit a transaction, read an account, read node status.

use crate::engine::{Engine, EconomicsResponse, SnapshotMeta, SnapshotPage, StarkProofError, StarkProofResponse, StateSnapshot, StatusResponse};
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
        .route("/stake/:address", get(get_stake))
        .route("/status", get(status))
        .route("/economics", get(economics))
        .route("/root", get(root))
        .route("/stark_proof", get(stark_proof))
        .route("/transfers", get(list_transfers))
        .route("/transfers/:hash", get(get_transfer))
        .route("/staking_activity", get(staking_activity))
        .route("/validators", get(validators))
        .route("/validator_registry", get(validator_registry))
        .route("/active_validators", get(active_validators))
        .route("/equivocation_evidence", get(equivocation_evidence))
        .route("/chain_id", get(chain_id))
        .route("/version", get(version))
        .route("/snapshot/meta", get(snapshot_meta))
        .route("/snapshot", get(snapshot))
        .route("/snapshot/page", get(snapshot_page))
        .with_state(engine)
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

async fn status(State(engine): State<Arc<Engine>>) -> Json<StatusResponse> {
    Json(engine.status().await)
}

/// `/economics` - real validator economics for the dashboard's validator
/// panel: live burn (fees + dust), validator earnings, staking pool, and the
/// current governance parameters. See `EconomicsResponse`.
async fn economics(State(engine): State<Arc<Engine>>) -> Json<EconomicsResponse> {
    Json(engine.economics().await)
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

impl From<&TransferReceipt> for TransferSummary {
    fn from(r: &TransferReceipt) -> Self {
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
        .map(|v| json!({ "validator": v.validator.to_string(), "address": v.address, "stake": v.stake }))
        .collect();
    Ok(Json(json!({ "validators": validators })))
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
