use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use supersol_core::Transaction;
use supersol_crypto::Pubkey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::Arc;

use crate::state::AppState;

#[derive(Deserialize)]
struct RpcRequest {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcErrorBody>,
}

#[derive(Serialize)]
struct RpcErrorBody {
    code: i32,
    message: String,
}

fn ok(id: Value, result: Value) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        id,
        result: Some(result),
        error: None,
    }
}

fn err(id: Value, message: impl Into<String>) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcErrorBody {
            code: -32000,
            message: message.into(),
        }),
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new().route("/", post(handle_rpc)).with_state(state)
}

async fn handle_rpc(State(state): State<Arc<AppState>>, Json(req): Json<RpcRequest>) -> Json<RpcResponse> {
    let id = req.id.clone();
    let response = dispatch(&state, &req).unwrap_or_else(|e| err(id, e));
    Json(response)
}

fn dispatch(state: &Arc<AppState>, req: &RpcRequest) -> Result<RpcResponse, String> {
    let id = req.id.clone();
    match req.method.as_str() {
        "getHealth" => Ok(ok(id, json!("ok"))),
        "getSlot" => Ok(ok(id, json!(state.slot()))),
        "getLatestBlockhash" => {
            let hash = state.latest_blockhash();
            Ok(ok(id, json!({ "blockhash": hex::encode(hash) })))
        }
        "getSupply" => {
            let treasury_units = state.ledger.lock().unwrap().get_balance(&Pubkey::treasury());
            let total_units = supersol_core::TOTAL_SUPPLY_UNITS;
            let circulating_units = total_units.saturating_sub(treasury_units);
            let per_ssol = supersol_core::UNITS_PER_SSOL as f64;
            Ok(ok(
                id,
                json!({
                    "total_units": total_units,
                    "total_ssol": total_units as f64 / per_ssol,
                    "circulating_units": circulating_units,
                    "circulating_ssol": circulating_units as f64 / per_ssol,
                    "treasury_units": treasury_units,
                    "treasury_ssol": treasury_units as f64 / per_ssol,
                }),
            ))
        }
        "getBalance" => {
            let pubkey = parse_pubkey_param(&req.params, 0)?;
            let ledger = state.ledger.lock().unwrap();
            let units = ledger.get_balance(&pubkey);
            Ok(ok(
                id,
                json!({ "units": units, "ssol": units as f64 / supersol_core::UNITS_PER_SSOL as f64 }),
            ))
        }
        "getAccountInfo" => {
            let pubkey = parse_pubkey_param(&req.params, 0)?;
            let ledger = state.ledger.lock().unwrap();
            match ledger.get_account(&pubkey) {
                Some(acc) => Ok(ok(
                    id,
                    json!({
                        "owner": acc.owner.to_string(),
                        "balance": acc.balance,
                        "data": hex::encode(&acc.data),
                        "executable": acc.executable,
                    }),
                )),
                None => Ok(ok(id, Value::Null)),
            }
        }
        "requestAirdrop" => handle_airdrop(state, &req.params).map(|v| ok(id, v)),
        "sendTransaction" => handle_send_transaction(state, &req.params).map(|v| ok(id, v)),
        "getBlock" => {
            let slot = req.params.get(0).and_then(|v| v.as_u64()).ok_or("missing slot param")?;
            match state.get_block(slot).map_err(|e| e.to_string())? {
                Some(block) => Ok(ok(id, serde_json::to_value(&block).map_err(|e| e.to_string())?)),
                None => Ok(ok(id, Value::Null)),
            }
        }
        other => Err(format!("unknown method: {other}")),
    }
}

fn parse_pubkey_param(params: &Value, index: usize) -> Result<Pubkey, String> {
    let s = params.get(index).and_then(|v| v.as_str()).ok_or("missing pubkey param")?;
    Pubkey::from_str(s).map_err(|e| e.to_string())
}

fn handle_airdrop(state: &Arc<AppState>, params: &Value) -> Result<Value, String> {
    if !state.faucet_enabled {
        return Err("faucet disabled on this node (start it with --enable-faucet)".into());
    }
    let pubkey = parse_pubkey_param(params, 0)?;
    let amount = params.get(1).and_then(|v| v.as_u64()).ok_or("missing amount param (base units)")?;
    if amount > state.faucet_max_units {
        return Err(format!(
            "amount exceeds faucet max of {} units per request",
            state.faucet_max_units
        ));
    }

    let entry = {
        let mut poh = state.poh.lock().unwrap();
        poh.record(format!("airdrop:{pubkey}:{amount}").as_bytes())
    };

    {
        let mut ledger = state.ledger.lock().unwrap();
        // Moves units out of the fixed-supply treasury - bounded by its
        // balance, never mints new ones.
        ledger
            .disburse_from_treasury(Pubkey::treasury(), pubkey, amount)
            .map_err(|e| e.to_string())?;
    }
    state.pending_airdrops.lock().unwrap().push((pubkey, amount));
    let sig = hex::encode(entry.hash);
    state.pending_poh_entries.lock().unwrap().push(entry);

    Ok(json!({ "signature": sig, "slot": state.slot() }))
}

fn handle_send_transaction(state: &Arc<AppState>, params: &Value) -> Result<Value, String> {
    let tx_value = params.get(0).ok_or("missing transaction param")?;
    let tx: Transaction =
        serde_json::from_value(tx_value.clone()).map_err(|e| format!("invalid transaction: {e}"))?;

    let entry = {
        let mut poh = state.poh.lock().unwrap();
        poh.record(&tx.hash())
    };

    {
        let mut ledger = state.ledger.lock().unwrap();
        ledger
            .apply_transaction(&tx, &state.programs, &state.identity, state.fee_units)
            .map_err(|e| e.to_string())?;
    }
    let sig = hex::encode(tx.hash());
    state.pending_txs.lock().unwrap().push(tx);
    state.pending_poh_entries.lock().unwrap().push(entry);

    Ok(json!({ "signature": sig, "slot": state.slot(), "fee": state.fee_units }))
}
