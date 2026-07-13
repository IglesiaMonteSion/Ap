//! qchain-wallet: a tiny local web wallet. Serves a simple browser UI to
//! create wallets, see balances, and send transfers between wallets - all the
//! everyday operations a non-technical person needs, with buttons instead of
//! the CLI.
//!
//! Why a local server and not a pure-browser wallet: transactions are signed
//! with this chain's hybrid *post-quantum* signature (Ed25519 + ML-DSA-65).
//! Reimplementing that (and the exact address/borsh encoding) in JavaScript
//! would be a large, error-prone parallel implementation whose smallest
//! mismatch produces silently-rejected transactions. Instead this reuses the
//! *exact same* `qchain-crypto`/`qchain-core` code the CLI and node use, so a
//! signed transaction is guaranteed byte-compatible. The browser is just the
//! UI; the private keys never leave this machine.
//!
//! Security: binds to `127.0.0.1` by default on purpose - whoever can reach
//! this port can spend the wallets it holds. Exposing it beyond localhost is
//! possible (`--bind`) but warned against loudly.

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use clap::Parser;
use qchain_core::{Account, Instruction, Transaction};
use qchain_crypto::{Keypair, Pubkey};
use qchain_execution::SystemInstruction;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(about = "Wallet web local para qchain: crear wallets, ver balances y transferir")]
struct Cli {
    /// RPC del nodo qchain al que hablarle (el mismo que ves en la página de estado).
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    rpc: String,
    /// Carpeta donde se guardan los archivos de las wallets (claves privadas).
    #[arg(long, default_value = "wallets")]
    wallets_dir: PathBuf,
    /// Dirección en la que escucha la interfaz web. `127.0.0.1` = solo esta máquina.
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,
    /// Puerto de la interfaz web.
    #[arg(long, default_value_t = 8090)]
    port: u16,
    /// Techo de fee por transacción (unidades). El fee real de una transferencia
    /// simple es ~1.002.780; este es solo el límite de seguridad.
    #[arg(long, default_value_t = 10_000_000)]
    fee_limit: u64,
    /// Contraseña para entrar a la wallet (usuario: cualquiera). OBLIGATORIA si
    /// la exponés fuera de localhost (`--bind` != 127.0.0.1), porque quien
    /// llega al puerto puede gastar las wallets. También se puede pasar por la
    /// variable de entorno QCHAIN_WALLET_PASSWORD (mejor, no queda en el
    /// historial de comandos).
    #[arg(long)]
    password: Option<String>,
}

struct AppState {
    rpc: String,
    wallets_dir: PathBuf,
    fee_limit: u64,
    http: reqwest::Client,
    /// If set, every request must carry HTTP Basic auth with this password.
    password: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.wallets_dir)?;

    // Password: from --password or the env var (env is preferred - it doesn't
    // land in shell history). Empty = none.
    let password = cli.password.or_else(|| std::env::var("QCHAIN_WALLET_PASSWORD").ok()).filter(|s| !s.is_empty());
    let exposed = cli.bind != "127.0.0.1" && cli.bind != "localhost";

    // Fail-safe: never expose a key-holding wallet to the network with no
    // password. Localhost-only needs none (only this machine can reach it).
    if exposed && password.is_none() {
        anyhow::bail!(
            "te estás por exponer la wallet a la red (--bind {}) SIN contraseña - cualquiera que llegue al puerto podría vaciar tus wallets.\n\
             Poné una contraseña, idealmente por variable de entorno para que no quede en el historial:\n\
             \n    QCHAIN_WALLET_PASSWORD='tu-clave-fuerte' qchain-wallet --bind {} ...\n",
            cli.bind, cli.bind
        );
    }

    let state = Arc::new(AppState {
        rpc: cli.rpc.trim_end_matches('/').to_string(),
        wallets_dir: cli.wallets_dir.clone(),
        fee_limit: cli.fee_limit,
        http: reqwest::Client::new(),
        password: password.clone(),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/api/config", get(config))
        .route("/api/node", get(node_status))
        .route("/api/wallets", get(list_wallets).post(new_wallet))
        .route("/api/balance/:address", get(balance))
        .route("/api/max/:name", get(max_amount))
        .route("/api/transfer", post(transfer))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state);

    let addr = format!("{}:{}", cli.bind, cli.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Wallet web abierta en:  http://{addr}");
    println!("Hablando con el nodo:   {}", cli.rpc);
    println!("Wallets guardadas en:   {}", cli.wallets_dir.display());
    if password.is_some() {
        println!("Protección:             contraseña activada (el navegador la va a pedir)");
    }
    if exposed {
        println!();
        println!("*** Expuesta a la red en {}. Está protegida por contraseña, pero sobre HTTP", cli.bind);
        println!("*** la clave viaja SIN cifrar - para uso serio poné un proxy con HTTPS (TLS)");
        println!("*** adelante. Para un testnet sin valor real, alcanza.");
    }
    axum::serve(listener, app).await?;
    Ok(())
}

/// HTTP Basic auth gate. If a password is configured, every request (the page
/// and the API) must carry `Authorization: Basic base64(user:password)` with
/// the right password (any username). Returns 401 with a `WWW-Authenticate`
/// challenge so the browser shows a login prompt. A no-op when no password is
/// set (localhost-only use). Honest limit: over plain HTTP the password is
/// only base64-encoded, not encrypted - put HTTPS in front for real exposure.
async fn require_auth(State(st): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let Some(expected) = &st.password else {
        return next.run(req).await;
    };
    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Basic "))
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|creds| creds.split_once(':').map(|(_, pass)| pass.to_string()));
    if provided.as_deref() == Some(expected.as_str()) {
        next.run(req).await
    } else {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"qchain wallet\"")
            .body(Body::from("autenticación requerida"))
            .expect("static 401 response always builds")
    }
}

async fn index() -> Html<&'static str> {
    Html(include_str!("wallet.html"))
}

async fn config(State(st): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({ "rpc": st.rpc }))
}

/// The node's `/status`, proxied through this server. The browser can't fetch
/// the node directly (it's a different origin - a different port - and the
/// node sends no CORS headers, so a cross-origin fetch is blocked), so the
/// wallet's own backend, which already talks to the node, relays it. Returns
/// `{ online: false }` if the node isn't reachable rather than erroring, so
/// the UI can show a clean "node down" state.
async fn node_status(State(st): State<Arc<AppState>>) -> Json<Value> {
    match st.http.get(format!("{}/status", st.rpc)).send().await {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(mut v) => {
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("online".to_string(), Value::Bool(true));
                }
                Json(v)
            }
            Err(_) => Json(json!({ "online": false })),
        },
        Err(_) => Json(json!({ "online": false })),
    }
}

#[derive(Serialize)]
struct WalletInfo {
    name: String,
    address: String,
    /// Balance in base units, as a string (u64 can exceed JS's safe integer range).
    balance: String,
}

async fn list_wallets(State(st): State<Arc<AppState>>) -> Result<Json<Vec<WalletInfo>>, ApiError> {
    let mut wallets = Vec::new();
    let entries = std::fs::read_dir(&st.wallets_dir).map_err(ApiError::internal)?;
    let mut names: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    for name in names {
        let path = wallet_path(&st, &name)?;
        let Ok(kp) = qchain_crypto::read_keypair_file(&path) else { continue };
        let address = kp.pubkey();
        let balance = fetch_account(&st, &address).await.map_err(ApiError::internal)?.map(|a| a.balance).unwrap_or(0);
        wallets.push(WalletInfo { name, address: address.to_string(), balance: balance.to_string() });
    }
    Ok(Json(wallets))
}

#[derive(Deserialize)]
struct NewWalletReq {
    name: String,
}

async fn new_wallet(State(st): State<Arc<AppState>>, Json(req): Json<NewWalletReq>) -> Result<Json<WalletInfo>, ApiError> {
    let name = sanitize_name(&req.name)?;
    let path = wallet_path(&st, &name)?;
    if path.exists() {
        return Err(ApiError::bad(format!("ya existe una wallet llamada '{name}'")));
    }
    let keypair = Keypair::generate().map_err(ApiError::internal)?;
    qchain_crypto::write_keypair_file(&keypair, &path).map_err(ApiError::internal)?;
    Ok(Json(WalletInfo { name, address: keypair.pubkey().to_string(), balance: "0".to_string() }))
}

async fn balance(State(st): State<Arc<AppState>>, Path(address): Path<String>) -> Result<Json<Value>, ApiError> {
    let pk: Pubkey = address.trim().parse().map_err(|e| ApiError::bad(format!("dirección inválida: {e}")))?;
    let bal = fetch_account(&st, &pk).await.map_err(ApiError::internal)?.map(|a| a.balance).unwrap_or(0);
    Ok(Json(json!({ "address": pk.to_string(), "balance": bal.to_string() })))
}

/// The most a wallet can send in one transfer: its balance minus the exact
/// network fee. Computed against reality, not a guess: builds a real signed
/// transfer with this wallet's own key to measure the transaction's byte size
/// (which depends on the signature scheme), and reads the live
/// `base_fee_per_byte` from the node - fee = size × base_fee_per_byte, the
/// same formula the ledger charges. The amount value doesn't affect the size
/// (a `u64` is fixed-width), so a zero-amount sample measures it exactly.
async fn max_amount(State(st): State<Arc<AppState>>, Path(name): Path<String>) -> Result<Json<Value>, ApiError> {
    let name = sanitize_name(&name)?;
    let path = wallet_path(&st, &name)?;
    let payer = qchain_crypto::read_keypair_file(&path).map_err(|_| ApiError::bad(format!("no encontré la wallet '{name}'")))?;
    let balance = fetch_account(&st, &payer.pubkey()).await.map_err(ApiError::internal)?.map(|a| a.balance).unwrap_or(0);
    let base_fee = fetch_base_fee(&st).await.map_err(ApiError::internal)?;
    let chain_id = fetch_chain_id(&st).await.map_err(ApiError::internal)?;
    let data = borsh::to_vec(&SystemInstruction::Transfer { amount: 0 }).map_err(ApiError::internal)?;
    let ix = Instruction { program_id: Pubkey::system_program_id(), accounts: vec![payer.pubkey(), payer.pubkey()], data };
    let sample = Transaction::new_signed(&payer, 0, chain_id, st.fee_limit, vec![ix]).map_err(ApiError::internal)?;
    let fee = base_fee.saturating_mul(sample.byte_size() as u64);
    let max = balance.saturating_sub(fee);
    Ok(Json(json!({ "max": max.to_string(), "fee": fee.to_string(), "balance": balance.to_string() })))
}

#[derive(Deserialize)]
struct TransferReq {
    /// Name of the sending wallet (a file in `wallets_dir`).
    from: String,
    /// Destination address (base58).
    to: String,
    /// Amount in base units, as a decimal string (avoids JS number-precision loss).
    amount: String,
}

async fn transfer(State(st): State<Arc<AppState>>, Json(req): Json<TransferReq>) -> Result<Json<Value>, ApiError> {
    let name = sanitize_name(&req.from)?;
    let path = wallet_path(&st, &name)?;
    let payer = qchain_crypto::read_keypair_file(&path).map_err(|_| ApiError::bad(format!("no encontré la wallet '{name}'")))?;
    let to_pk: Pubkey = req.to.trim().parse().map_err(|e| ApiError::bad(format!("dirección destino inválida: {e}")))?;
    let amount: u64 = req.amount.trim().parse().map_err(|_| ApiError::bad("el monto debe ser un número entero de unidades".to_string()))?;
    if amount == 0 {
        return Err(ApiError::bad("el monto debe ser mayor que cero".to_string()));
    }

    let nonce = fetch_account(&st, &payer.pubkey()).await.map_err(ApiError::internal)?.map(|a| a.nonce).unwrap_or(0);
    let chain_id = fetch_chain_id(&st).await.map_err(ApiError::internal)?;
    let data = borsh::to_vec(&SystemInstruction::Transfer { amount }).map_err(ApiError::internal)?;
    let ix = Instruction { program_id: Pubkey::system_program_id(), accounts: vec![payer.pubkey(), to_pk], data };
    let tx = Transaction::new_signed(&payer, nonce, chain_id, st.fee_limit, vec![ix]).map_err(ApiError::internal)?;

    let resp = st.http.post(format!("{}/tx", st.rpc)).json(&tx).send().await.map_err(ApiError::internal)?;
    if !resp.status().is_success() {
        let msg = resp.text().await.unwrap_or_default();
        return Err(ApiError::bad(format!("el nodo rechazó la transacción: {msg}")));
    }
    let body: Value = resp.json().await.map_err(ApiError::internal)?;
    Ok(Json(json!({ "ok": true, "tx": body, "from": payer.pubkey().to_string(), "to": to_pk.to_string(), "amount": amount.to_string() })))
}

// ---- helpers --------------------------------------------------------------

async fn fetch_account(st: &AppState, address: &Pubkey) -> anyhow::Result<Option<Account>> {
    let resp = st.http.get(format!("{}/account/{address}", st.rpc)).send().await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    Ok(Some(resp.error_for_status()?.json().await?))
}

/// Live `base_fee_per_byte` from the node's `/status` - the current network
/// fee rate, so "send max" and any fee display track governance changes.
async fn fetch_base_fee(st: &AppState) -> anyhow::Result<u64> {
    let resp: Value = st.http.get(format!("{}/status", st.rpc)).send().await?.error_for_status()?.json().await?;
    Ok(resp["base_fee_per_byte"].as_u64().unwrap_or(0))
}

async fn fetch_chain_id(st: &AppState) -> anyhow::Result<[u8; 32]> {
    let resp: Value = st.http.get(format!("{}/chain_id", st.rpc)).send().await?.error_for_status()?.json().await?;
    let hex_str = resp["chain_id"].as_str().ok_or_else(|| anyhow::anyhow!("respuesta /chain_id malformada"))?;
    let bytes = hex::decode(hex_str)?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("chain_id debe ser de 32 bytes"))
}

/// Reject anything that isn't a plain, safe wallet name (no path traversal,
/// no separators) - these become filenames under `wallets_dir`.
fn sanitize_name(name: &str) -> Result<String, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(ApiError::bad("el nombre de la wallet debe tener entre 1 y 64 caracteres".to_string()));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(ApiError::bad("el nombre solo puede tener letras, números, '_' y '-'".to_string()));
    }
    Ok(name.to_string())
}

fn wallet_path(st: &AppState, name: &str) -> Result<PathBuf, ApiError> {
    let name = sanitize_name(name)?;
    Ok(st.wallets_dir.join(format!("{name}.json")))
}

/// A JSON error the frontend can show directly.
struct ApiError(StatusCode, String);

impl ApiError {
    fn bad(msg: String) -> Self {
        ApiError(StatusCode::BAD_REQUEST, msg)
    }
    fn internal(e: impl std::fmt::Display) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}
