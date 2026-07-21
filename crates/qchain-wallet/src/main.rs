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

mod keystore;

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
    /// URL del faucet de la red (el `qchain-faucet`), si el operador tiene uno.
    /// Cuando se setea, la pantalla "Comprar" de la wallet muestra un botón
    /// "Pedir QCH de prueba" que pide fondos al faucet para la cuenta activa.
    /// El navegador no puede llamar al faucet directo (otro origen, sin CORS),
    /// así que la wallet lo proxya en `/api/faucet`. Ausente = botón oculto.
    #[arg(long)]
    faucet: Option<String>,
    /// Origen EXACTO (esquema+host, ej. `https://scan.qchainhq.com`) del
    /// explorador QScan autorizado a pedirle firmas a esta wallet por el puente
    /// wallet-connect. Cuando se setea, la wallet escucha pedidos `postMessage`
    /// SÓLO de ese origen y, tras aprobación HUMANA explícita, firma el deploy /
    /// interacción de contratos (la semilla nunca sale del navegador). Ausente =
    /// el puente está APAGADO (la wallet ignora todo `postMessage`). También por
    /// la variable de entorno QCHAIN_CONNECT_ORIGIN.
    #[arg(long)]
    connect_origin: Option<String>,
}

struct AppState {
    rpc: String,
    wallets_dir: PathBuf,
    fee_limit: u64,
    http: reqwest::Client,
    /// If set, every request to a custodial route must carry HTTP Basic auth
    /// with this password.
    password: Option<String>,
    /// Whether the custodial (server-holds-the-keys) wallet is reachable at all.
    /// False when the wallet is exposed to the network with no password: rather
    /// than refuse to boot (which would also kill the safe non-custodial wallet
    /// at `/`), we just serve a 403 on the custodial routes and keep the
    /// key-less browser wallet available to everyone.
    custodial_enabled: bool,
    /// True when the server is bound to a loopback address (127.0.0.1 /
    /// localhost). Only in that case do we enforce a Host-header allowlist on
    /// custodial routes: DNS-rebinding attacks specifically target a
    /// loopback-only server (a malicious page rebinds its own domain to
    /// 127.0.0.1 to reach a server the victim can reach but the attacker's
    /// origin normally can't). When the wallet is deliberately exposed (a
    /// public bind, or fronted by a Cloudflare tunnel), the Host header is a
    /// legitimately arbitrary domain and the password is the real defense, so
    /// we do NOT gate on it there - enforcing an allowlist would break the
    /// user's real tunnel deployment.
    loopback_bound: bool,
    /// Optional testnet faucet URL (the `qchain-faucet`). When set, the browser
    /// can ask for test QCH via the `/api/faucet` proxy (the faucet is a
    /// separate origin the browser can't reach directly). None = feature off.
    faucet: Option<String>,
    /// Exact origin (scheme+host) of the QScan explorer allowed to request
    /// signatures from this wallet over the wallet-connect bridge. The browser
    /// enforces `event.origin === connect_origin` on every postMessage. None =
    /// the bridge is OFF (the wallet ignores all postMessage). See the bridge
    /// listener in `wasm_wallet.html`.
    connect_origin: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    std::fs::create_dir_all(&cli.wallets_dir)?;

    // Password: from --password or the env var (env is preferred - it doesn't
    // land in shell history). Empty = none.
    let password = cli.password.or_else(|| std::env::var("QCHAIN_WALLET_PASSWORD").ok()).filter(|s| !s.is_empty());
    let exposed = cli.bind != "127.0.0.1" && cli.bind != "localhost";
    let loopback_bound = cli.bind == "127.0.0.1" || cli.bind == "localhost" || cli.bind == "::1";

    // The custodial wallet (server holds the keys) is only reachable when it's
    // safe: either we're localhost-only, or a password is set. Exposed with no
    // password, the custodial routes are turned off (403) instead of refusing
    // to boot - the safe, key-less non-custodial wallet at `/` stays up for
    // everyone. This is why exposing without a password is no longer a hard
    // error: the thing that used to be dangerous (open server-held keys) is now
    // simply disabled, while the wallet a stranger actually lands on holds no
    // keys on the server at all.
    let custodial_enabled = !exposed || password.is_some();
    if exposed && password.is_none() {
        println!("*** Sin contraseña y expuesta a la red: la wallet CUSTODIAL (/custodial) queda DESACTIVADA.");
        println!("*** Solo la wallet no-custodial (/) - claves en el navegador - está disponible. Eso es lo seguro.");
        println!("*** Si querés la custodial, poné una contraseña:  QCHAIN_WALLET_PASSWORD='...' qchain-wallet --bind {} ...", cli.bind);
    }

    let state = Arc::new(AppState {
        rpc: cli.rpc.trim_end_matches('/').to_string(),
        wallets_dir: cli.wallets_dir.clone(),
        fee_limit: cli.fee_limit,
        // QCH-WALLET-004: bound every proxy call to the node with real timeouts,
        // so a slow/hung node can't pin a wallet request (and thus a browser
        // connection) open indefinitely. A default `Client::new()` has NO
        // timeout at all.
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new()),
        password: password.clone(),
        custodial_enabled,
        loopback_bound,
        faucet: cli.faucet.clone().map(|u| u.trim_end_matches('/').to_string()),
        connect_origin: cli
            .connect_origin
            .clone()
            .or_else(|| std::env::var("QCHAIN_CONNECT_ORIGIN").ok())
            .map(|u| u.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty()),
    });

    // Public routes: the non-custodial (WASM) wallet holds NO keys on the
    // server - the private key is generated, encrypted and used entirely in the
    // browser, protected by the user's own password there. So it needs no
    // server login. Its endpoints are the static assets plus read-only proxies
    // (chain_id, account) and a relay that just forwards an already-signed tx
    // to the node's /tx (itself open) - no new attack surface. `/api/config`
    // and `/api/node` are read-only and shared by both wallets.
    let public = Router::new()
        // The default landing page is the NON-CUSTODIAL wallet: keys live in
        // the browser, so it needs no server login. This is what a stranger
        // opening the wallet from any browser gets - no username/password.
        .route("/", get(wasm_page))
        .route("/wasm", get(wasm_page))
        .route("/wasm/qchain_wasm.js", get(wasm_js))
        .route("/wasm/qchain_wasm_bg.wasm", get(wasm_bg))
        .route("/vendor/jsQR.min.js", get(jsqr_js))
        // brand / PWA assets (favicon, home-screen icons, manifest)
        .route("/icon.svg", get(icon_svg))
        .route("/favicon.ico", get(icon_svg))
        .route("/apple-touch-icon.png", get(apple_touch_icon))
        // iOS also requests these precomposed variants by convention
        .route("/apple-touch-icon-precomposed.png", get(apple_touch_icon))
        .route("/icon-192.png", get(icon_192))
        .route("/icon-512.png", get(icon_512))
        .route("/icon-512-maskable.png", get(icon_512_maskable))
        .route("/manifest.webmanifest", get(manifest))
        .route("/api/chain_id", get(chain_id_ep))
        .route("/api/account/:address", get(account_ep))
        .route("/api/stake/:address", get(stake_ep))
        .route("/api/stake_v7/:address", get(stake_v7_ep))
        .route("/api/relay-tx", post(relay_tx))
        .route("/api/config", get(config))
        .route("/api/node", get(node_status))
        // Info pública (no expone claves): el QR es solo la dirección
        // codificada, y el historial de transferencias ya es visible en el
        // dashboard del nodo. La wallet no-custodial (/) los usa para recibir
        // y mostrar actividad sin necesitar login.
        .route("/api/qr/:address", get(qr_code))
        .route("/api/transfers", get(recent_transfers))
        .route("/api/staking_activity/:address", get(staking_activity))
        .route("/api/validators", get(validators))
        .route("/api/programs", get(programs))
        .route("/api/proposal/:address", get(proposal_ep))
        .route("/api/economics", get(economics))
        .route("/api/faucet", post(faucet_request));

    // Protected routes: the custodial wallet (keys held on the server), now at
    // `/custodial`. These DO need the password gate - whoever reaches them could
    // otherwise create, read, export or spend server-held wallets.
    let protected = Router::new()
        .route("/custodial", get(index))
        .route("/api/wallets", get(list_wallets).post(new_wallet))
        .route("/api/balance/:address", get(balance))
        .route("/api/max/:name", get(max_amount))
        .route("/api/transfer", post(transfer))
        .route("/api/import", post(import_wallet))
        .route("/api/export/:name", get(export_wallet))
        .route("/api/export-encrypted", post(export_encrypted))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_auth));

    let app = public
        .merge(protected)
        .layer(axum::middleware::from_fn(security_headers))
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

/// Baseline security headers on every response. This wallet holds the user's
/// seed in browser memory + an encrypted blob in localStorage and is often
/// exposed publicly (Cloudflare tunnel), so the only barrier between any future
/// injection and total seed theft is the hand-rolled `esc()` - CSP is the
/// backstop if one were ever missed. `'unsafe-inline'` + `'wasm-unsafe-eval'`
/// are required (the whole app is inline JS/CSS + a WASM signer), so the CSP is
/// weaker than ideal, but `object-src 'none'`/`base-uri 'none'`/`frame-ancestors
/// 'none'` still cut the main injection-escalation and framing vectors. The
/// three simple headers are unconditionally safe: every handler sets an explicit
/// Content-Type (nosniff), the wallet is never meant to be framed (clickjacking
/// the send/confirm flow), and the URL/path shouldn't leak outward (no-referrer).
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; \
             object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    h.insert(header::X_FRAME_OPTIONS, header::HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, header::HeaderValue::from_static("no-referrer"));
    resp
}

/// HTTP Basic auth gate. If a password is configured, every request (the page
/// and the API) must carry `Authorization: Basic base64(user:password)` with
/// the right password (any username). Returns 401 with a `WWW-Authenticate`
/// challenge so the browser shows a login prompt. A no-op when no password is
/// set (localhost-only use). Honest limit: over plain HTTP the password is
/// only base64-encoded, not encrypted - put HTTPS in front for real exposure.
async fn require_auth(State(st): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    // Custodial wallet disabled (exposed to the network with no password set):
    // refuse every custodial route outright. The non-custodial wallet at `/` is
    // public and unaffected.
    if !st.custodial_enabled {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from(
                "la wallet custodial está desactivada (expuesta sin contraseña). \
                 Usá la wallet no-custodial en / , o reiniciá con una contraseña.",
            ))
            .expect("static 403 response always builds");
    }
    // DNS-rebinding defense, but ONLY when bound to loopback (see
    // `loopback_bound` doc). A malicious web page can rebind its own hostname
    // to 127.0.0.1 and drive the victim's browser to POST at these custodial
    // routes; the browser will send the *attacker's* domain in the Host
    // header. Since a legitimate loopback client always addresses the server
    // as localhost/127.0.0.1, rejecting any other Host closes the rebinding
    // path without a password ever being involved. Skipped entirely when
    // exposed, where an arbitrary Host (a tunnel domain) is legitimate.
    if st.loopback_bound {
        let host_ok = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| {
                let host = h.rsplit_once(':').map(|(hp, _)| hp).unwrap_or(h);
                host == "127.0.0.1" || host == "localhost" || host == "[::1]" || host == "::1"
            })
            .unwrap_or(false);
        if !host_ok {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from(
                    "Host no permitido para la wallet custodial local (defensa anti DNS-rebinding). \
                     Accedé por http://127.0.0.1 o localhost.",
                ))
                .expect("static 403 response always builds");
        }
    }
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
    // The canonical burn address: the all-`0xFF` public key. No keypair can
    // derive to it (finding a preimage is infeasible), so any funds sent here
    // are permanently unspendable - a real, if untracked-by-`total_burned`,
    // removal from circulation. Computed with the node's exact base58 encoding
    // (`Pubkey`'s `Display`) so the string the wallet sends matches byte-for-byte
    // what the node parses. Used by "delete wallet" to burn any residual balance.
    Json(json!({
        "rpc": st.rpc,
        "burn_address": Pubkey([0xFFu8; 32]).to_string(),
        // Only whether a faucet is configured (the UI shows/hides the button) -
        // the faucet URL itself is never leaked to the browser; requests go
        // through the `/api/faucet` proxy.
        "faucet_enabled": st.faucet.is_some(),
        // The wallet-connect bridge's allowed origin (the QScan explorer that may
        // request signatures). null = bridge off. The browser enforces
        // `event.origin === connect_origin` on every postMessage.
        "connect_origin": st.connect_origin,
    }))
}

/// Proxy a faucet drip request to the configured `qchain-faucet`. The browser
/// can't call the faucet directly (a different origin with no CORS headers), so
/// the wallet's own backend relays it. The recipient address is the only
/// client-supplied field; the faucet decides the amount (never the caller) and
/// rate-limits per address. Returns 404 if no faucet is configured.
async fn faucet_request(
    State(st): State<Arc<AppState>>,
    Json(req): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let faucet = st
        .faucet
        .as_deref()
        .ok_or((StatusCode::NOT_FOUND, "no hay faucet configurado en esta wallet".to_string()))?;
    // Validate the address before forwarding: reject anything that isn't a real
    // Pubkey (no path/query injection into the faucet URL, and a clean 400
    // instead of bouncing garbage off the faucet).
    let address = req.get("address").and_then(|v| v.as_str()).unwrap_or_default();
    let _pk: Pubkey = address
        .parse()
        .map_err(|e: anyhow::Error| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let resp = st
        .http
        .post(format!("{faucet}/faucet"))
        .json(&json!({ "address": address }))
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("no pude contactar el faucet: {e}")))?;
    let status = resp.status();
    // The faucet returns JSON on success but a plain-text body on error
    // (its handler's `Err` arm is `(StatusCode, String)`), so read text and
    // parse leniently.
    let text = resp.text().await.unwrap_or_default();
    if status.is_success() {
        let body: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "ok": true }));
        Ok(Json(body))
    } else {
        Err((
            StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            if text.is_empty() { "el faucet rechazó el pedido".to_string() } else { text },
        ))
    }
}

// ---- non-custodial WASM wallet (keys live in the browser) ----------------

async fn wasm_page() -> Html<&'static str> {
    Html(include_str!("wasm_wallet.html"))
}

async fn wasm_js() -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/javascript")
        .body(Body::from(include_str!("wasm_assets/qchain_wasm.js")))
        .expect("static js response always builds")
}

async fn wasm_bg() -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/wasm")
        .body(Body::from(&include_bytes!("wasm_assets/qchain_wasm_bg.wasm")[..]))
        .expect("static wasm response always builds")
}

/// jsQR (MIT), a pure-JS QR decoder, vendored so the wallet's camera scanner
/// works on ANY browser — including iOS Safari, which lacks the native
/// `BarcodeDetector` API. Served from the binary (no CDN, no external trust
/// surface); the browser decodes camera frames locally, nothing leaves the
/// device.
async fn jsqr_js() -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/javascript")
        .header(header::CACHE_CONTROL, "public, max-age=604800")
        .body(Body::from(include_str!("wasm_assets/jsQR.min.js")))
        .expect("static js response always builds")
}

// ---- brand / PWA assets (favicon, home-screen app icons, manifest) --------
// So the wallet looks like a real app: a proper favicon in the tab and, when
// added to the phone's home screen ("Añadir a inicio"), a native-looking app
// icon + name instead of a screenshot. iOS reads `apple-touch-icon` (PNG only);
// Android reads the web manifest's PNG icons. All embedded in the binary.

fn static_asset(content_type: &str, body: Body) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        // Icons/manifest are versioned with the binary; let clients cache them.
        .header(header::CACHE_CONTROL, "public, max-age=604800")
        .body(body)
        .expect("static asset response always builds")
}

async fn icon_svg() -> Response {
    static_asset("image/svg+xml", Body::from(include_str!("wasm_assets/icon.svg")))
}
async fn apple_touch_icon() -> Response {
    static_asset("image/png", Body::from(&include_bytes!("wasm_assets/apple-touch-icon.png")[..]))
}
async fn icon_192() -> Response {
    static_asset("image/png", Body::from(&include_bytes!("wasm_assets/icon-192.png")[..]))
}
async fn icon_512() -> Response {
    static_asset("image/png", Body::from(&include_bytes!("wasm_assets/icon-512.png")[..]))
}
async fn icon_512_maskable() -> Response {
    static_asset("image/png", Body::from(&include_bytes!("wasm_assets/icon-512-maskable.png")[..]))
}
async fn manifest() -> Response {
    static_asset("application/manifest+json", Body::from(include_str!("wasm_assets/manifest.webmanifest")))
}

/// The network's chain id (hex), so the browser can sign a chain-bound tx.
async fn chain_id_ep(State(st): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let cid = fetch_chain_id(&st).await.map_err(ApiError::internal)?;
    Ok(Json(json!({ "chain_id": hex::encode(cid) })))
}

/// An account's balance and nonce - both needed to build a transaction in the
/// browser (the nonce especially). Proxied so it's same-origin (no CORS).
async fn account_ep(State(st): State<Arc<AppState>>, Path(address): Path<String>) -> Result<Json<Value>, ApiError> {
    let pk: Pubkey = address.trim().parse().map_err(|e| ApiError::bad(format!("dirección inválida: {e}")))?;
    let acct = fetch_account(&st, &pk).await.map_err(ApiError::internal)?;
    Ok(Json(json!({
        "address": pk.to_string(),
        "balance": acct.as_ref().map(|a| a.balance).unwrap_or(0).to_string(),
        "nonce": acct.map(|a| a.nonce).unwrap_or(0),
    })))
}

/// Live state of a stake account, proxied from the node's `/stake/:address`
/// (pending reward + bonding/lock rounds). Read-only, no keys - lets the
/// non-custodial wallet show real rewards and pre-check an Undelegate.
async fn stake_ep(State(st): State<Arc<AppState>>, Path(address): Path<String>) -> Result<Json<Value>, ApiError> {
    // Parse to a real Pubkey before interpolating into the node URL: this
    // rejects anything that isn't a canonical address (no slashes, no query
    // fragments, no path traversal) so a caller can't smuggle a different
    // node path through this proxy. Re-encode from the parsed value, not the
    // raw string, so only a well-formed address ever reaches the node.
    let pk: Pubkey = address.trim().parse().map_err(|e| ApiError::bad(format!("dirección inválida: {e}")))?;
    let url = format!("{}/stake/{}", st.rpc, pk);
    let resp = st.http.get(&url).send().await.map_err(ApiError::internal)?;
    let val: Value = resp.json().await.map_err(ApiError::internal)?;
    Ok(Json(val))
}

/// Live state of a v7 staking position, proxied from the node's
/// `/stake_v7/:address` (index-accrued value + unbonding state). Read-only, no
/// keys - the v7 staking UI reads this instead of `/api/stake` (v6 format).
async fn stake_v7_ep(State(st): State<Arc<AppState>>, Path(address): Path<String>) -> Result<Json<Value>, ApiError> {
    let pk: Pubkey = address.trim().parse().map_err(|e| ApiError::bad(format!("dirección inválida: {e}")))?;
    let url = format!("{}/stake_v7/{}", st.rpc, pk);
    let resp = st.http.get(&url).send().await.map_err(ApiError::internal)?;
    let val: Value = resp.json().await.map_err(ApiError::internal)?;
    Ok(Json(val))
}

/// Decoded governance proposal, proxied from the node's `/account/:addr` and
/// deserialized here (the browser can't decode Borsh). Read-only, no keys.
/// Powers the wallet governance panel: the tally, the current status, and -
/// crucially - the risk tier, which tells the browser which singleton to name
/// as `Execute`'s target account (params vs registry). The node still enforces
/// the correct singleton for the proposal's real tier, so this is a UX aid,
/// never a trust boundary.
async fn proposal_ep(State(st): State<Arc<AppState>>, Path(address): Path<String>) -> Result<Json<Value>, ApiError> {
    use qchain_governance::{Proposal, ProposalAction, RiskTier};
    let pk: Pubkey = address.trim().parse().map_err(|e| ApiError::bad(format!("dirección de propuesta inválida: {e}")))?;
    let acct = fetch_account(&st, &pk).await.map_err(ApiError::internal)?;
    let acct = acct.ok_or_else(|| ApiError::bad("la propuesta no existe".into()))?;
    let p: Proposal = borsh::from_slice(&acct.data).map_err(|e| ApiError::bad(format!("esa cuenta no es una propuesta de gobernanza: {e}")))?;
    let tier = p.action.risk_tier();
    let action_label = match &p.action {
        ProposalAction::SetBaseFeePerByte(v) => format!("Fijar fee base por byte = {v}"),
        ProposalAction::SetDustThreshold(v) => format!("Fijar umbral de polvo = {v}"),
        ProposalAction::SetGasPricePerFuel(v) => format!("Fijar precio de gas por fuel = {v}"),
        ProposalAction::SetStakingCommissionBps(v) => format!("Fijar comisión de staking = {v} bps"),
        ProposalAction::SetEmissionApr(v) => format!("Fijar emisión (APR) = {v} bps"),
        ProposalAction::ActivateAlgorithm(e) => format!("Activar algoritmo {} (id {})", e.name, e.id.0),
        ProposalAction::DeprecateAlgorithm { id, .. } => format!("Deprecar algoritmo id {}", id.0),
        ProposalAction::RetireAlgorithm { id } => format!("Retirar algoritmo id {}", id.0),
    };
    Ok(Json(json!({
        "address": pk.to_string(),
        "id": p.id,
        "proposer": p.proposer.to_string(),
        "action": action_label,
        "tier": match tier { RiskTier::Low => "low", RiskTier::Registry => "registry" },
        "registry": matches!(tier, RiskTier::Registry),
        "status": format!("{:?}", p.status),
        "created_round": p.created_round,
        "voting_ends_round": p.voting_ends_round,
        "yes_stake": p.yes_stake.to_string(),
        "no_stake": p.no_stake.to_string(),
        "abstain_stake": p.abstain_stake.to_string(),
        "votes": p.voted_stake_accounts.len(),
    })))
}

/// Relay a browser-signed transaction (raw signed-Transaction JSON) to the
/// node's `/tx`. The server never signs anything - it just forwards, so the
/// key stays in the browser. Same-origin relay avoids the node needing CORS.
async fn relay_tx(State(st): State<Arc<AppState>>, body: axum::body::Bytes) -> Result<Json<Value>, ApiError> {
    // A signed Transaction (hybrid Ed25519+ML-DSA-65, ~5.5KB) is small; the
    // node itself already caps `/tx` bodies. Cap here too so this open relay
    // can't be used to shovel arbitrarily large payloads at the node in a
    // single request. 256KB is generous headroom over a real signed tx.
    const MAX_RELAY_BODY: usize = 256 * 1024;
    if body.len() > MAX_RELAY_BODY {
        return Err(ApiError::bad(format!(
            "transacción demasiado grande ({} bytes, máximo {})",
            body.len(),
            MAX_RELAY_BODY
        )));
    }
    let resp = st
        .http
        .post(format!("{}/tx", st.rpc))
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(ApiError::internal)?;
    if !resp.status().is_success() {
        let msg = resp.text().await.unwrap_or_default();
        return Err(ApiError::bad(format!("el nodo rechazó la transacción: {msg}")));
    }
    let v: Value = resp.json().await.map_err(ApiError::internal)?;
    Ok(Json(v))
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

/// A QR code (SVG) of an address, so someone can scan it to send funds -
/// standard "receive" UX. Generated server-side (pure-Rust `qrcode`) so the
/// page stays self-contained with no external QR service.
async fn qr_code(Path(address): Path<String>) -> Result<Response, ApiError> {
    let code = qrcode::QrCode::new(address.as_bytes())
        .map_err(|e| ApiError::bad(format!("no se pudo generar el QR: {e}")))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(qrcode::render::svg::Color("#111827"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Response::builder()
        .header(header::CONTENT_TYPE, "image/svg+xml")
        .header(header::CACHE_CONTROL, "public, max-age=86400")
        .body(Body::from(svg))
        .map_err(ApiError::internal)
}

/// The node's recent transfers, proxied (same-origin) so the browser can show
/// per-wallet activity by filtering this list by address client-side.
async fn recent_transfers(State(st): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let resp = st.http.get(format!("{}/transfers?limit=100", st.rpc)).send().await.map_err(ApiError::internal)?;
    let body: Value = resp.json().await.map_err(ApiError::internal)?;
    Ok(Json(body))
}

/// The validator directory (address, name, stake), proxied so the staking UI
/// can show a named list to pick a delegation target instead of asking the user
/// to paste a raw address.
async fn validators(State(st): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let resp = st.http.get(format!("{}/validators", st.rpc)).send().await.map_err(ApiError::internal)?;
    let body: Value = resp.json().await.map_err(ApiError::internal)?;
    Ok(Json(body))
}

/// Read-only list of deployed programs, proxied from the node's `/programs`
/// (address, code_hash, entry_point, size, balance - metadata only, never the
/// bytecode). The connect-bridge uses it to pick a fresh (undeployed) program
/// address for a deploy, since `/api/account` can't tell an empty slot from a
/// program-owned one.
async fn programs(State(st): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let resp = st.http.get(format!("{}/programs?limit=1000", st.rpc)).send().await.map_err(ApiError::internal)?;
    let body: Value = resp.json().await.map_err(ApiError::internal)?;
    Ok(Json(body))
}

/// Live network economics (read-only proxy of the node's `/economics`): the
/// staking view uses `emission_apr_bps` (the reward APR) and
/// `staking_commission_bps` (the validator commission) to show a real APY and
/// commission instead of a hard-coded number.
async fn economics(State(st): State<Arc<AppState>>) -> Result<Json<Value>, ApiError> {
    let resp = st.http.get(format!("{}/economics", st.rpc)).send().await.map_err(ApiError::internal)?;
    let body: Value = resp.json().await.map_err(ApiError::internal)?;
    Ok(Json(body))
}

/// The node's recent staking activity for a specific address, proxied so the
/// wallet's activity view can show staking (delegate/undelegate/claim) - which
/// never appears in the transfer list. Parses the address before interpolation
/// (no path injection).
async fn staking_activity(State(st): State<Arc<AppState>>, Path(address): Path<String>) -> Result<Json<Value>, ApiError> {
    let pk: Pubkey = address.trim().parse().map_err(|e| ApiError::bad(format!("dirección inválida: {e}")))?;
    let url = format!("{}/staking_activity?limit=100&staker={}", st.rpc, pk);
    let resp = st.http.get(&url).send().await.map_err(ApiError::internal)?;
    let body: Value = resp.json().await.map_err(ApiError::internal)?;
    Ok(Json(body))
}

#[derive(Deserialize)]
struct ImportReq {
    name: String,
    /// The full contents of a keypair `.json` file (a real qchain key backup),
    /// OR an encrypted keystore JSON (with `qchain_keystore`) - in that case
    /// `password` is required to decrypt it first.
    keypair: String,
    #[serde(default)]
    password: Option<String>,
}

/// Import an existing wallet from its key-file contents (the "ya tengo una
/// wallet" flow). Accepts either a plain key file or a password-encrypted
/// keystore (auto-detected). Validated by actually parsing the result as a
/// real keypair; a bad file is rejected and not kept.
async fn import_wallet(State(st): State<Arc<AppState>>, Json(req): Json<ImportReq>) -> Result<Json<WalletInfo>, ApiError> {
    let name = sanitize_name(&req.name)?;
    let path = wallet_path(&st, &name)?;
    if path.exists() {
        return Err(ApiError::bad(format!("ya existe una wallet llamada '{name}'")));
    }

    // Encrypted keystore? Decrypt with the provided password first.
    let content = match serde_json::from_str::<Value>(&req.keypair) {
        Ok(v) if v.get("qchain_keystore").is_some() => {
            let pw = req.password.as_deref().filter(|p| !p.is_empty()).ok_or_else(|| {
                ApiError::bad("este respaldo está cifrado - hace falta la contraseña que usaste al descargarlo".to_string())
            })?;
            keystore::decrypt(&v, pw).map_err(|e| ApiError::bad(e.to_string()))?
        }
        _ => req.keypair.clone(),
    };

    std::fs::write(&path, content.as_bytes()).map_err(ApiError::internal)?;
    match qchain_crypto::read_keypair_file(&path) {
        Ok(kp) => Ok(Json(WalletInfo { name, address: kp.pubkey().to_string(), balance: "0".to_string() })),
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            Err(ApiError::bad(format!("el archivo no es una clave válida de qchain: {e}")))
        }
    }
}

/// Download a wallet's key file, unencrypted - the raw backup. Kept for
/// advanced use; the password-protected `export-encrypted` is the recommended
/// path (see below).
async fn export_wallet(State(st): State<Arc<AppState>>, Path(name): Path<String>) -> Result<Response, ApiError> {
    let name = sanitize_name(&name)?;
    let path = wallet_path(&st, &name)?;
    let content = std::fs::read_to_string(&path).map_err(|_| ApiError::bad(format!("no encontré la wallet '{name}'")))?;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}.json\""))
        .body(Body::from(content))
        .map_err(ApiError::internal)
}

#[derive(Deserialize)]
struct ExportEncReq {
    name: String,
    password: String,
}

/// Download a wallet's backup **encrypted with a password** (a keystore). Even
/// if someone gets the file, it's useless without the password. Recommended
/// over the plain export.
async fn export_encrypted(State(st): State<Arc<AppState>>, Json(req): Json<ExportEncReq>) -> Result<Response, ApiError> {
    let name = sanitize_name(&req.name)?;
    if req.password.chars().count() < 6 {
        return Err(ApiError::bad("la contraseña del respaldo debe tener al menos 6 caracteres".to_string()));
    }
    let path = wallet_path(&st, &name)?;
    let content = std::fs::read_to_string(&path).map_err(|_| ApiError::bad(format!("no encontré la wallet '{name}'")))?;
    let keystore_json = keystore::encrypt(&content, &req.password).map_err(ApiError::internal)?;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}.qchain-keystore.json\""))
        .body(Body::from(keystore_json))
        .map_err(ApiError::internal)
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
