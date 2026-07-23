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
use axum::extract::{ConnectInfo, Extension, Path, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use std::net::SocketAddr;
use clap::Parser;
use qchain_core::{Account, Instruction, Transaction};
use qchain_crypto::{Keypair, Pubkey};
use qchain_execution::SystemInstruction;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;

mod keystore;
mod ratelimit;

use ratelimit::{resolve_client_ip, SimRateLimiter};

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
    /// Poné este flag cuando la wallet esté detrás de un reverse-proxy de CONFIANZA
    /// en el MISMO host (el túnel de Cloudflare `cloudflared`, o un nginx/Caddy
    /// local) — es decir, la wallet queda bindeada a loopback y el punto de entrada
    /// público es el proxy. Efectos: (1) el rate limit OBLIGATORIO de `/api/simulate`
    /// se activa aunque el bind sea loopback (si no, una wallet tunelizada — la
    /// exposición recomendada del proyecto — quedaría SIN esa protección); (2) la IP
    /// del cliente se lee de `CF-Connecting-IP` o `X-Forwarded-For`, pero SÓLO cuando
    /// el peer TCP directo es loopback (el proxy local), y se reenvía saneada al nodo
    /// para que su segundo rate limit por IP no agrupe a todos bajo 127.0.0.1. También
    /// por la variable de entorno QCHAIN_WALLET_BEHIND_PROXY (=1/true).
    #[arg(long)]
    behind_trusted_proxy: bool,
    /// Cap por IP de `POST /api/simulate` en una ventana de 10 s. `/simulate` corre
    /// un verify de firma post-cuántica y puede compilar+ejecutar WASM en el nodo,
    /// así que es la superficie más cara. OBLIGATORIO cuando la wallet es alcanzable
    /// por clientes remotos (bind no-loopback, o `--behind-trusted-proxy`): un valor
    /// ausente usa el default (8) y uno muy bajo se sube al piso (5); en un loopback
    /// genuinamente privado queda opt-in. También por QCHAIN_WALLET_SIMULATE_RL.
    #[arg(long)]
    simulate_rate_limit_per_10s: Option<u32>,

    /// Cap por IP de `POST /api/relay-tx` en una ventana de 10 s (task #210).
    /// `/api/relay-tx` reenvía una transacción FIRMADA al `/tx` del nodo, que corre
    /// un verify de firma post-cuántica por llamada — la segunda superficie más
    /// cara. Mismo modelo que `/api/simulate`: OBLIGATORIO cuando la wallet es
    /// alcanzable por clientes remotos (bind no-loopback o `--behind-trusted-proxy`),
    /// opt-in en loopback privado. También por `QCHAIN_WALLET_TX_RL`.
    #[arg(long)]
    tx_rate_limit_per_10s: Option<u32>,

    /// Perfil de red (`mainnet` / `testnet`, tarea #211). En `mainnet` la wallet
    /// SE NIEGA A ARRANCAR si no está detrás de un reverse-proxy de CONFIANZA que
    /// termine TLS (`--behind-trusted-proxy`): un servicio público de mainnet DEBE
    /// servirse por HTTPS (túnel de Cloudflare / nginx / Caddy con TLS), nunca HTTP
    /// en claro a internet. Ausente / `testnet` = sin requisito, como antes.
    /// También por `QCHAIN_WALLET_NETWORK_PROFILE`.
    #[arg(long)]
    network_profile: Option<String>,
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
    /// Dedicated per-IP + per-txid rate limiter for the public `/api/simulate`
    /// proxy. `Some` (mandatory) when the wallet is reachable by remote clients
    /// (a non-loopback bind or `behind_trusted_proxy`); `None` on a genuinely
    /// private loopback bind unless explicitly opted in. See `ratelimit.rs`.
    sim_limiter: Option<SimRateLimiter>,
    /// Dedicated per-IP + per-txid rate limiter for the public `/api/relay-tx`
    /// proxy (task #210) — the SIGNED-transaction relay to the node's `/tx`. Same
    /// mandatory-when-public policy as `sim_limiter`. Independent window from
    /// simulate so a user simulating a lot never blocks their sends.
    tx_limiter: Option<SimRateLimiter>,
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

    // Trusted-proxy mode (Cloudflare tunnel / local nginx on the same host): from
    // the flag or the env var (`1`/`true`).
    let behind_proxy = cli.behind_trusted_proxy
        || std::env::var("QCHAIN_WALLET_BEHIND_PROXY")
            .ok()
            .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"))
            .unwrap_or(false);
    let sim_rl_configured = cli
        .simulate_rate_limit_per_10s
        .or_else(|| std::env::var("QCHAIN_WALLET_SIMULATE_RL").ok().and_then(|s| s.trim().parse().ok()));
    // MANDATORY when the wallet is reachable by remote clients (public bind or a
    // trusted proxy) — its own per-IP + per-txid gate on the most expensive proxy
    // endpoint. Opt-in on a genuinely private loopback bind.
    let sim_limiter = SimRateLimiter::for_wallet(exposed, behind_proxy, sim_rl_configured);
    // Same mandatory-when-public policy for the `/api/relay-tx` limiter (task #210).
    let tx_rl_configured = cli
        .tx_rate_limit_per_10s
        .or_else(|| std::env::var("QCHAIN_WALLET_TX_RL").ok().and_then(|s| s.trim().parse().ok()));
    let tx_limiter = SimRateLimiter::for_wallet(exposed, behind_proxy, tx_rl_configured);

    // MANDATORY MAINNET PROFILE (task #211, req 11 — TLS in wallet/public
    // services). Under `network_profile: mainnet` the wallet REFUSES TO START
    // unless it sits behind a TLS-terminating trusted proxy (`--behind-trusted-
    // proxy`): a mainnet public service must be HTTPS, never plaintext HTTP to the
    // internet. A no-op for a testnet (the default). Fail-loud on a typo.
    let network_profile = cli
        .network_profile
        .or_else(|| std::env::var("QCHAIN_WALLET_NETWORK_PROFILE").ok())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty());
    if let Some(p) = network_profile.as_deref() {
        if p != "mainnet" && p != "testnet" {
            anyhow::bail!("network_profile {p:?} is not a known profile — use \"mainnet\" or \"testnet\".");
        }
        if p == "mainnet" && !behind_proxy {
            anyhow::bail!(
                "network_profile=\"mainnet\": REFUSING TO START — the wallet must sit behind a TLS-terminating trusted proxy (pass --behind-trusted-proxy / QCHAIN_WALLET_BEHIND_PROXY=1, and front it with a Cloudflare tunnel or nginx/Caddy that terminates HTTPS). A mainnet public service must be served over TLS, never plaintext HTTP."
            );
        }
    }

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
        sim_limiter: sim_limiter.clone(),
        tx_limiter: tx_limiter.clone(),
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
        // App JS externalizado + versionado por content-hash + SRI (#214).
        .route("/app/:name", get(app_js))
        // Provenance del build (versión + hashes) para verificar en la app.
        .route("/api/version", get(wallet_version))
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
        // `/api/relay-tx` gets its dedicated per-IP rate-limit middleware (when the
        // limiter is present): the gate runs BEFORE the handler reads/forwards the
        // signed tx, so a flood is rejected with 429 without forwarding anything to
        // the node (task #210).
        .route(
            "/api/relay-tx",
            match &state.tx_limiter {
                Some(_) => post(relay_tx).layer(axum::middleware::from_fn_with_state(state.clone(), relay_rate_limit_mw)),
                None => post(relay_tx),
            },
        )
        // `/api/simulate` gets its dedicated per-IP rate-limit middleware (when the
        // limiter is present): the gate runs BEFORE the handler reads the body, so
        // a flood is rejected with 429 without buffering/forwarding anything.
        .route(
            "/api/simulate",
            match &state.sim_limiter {
                Some(_) => post(simulate_tx).layer(axum::middleware::from_fn_with_state(state.clone(), simulate_rate_limit_mw)),
                None => post(simulate_tx),
            },
        )
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
        .route("/api/program/:address", get(program_ep))
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
    match &sim_limiter {
        Some(_) if exposed || behind_proxy => {
            println!(
                "Rate limit /api/simulate: OBLIGATORIO ACTIVO ({})",
                if behind_proxy { "detrás de proxy de confianza - IP del cliente vía CF-Connecting-IP / X-Forwarded-For, reenviada saneada al nodo" } else { "bind público directo - IP del cliente = peer TCP" }
            );
        }
        Some(_) => println!("Rate limit /api/simulate: activo (opt-in en loopback)"),
        None => {}
    }
    match &tx_limiter {
        Some(_) if exposed || behind_proxy => println!(
            "Rate limit /api/relay-tx: OBLIGATORIO ACTIVO ({})",
            if behind_proxy { "detrás de proxy de confianza - IP del cliente vía CF-Connecting-IP / X-Forwarded-For, reenviada saneada al nodo" } else { "bind público directo - IP del cliente = peer TCP" }
        ),
        Some(_) => println!("Rate limit /api/relay-tx: activo (opt-in en loopback)"),
        None => {}
    }
    // `into_make_service_with_connect_info` so the `/api/simulate` limiter can read
    // each client's peer address (and, behind a trusted proxy, resolve the real
    // client from CF-Connecting-IP / X-Forwarded-For). Harmless for every other
    // route.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

/// Baseline security headers on every response. This wallet holds the user's
/// seed in browser memory + an encrypted blob in localStorage and is often
/// exposed publicly (Cloudflare tunnel), so the only barrier between any future
/// injection and total seed theft is the hand-rolled `esc()` - CSP is the
/// backstop if one were ever missed. Tras #214 el `script-src` YA NO lleva
/// `'unsafe-inline'` (el JS de la app va externo con SRI), así un `<script>`
/// inyectado por un XSS no corre; sólo queda `'wasm-unsafe-eval'` (instanciar el
/// firmante WASM). `style-src 'unsafe-inline'` se conserva (los `style=` inline
/// no exfiltran la semilla con connect-src/img-src acotados). Más
/// `object-src`/`base-uri`/`frame-ancestors 'none'`. The
/// three simple headers are unconditionally safe: every handler sets an explicit
/// Content-Type (nosniff), the wallet is never meant to be framed (clickjacking
/// the send/confirm flow), and the URL/path shouldn't leak outward (no-referrer).
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            // script-src SIN 'unsafe-inline' (#214): todo el JS de la app se sirve
            // como un archivo externo con SRI (`/app/app-<hash>.js`), así un
            // <script> inline inyectado por un XSS NO se ejecuta. 'wasm-unsafe-eval'
            // sigue (el firmante WASM lo necesita para instanciar el módulo; no es
            // 'unsafe-inline'). style-src conserva 'unsafe-inline' a propósito: la
            // UI usa ~155 `style=` inline (no hasheables por atributo) y una
            // inyección de CSS NO puede exfiltrar la semilla con connect-src 'self'
            // + img-src acotado (un `url(https://evil/…)` de CSS lo bloquea img-src).
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; \
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
    // Constant-time password check (re-audit QCH-WALLET auth): comparing the
    // password with `==` short-circuits on the first differing byte, a timing
    // side-channel that (over a low-jitter path) could leak the password
    // byte-by-byte. Hash both to a FIXED 32-byte digest first (so neither the
    // length nor the bytes leak via timing) and compare with `subtle`'s
    // constant-time equality. A missing/garbled Authorization header hashes the
    // empty string, which never equals a real password.
    let ok = provided.map(|p| ct_password_eq(&p, expected)).unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Basic realm=\"qchain wallet\"")
            .body(Body::from("autenticación requerida"))
            .expect("static 401 response always builds")
    }
}

/// Constant-time password equality (re-audit QCH-WALLET auth). Hashes both
/// sides to a fixed 32-byte SHA3-256 digest — so the comparison is over a
/// constant length regardless of how long either password is (no length leak) —
/// then compares the digests with `subtle`'s data-independent `ct_eq`, which the
/// compiler can't turn back into a short-circuiting branch. Result is identical
/// to `a == b`; only the timing is now flat.
fn ct_password_eq(a: &str, b: &str) -> bool {
    use sha3::{Digest, Sha3_256};
    use subtle::ConstantTimeEq;
    let ha: [u8; 32] = Sha3_256::digest(a.as_bytes()).into();
    let hb: [u8; 32] = Sha3_256::digest(b.as_bytes()).into();
    ha.ct_eq(&hb).into()
}

async fn index() -> Html<&'static str> {
    // Custodial wallet HTML with its external-JS src/SRI placeholders filled in
    // (#214): its inline <script> was externalized so the strict CSP applies here too.
    Html(asset_hashes().custodial_html.as_str())
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

// ---- Endurecimiento de assets (#214) --------------------------------------
// El JS de la wallet (la superficie que toca la semilla) se sirve como un
// ARCHIVO EXTERNO versionado por content-hash (`/app/app-<hash>.js`) con
// integridad SRI, en vez de inline — así la CSP puede quitar `'unsafe-inline'`
// del `script-src` (un `<script>` inyectado por un XSS ya no se ejecuta). El
// hash SRI (SHA-384) y la URL versionada (SHA-256[:12]) se computan EN RUST a
// partir de los mismos bytes embebidos, así el `integrity=` del HTML NUNCA
// puede driftear de lo que se sirve (una sola fuente de verdad, sin build step).
//
// LÍMITE HONESTO (documentado): SRI servido por el MISMO origen NO defiende
// contra un SERVIDOR malicioso (que reescribe el `integrity` para que calce con
// su JS malicioso). Sí frena un XSS/inyección (CSP) y una manipulación de UN
// recurso en tránsito. La defensa real contra un servidor malicioso es que el
// usuario compare el hash mostrado en la app (`/api/version`) contra un release
// FIRMADO publicado fuera de banda (o use una extensión/hardware wallet). El
// hash visible + el manifiesto firmado + el build reproducible existen para
// ESO: detectabilidad de bytes servidos != release firmado.
const APP_JS: &str = include_str!("wasm_assets/app.js");
const CUSTODIAL_JS: &str = include_str!("wasm_assets/custodial.js");
const WALLET_HTML: &str = include_str!("wasm_wallet.html");
const CUSTODIAL_HTML: &str = include_str!("wallet.html");
const WASM_GLUE_JS: &str = include_str!("wasm_assets/qchain_wasm.js");
const WASM_BG_BYTES: &[u8] = include_bytes!("wasm_assets/qchain_wasm_bg.wasm");

struct AssetHashes {
    app_js_url: String,        // "/app/app-<sha256hex12>.js"
    app_js_sri: String,        // "sha384-<b64>"
    app_js_sha256: String,     // hex, full
    glue_sha256: String,       // hex
    wasm_sha256: String,       // hex
    html: String,              // non-custodial HTML with placeholders filled
    custodial_html: String,    // custodial HTML with placeholders filled
}

fn asset_hashes() -> &'static AssetHashes {
    use base64::engine::general_purpose::STANDARD;
    use sha2::{Digest, Sha256, Sha384};
    static H: std::sync::OnceLock<AssetHashes> = std::sync::OnceLock::new();
    H.get_or_init(|| {
        let sri = |b: &[u8]| format!("sha384-{}", STANDARD.encode(Sha384::digest(b)));
        let s256 = |b: &[u8]| hex::encode(Sha256::digest(b));
        let app_sha256 = s256(APP_JS.as_bytes());
        let app_url = format!("/app/app-{}.js", &app_sha256[..12]);
        let cust_sha256 = s256(CUSTODIAL_JS.as_bytes());
        let cust_url = format!("/app/custodial-{}.js", &cust_sha256[..12]);
        let html = WALLET_HTML
            .replace("__APP_JS_SRC__", &app_url)
            .replace("__APP_JS_SRI__", &sri(APP_JS.as_bytes()));
        let custodial_html = CUSTODIAL_HTML
            .replace("__CUSTODIAL_JS_SRC__", &cust_url)
            .replace("__CUSTODIAL_JS_SRI__", &sri(CUSTODIAL_JS.as_bytes()));
        AssetHashes {
            app_js_url: app_url,
            app_js_sri: sri(APP_JS.as_bytes()),
            app_js_sha256: app_sha256,
            glue_sha256: s256(WASM_GLUE_JS.as_bytes()),
            wasm_sha256: s256(WASM_BG_BYTES),
            html,
            custodial_html,
        }
    })
}

async fn wasm_page() -> Html<&'static str> {
    Html(asset_hashes().html.as_str())
}

/// Serves the external, SRI-pinned wallet JS. Content-addressed URL
/// (`/app/app-<hash>.js` for the non-custodial wallet, `/app/custodial-<hash>.js`
/// for the custodial one) + immutable cache. The freshly-served HTML always
/// carries the matching `integrity=`. A name we don't mint → 404 (avoids
/// serving mismatched-hash bytes under a stale SRI).
async fn app_js(Path(name): Path<String>) -> Response {
    let js: &'static str = if name.starts_with("custodial-") {
        CUSTODIAL_JS
    } else if name.starts_with("app-") {
        APP_JS
    } else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    Response::builder()
        .header(header::CONTENT_TYPE, "text/javascript; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=604800, immutable")
        .body(Body::from(js))
        .expect("static js response always builds")
}

/// Build/version provenance: the wallet version + SHA-256 of every served
/// script/wasm asset + the SRI of the app JS. Shown IN-APP (Settings) so a user
/// can compare against a signed release note (see docs/WALLET-HARDENING.md) —
/// the real defense against a malicious server, which same-origin SRI cannot
/// provide. Read-only, safe to expose.
async fn wallet_version() -> Json<serde_json::Value> {
    let h = asset_hashes();
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "app_js_url": h.app_js_url,
        "app_js_sri": h.app_js_sri,
        "app_js_sha256": h.app_js_sha256,
        "wasm_glue_sha256": h.glue_sha256,
        "wasm_bg_sha256": h.wasm_sha256,
    }))
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
        "tier": match tier { RiskTier::Low => "low", RiskTier::Economic => "economic", RiskTier::Registry => "registry" },
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
async fn relay_tx(State(st): State<Arc<AppState>>, client_ip: Option<Extension<ClientIp>>, body: axum::body::Bytes) -> Result<Json<Value>, ApiError> {
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
    // Per-txid gate (task #210): a wallet-wide window cap on how often ONE signed
    // tx is relayed — kills the distributed single-tx resubmission that per-IP
    // alone can't catch. Best-effort: if the body doesn't parse as a Transaction
    // the node is the authority, so forward and let it decide (the per-IP gate
    // already ran in `relay_rate_limit_mw`).
    if let Some(rl) = &st.tx_limiter {
        if let Ok(tx) = serde_json::from_slice::<Transaction>(&body) {
            if !rl.allow_txid(tx.txid()) {
                return Err(ApiError::too_many("esta transacción se está enviando demasiado seguido - probá en unos segundos"));
            }
        }
    }
    let mut outbound = st.http.post(format!("{}/tx", st.rpc)).header("content-type", "application/json");
    // Forward the resolved real client IP to the node as a SINGLE, sanitized
    // X-Forwarded-For (a fresh request, so any client-supplied header is dropped),
    // so the node's own per-IP `/tx` limiter meters the real client, not `127.0.0.1`.
    if let Some(Extension(ClientIp(ip))) = client_ip {
        outbound = outbound.header("X-Forwarded-For", ip.to_string());
    }
    let resp = outbound.body(body.to_vec()).send().await.map_err(ApiError::internal)?;
    let status = resp.status();
    if !status.is_success() {
        let msg = resp.text().await.unwrap_or_default();
        // Propagate a downstream throttle as a real 429 (not a 400), so the browser
        // sees the actual rate-limit and backs off instead of showing "bad request".
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(ApiError::too_many(if msg.is_empty() { "el nodo alcanzó su límite de solicitudes - probá en unos segundos".to_string() } else { msg }));
        }
        return Err(ApiError::bad(format!("el nodo rechazó la transacción: {msg}")));
    }
    let v: Value = resp.json().await.map_err(ApiError::internal)?;
    Ok(Json(v))
}

/// Per-route middleware for `POST /api/relay-tx`: the PER-IP gate, run BEFORE the
/// handler forwards the signed tx. Resolves the REAL client IP (peer, or the
/// trusted proxy's forwarded IP), fails CLOSED (429) when no trustworthy identity
/// can be established, and stashes the IP for `relay_tx` to forward sanitized to
/// the node. Task #210 — the twin of `simulate_rate_limit_mw`.
async fn relay_rate_limit_mw(State(st): State<Arc<AppState>>, conn: Option<ConnectInfo<SocketAddr>>, mut req: Request, next: Next) -> Response {
    let Some(rl) = st.tx_limiter.clone() else {
        return next.run(req).await;
    };
    let Some(ConnectInfo(peer)) = conn else {
        return ApiError::too_many("no se pudo determinar la IP del cliente").into_response();
    };
    let Some(ip) = resolve_client_ip(rl.trust_proxy(), peer.ip(), req.headers()) else {
        return ApiError::too_many("no se pudo identificar el cliente de forma confiable detrás del proxy").into_response();
    };
    if !rl.allow_ip(ip) {
        return ApiError::too_many("demasiadas transacciones desde tu IP - probá de nuevo en unos segundos").into_response();
    }
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}

/// The real client IP resolved by `simulate_rate_limit_mw`, stashed in the request
/// extensions so `simulate_tx` can forward it, sanitized, to the node.
#[derive(Clone, Copy)]
struct ClientIp(std::net::IpAddr);

/// Per-route middleware for `POST /api/simulate`: the PER-IP gate, run BEFORE the
/// handler reads/forwards the body so a flood is rejected with 429 immediately.
/// It resolves the REAL client IP (peer, or the trusted proxy's forwarded IP) and
/// stashes it in the request extensions for the handler to forward to the node.
/// FAILS CLOSED (429) when no trustworthy client identity can be established —
/// never bucketing every user under the proxy's loopback address.
async fn simulate_rate_limit_mw(State(st): State<Arc<AppState>>, conn: Option<ConnectInfo<SocketAddr>>, mut req: Request, next: Next) -> Response {
    let Some(rl) = st.sim_limiter.clone() else {
        return next.run(req).await;
    };
    let Some(ConnectInfo(peer)) = conn else {
        // No peer address (shouldn't happen with into_make_service_with_connect_info).
        // Fail closed: without a client identity we can't rate-limit safely.
        return ApiError::too_many("no se pudo determinar la IP del cliente").into_response();
    };
    let Some(ip) = resolve_client_ip(rl.trust_proxy(), peer.ip(), req.headers()) else {
        return ApiError::too_many("no se pudo identificar el cliente de forma confiable detrás del proxy").into_response();
    };
    if !rl.allow_ip(ip) {
        return ApiError::too_many("simulación: demasiadas solicitudes desde tu IP - probá de nuevo en unos segundos").into_response();
    }
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}

/// DRY-RUN a browser-signed transaction against the node's `/simulate` (read-only)
/// so the wallet can show the user the real predicted outcome (fee, resulting
/// balance, success/failure) BEFORE they authorize broadcasting it — QCH-WALLET-001.
/// Nothing is committed; the node runs it on a scratch ledger.
///
/// The public edge for `/simulate` is HERE (not the node): the per-IP gate ran in
/// `simulate_rate_limit_mw`; this adds the per-txid gate and forwards the resolved
/// real client IP to the node as a SANITIZED `X-Forwarded-For` so the node's own
/// per-IP limiter meters real clients (not `127.0.0.1`).
async fn simulate_tx(State(st): State<Arc<AppState>>, client_ip: Option<Extension<ClientIp>>, body: axum::body::Bytes) -> Result<Json<Value>, ApiError> {
    const MAX_RELAY_BODY: usize = 256 * 1024;
    if body.len() > MAX_RELAY_BODY {
        return Err(ApiError::bad(format!("transacción demasiado grande ({} bytes, máximo {})", body.len(), MAX_RELAY_BODY)));
    }
    // Per-txid gate (defense in depth on top of the node's own): a wallet-wide
    // window cap on how often ONE signed tx is simulated. Best-effort — if the
    // body doesn't parse as a Transaction the node is the authority, so we forward
    // it and let the node decide; the per-IP gate already ran.
    if let Some(rl) = &st.sim_limiter {
        if let Ok(tx) = serde_json::from_slice::<Transaction>(&body) {
            if !rl.allow_txid(tx.txid()) {
                return Err(ApiError::too_many("simulación: esta transacción se está simulando demasiado seguido - probá en unos segundos"));
            }
        }
    }
    let mut outbound = st.http.post(format!("{}/simulate", st.rpc)).header("content-type", "application/json");
    // Forward the resolved real client IP to the node as a SINGLE, sanitized
    // X-Forwarded-For (we build a fresh request, so any client-supplied header is
    // dropped — the node reads the rightmost hop, which is exactly this value).
    // Only when a limiter is active; a private loopback dev setup forwards nothing.
    if let Some(Extension(ClientIp(ip))) = client_ip {
        outbound = outbound.header("X-Forwarded-For", ip.to_string());
    }
    let resp = outbound.body(body.to_vec()).send().await.map_err(ApiError::internal)?;
    let status = resp.status();
    if !status.is_success() {
        let msg = resp.text().await.unwrap_or_default();
        // Surface a downstream rate-limit as a 429 (not a 400), so the browser
        // sees the real throttle instead of a generic "bad request".
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(ApiError::too_many(if msg.is_empty() { "simulación: límite de solicitudes del nodo alcanzado".to_string() } else { msg }));
        }
        return Err(ApiError::bad(format!("el nodo no pudo simular la transacción: {msg}")));
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

/// One deployed contract's metadata (read-only proxy of the node's
/// `/program/:address`): `code_hash`, `entry_point`, `size_bytes`, `deployer`
/// (who deployed it) and `balance`. The WalletConnect approval modal shows the
/// code_hash + deployer so the user can confirm the contract they're authorizing
/// is the one they expect, not a look-alike (re-audit QCH-WALLET, MED). The
/// address is parsed to a `Pubkey` before it's interpolated into the node URL
/// (no path injection).
async fn program_ep(State(st): State<Arc<AppState>>, Path(address): Path<String>) -> Result<Json<Value>, ApiError> {
    let pk: Pubkey = address.parse().map_err(|_| ApiError::bad("dirección de contrato inválida".to_string()))?;
    let resp = st.http.get(format!("{}/program/{}", st.rpc, pk)).send().await.map_err(ApiError::internal)?;
    let status = resp.status();
    let body: Value = resp.json().await.map_err(ApiError::internal)?;
    if !status.is_success() {
        return Err(ApiError(StatusCode::NOT_FOUND, "contrato no encontrado".to_string()));
    }
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
    fn too_many(msg: impl Into<String>) -> Self {
        ApiError(StatusCode::TOO_MANY_REQUESTS, msg.into())
    }
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::ct_password_eq;

    #[test]
    fn constant_time_password_check_matches_string_equality() {
        // Same result as `==`, only the timing differs.
        assert!(ct_password_eq("hunter2", "hunter2"));
        assert!(!ct_password_eq("hunter2", "hunter3"));
        assert!(!ct_password_eq("hunter2", "hunter2 "));
        assert!(!ct_password_eq("", "hunter2"));
        assert!(!ct_password_eq("hunter2", ""));
        assert!(ct_password_eq("", ""));
        // Length is not what's compared (hashes are fixed 32 bytes): a short and
        // a long non-matching password both simply return false.
        assert!(!ct_password_eq("a", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    /// FULL-PATH integration test: client → (trusted proxy sets CF-Connecting-IP) →
    /// wallet `/api/simulate` (real middleware + handler) → node. A real mock node
    /// records the `X-Forwarded-For` it receives. Proves, over real HTTP:
    ///  - a client is 429'd after its per-IP window cap (at the WALLET edge),
    ///  - a DIFFERENT real client keeps working (its own bucket),
    ///  - a request with NO trustworthy client identity fails CLOSED (429),
    ///  - the node receives each client's REAL IP, sanitized — never `127.0.0.1`
    ///    (so users are not collapsed into the loopback-proxy bucket).
    #[tokio::test]
    async fn full_path_client_proxy_wallet_node_meters_and_forwards_the_real_ip() {
        use std::sync::{Arc, Mutex};

        // --- mock node: record every X-Forwarded-For seen on /simulate ---
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_h = seen.clone();
        let mock = super::Router::new().route(
            "/simulate",
            super::post(move |headers: axum::http::HeaderMap, _b: axum::body::Bytes| {
                let s = seen_h.clone();
                async move {
                    let xff = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("<none>").to_string();
                    s.lock().unwrap().push(xff);
                    super::Json(serde_json::json!({ "ok": true }))
                }
            }),
        );
        let ml = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let maddr = ml.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(ml, mock).await.unwrap() });

        // --- wallet: the REAL /api/simulate route (real mw + handler), trusted
        // proxy, pointing at the mock node. A public/proxied limiter is floored at
        // MIN_SIM_PER_IP_10S (5), so the effective per-IP cap here is 5. ---
        const CAP: usize = 5;
        let rl = super::SimRateLimiter::for_wallet(false, true, Some(CAP as u32)).unwrap();
        let st = Arc::new(super::AppState {
            rpc: format!("http://{maddr}"),
            wallets_dir: std::path::PathBuf::from("."),
            fee_limit: 10_000_000,
            http: reqwest::Client::new(),
            password: None,
            custodial_enabled: false,
            loopback_bound: true,
            faucet: None,
            connect_origin: None,
            sim_limiter: Some(rl),
            tx_limiter: None,
        });
        let app = super::Router::new()
            .route("/api/simulate", super::post(super::simulate_tx).layer(axum::middleware::from_fn_with_state(st.clone(), super::simulate_rate_limit_mw)))
            .with_state(st);
        let wl = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let waddr = wl.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(wl, app.into_make_service_with_connect_info::<super::SocketAddr>()).await.unwrap() });

        let client = reqwest::Client::new();
        let url = format!("http://{waddr}/api/simulate");
        let post = |cf: Option<&'static str>| {
            let mut b = client.post(&url).header("content-type", "application/json").body("{}");
            if let Some(ip) = cf {
                b = b.header("CF-Connecting-IP", ip);
            }
            b.send()
        };

        // Client A: CAP allowed, the next over the per-IP cap → 429 (wallet edge).
        let mut a = Vec::new();
        for _ in 0..CAP + 1 {
            a.push(post(Some("203.0.113.7")).await.unwrap().status().as_u16());
        }
        let mut expect_a = vec![200u16; CAP];
        expect_a.push(429);
        assert_eq!(a, expect_a, "per-IP window cap at the wallet edge");

        // Client B: a different real client is unaffected (its own bucket).
        assert_eq!(post(Some("198.51.100.4")).await.unwrap().status().as_u16(), 200, "a different real client keeps working");

        // No trustworthy identity (no CF-Connecting-IP / X-Forwarded-For) → fail closed.
        assert_eq!(post(None).await.unwrap().status().as_u16(), 429, "missing client identity → fail closed");

        // The node received the REAL client IPs, sanitized — never the loopback
        // proxy, never nothing. (The 429'd and fail-closed requests never reached it.)
        let got = seen.lock().unwrap().clone();
        assert!(got.iter().all(|x| x != "127.0.0.1" && x != "<none>"), "node must never see the loopback proxy or an empty IP: {got:?}");
        assert!(got.contains(&"203.0.113.7".to_string()), "client A's real IP reached the node: {got:?}");
        assert!(got.contains(&"198.51.100.4".to_string()), "client B's real IP reached the node: {got:?}");
        assert_eq!(got.len(), CAP + 1, "exactly the admitted requests reached the node (CAP from A + 1 from B): {got:?}");
    }
}
