//! Daemon del firmante remoto / HSM de la clave de validador (tarea #193 + #4.2).
//!
//! Sostiene el `keypair.json` del validador y firma votos de consenso + bytes de
//! handshake por un socket, para que la clave NO viva en el proceso del nodo. El
//! nodo se conecta con `remote_signer: "<host:puerto>"` (o `"unix:/ruta.sock"`) en
//! su `config.json`.
//!
//!   # TCP loopback + token de auth (recomendado):
//!   qchain-remote-signer --keypair /opt/qchain/keypair.json \
//!       --listen 127.0.0.1:9200 --auth-token-file /opt/qchain/signer.token
//!
//!   # Socket Unix (aislamiento por permisos del SO) + token:
//!   qchain-remote-signer --keypair /opt/qchain/keypair.json \
//!       --listen unix:/run/qchain/signer.sock --auth-token-file /opt/qchain/signer.token
//!
//! **Seguridad (#4.2, auditoría v8.6.13):** el cliente se AUTENTICA. Con
//! `--auth-token-file` cada conexión debe probar que conoce el token
//! (challenge-response) ANTES de que se firme nada — un proceso local que no lo
//! conoce es rechazado. Con un socket Unix, además, sólo un proceso del MISMO
//! usuario puede abrir el socket (dir 0700, socket 0600). El daemon bindea
//! loopback/UDS por defecto; `--allow-non-loopback` es necesario a propósito para
//! una dirección TCP pública (desaconsejado sin un enlace privado + firewall + el
//! token). El perfil mainnet del NODO exige tanto loopback/UDS como el token.

use anyhow::Context;
use clap::Parser;
use qchain_remote_signer::SignerListener;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "qchain-remote-signer", about = "Firmante remoto/HSM de la clave de validador de qchain (#193 + #4.2)")]
struct Cli {
    /// Ruta al keypair.json del validador (la clave que firma bloques).
    #[arg(long)]
    keypair: String,
    /// Dónde escuchar. `host:puerto` (TCP, por defecto loopback) o `unix:/ruta`
    /// (socket Unix). Ej: 127.0.0.1:9200  |  unix:/run/qchain/signer.sock
    #[arg(long, default_value = "127.0.0.1:9200")]
    listen: String,
    /// Archivo con el TOKEN pre-compartido de autenticación del cliente (#4.2).
    /// Cuando se pasa, cada conexión debe probar que conoce el token antes de que
    /// el daemon firme nada. El MISMO archivo lo lee el nodo
    /// (`remote_signer_auth_token_path`). Sin él, el socket queda sin auth
    /// criptográfica (sólo aceptable en loopback/UDS de desarrollo).
    #[arg(long)]
    auth_token_file: Option<String>,
    /// Archivo de la guardia anti-doble-firma (persiste la ronda/vértice propio
    /// más alto firmado). Por defecto, junto al keypair.
    #[arg(long)]
    guard_file: Option<String>,
    /// Permitir bindear una dirección TCP NO-loopback (desaconsejado sin enlace
    /// privado + firewall + token — no aplica a UDS).
    #[arg(long, default_value_t = false)]
    allow_non_loopback: bool,
    /// (KM#7) `chain_id` (hex de 64 chars) de la red para la que ESTE firmante
    /// puede firmar. Cuando se pasa, un pedido que nombre otro chain_id
    /// (SignCheckpoint/SignNetworkKeyCert) se rechaza — impide usar el firmante para
    /// atestar la red equivocada. Es el mismo `chain_id` que imprime el nodo/genesis.
    #[arg(long)]
    chain_id: Option<String>,
    /// (KM#7) Rate-limit: máximo de pedidos de FIRMA por ventana. Sin él, sin tope.
    #[arg(long)]
    max_signs_per_window: Option<u32>,
    /// (KM#7) Largo de la ventana del rate-limit en segundos (default 10).
    #[arg(long, default_value_t = 10)]
    rate_window_secs: u64,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let keypair = qchain_crypto::read_keypair_file(std::path::Path::new(&cli.keypair))
        .with_context(|| format!("cannot read validator keypair from {}", cli.keypair))?;
    let bundle = keypair.public_key_bundle();

    let guard_path = cli
        .guard_file
        .unwrap_or_else(|| format!("{}.doublesign-guard", cli.keypair));
    let guard = Arc::new(Mutex::new(
        qchain_remote_signer::DoubleSignGuard::load(&guard_path)
            .with_context(|| format!("cannot load double-sign guard from {guard_path}"))?,
    ));

    // Token de auth del cliente (#4.2). Se lee crudo del archivo (que el operador
    // protege 0600); un archivo vacío se rechaza (un token vacío no autentica).
    let auth_token = match &cli.auth_token_file {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("cannot read auth token file {path}"))?;
            let trimmed = trim_token(&bytes);
            if trimmed.is_empty() {
                anyhow::bail!("auth token file {path} is empty — refusing to run with an empty token");
            }
            Some(trimmed)
        }
        None => None,
    };

    // Bindear el listener: UDS (permisos estrictos del SO) o TCP.
    let listener = if let Some(path) = qchain_remote_signer::unix_endpoint_path(&cli.listen) {
        bind_unix(path)?
    } else {
        let l = std::net::TcpListener::bind(&cli.listen)
            .with_context(|| format!("cannot bind signer socket on {}", cli.listen))?;
        let bound = l.local_addr()?;
        if !bound.ip().is_loopback() && !cli.allow_non_loopback {
            anyhow::bail!(
                "refusing to bind a NON-loopback address ({bound}) without --allow-non-loopback: \
                 use a loopback endpoint or a unix socket. Even with --allow-non-loopback, set \
                 --auth-token-file so clients must authenticate."
            );
        }
        SignerListener::Tcp(l)
    };

    // (KM#7) Política del firmante: binding de chain_id + rate-limit.
    let expected_chain_id = match &cli.chain_id {
        Some(hex_id) => Some(parse_hex32(hex_id.trim()).with_context(|| format!("invalid --chain-id: {hex_id}"))?),
        None => None,
    };
    let rate_limit = cli.max_signs_per_window.map(|max_signs| qchain_remote_signer::RateLimit {
        max_signs,
        window: std::time::Duration::from_secs(cli.rate_window_secs),
    });
    let policy = qchain_remote_signer::SignerPolicy { expected_chain_id, rate_limit };

    tracing::info!(
        "qchain remote signer up: validator {} listening on {} (guard: {guard_path}) [client auth: {}] [chain binding: {}] [rate limit: {}]",
        bundle.to_address(),
        cli.listen,
        if auth_token.is_some() { "TOKEN required" } else { "NONE — dev/loopback only" },
        if expected_chain_id.is_some() { "ON" } else { "off" },
        match &rate_limit { Some(rl) => format!("{}/{}s", rl.max_signs, cli.rate_window_secs), None => "off".to_string() },
    );
    if auth_token.is_none() {
        tracing::warn!(
            "signer running WITHOUT a client auth token — any process that reaches the socket can request signatures. Set --auth-token-file for production (required by the node's mainnet profile)."
        );
    }

    qchain_remote_signer::serve(keypair, listener, guard, auth_token, policy);
    Ok(())
}

/// Recorta espacios/nueva-línea de los bordes del token (para que un archivo con
/// un `\n` final no cambie el secreto respecto de lo que el nodo lee).
fn trim_token(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !b.is_ascii_whitespace()).map(|i| i + 1).unwrap_or(start);
    bytes[start..end].to_vec()
}

/// (KM#7) Parsea un `chain_id` de EXACTAMENTE 64 chars hex a `[u8; 32]` (sin
/// dependencia `hex` nueva — es un parseo trivial de 32 bytes).
fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    if s.len() != 64 {
        anyhow::bail!("expected 64 hex chars (32 bytes), got {}", s.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = (s.as_bytes()[2 * i] as char).to_digit(16).ok_or_else(|| anyhow::anyhow!("non-hex character"))?;
        let lo = (s.as_bytes()[2 * i + 1] as char).to_digit(16).ok_or_else(|| anyhow::anyhow!("non-hex character"))?;
        *byte = (hi * 16 + lo) as u8;
    }
    Ok(out)
}

/// Bindea un socket Unix con permisos estrictos: el directorio a 0700 y el socket
/// a 0600, de modo que sólo un proceso del MISMO usuario pueda alcanzarlo.
fn bind_unix(path: &str) -> anyhow::Result<SignerListener> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = std::path::Path::new(path);
        // Un socket previo (de un reinicio) impide el bind → removerlo.
        let _ = std::fs::remove_file(p);
        if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create signer socket dir {}", dir.display()))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("cannot chmod 0700 signer socket dir {}", dir.display()))?;
        }
        let listener = std::os::unix::net::UnixListener::bind(p)
            .with_context(|| format!("cannot bind unix signer socket {path}"))?;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot chmod 0600 signer socket {path}"))?;
        Ok(SignerListener::Unix(listener))
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("unix-socket listen endpoints require a unix platform: {path}");
    }
}
