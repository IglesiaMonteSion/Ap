//! Daemon del firmante remoto / HSM de la clave de validador (tarea #193).
//!
//! Sostiene el `keypair.json` del validador y firma votos de consenso + bytes de
//! handshake por un socket, para que la clave NO viva en el proceso del nodo. El
//! nodo se conecta con `remote_signer: "<host:puerto>"` en su `config.json`.
//!
//!   qchain-remote-signer --keypair /opt/qchain/keypair.json --listen 127.0.0.1:9200
//!
//! **Seguridad:** bindea LOOPBACK por defecto. Quien alcance el socket puede
//! pedir firmas (nunca un auto-voto en conflicto — la guardia lo bloquea, y la
//! clave nunca sale del daemon), así que corré el firmante en el MISMO host que
//! el nodo (o un host de firma dedicado con un enlace privado + firewall).
//! `--allow-non-loopback` es necesario, a propósito, para bindear una dirección
//! pública (desaconsejado sin un enlace protegido).

use anyhow::Context;
use clap::Parser;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(name = "qchain-remote-signer", about = "Firmante remoto/HSM de la clave de validador de qchain (#193)")]
struct Cli {
    /// Ruta al keypair.json del validador (la clave que firma bloques).
    #[arg(long)]
    keypair: String,
    /// Dirección donde escuchar (por defecto loopback). Ej: 127.0.0.1:9200
    #[arg(long, default_value = "127.0.0.1:9200")]
    listen: String,
    /// Archivo de la guardia anti-doble-firma (persiste la ronda/vértice propio
    /// más alto firmado). Por defecto, junto al keypair.
    #[arg(long)]
    guard_file: Option<String>,
    /// Permitir bindear una dirección NO-loopback (desaconsejado sin enlace
    /// privado + firewall — cualquiera que alcance el socket puede pedir firmas).
    #[arg(long, default_value_t = false)]
    allow_non_loopback: bool,
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

    let listener = TcpListener::bind(&cli.listen)
        .with_context(|| format!("cannot bind signer socket on {}", cli.listen))?;
    let bound = listener.local_addr()?;
    let is_loopback = bound.ip().is_loopback();
    if !is_loopback && !cli.allow_non_loopback {
        anyhow::bail!(
            "refusing to bind a NON-loopback address ({bound}) without --allow-non-loopback: \
             anyone reaching this socket can request signatures. Run the signer on the node's \
             host (loopback), or pass --allow-non-loopback only over a private, firewalled link."
        );
    }

    tracing::info!(
        "qchain remote signer up: validator {} listening on {bound} (guard: {guard_path}){}",
        bundle.to_address(),
        if is_loopback { "" } else { " [NON-LOOPBACK — ensure the link is private]" }
    );

    qchain_remote_signer::serve(keypair, listener, guard);
    Ok(())
}
