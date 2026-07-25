//! `qchain-byzantine-injector` — corre como un validador MALICIOSO real contra
//! una red honesta: sostiene una clave del comité (`--keypair`) y le envía a los
//! nodos honestos mensajes P2P genuinamente firmados pero maliciosos. La lógica
//! de construcción vive (unit-testeada) en `lib.rs`; acá va sólo el transporte.
//!
//! Modelo de amenaza. Un validador bizantino es un MIEMBRO del comité (no un
//! extraño): su clave está en el set de génesis, así que su firma verifica y sus
//! mensajes se procesan. Para probar de verdad las defensas hay que correr con
//! una clave del comité y NO correr el nodo honesto de esa identidad — este tool
//! la impersona. Es exactamente el escenario que las defensas de equivocación /
//! withholding / cotas estructurales existen para contener.
//!
//! Transporte. Soporta el camino NO autenticado (el default de la red del
//! usuario: `[u32 LE len][Borsh(Envelope)]` crudo) y el AUTENTICADO (completa el
//! handshake ML-DSA como el validador que impersona — un miembro autorizado SÍ
//! puede handshakear; la auth sólo frena a los NO-miembros). No prueba éxito por
//! sí mismo: el oráculo es la red honesta observada por RPC (ver
//! `deploy/byzantine-injector.sh`), que asserta que NO forkea y sigue viva.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use qchain_core::Batch;
use qchain_crypto::Pubkey;
use qchain_network::NetMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Parser)]
#[command(name = "qchain-byzantine-injector", about = "Inyector bizantino: corre como un validador malicioso del comité y envía mensajes P2P firmados pero maliciosos a nodos honestos.")]
struct Cli {
    /// Keypair de la identidad de validador a impersonar. DEBE ser un miembro del
    /// comité (su dirección en el set de génesis) o el nodo dropea todo lo que
    /// firme por "validador desconocido".
    #[arg(long, global = true)]
    keypair: Option<String>,
    /// `chain_id` de la red objetivo, hex de 64 chars (`GET /chain_id`). Las
    /// firmas de voto/vértice van atadas a él (#187).
    #[arg(long, global = true)]
    chain_id: Option<String>,
    /// Direcciones P2P (`host:puerto`) de los nodos honestos a atacar, separadas
    /// por coma. Son los `listen_addr`, NO los puertos RPC.
    #[arg(long, global = true)]
    targets: Option<String>,
    /// SÓLO para transporte autenticado: los ids base58 de cada objetivo, en el
    /// MISMO orden que `--targets`. El handshake exige saber a quién se dialoga
    /// (anti-misrouting), así que bajo auth hay que pasarlos. En transporte plano
    /// se ignora.
    #[arg(long, global = true)]
    target_ids: Option<String>,
    /// Correr el handshake AUTENTICADO (la red objetivo tiene
    /// `authenticated_transport: true`). Por defecto usa el transporte plano.
    #[arg(long, global = true, default_value_t = false)]
    authenticated: bool,
    /// Además cifrar (la red tiene `encrypted_transport: true`). Implica
    /// `--authenticated`.
    #[arg(long, global = true, default_value_t = false)]
    encrypted: bool,
    #[command(subcommand)]
    attack: Attack,
}

#[derive(Subcommand)]
enum Attack {
    /// Proponer DOS vértices en conflicto para la misma (ronda, autor) — el nodo
    /// debe capturar evidencia de equivocación y NO forkear.
    Equivocate {
        /// La ronda para la que equivocar (usar la ronda actual de `/status`).
        #[arg(long)]
        round: u64,
    },
    /// Proponer un vértice que referencia un batch que NUNCA se gossipea — el
    /// nodo NO debe votarlo (gate de disponibilidad) → jamás se certifica.
    Withhold {
        #[arg(long)]
        round: u64,
        /// Cuántas veces repetir el vértice retenido (best-effort spam).
        #[arg(long, default_value_t = 5)]
        count: usize,
    },
    /// Proponer un vértice válidamente firmado con MUCHOS más `parents` de los
    /// permitidos — el nodo debe dropearlo por la cota estructural sin explotar.
    Oversized {
        #[arg(long)]
        round: u64,
        /// Número de `parents` fabricados (muy por encima de `n`).
        #[arg(long, default_value_t = 5000)]
        parents: usize,
    },
    /// Flood de `TransactionGossip` de tx reales firmadas por un pagador SIN
    /// FONDOS — ejercita la cuota de admisión + verify concurrente sin poder
    /// amplificar. La red honesta debe seguir sana.
    Flood {
        /// Cuántas tx enviar por objetivo.
        #[arg(long, default_value_t = 500)]
        count: usize,
    },
}

fn parse_chain_id(hex_str: &str) -> Result<[u8; 32]> {
    hex::decode(hex_str.trim().trim_start_matches("0x"))
        .context("--chain-id no es hex válido")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("--chain-id debe ser exactamente 32 bytes (64 hex chars)"))
}

fn parse_targets(s: &str) -> Result<Vec<SocketAddr>> {
    s.split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| t.parse::<SocketAddr>().with_context(|| format!("target inválido: {t}")))
        .collect()
}

/// Todo lo que el envío necesita saber de la red (armado una vez). El `chain_id`
/// y el modo de cifrado ya viven dentro de `auth`, así que no se repiten acá.
struct Transport {
    keypair: Arc<qchain_crypto::Keypair>,
    /// `Some` bajo transporte autenticado (con o sin cifrado); `None` = plano.
    auth: Option<Arc<qchain_network::AuthState>>,
}

/// Envía un `NetMessage` a UN objetivo, dialogando y (si corresponde) haciendo el
/// handshake autenticado como el validador impersonado. `target_id` sólo se usa
/// bajo auth (el handshake exige saber a quién se dialoga). Devuelve Ok aunque el
/// nodo cierre la conexión tras recibir el mensaje (lo esperado para uno malicioso).
async fn send_one(tp: &Transport, target: SocketAddr, target_id: Option<Pubkey>, msg: &NetMessage) -> Result<()> {
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(target))
        .await
        .with_context(|| format!("timeout conectando a {target}"))?
        .with_context(|| format!("no pude conectar a {target}"))?;

    let envelope = qchain_network::Envelope { from: tp.keypair.pubkey(), message: msg.clone() };
    let bytes = borsh::to_vec(&envelope)?;

    match &tp.auth {
        Some(auth) => {
            let want = target_id.context("transporte auth requiere --target-ids alineado con --targets")?;
            let (_server_id, session) =
                qchain_network::handshake::client_handshake(&mut stream, auth, Some(want))
                    .await
                    .with_context(|| format!("handshake autenticado con {target} falló"))?;
            // En modo cifrado el handshake devuelve una `Session`; sellamos con ella.
            let framed = match session {
                Some(mut s) => s.seal(&bytes)?,
                None => bytes,
            };
            write_frame(&mut stream, &framed).await?;
        }
        None => {
            // Camino plano: exactamente `[u32 LE len][Borsh(Envelope)]`.
            write_frame(&mut stream, &bytes).await?;
        }
    }
    let _ = tokio::time::timeout(Duration::from_millis(200), stream.flush()).await;
    Ok(())
}

async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Enviar bytes de un frame CRUDO (posiblemente corrupto) a un objetivo — para el
/// sub-ataque de bytes-basura, que no pasa por `NetMessage`.
async fn send_raw(target: SocketAddr, frame: &[u8]) -> Result<()> {
    let mut stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(target))
        .await
        .with_context(|| format!("timeout conectando a {target}"))??;
    write_frame(&mut stream, frame).await?;
    let _ = tokio::time::timeout(Duration::from_millis(100), stream.read_u8()).await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();

    let keypair = Arc::new(qchain_crypto::read_keypair_file(std::path::Path::new(
        cli.keypair.as_deref().context("--keypair es obligatorio")?,
    ))?);
    let chain_id = parse_chain_id(cli.chain_id.as_deref().context("--chain-id es obligatorio")?)?;
    let targets = parse_targets(cli.targets.as_deref().context("--targets es obligatorio")?)?;
    let encrypted = cli.encrypted;
    let authenticated = cli.authenticated || encrypted;
    let byz_id = keypair.pubkey();

    // Bajo auth: los ids de los objetivos, alineados con `--targets`.
    let target_ids: Vec<Option<Pubkey>> = if authenticated {
        let ids_str = cli.target_ids.as_deref().context("transporte auth requiere --target-ids")?;
        let ids: Vec<Pubkey> = ids_str
            .split(',')
            .map(|s| s.trim().parse::<Pubkey>().map_err(|e| anyhow::anyhow!("--target-ids inválido: {e}")))
            .collect::<Result<_>>()?;
        anyhow::ensure!(ids.len() == targets.len(), "--target-ids debe tener el mismo número de entradas que --targets");
        ids.into_iter().map(Some).collect()
    } else {
        vec![None; targets.len()]
    };

    // Bajo auth construimos el `AuthState` una vez (impersonando al validador),
    // autorizando a todos los objetivos + a nosotros.
    let auth = if authenticated {
        let mut authorized: HashSet<Pubkey> = target_ids.iter().flatten().copied().collect();
        authorized.insert(byz_id);
        Some(Arc::new(qchain_network::AuthState::new_with_encryption(
            keypair.clone() as Arc<dyn qchain_crypto::Signer>,
            chain_id,
            authorized,
            encrypted,
        )))
    } else {
        None
    };
    let tp = Transport { keypair: keypair.clone(), auth };

    tracing::info!(
        "inyector bizantino: impersono al validador {byz_id}, ataco {} objetivo(s), transporte={}",
        targets.len(),
        if encrypted { "auth+cifrado" } else if authenticated { "auth" } else { "plano" }
    );

    match cli.attack {
        Attack::Equivocate { round } => {
            let (a, b) = qchain_byzantine_injector::equivocation_pair(&keypair, &chain_id, round)?;
            for (t, tid) in targets.iter().zip(&target_ids) {
                // Ambos vértices en conflicto al MISMO nodo, así detecta la
                // equivocación (necesita ver los dos).
                send_one(&tp, *t, *tid, &a).await.ok();
                send_one(&tp, *t, *tid, &b).await.ok();
                tracing::info!("equivocación enviada a {t} (ronda {round})");
            }
        }
        Attack::Withhold { round, count } => {
            let batch = Batch { transactions: vec![] };
            let (msg, withheld) = qchain_byzantine_injector::withholding_vertex(&keypair, &chain_id, round, 0, &batch)?;
            tracing::info!("withholding: vértice referencia el batch {} que NUNCA envío", hex::encode(withheld));
            for (t, tid) in targets.iter().zip(&target_ids) {
                for _ in 0..count {
                    send_one(&tp, *t, *tid, &msg).await.ok();
                }
                tracing::info!("withholding enviado a {t} ×{count}");
            }
        }
        Attack::Oversized { round, parents } => {
            let msg = qchain_byzantine_injector::oversized_parents_vertex(&keypair, &chain_id, round, parents)?;
            for (t, tid) in targets.iter().zip(&target_ids) {
                send_one(&tp, *t, *tid, &msg).await.ok();
                tracing::info!("vértice sobre-dimensionado ({parents} parents) enviado a {t}");
            }
            // Además unos frames de BYTES BASURA (sólo camino plano — un frame
            // corrupto no pasaría el handshake auth de todos modos): el
            // deserializador de wire debe rechazarlos sin panicar.
            if !authenticated {
                for t in &targets {
                    send_raw(*t, &[0xffu8; 512]).await.ok();
                    send_raw(*t, &[]).await.ok();
                    tracing::info!("frames de bytes basura enviados a {t}");
                }
            }
        }
        Attack::Flood { count } => {
            let flooder = qchain_crypto::Keypair::generate()?;
            let victim = keypair.pubkey();
            tracing::info!("flood: {count} tx/objetivo desde un pagador SIN FONDOS {}", flooder.pubkey());
            for (t, tid) in targets.iter().zip(&target_ids) {
                for n in 0..count as u64 {
                    let msg = qchain_byzantine_injector::flood_tx_gossip(&flooder, &chain_id, n, &victim)?;
                    send_one(&tp, *t, *tid, &msg).await.ok();
                }
                tracing::info!("flood de {count} tx enviado a {t}");
            }
        }
    }

    tracing::info!("ataque terminado. El veredicto lo da la red honesta observada por RPC (deploy/byzantine-injector.sh).");
    Ok(())
}
