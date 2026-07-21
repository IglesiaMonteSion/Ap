//! Firmante remoto / HSM de la clave de validador — tarea #193 (separación de
//! claves de validador por rol + soporte HSM/firmante remoto), incremento A.
//!
//! # Qué resuelve
//!
//! Hoy la clave que firma bloques (consenso) vive DENTRO del proceso del nodo,
//! que es la superficie más expuesta a internet (RPC, P2P, dashboard). Si ese
//! proceso se compromete, la clave se filtra. Este crate mueve la clave a un
//! proceso SEPARADO (o un HSM): el nodo le pide firmas por un socket local y
//! **nunca ve el material de clave**. Es el modelo `tmkms` de Cosmos.
//!
//! - `RemoteSigner` (cliente) implementa `qchain_crypto::Signer`, así que el
//!   nodo lo usa transparentemente en los mismos 2 sitios de firma de consenso
//!   (+ el handshake P2P) — sin cambiar NADA de lo que se firma (mismas
//!   preimágenes domain-tagged de #187, mismo consenso, mismo wire).
//! - `serve` (servidor) sostiene el `Keypair` y firma por request, con una
//!   `DoubleSignGuard` PERSISTIDA (persist-before-sign) que rechaza firmar dos
//!   vértices PROPIOS distintos para la misma ronda — la propiedad de seguridad
//!   central de un firmante de validador (evita la auto-equivocación aun si el
//!   proceso del nodo estuviera buggeado/comprometido).
//!
//! # Modelo de confianza del socket
//!
//! Quien alcanza el socket puede pedir firmas (votos de peer + bytes de
//! handshake; NUNCA un auto-voto en conflicto, por la guardia). Por eso el
//! daemon **bindea loopback por defecto** y el operador lo corre en el mismo
//! host que el nodo (o un host de firma dedicado con un enlace privado). La
//! guardia acota el peor caso a "no hay auto-equivocación", nunca "robar
//! fondos" (la clave nunca sale del daemon).

use borsh::{BorshDeserialize, BorshSerialize};
use qchain_crypto::{Keypair, MultiSignature, PublicKeyBundle};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Versión del protocolo del socket (por si cambia el framing/enum a futuro).
pub const PROTO_VERSION: u8 = 1;
/// Cota dura de un frame (anti-OOM de un cliente malicioso en el socket).
pub const MAX_FRAME_BYTES: u32 = 1 << 20; // 1 MiB — de sobra para un bundle/firma híbrida (~35 KB).
/// Timeout de I/O del socket (una firma es sub-ms local; un HSM real, unos ms).
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Pedido del nodo al firmante. Los votos de consenso llevan la metadata (ronda,
/// si es el vértice PROPIO) para que la guardia anti-doble-firma funcione — el
/// firmante no puede derivarla de los bytes crudos del digest.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum SignerRequest {
    /// Devolver el bundle de clave pública (el nodo lo usa como su identidad al
    /// arrancar en modo remoto, y para cross-checkear que el firmante tiene la
    /// clave del validador configurado).
    GetBundle,
    /// Auto-voto del proposer sobre su PROPIO vértice de la ronda `round` —
    /// sujeto a la guardia anti-doble-firma.
    SignOwnVote { round: u64, digest: [u8; 32] },
    /// Voto sobre el vértice de OTRO validador — sin guardia (no es
    /// auto-equivocación).
    SignPeerVote { digest: [u8; 32] },
    /// Firmar exactamente estos bytes (transcript del handshake P2P, ya domainado
    /// por el llamador) — sin guardia.
    SignRaw { msg: Vec<u8> },
}

/// Respuesta del firmante.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum SignerResponse {
    Bundle(PublicKeyBundle),
    Signature(MultiSignature),
    /// La guardia rechazó (intento de doble-firma / ronda regresiva) o hubo un
    /// error — el nodo lo trata como un fallo de firma (recuperable: salta esa
    /// ronda, reintenta cuando corresponda).
    Refused(String),
}

// ---- framing (u32 LE len-prefix, ambos sentidos), bloqueante ----

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> anyhow::Result<()> {
    let len = bytes.len();
    if len as u64 > MAX_FRAME_BYTES as u64 {
        anyhow::bail!("frame too large: {len} bytes");
    }
    stream.write_all(&(len as u32).to_le_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("declared frame length {len} exceeds cap {MAX_FRAME_BYTES}");
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

// ============================ CLIENTE ============================

/// Cliente del firmante remoto. Implementa `qchain_crypto::Signer`, así que el
/// nodo lo usa en `Arc<dyn Signer>` sin saber si la clave es local o remota.
/// Conexión TCP persistente cacheada con reconexión transparente (mismo patrón
/// que `qchain-network::transport`): un fallo de I/O descarta la conexión y
/// reintenta una vez.
pub struct RemoteSigner {
    endpoint: String,
    bundle: PublicKeyBundle,
    conn: Mutex<Option<TcpStream>>,
}

impl RemoteSigner {
    /// Conecta al firmante y obtiene su bundle (la identidad del validador).
    /// Falla ruidoso si el firmante no responde al arrancar — mejor no arrancar
    /// que arrancar sin poder firmar.
    pub fn connect(endpoint: &str) -> anyhow::Result<Self> {
        let s = RemoteSigner {
            endpoint: endpoint.to_string(),
            bundle: PublicKeyBundle { components: Vec::new() },
            conn: Mutex::new(None),
        };
        let bundle = match s.request(&SignerRequest::GetBundle)? {
            SignerResponse::Bundle(b) => b,
            other => anyhow::bail!("remote signer returned an unexpected response to GetBundle: {other:?}"),
        };
        Ok(RemoteSigner { endpoint: s.endpoint, bundle, conn: Mutex::new(None) })
    }

    fn dial(&self) -> anyhow::Result<TcpStream> {
        let stream = TcpStream::connect(&self.endpoint)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        stream.set_nodelay(true).ok();
        Ok(stream)
    }

    /// Una request/respuesta. Reusa la conexión cacheada; si falla la I/O,
    /// reconecta y reintenta UNA vez (una conexión muerta es transparente).
    fn request(&self, req: &SignerRequest) -> anyhow::Result<SignerResponse> {
        let req_bytes = borsh::to_vec(req)?;
        let mut guard = self.conn.lock().expect("signer conn mutex poisoned");
        for attempt in 0..2 {
            if guard.is_none() {
                *guard = Some(self.dial()?);
            }
            let stream = guard.as_mut().expect("just set");
            let io: anyhow::Result<SignerResponse> = (|| {
                write_frame(stream, &req_bytes)?;
                let resp = read_frame(stream)?;
                Ok(borsh::from_slice::<SignerResponse>(&resp)?)
            })();
            match io {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    // Conexión muerta: descartarla y (si queda intento) reconectar.
                    *guard = None;
                    if attempt == 1 {
                        return Err(e);
                    }
                }
            }
        }
        unreachable!("loop returns on the last attempt")
    }

    fn signature_from(resp: SignerResponse) -> anyhow::Result<MultiSignature> {
        match resp {
            SignerResponse::Signature(s) => Ok(s),
            SignerResponse::Refused(m) => Err(anyhow::anyhow!("remote signer refused: {m}")),
            other => Err(anyhow::anyhow!("remote signer returned an unexpected response: {other:?}")),
        }
    }
}

impl qchain_crypto::Signer for RemoteSigner {
    fn bundle(&self) -> PublicKeyBundle {
        self.bundle.clone()
    }
    fn sign_own_vote(&self, round: u64, digest: &[u8; 32]) -> anyhow::Result<MultiSignature> {
        Self::signature_from(self.request(&SignerRequest::SignOwnVote { round, digest: *digest })?)
    }
    fn sign_peer_vote(&self, digest: &[u8; 32]) -> anyhow::Result<MultiSignature> {
        Self::signature_from(self.request(&SignerRequest::SignPeerVote { digest: *digest })?)
    }
    fn sign_raw(&self, msg: &[u8]) -> anyhow::Result<MultiSignature> {
        Self::signature_from(self.request(&SignerRequest::SignRaw { msg: msg.to_vec() })?)
    }
}

// ============================ GUARDIA ============================

/// Guardia anti-doble-firma PERSISTIDA (persist-before-sign, estilo tmkms). Sólo
/// aplica a los AUTO-VOTOS (`SignOwnVote`): un validador propone UN vértice por
/// ronda, así que firmar un segundo vértice PROPIO distinto para la misma ronda
/// es auto-equivocación (slasheable). Los votos sobre vértices de OTROS y los
/// bytes de handshake no se guardan (no son auto-equivocación).
///
/// La regla: monotonía de ronda + un solo digest por ronda propia. Se persiste
/// ANTES de devolver "permitido" para que un crash del daemon justo después de
/// firmar no le haga "olvidar" que ya firmó esa ronda al reiniciar.
pub struct DoubleSignGuard {
    path: std::path::PathBuf,
    state: Option<GuardState>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
struct GuardState {
    last_own_round: u64,
    last_own_digest: [u8; 32],
}

impl DoubleSignGuard {
    /// Carga el estado persistido (si existe). Un archivo corrupto/ilegible es
    /// FATAL a propósito: preferimos no arrancar el firmante a arrancar sin la
    /// memoria de qué se firmó (que permitiría una doble-firma).
    pub fn load(path: impl Into<std::path::PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let state = match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => Some(
                borsh::from_slice::<GuardState>(&bytes)
                    .map_err(|e| anyhow::anyhow!("double-sign guard file {} is corrupt: {e}", path.display()))?,
            ),
            Ok(_) => None,          // vacío
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(anyhow::anyhow!("cannot read double-sign guard file {}: {e}", path.display())),
        };
        Ok(DoubleSignGuard { path, state })
    }

    /// Chequea+registra un auto-voto. Devuelve `Ok(())` si se permite (habiéndolo
    /// persistido primero), `Err(motivo)` si se rechaza. El llamador firma SÓLO
    /// tras un `Ok`.
    pub fn check_and_record_own(&mut self, round: u64, digest: &[u8; 32]) -> Result<(), String> {
        if let Some(st) = self.state {
            if round < st.last_own_round {
                return Err(format!(
                    "refusing to sign own vertex for round {round}: already signed a higher round {}",
                    st.last_own_round
                ));
            }
            if round == st.last_own_round {
                if &st.last_own_digest != digest {
                    return Err(format!(
                        "DOUBLE-SIGN BLOCKED: already signed a DIFFERENT own vertex for round {round}"
                    ));
                }
                // Mismo (ronda, digest) ya firmado → re-firma idempotente (retry legítimo).
                return Ok(());
            }
        }
        // Ronda nueva (mayor o primera): persistir ANTES de permitir la firma.
        let next = GuardState { last_own_round: round, last_own_digest: *digest };
        self.persist(&next).map_err(|e| format!("cannot persist double-sign guard: {e}"))?;
        self.state = Some(next);
        Ok(())
    }

    /// Persiste el estado con DURABILIDAD real (persist-before-sign de verdad).
    /// `std::fs::write` sólo escribe al page-cache: sobrevive un reinicio normal
    /// del proceso pero NO un corte de energía / crash del kernel, así que la
    /// guardia podría "olvidar" que firmó una ronda y permitir una doble-firma
    /// tras un apagado abrupto. Por eso: (1) archivo temporal 0600 (el material
    /// de la guardia no debe ser world-readable), (2) `sync_all()` = fsync del
    /// archivo (bytes + metadata durables), (3) rename atómico, (4) fsync del
    /// DIRECTORIO padre para que el propio rename sea durable (un rename se puede
    /// perder ante un corte si el directorio no se sincroniza). Para un HSM real
    /// la defensa definitiva es un contador anti-rollback en el hardware.
    fn persist(&self, st: &GuardState) -> anyhow::Result<()> {
        use std::io::Write;
        let bytes = borsh::to_vec(st)?;
        let tmp = self.path.with_extension("tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?; // fsync del archivo: durable antes del rename.
        }
        std::fs::rename(&tmp, &self.path)?;
        // fsync del directorio padre → el rename es durable ante un corte.
        // Best-effort: en una plataforma que no permita abrir/fsync un dir, el
        // fsync del archivo de arriba ya cubre el caso común de reinicio.
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

// ============================ SERVIDOR ============================

/// Sirve pedidos de firma sobre `listener`, sosteniendo `keypair` y aplicando
/// `guard` a los auto-votos. Bloqueante: una conexión por vez en un bucle (un
/// nodo mantiene una sola conexión persistente; el volumen es ~una firma por
/// ronda). Cada conexión se atiende hasta que el par la cierra.
pub fn serve(keypair: Keypair, listener: TcpListener, guard: Arc<Mutex<DoubleSignGuard>>) {
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                s.set_read_timeout(Some(IO_TIMEOUT)).ok();
                s.set_write_timeout(Some(IO_TIMEOUT)).ok();
                s.set_nodelay(true).ok();
                let peer = s.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
                tracing::info!("signer: connection from {peer}");
                if let Err(e) = handle_conn(&mut s, &keypair, &guard) {
                    tracing::warn!("signer: connection from {peer} ended: {e}");
                }
            }
            Err(e) => {
                tracing::warn!("signer: accept error: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn handle_conn(stream: &mut TcpStream, keypair: &Keypair, guard: &Arc<Mutex<DoubleSignGuard>>) -> anyhow::Result<()> {
    loop {
        let req_bytes = match read_frame(stream) {
            Ok(b) => b,
            Err(_) => return Ok(()), // el par cerró / timeout → fin de la conexión
        };
        let req = borsh::from_slice::<SignerRequest>(&req_bytes)
            .map_err(|e| anyhow::anyhow!("malformed request: {e}"))?;
        let resp = respond(&req, keypair, guard);
        write_frame(stream, &borsh::to_vec(&resp)?)?;
    }
}

/// Computa la respuesta a un pedido (extraído para poder testearlo aislado).
pub fn respond(req: &SignerRequest, keypair: &Keypair, guard: &Arc<Mutex<DoubleSignGuard>>) -> SignerResponse {
    match req {
        SignerRequest::GetBundle => SignerResponse::Bundle(keypair.public_key_bundle()),
        SignerRequest::SignOwnVote { round, digest } => {
            // Guardia PRIMERO (persist-before-sign): sólo firmamos tras un Ok.
            let mut g = guard.lock().expect("guard mutex poisoned");
            match g.check_and_record_own(*round, digest) {
                Ok(()) => match qchain_crypto::sign_vertex_vote(keypair, digest) {
                    Ok(sig) => SignerResponse::Signature(sig),
                    Err(e) => SignerResponse::Refused(format!("sign error: {e}")),
                },
                Err(reason) => {
                    tracing::error!("signer: {reason}");
                    SignerResponse::Refused(reason)
                }
            }
        }
        SignerRequest::SignPeerVote { digest } => match qchain_crypto::sign_vertex_vote(keypair, digest) {
            Ok(sig) => SignerResponse::Signature(sig),
            Err(e) => SignerResponse::Refused(format!("sign error: {e}")),
        },
        SignerRequest::SignRaw { msg } => {
            // #193-B (D1) — ALLOWLIST estricta (endurecido tras auditoría). El
            // firmante de consenso es un firmante de BLOQUES, jamás de valor.
            // `sign_raw` existe ÚNICAMENTE para el transcript del handshake P2P,
            // que se firma como `P2P_AUTH_V1 ‖ transcript` (#176). En vez de una
            // BLACKLIST (negar sólo `TX_SIG_V1`), que quedaría débil ante un tipo
            // de tx / dominio / protocolo NUEVO agregado después, se exige que el
            // mensaje empiece EXACTAMENTE por el dominio del handshake — todo lo
            // demás (una tx `TX_SIG_V1`, un voto, cualquier bytes arbitrario) se
            // RECHAZA por defecto. Así la clave de consenso remota no puede
            // autorizar una transferencia de valor NI ningún objeto futuro,
            // aunque el proceso del nodo esté comprometido: puede equivocar
            // (slasheable) pero nunca gastar.
            if !msg.starts_with(qchain_crypto::domains::P2P_AUTH_V1) {
                let reason = "refusing SignRaw: only a P2P_AUTH_V1-domained handshake transcript is signable via sign_raw; the consensus signer never signs value/other objects (#193-B allowlist)".to_string();
                tracing::error!("signer: {reason}");
                return SignerResponse::Refused(reason);
            }
            match keypair.sign(msg) {
                Ok(sig) => SignerResponse::Signature(sig),
                Err(e) => SignerResponse::Refused(format!("sign error: {e}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(dir: &std::path::Path) -> Arc<Mutex<DoubleSignGuard>> {
        Arc::new(Mutex::new(DoubleSignGuard::load(dir.join("guard.bin")).unwrap()))
    }

    #[test]
    fn double_sign_guard_blocks_a_conflicting_own_vertex_but_allows_the_rest() {
        let tmp = std::env::temp_dir().join(format!("qrs-guard-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let kp = Keypair::generate().unwrap();
        let g = guard(&tmp);

        let d1 = [1u8; 32];
        let d2 = [2u8; 32];

        // Auto-voto de la ronda 5 con d1 → OK.
        assert!(matches!(respond(&SignerRequest::SignOwnVote { round: 5, digest: d1 }, &kp, &g), SignerResponse::Signature(_)));
        // Re-firma idéntica (retry) del MISMO (5, d1) → OK (idempotente).
        assert!(matches!(respond(&SignerRequest::SignOwnVote { round: 5, digest: d1 }, &kp, &g), SignerResponse::Signature(_)));
        // Auto-voto de la ronda 5 con d2 DISTINTO → RECHAZADO (doble-firma).
        assert!(matches!(respond(&SignerRequest::SignOwnVote { round: 5, digest: d2 }, &kp, &g), SignerResponse::Refused(_)));
        // Ronda regresiva (4) → RECHAZADO.
        assert!(matches!(respond(&SignerRequest::SignOwnVote { round: 4, digest: d1 }, &kp, &g), SignerResponse::Refused(_)));
        // Ronda mayor (6) con cualquier digest → OK.
        assert!(matches!(respond(&SignerRequest::SignOwnVote { round: 6, digest: d2 }, &kp, &g), SignerResponse::Signature(_)));
        // Un VOTO DE PEER con un digest cualquiera para una ronda vieja → OK (sin guardia).
        assert!(matches!(respond(&SignerRequest::SignPeerVote { digest: d1 }, &kp, &g), SignerResponse::Signature(_)));
        // SignRaw de un transcript de handshake (dominio P2P) → OK.
        let hs = [qchain_crypto::domains::P2P_AUTH_V1, b" transcript"].concat();
        assert!(matches!(respond(&SignerRequest::SignRaw { msg: hs }, &kp, &g), SignerResponse::Signature(_)));

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// #193-B (D1): the consensus signer refuses to sign a `TX_SIG_V1`-domained
    /// message, so it can never be turned into a value-transfer signing oracle —
    /// a P2P-handshake (`qchain-p2p-auth-v1`) or any other non-tx raw message is
    /// still signed normally.
    #[test]
    fn sign_raw_refuses_a_tx_domained_message_but_signs_others() {
        let tmp = std::env::temp_dir().join(format!("qrs-txoracle-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let kp = Keypair::generate().unwrap();
        let g = guard(&tmp);

        // A message domained as a value transfer (what a payer signs, #187) → REFUSED.
        let mut tx_msg = qchain_crypto::domains::TX_SIG_V1.to_vec();
        tx_msg.extend_from_slice(b"...borsh(Message) would follow...");
        assert!(
            matches!(respond(&SignerRequest::SignRaw { msg: tx_msg }, &kp, &g), SignerResponse::Refused(_)),
            "the consensus signer must refuse to sign a TX_SIG_V1-domained message (no value oracle)"
        );
        // ALLOWLIST: anything that is NOT a handshake transcript is refused too —
        // arbitrary bytes, a future/unknown domain, a vote-domained digest — not
        // just the tx domain. "todo lo no permitido está prohibido".
        for bad in [
            b"arbitrary bytes".to_vec(),
            qchain_crypto::domains::VERTEX_VOTE_V1.to_vec(),
            b"qchain-some-future-protocol-v1 ...".to_vec(),
        ] {
            assert!(
                matches!(respond(&SignerRequest::SignRaw { msg: bad }, &kp, &g), SignerResponse::Refused(_)),
                "the consensus signer only signs raw bytes that are a P2P_AUTH_V1 handshake transcript"
            );
        }
        // The real handshake transcript (the ONLY permitted raw domain) is signed.
        let hs = [qchain_crypto::domains::P2P_AUTH_V1, b" transcript..."].concat();
        assert!(matches!(respond(&SignerRequest::SignRaw { msg: hs }, &kp, &g), SignerResponse::Signature(_)));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn guard_state_persists_across_reload() {
        let tmp = std::env::temp_dir().join(format!("qrs-guard-persist-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let kp = Keypair::generate().unwrap();
        let path = tmp.join("guard.bin");
        {
            let g = Arc::new(Mutex::new(DoubleSignGuard::load(&path).unwrap()));
            assert!(matches!(respond(&SignerRequest::SignOwnVote { round: 9, digest: [7u8; 32] }, &kp, &g), SignerResponse::Signature(_)));
        }
        // Reiniciar el firmante (recargar el guard del disco): una ronda <= 9 con
        // distinto digest sigue bloqueada.
        let g2 = Arc::new(Mutex::new(DoubleSignGuard::load(&path).unwrap()));
        assert!(matches!(respond(&SignerRequest::SignOwnVote { round: 9, digest: [8u8; 32] }, &kp, &g2), SignerResponse::Refused(_)));
        assert!(matches!(respond(&SignerRequest::SignOwnVote { round: 8, digest: [8u8; 32] }, &kp, &g2), SignerResponse::Refused(_)));
        // Y una ronda mayor sigue permitida.
        assert!(matches!(respond(&SignerRequest::SignOwnVote { round: 10, digest: [8u8; 32] }, &kp, &g2), SignerResponse::Signature(_)));

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Round-trip cliente↔servidor real por un socket loopback: el cliente
    /// obtiene el bundle correcto y una firma de voto que VERIFICA bajo ese
    /// bundle (el mismo dominio VERTEX_VOTE_V1 de #187).
    #[test]
    fn client_server_roundtrip_over_a_real_socket() {
        use qchain_crypto::Signer;
        let tmp = std::env::temp_dir().join(format!("qrs-rt-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let kp = Keypair::generate().unwrap();
        let expected_bundle = kp.public_key_bundle();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let g = guard(&tmp);
        std::thread::spawn(move || serve(kp, listener, g));

        let client = RemoteSigner::connect(&addr).unwrap();
        assert_eq!(client.bundle().to_address(), expected_bundle.to_address());
        let digest = [42u8; 32];
        let sig = client.sign_own_vote(1, &digest).unwrap();
        assert!(qchain_crypto::verify_vertex_vote(&expected_bundle, &digest, &sig), "la firma del firmante remoto verifica bajo el dominio de voto");
        // Un peer-vote también funciona.
        let sig2 = client.sign_peer_vote(&[43u8; 32]).unwrap();
        assert!(qchain_crypto::verify_vertex_vote(&expected_bundle, &[43u8; 32], &sig2));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
