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
//! # Modelo de confianza del socket (#4.2, auditoría v8.6.13 — CERRADO)
//!
//! El socket tiene ahora **DOS capas de autenticación del cliente**, cerrando el
//! residual "cualquier proceso local puede pedir firmas sin autenticarse":
//!
//! 1. **Transporte** — se soporta un **socket Unix (UDS)** con permisos estrictos
//!    del SO (dir `0700`, socket `0600`) además de TCP loopback. Con UDS, sólo un
//!    proceso que corre como el MISMO usuario del firmante puede siquiera abrir el
//!    socket (aislamiento reforzado por el kernel, el modelo `tmkms` local).
//! 2. **Criptográfica** — **challenge-response de token pre-compartido** (opcional
//!    en el protocolo, OBLIGATORIA en el perfil mainnet). Al conectar, el servidor
//!    manda un `AuthChallenge` con un nonce FRESCO (getrandom); el cliente responde
//!    con `tag = SHA3-256(dominio ‖ len(token) ‖ token ‖ nonce)` y el servidor lo
//!    verifica en tiempo constante ANTES de servir cualquier pedido de firma. Un
//!    proceso que no conoce el token es rechazado sin poder firmar nada. El nonce
//!    fresco por conexión evita replay; SHA3 es resistente a extensión de longitud
//!    (FIPS 202 — la base del prefix-MAC de KMAC), así que el prefix-MAC es un
//!    autenticador sólido (no se inventa cripto).
//!
//! 3. **Binding de canal (mutuo + integridad, cross-host).** El handshake es
//!    MUTUO (ambos lados aportan un nonce), y tras autenticar se deriva una
//!    **clave de sesión** `SHA3-256(dominio ‖ token ‖ nonce_s ‖ nonce_c)` con la
//!    que se **MAC-ea CADA frame** (`SHA3-256(clave ‖ dirección ‖ seq ‖ payload)`,
//!    seq monótono por dirección, verificado en tiempo constante). Esto da, sobre
//!    un enlace TCP cross-host NO confiable, lo que un mTLS daría —autenticación
//!    mutua + integridad + anti-inyección + anti-replay/reorder— **sin cripto
//!    clásica** (nada de X25519/RSA/ECDSA, roto por Shor): un atacante on-path que
//!    no conoce el token no puede inyectar/alterar un pedido ni reordenar frames.
//!    NO cifra (el tráfico del firmante es público: digests/vértices/firmas), sólo
//!    autentica — que es lo que hace falta acá.
//!
//! Defensa en profundidad, ADEMÁS de lo previo: la `DoubleSignGuard` (peor caso
//! "no hay auto-equivocación"), la verificación de AUTORÍA de `SignPeerVote`
//! (#4.1) y la allowlist estricta de `SignRaw` (sólo el transcript de handshake).
//! El daemon **bindea loopback por defecto** (o un UDS local); en mainnet el
//! endpoint debe ser loopback/UDS **y** llevar token (fail-stop en `config.rs`).

use borsh::{BorshDeserialize, BorshSerialize};
use qchain_crypto::{Keypair, MultiSignature, PublicKeyBundle};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Versión del protocolo del socket. v2 agregó el handshake de auth (#4.2); v3
/// agregó el nonce del cliente (handshake mutuo) + el binding de canal por-frame.
pub const PROTO_VERSION: u8 = 3;
/// Dominio del prefix-MAC del challenge-response (separación de dominio).
pub const RS_AUTH_DOMAIN: &[u8] = b"qchain-remote-signer-auth-v1";
/// Dominio de la derivación de la clave de sesión (binding de canal, #4.2 v3).
pub const RS_SESSION_DOMAIN: &[u8] = b"qchain-remote-signer-session-v1";
/// Dirección de un frame para el MAC de sesión (separa los dos sentidos → un
/// frame cliente→servidor nunca se puede reflejar como servidor→cliente).
const DIR_C2S: u8 = 0;
const DIR_S2C: u8 = 1;
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
    /// Voto sobre el vértice de OTRO validador. Lleva los BYTES borsh del vértice
    /// además del digest: el daemon deserializa el vértice, recomputa su digest
    /// (debe coincidir con `digest`) y REHÚSA si el autor es NUESTRA propia clave
    /// — un auto-voto DEBE ir por `SignOwnVote`, que sí está guardado. Cierra el
    /// bypass de auto-equivocación por SignPeerVote (#4, auditoría v8.6.13): sin
    /// esto un nodo comprometido podía enrutar su SEGUNDO vértice propio de una
    /// ronda por aquí y firmar evidencia de auto-equivocación (slasheable).
    SignPeerVote { vertex_bytes: Vec<u8>, digest: [u8; 32] },
    /// Firmar exactamente estos bytes (transcript del handshake P2P, ya domainado
    /// por el llamador) — sin guardia.
    SignRaw { msg: Vec<u8> },
    /// Firmar un checkpoint de estado (`STATE_CHECKPOINT_V1 ‖ chain_id ‖ round ‖
    /// root`, tarea #212) — una atestación de state-sync, no un voto. Sin guardia:
    /// un validador honesto sólo firma su root REAL determinista por ronda, y el
    /// dominio la separa de un voto/tx. Estructurada (no `SignRaw`), así el
    /// allowlist estricto de `SignRaw` (sólo `P2P_AUTH_V1`) queda intacto.
    SignCheckpoint { chain_id: [u8; 32], round: u64, merkle_root: [u8; 32] },
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

/// #4.2 — Primer mensaje que el SERVIDOR manda en cada conexión: negocia la
/// versión y (si el daemon corre con token) exige el challenge-response. El nonce
/// es fresco por conexión (anti-replay).
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct AuthChallenge {
    pub proto_version: u8,
    pub auth_required: bool,
    pub nonce: [u8; 32],
}

/// #4.2 — Respuesta del CLIENTE al challenge: prueba que conoce el token sin
/// enviarlo, y aporta su propio nonce (handshake MUTUO → la clave de sesión
/// depende de ambos lados). `tag = SHA3-256(RS_AUTH_DOMAIN ‖ len(token) ‖ token ‖
/// server_nonce ‖ client_nonce)`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct AuthResponse {
    pub client_nonce: [u8; 32],
    pub tag: [u8; 32],
}

/// Prefix-MAC del challenge-response. SHA3-256 es resistente a extensión de
/// longitud (FIPS 202; es la base del prefix-MAC de KMAC), así que
/// `SHA3-256(dominio ‖ len(token) ‖ token ‖ nonce)` es un autenticador sólido:
/// el nonce es fresco por conexión (anti-replay) y sólo quien tiene el token
/// puede producir el tag. Se prefija la longitud del token para que no haya
/// ambigüedad de frontera token/nonce. No se inventa cripto — es un keyed-hash
/// SHA3 estándar.
pub fn auth_tag(token: &[u8], server_nonce: &[u8; 32], client_nonce: &[u8; 32]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(RS_AUTH_DOMAIN);
    h.update((token.len() as u64).to_le_bytes());
    h.update(token);
    h.update(server_nonce);
    h.update(client_nonce);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&h.finalize());
    tag
}

/// Clave de sesión para el binding de canal (#4.2 v3). Depende de AMBOS nonces
/// (fresca por conexión) y del token (sólo quien lo conoce la deriva). Mismo
/// keyed-hash SHA3 length-extension-resistente que el tag de auth.
fn derive_session_key(token: &[u8], server_nonce: &[u8; 32], client_nonce: &[u8; 32]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(RS_SESSION_DOMAIN);
    h.update((token.len() as u64).to_le_bytes());
    h.update(token);
    h.update(server_nonce);
    h.update(client_nonce);
    let mut key = [0u8; 32];
    key.copy_from_slice(&h.finalize());
    key
}

/// MAC de un frame de sesión: `SHA3-256(clave ‖ dirección ‖ seq ‖ payload)`. La
/// dirección separa los dos sentidos (anti-reflexión) y `seq` (monótono por
/// dirección) da anti-replay/reorder dentro de la sesión.
fn frame_mac(key: &[u8; 32], dir: u8, seq: u64, payload: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(key);
    h.update([dir]);
    h.update(seq.to_le_bytes());
    h.update((payload.len() as u64).to_le_bytes());
    h.update(payload);
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&h.finalize());
    mac
}

/// Estado de una sesión autenticada: la clave + los contadores de secuencia por
/// dirección. `None` = conexión sin token (dev/loopback) → frames en claro.
struct Session {
    key: [u8; 32],
    send_seq: u64,
    recv_seq: u64,
}

/// Envía un frame: en claro si no hay sesión, o con MAC de sesión anexado
/// (payload ‖ mac(32), como UN frame len-prefixado) si la hay. `dir` es el
/// sentido de ESTE envío (C2S en el cliente, S2C en el servidor).
fn send_frame<S: Write>(stream: &mut S, payload: &[u8], sess: Option<&mut Session>, dir: u8) -> anyhow::Result<()> {
    match sess {
        None => write_frame(stream, payload),
        Some(s) => {
            let mac = frame_mac(&s.key, dir, s.send_seq, payload);
            s.send_seq = s.send_seq.checked_add(1).ok_or_else(|| anyhow::anyhow!("signer session frame seq overflow"))?;
            let mut buf = Vec::with_capacity(payload.len() + 32);
            buf.extend_from_slice(payload);
            buf.extend_from_slice(&mac);
            write_frame(stream, &buf)
        }
    }
}

/// Recibe un frame: en claro si no hay sesión, o verificando+quitando el MAC de
/// sesión si la hay (rechaza un frame alterado/inyectado/reordenado). `dir` es el
/// sentido de la RECEPCIÓN (S2C en el cliente, C2S en el servidor).
fn recv_frame<S: Read>(stream: &mut S, sess: Option<&mut Session>, dir: u8) -> anyhow::Result<Vec<u8>> {
    let raw = read_frame(stream)?;
    match sess {
        None => Ok(raw),
        Some(s) => {
            if raw.len() < 32 {
                anyhow::bail!("authed frame too short (missing session MAC)");
            }
            let (payload, mac) = raw.split_at(raw.len() - 32);
            let expected = frame_mac(&s.key, dir, s.recv_seq, payload);
            if !ct_eq(mac, &expected) {
                anyhow::bail!("session frame MAC verification failed — channel tampered, injected, reordered, or wrong token");
            }
            s.recv_seq = s.recv_seq.checked_add(1).ok_or_else(|| anyhow::anyhow!("signer session frame seq overflow"))?;
            Ok(payload.to_vec())
        }
    }
}

/// Comparación en tiempo constante (sin cortar temprano) para el tag del MAC —
/// evita un canal lateral de temporización al verificar la autenticación.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn fresh_nonce() -> anyhow::Result<[u8; 32]> {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n)
        .map_err(|e| anyhow::anyhow!("OS randomness unavailable for the signer auth nonce: {e}"))?;
    Ok(n)
}

/// ¿Es `endpoint` una ruta de socket Unix? (`unix:/ruta`, o una ruta absoluta /
/// relativa `./`). Si no, es un `host:puerto` TCP. Compat hacia atrás: un
/// `127.0.0.1:9200` existente sigue siendo TCP.
pub fn unix_endpoint_path(endpoint: &str) -> Option<&str> {
    if let Some(p) = endpoint.strip_prefix("unix:") {
        return Some(p);
    }
    if endpoint.starts_with('/') || endpoint.starts_with("./") {
        return Some(endpoint);
    }
    None
}

// ---- framing (u32 LE len-prefix, ambos sentidos), bloqueante, genérico sobre
// Read/Write para servir TCP y UDS con el mismo código ----

fn write_frame<S: Write>(stream: &mut S, bytes: &[u8]) -> anyhow::Result<()> {
    let len = bytes.len();
    if len as u64 > MAX_FRAME_BYTES as u64 {
        anyhow::bail!("frame too large: {len} bytes");
    }
    stream.write_all(&(len as u32).to_le_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_frame<S: Read>(stream: &mut S) -> anyhow::Result<Vec<u8>> {
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

// ---- transporte: TCP (loopback / enlace privado) o UDS (mismo host) ----

/// Un flujo del firmante: TCP o socket Unix. Ambos implementan `Read`+`Write`,
/// así que el framing y el handshake son idénticos.
pub enum SignerStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl Read for SignerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            SignerStream::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            SignerStream::Unix(s) => s.read(buf),
        }
    }
}

impl Write for SignerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            SignerStream::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            SignerStream::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            SignerStream::Tcp(s) => s.flush(),
            #[cfg(unix)]
            SignerStream::Unix(s) => s.flush(),
        }
    }
}

impl SignerStream {
    fn configure(&self, timeout: Duration) {
        match self {
            SignerStream::Tcp(s) => {
                s.set_read_timeout(Some(timeout)).ok();
                s.set_write_timeout(Some(timeout)).ok();
                s.set_nodelay(true).ok();
            }
            #[cfg(unix)]
            SignerStream::Unix(s) => {
                s.set_read_timeout(Some(timeout)).ok();
                s.set_write_timeout(Some(timeout)).ok();
            }
        }
    }
    fn peer_desc(&self) -> String {
        match self {
            SignerStream::Tcp(s) => s.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into()),
            #[cfg(unix)]
            SignerStream::Unix(_) => "unix-socket".into(),
        }
    }
}

/// Un listener del firmante: TCP o socket Unix.
pub enum SignerListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixListener),
}

impl SignerListener {
    fn accept(&self) -> std::io::Result<SignerStream> {
        match self {
            SignerListener::Tcp(l) => l.accept().map(|(s, _)| SignerStream::Tcp(s)),
            #[cfg(unix)]
            SignerListener::Unix(l) => l.accept().map(|(s, _)| SignerStream::Unix(s)),
        }
    }
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
    /// Token pre-compartido para el challenge-response (#4.2). `None` = sin token
    /// (sólo aceptable en loopback/UDS de desarrollo; el perfil mainnet lo exige).
    auth_token: Option<Vec<u8>>,
    /// Conexión cacheada + su sesión autenticada (si hay token). Reconexión
    /// transparente re-hace el handshake y deriva una sesión fresca.
    conn: Mutex<Option<(SignerStream, Option<Session>)>>,
}

impl RemoteSigner {
    /// Conecta SIN token (compat: loopback/UDS de desarrollo). Prefiere
    /// `connect_with_token` en producción; mainnet exige el token.
    pub fn connect(endpoint: &str) -> anyhow::Result<Self> {
        Self::connect_with_token(endpoint, None)
    }

    /// Conecta al firmante y obtiene su bundle (la identidad del validador),
    /// autenticándose con `auth_token` si el daemon lo exige. Falla ruidoso si el
    /// firmante no responde o si exige auth y no tenemos token — mejor no arrancar
    /// que arrancar sin poder firmar.
    pub fn connect_with_token(endpoint: &str, auth_token: Option<Vec<u8>>) -> anyhow::Result<Self> {
        let s = RemoteSigner {
            endpoint: endpoint.to_string(),
            bundle: PublicKeyBundle { components: Vec::new() },
            auth_token: auth_token.clone(),
            conn: Mutex::new(None),
        };
        let bundle = match s.request(&SignerRequest::GetBundle)? {
            SignerResponse::Bundle(b) => b,
            other => anyhow::bail!("remote signer returned an unexpected response to GetBundle: {other:?}"),
        };
        Ok(RemoteSigner { endpoint: s.endpoint, bundle, auth_token, conn: Mutex::new(None) })
    }

    /// Conecta y hace el handshake de auth MUTUO (#4.2 v3): lee el
    /// `AuthChallenge` del servidor y, si exige auth, responde con su nonce + el
    /// tag del token y deriva la clave de sesión. Devuelve un stream YA
    /// autenticado + su sesión (para el binding de canal por-frame).
    fn dial(&self) -> anyhow::Result<(SignerStream, Option<Session>)> {
        let mut stream = if let Some(path) = unix_endpoint_path(&self.endpoint) {
            #[cfg(unix)]
            {
                SignerStream::Unix(std::os::unix::net::UnixStream::connect(path)?)
            }
            #[cfg(not(unix))]
            {
                anyhow::bail!("unix-socket signer endpoints require a unix platform: {path}");
            }
        } else {
            SignerStream::Tcp(TcpStream::connect(&self.endpoint)?)
        };
        stream.configure(IO_TIMEOUT);
        // Handshake de auth: el servidor habla primero (en claro — aún no hay clave).
        let ch_bytes = read_frame(&mut stream)?;
        let ch: AuthChallenge = borsh::from_slice(&ch_bytes)
            .map_err(|e| anyhow::anyhow!("malformed AuthChallenge from signer: {e}"))?;
        if ch.proto_version != PROTO_VERSION {
            anyhow::bail!(
                "remote signer speaks protocol v{} but this node speaks v{PROTO_VERSION} — update both together",
                ch.proto_version
            );
        }
        if ch.auth_required {
            let token = self.auth_token.as_ref().ok_or_else(|| {
                anyhow::anyhow!("remote signer requires client authentication but no auth token is configured on this node")
            })?;
            let client_nonce = fresh_nonce()?;
            let tag = auth_tag(token, &ch.nonce, &client_nonce);
            write_frame(&mut stream, &borsh::to_vec(&AuthResponse { client_nonce, tag })?)?;
            let key = derive_session_key(token, &ch.nonce, &client_nonce);
            Ok((stream, Some(Session { key, send_seq: 0, recv_seq: 0 })))
        } else {
            Ok((stream, None))
        }
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
            let (stream, sess) = guard.as_mut().expect("just set");
            let io: anyhow::Result<SignerResponse> = (|| {
                // Cliente: envía C2S, recibe S2C (con el MAC de sesión si hay token).
                send_frame(stream, &req_bytes, sess.as_mut(), DIR_C2S)?;
                let resp = recv_frame(stream, sess.as_mut(), DIR_S2C)?;
                Ok(borsh::from_slice::<SignerResponse>(&resp)?)
            })();
            match io {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    // Conexión muerta / MAC fallido: descartarla y (si queda intento)
                    // reconectar con una sesión fresca.
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
    fn sign_peer_vote(&self, vertex_bytes: &[u8], digest: &[u8; 32]) -> anyhow::Result<MultiSignature> {
        Self::signature_from(self.request(&SignerRequest::SignPeerVote { vertex_bytes: vertex_bytes.to_vec(), digest: *digest })?)
    }
    fn sign_raw(&self, msg: &[u8]) -> anyhow::Result<MultiSignature> {
        Self::signature_from(self.request(&SignerRequest::SignRaw { msg: msg.to_vec() })?)
    }
    fn sign_checkpoint(&self, chain_id: &[u8; 32], round: u64, merkle_root: &[u8; 32]) -> anyhow::Result<MultiSignature> {
        Self::signature_from(self.request(&SignerRequest::SignCheckpoint { chain_id: *chain_id, round, merkle_root: *merkle_root })?)
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

/// Sirve pedidos de firma sobre `listener` (TCP o UDS), sosteniendo `keypair` y
/// aplicando `guard` a los auto-votos. Si `auth_token` es `Some`, cada conexión
/// DEBE pasar el challenge-response antes de que se sirva ningún pedido (#4.2).
/// Bloqueante: una conexión por vez en un bucle (un nodo mantiene una sola
/// conexión persistente; el volumen es ~una firma por ronda).
pub fn serve(
    keypair: Keypair,
    listener: SignerListener,
    guard: Arc<Mutex<DoubleSignGuard>>,
    auth_token: Option<Vec<u8>>,
) {
    loop {
        match listener.accept() {
            Ok(mut s) => {
                s.configure(IO_TIMEOUT);
                let peer = s.peer_desc();
                tracing::info!("signer: connection from {peer}");
                if let Err(e) = handle_conn(&mut s, &keypair, &guard, auth_token.as_deref()) {
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

fn handle_conn(
    stream: &mut SignerStream,
    keypair: &Keypair,
    guard: &Arc<Mutex<DoubleSignGuard>>,
    auth_token: Option<&[u8]>,
) -> anyhow::Result<()> {
    // #4.2 — Handshake de auth MUTUO PRIMERO: el servidor habla (en claro). Si
    // corremos con token, el cliente debe probar que lo conoce ANTES de que
    // firmemos nada, y desde ahí el canal queda con binding por-frame.
    let auth_required = auth_token.is_some();
    let server_nonce = fresh_nonce()?;
    write_frame(
        stream,
        &borsh::to_vec(&AuthChallenge { proto_version: PROTO_VERSION, auth_required, nonce: server_nonce })?,
    )?;
    let mut sess: Option<Session> = None;
    if let Some(token) = auth_token {
        let resp_bytes = match read_frame(stream) {
            Ok(b) => b,
            Err(_) => return Ok(()), // el cliente no completó el handshake → cerrar
        };
        let resp: AuthResponse = borsh::from_slice(&resp_bytes)
            .map_err(|e| anyhow::anyhow!("malformed AuthResponse: {e}"))?;
        let expected = auth_tag(token, &server_nonce, &resp.client_nonce);
        if !ct_eq(&resp.tag, &expected) {
            tracing::warn!("signer: client authentication FAILED — closing without signing");
            return Ok(()); // cerrar sin firmar; no se sirve ningún pedido
        }
        let key = derive_session_key(token, &server_nonce, &resp.client_nonce);
        sess = Some(Session { key, send_seq: 0, recv_seq: 0 });
        tracing::info!("signer: client authenticated (channel bound)");
    }
    loop {
        // Servidor: recibe C2S, envía S2C (con el MAC de sesión si hay token). Un
        // frame alterado/inyectado/reordenado por un atacante on-path se rechaza.
        let req_bytes = match recv_frame(stream, sess.as_mut(), DIR_C2S) {
            Ok(b) => b,
            Err(e) => {
                // Un fallo de MAC (no un cierre limpio) es un ataque/corrupción:
                // logueá y cerrá — no sirvas ningún pedido más en esta conexión.
                if sess.is_some() {
                    tracing::warn!("signer: closing connection: {e}");
                }
                return Ok(());
            }
        };
        let req = borsh::from_slice::<SignerRequest>(&req_bytes)
            .map_err(|e| anyhow::anyhow!("malformed request: {e}"))?;
        let resp = respond(&req, keypair, guard);
        send_frame(stream, &borsh::to_vec(&resp)?, sess.as_mut(), DIR_S2C)?;
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
        SignerRequest::SignPeerVote { vertex_bytes, digest } => {
            // GUARDIA DE AUTORÍA (#4, auditoría v8.6.13 — cierra el bypass de
            // auto-equivocación): un voto de "peer" DEBE ser sobre el vértice de
            // OTRO validador. Deserializamos el vértice, recomputamos su digest
            // (debe coincidir con el pedido — si no, un digest arbitrario firmado
            // no atado al vértice), y REHUSAMOS si el autor es NUESTRA propia clave
            // — un auto-voto DEBE ir por `SignOwnVote`, que sí está guardado por la
            // `DoubleSignGuard`. Sin esto, un proceso de nodo comprometido podía
            // enrutar su SEGUNDO vértice propio de una ronda por aquí y obtener una
            // firma de voto sobre él → evidencia de auto-equivocación slasheable,
            // derrotando la promesa central del firmante remoto.
            let vertex = match qchain_core::dag::Vertex::try_from_slice(vertex_bytes) {
                Ok(v) => v,
                Err(e) => {
                    let reason = format!("refusing SignPeerVote: malformed vertex bytes: {e}");
                    tracing::error!("signer: {reason}");
                    return SignerResponse::Refused(reason);
                }
            };
            if &vertex.digest() != digest {
                let reason = "refusing SignPeerVote: the vertex digest does not match the requested digest (a peer-vote must attest the given vertex, not an arbitrary digest)".to_string();
                tracing::error!("signer: {reason}");
                return SignerResponse::Refused(reason);
            }
            if vertex.author == keypair.public_key_bundle().to_address() {
                let reason = "DOUBLE-SIGN BLOCKED: refusing to peer-sign OUR OWN vertex — an own-authored vertex must be signed via SignOwnVote (double-sign guarded)".to_string();
                tracing::error!("signer: {reason}");
                return SignerResponse::Refused(reason);
            }
            match qchain_crypto::sign_vertex_vote(keypair, digest) {
                Ok(sig) => SignerResponse::Signature(sig),
                Err(e) => SignerResponse::Refused(format!("sign error: {e}")),
            }
        }
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
        SignerRequest::SignCheckpoint { chain_id, round, merkle_root } => {
            // #212 — atestación de state-sync bajo el dominio STATE_CHECKPOINT_V1,
            // NO un voto ni valor. Es una firma sobre un (chain_id, round, root)
            // público y determinista, sin poder de gasto — segura de servir. No
            // toca el allowlist de `sign_raw` (es una request estructurada aparte).
            match qchain_crypto::sign_state_checkpoint(keypair, chain_id, *round, merkle_root) {
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
        // Un VOTO DE PEER sobre el vértice de OTRO validador → OK (sin guardia).
        let peer_v = qchain_core::dag::Vertex {
            round: 3,
            author: Keypair::generate().unwrap().public_key_bundle().to_address(),
            batch_digests: vec![],
            parents: vec![],
        };
        assert!(matches!(
            respond(&SignerRequest::SignPeerVote { vertex_bytes: borsh::to_vec(&peer_v).unwrap(), digest: peer_v.digest() }, &kp, &g),
            SignerResponse::Signature(_)
        ));
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
        std::thread::spawn(move || serve(kp, SignerListener::Tcp(listener), g, None));

        let client = RemoteSigner::connect(&addr).unwrap();
        assert_eq!(client.bundle().to_address(), expected_bundle.to_address());
        let digest = [42u8; 32];
        let sig = client.sign_own_vote(1, &digest).unwrap();
        assert!(qchain_crypto::verify_vertex_vote(&expected_bundle, &digest, &sig), "la firma del firmante remoto verifica bajo el dominio de voto");
        // Un peer-vote sobre el vértice de OTRO validador también funciona.
        let peer_v = qchain_core::dag::Vertex {
            round: 1,
            author: Keypair::generate().unwrap().public_key_bundle().to_address(),
            batch_digests: vec![],
            parents: vec![],
        };
        let pd = peer_v.digest();
        let sig2 = client.sign_peer_vote(&borsh::to_vec(&peer_v).unwrap(), &pd).unwrap();
        assert!(qchain_crypto::verify_vertex_vote(&expected_bundle, &pd, &sig2));

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// #4 (auditoría v8.6.13) — el firmante remoto verifica la AUTORÍA de un
    /// peer-vote: un nodo comprometido NO puede enrutar su PROPIO segundo vértice
    /// por `SignPeerVote` para auto-equivocar (el bypass que dejaba abierto que la
    /// `DoubleSignGuard` sólo cubriera `SignOwnVote`). El daemon deserializa el
    /// vértice, recomputa el digest, y rehúsa si el autor es la propia clave o si
    /// el digest no ata al vértice; un vértice de OTRO validador se firma normal.
    #[test]
    fn sign_peer_vote_refuses_our_own_vertex_closing_the_self_equivocation_bypass() {
        let tmp = std::env::temp_dir().join(format!("qrs-peerauthor-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let kp = Keypair::generate().unwrap();
        let my_addr = kp.public_key_bundle().to_address();
        let g = guard(&tmp);

        // Un vértice PROPIO (autor == nuestra clave) enrutado por SignPeerVote → RECHAZADO.
        let own_v = qchain_core::dag::Vertex { round: 7, author: my_addr, batch_digests: vec![], parents: vec![] };
        assert!(
            matches!(
                respond(&SignerRequest::SignPeerVote { vertex_bytes: borsh::to_vec(&own_v).unwrap(), digest: own_v.digest() }, &kp, &g),
                SignerResponse::Refused(_)
            ),
            "a compromised node must NOT be able to peer-sign its OWN vertex (self-equivocation bypass)"
        );
        // Un vértice de OTRO validador → FIRMADO.
        let peer_v = qchain_core::dag::Vertex { round: 7, author: Keypair::generate().unwrap().public_key_bundle().to_address(), batch_digests: vec![], parents: vec![] };
        assert!(
            matches!(
                respond(&SignerRequest::SignPeerVote { vertex_bytes: borsh::to_vec(&peer_v).unwrap(), digest: peer_v.digest() }, &kp, &g),
                SignerResponse::Signature(_)
            ),
            "a vote over another validator's vertex must be signed"
        );
        // Un digest que NO ata al vértice pasado → RECHAZADO (no se firma un digest arbitrario).
        assert!(
            matches!(
                respond(&SignerRequest::SignPeerVote { vertex_bytes: borsh::to_vec(&peer_v).unwrap(), digest: [9u8; 32] }, &kp, &g),
                SignerResponse::Refused(_)
            ),
            "the requested digest must match the passed vertex; an arbitrary digest is refused"
        );
        // Bytes de vértice malformados → RECHAZADO (sin panic).
        assert!(
            matches!(
                respond(&SignerRequest::SignPeerVote { vertex_bytes: vec![0xff; 3], digest: [9u8; 32] }, &kp, &g),
                SignerResponse::Refused(_)
            ),
            "malformed vertex bytes must be refused, not panic"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// El prefix-MAC del challenge-response es determinista, sensible al token y
    /// al nonce; la comparación en tiempo constante acepta iguales y rechaza
    /// distintos y longitudes distintas.
    #[test]
    fn auth_tag_is_deterministic_token_and_nonce_sensitive() {
        let tok_a = b"shared-secret-A".to_vec();
        let tok_b = b"shared-secret-B".to_vec();
        let ns = [1u8; 32];
        let ns2 = [2u8; 32];
        let nc = [9u8; 32];
        let nc2 = [8u8; 32];
        assert_eq!(auth_tag(&tok_a, &ns, &nc), auth_tag(&tok_a, &ns, &nc), "determinista");
        assert_ne!(auth_tag(&tok_a, &ns, &nc), auth_tag(&tok_b, &ns, &nc), "sensible al token");
        assert_ne!(auth_tag(&tok_a, &ns, &nc), auth_tag(&tok_a, &ns2, &nc), "sensible al nonce del servidor");
        assert_ne!(auth_tag(&tok_a, &ns, &nc), auth_tag(&tok_a, &ns, &nc2), "sensible al nonce del cliente");
        // La longitud del token se prefija → dos tokens con un byte-boundary
        // ambiguo NO colisionan.
        assert_ne!(auth_tag(b"ab", &ns, &nc), auth_tag(b"a", &ns, &nc));
        let t = auth_tag(&tok_a, &ns, &nc);
        assert!(ct_eq(&t, &t));
        assert!(!ct_eq(&t, &auth_tag(&tok_b, &ns, &nc)));
        assert!(!ct_eq(&t, &t[..31])); // longitud distinta
        // La clave de sesión también depende del token + ambos nonces.
        let k = derive_session_key(&tok_a, &ns, &nc);
        assert_eq!(k, derive_session_key(&tok_a, &ns, &nc));
        assert_ne!(k, derive_session_key(&tok_b, &ns, &nc));
        assert_ne!(k, derive_session_key(&tok_a, &ns2, &nc));
        assert_ne!(k, derive_session_key(&tok_a, &ns, &nc2));
        // El dominio separa el tag de auth de la clave de sesión (mismos inputs).
        assert_ne!(auth_tag(&tok_a, &ns, &nc).to_vec(), k.to_vec());
    }

    /// #4.2 v3 — binding de canal: el MAC por-frame depende de la clave de sesión,
    /// la dirección y el seq; un frame alterado, reflejado (dirección cambiada) o
    /// reordenado (seq cambiado) NO verifica → un atacante on-path sin el token no
    /// puede inyectar/alterar/reordenar sobre un enlace cross-host.
    #[test]
    fn per_frame_session_mac_rejects_tamper_reflection_and_reorder() {
        let key = derive_session_key(b"tok", &[1u8; 32], &[2u8; 32]);
        let payload = b"a signing request";
        let good = frame_mac(&key, DIR_C2S, 0, payload);
        assert!(ct_eq(&good, &frame_mac(&key, DIR_C2S, 0, payload)), "determinista");
        // Payload alterado → MAC distinto.
        assert!(!ct_eq(&good, &frame_mac(&key, DIR_C2S, 0, b"a signing requesX")));
        // Dirección reflejada (C2S ↔ S2C) → MAC distinto (anti-reflexión).
        assert!(!ct_eq(&good, &frame_mac(&key, DIR_S2C, 0, payload)));
        // Seq reordenado → MAC distinto (anti-replay/reorder).
        assert!(!ct_eq(&good, &frame_mac(&key, DIR_C2S, 1, payload)));
        // Clave (token) distinta → MAC distinto.
        assert!(!ct_eq(&good, &frame_mac(&derive_session_key(b"other", &[1u8; 32], &[2u8; 32]), DIR_C2S, 0, payload)));

        // Round-trip real de send/recv sobre un buffer en memoria: lo que un
        // sender MAC-ea, el receiver con la MISMA clave/dirección/seq lo acepta,
        // y un bit-flip del byte de wire lo rechaza.
        let mut tx = Session { key, send_seq: 0, recv_seq: 0 };
        let mut buf: Vec<u8> = Vec::new();
        send_frame(&mut buf, payload, Some(&mut tx), DIR_C2S).unwrap();
        // Receiver correcto.
        let mut rx = Session { key, send_seq: 0, recv_seq: 0 };
        let got = recv_frame(&mut &buf[..], Some(&mut rx), DIR_C2S).unwrap();
        assert_eq!(got, payload);
        // Un bit-flip en el frame de wire → recv rechaza.
        let mut tampered = buf.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let mut rx2 = Session { key, send_seq: 0, recv_seq: 0 };
        assert!(recv_frame(&mut &tampered[..], Some(&mut rx2), DIR_C2S).is_err(), "un frame alterado se rechaza");
        // El receiver esperando la dirección equivocada (reflexión) rechaza.
        let mut rx3 = Session { key, send_seq: 0, recv_seq: 0 };
        assert!(recv_frame(&mut &buf[..], Some(&mut rx3), DIR_S2C).is_err(), "un frame reflejado se rechaza");
    }

    /// #4.2 (auditoría v8.6.13) — el socket AUTENTICA al cliente por
    /// challenge-response de token: con el token correcto el cliente obtiene el
    /// bundle y una firma que verifica; un token INCORRECTO o AUSENTE es rechazado
    /// ANTES de firmar nada. Cierra "cualquier proceso local puede pedir firmas
    /// sin autenticarse".
    #[test]
    fn a_client_without_the_right_token_cannot_get_any_signature() {
        use qchain_crypto::Signer;
        let tmp = std::env::temp_dir().join(format!("qrs-auth-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let kp = Keypair::generate().unwrap();
        let expected = kp.public_key_bundle();
        let token = b"the-pre-shared-signer-token".to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let g = guard(&tmp);
        let tok_srv = token.clone();
        std::thread::spawn(move || serve(kp, SignerListener::Tcp(listener), g, Some(tok_srv)));

        // (a) Token CORRECTO → autentica, obtiene bundle y firma un voto que verifica.
        let ok = RemoteSigner::connect_with_token(&addr, Some(token.clone())).unwrap();
        assert_eq!(ok.bundle().to_address(), expected.to_address());
        let digest = [3u8; 32];
        let sig = ok.sign_own_vote(1, &digest).unwrap();
        assert!(qchain_crypto::verify_vertex_vote(&expected, &digest, &sig));

        // (b) Token INCORRECTO → la conexión se cierra sin servir; GetBundle falla.
        assert!(
            RemoteSigner::connect_with_token(&addr, Some(b"wrong-token".to_vec())).is_err(),
            "a wrong token must not authenticate — no signing oracle"
        );
        // (c) SIN token cuando el servidor lo EXIGE → falla (no puede responder el challenge).
        assert!(
            RemoteSigner::connect_with_token(&addr, None).is_err(),
            "a client with no token must be rejected when the daemon requires auth"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// #4.2 — el transporte por SOCKET UNIX funciona de punta a punta con token:
    /// un peer-vote firma correctamente sobre el UDS (aislamiento de permisos del
    /// SO + challenge-response encima).
    #[cfg(unix)]
    #[test]
    fn client_server_roundtrip_over_a_unix_socket_with_token() {
        use qchain_crypto::Signer;
        let tmp = std::env::temp_dir().join(format!("qrs-uds-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let sock = tmp.join("signer.sock");
        let _ = std::fs::remove_file(&sock);
        let kp = Keypair::generate().unwrap();
        let expected = kp.public_key_bundle();
        let token = b"uds-token".to_vec();
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let g = guard(&tmp);
        let tok_srv = token.clone();
        std::thread::spawn(move || serve(kp, SignerListener::Unix(listener), g, Some(tok_srv)));

        let endpoint = format!("unix:{}", sock.display());
        let client = RemoteSigner::connect_with_token(&endpoint, Some(token)).unwrap();
        assert_eq!(client.bundle().to_address(), expected.to_address());
        let peer_v = qchain_core::dag::Vertex {
            round: 4,
            author: Keypair::generate().unwrap().public_key_bundle().to_address(),
            batch_digests: vec![],
            parents: vec![],
        };
        let pd = peer_v.digest();
        let sig = client.sign_peer_vote(&borsh::to_vec(&peer_v).unwrap(), &pd).unwrap();
        assert!(qchain_crypto::verify_vertex_vote(&expected, &pd, &sig));
        // Un endpoint UDS se reconoce como tal; un host:puerto no.
        assert_eq!(unix_endpoint_path(&endpoint), Some(sock.to_str().unwrap()));
        assert_eq!(unix_endpoint_path("127.0.0.1:9200"), None);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
