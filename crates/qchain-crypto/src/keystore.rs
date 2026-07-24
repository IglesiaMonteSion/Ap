//! KM#8 — **Keystore V2: cifrado en reposo del keypair del validador/operador.**
//!
//! El `keypair.json` de disco (`write_keypair_file`) guarda las claves secretas
//! CRUDAS en texto plano (0600). Este módulo envuelve ese MISMO blob canónico
//! (`keypair_to_canonical_bytes`) en un **keystore cifrado**, con la cadena que
//! el auditor pidió (KM#8):
//!
//!   **Argon2id → HKDF-SHA3 → XChaCha20-Poly1305**
//!
//! - **Argon2id** (memory-hard, GPU/ASIC-resistente): deriva la clave MAESTRA de
//!   la passphrase + un salt aleatorio. Es la fase de EXTRACT — su salida ya es
//!   un PRK uniforme. Los params (m/t/p) se validan **AL LEER** contra un rango
//!   documentado ANTES de correr Argon2 (anti-OOM: un keystore hostil con m de
//!   varios GiB colgaría/OOMearía al cargador — la lección #10 de la wallet).
//! - **HKDF-SHA3** (expand domain-separada, sin dependencia nueva): expande
//!   sub-claves de la maestra con `SHA3-256(KEYSTORE_HKDF_V2 ‖ master ‖ label)`.
//!   SHA3 es resistente a extensión de longitud (postura prefix-MAC de FIPS 202),
//!   así que es un PRF-expand sólido para un PRK uniforme — el MISMO patrón que
//!   `generate_from_seed` ya usa. `b"enc"` cifra el keystore; `b"role/..."`
//!   deriva claves por ROL de forma jerárquica sin re-correr Argon2.
//! - **XChaCha20-Poly1305** (AEAD, nonce aleatorio de 24 B): cifra el blob con la
//!   sub-clave `enc`. El nonce de 24 B es aleatorio por cifrado → sin riesgo de
//!   reúso de nonce aunque se re-cifre con la misma passphrase.
//!
//! **Anti-rollback:** un contador monotónico `counter` va AUTENTICADO en el AAD
//! del AEAD (no se puede bajar sin romper el tag), y una `RollbackGuard`
//! persistida rechaza cargar un keystore cuyo contador sea MENOR que el más alto
//! ya visto — cerrando que un atacante que guardó una copia vieja del archivo la
//! re-inserte tras una rotación.
//!
//! **Node-only** (`#[cfg(not(target_arch = "wasm32"))]`): la wallet del navegador
//! tiene su propio cifrado (Argon2id + AES-GCM en JS). **Opt-in y compatible hacia
//! atrás:** un `keypair.json` en texto plano sigue cargando
//! (`read_keypair_or_keystore`).

use crate::{domains, keypair_from_canonical_bytes, keypair_to_canonical_bytes, Keypair};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

/// Magic que identifica un archivo keystore V2 (para distinguirlo de un
/// `keypair.json` en texto plano, que es un array JSON de bytes sin este campo).
pub const KEYSTORE_MAGIC: &str = "qchain-keystore-v2";
/// Versión del formato del keystore.
pub const KEYSTORE_VERSION: u16 = 2;

// Cotas de los parámetros de Argon2, validadas AL LEER (anti-OOM — la lección #10
// de la wallet: un blob hostil con m de varios GiB / t enorme colgaría u OOMearía
// al cargador). Mismo rango que `decryptSeed` de la wallet ya fuerza.
/// Mínimo de memoria de Argon2 (KiB).
pub const MIN_M_COST_KIB: u32 = 8;
/// Máximo de memoria de Argon2 (KiB) = 1 GiB.
pub const MAX_M_COST_KIB: u32 = 1_048_576;
/// Mínimo de pasadas (time cost).
pub const MIN_T_COST: u32 = 1;
/// Máximo de pasadas.
pub const MAX_T_COST: u32 = 24;
/// Mínimo de lanes (parallelism).
pub const MIN_P_COST: u32 = 1;
/// Máximo de lanes.
pub const MAX_P_COST: u32 = 16;

// Defaults OWASP-2023 para cifrar (los MISMOS que usa la wallet custodial/no-custodial).
/// Memoria por defecto = 19 MiB.
pub const DEFAULT_M_COST_KIB: u32 = 19_456;
/// Pasadas por defecto.
pub const DEFAULT_T_COST: u32 = 2;
/// Lanes por defecto.
pub const DEFAULT_P_COST: u32 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20-Poly1305

/// Parámetros de Argon2id para cifrar un keystore.
#[derive(Clone, Copy, Debug)]
pub struct KeystoreParams {
    /// Memoria en KiB.
    pub m_cost_kib: u32,
    /// Pasadas.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl Default for KeystoreParams {
    fn default() -> Self {
        Self { m_cost_kib: DEFAULT_M_COST_KIB, t_cost: DEFAULT_T_COST, p_cost: DEFAULT_P_COST }
    }
}

impl KeystoreParams {
    /// Valida las cotas ANTES de correr Argon2 (anti-OOM). Un keystore cuyo
    /// header declara params fuera de rango se RECHAZA sin gastar memoria.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&self.m_cost_kib) {
            anyhow::bail!(
                "argon2 m_cost {} KiB out of bounds [{}..={}]",
                self.m_cost_kib,
                MIN_M_COST_KIB,
                MAX_M_COST_KIB
            );
        }
        if !(MIN_T_COST..=MAX_T_COST).contains(&self.t_cost) {
            anyhow::bail!("argon2 t_cost {} out of bounds [{}..={}]", self.t_cost, MIN_T_COST, MAX_T_COST);
        }
        if !(MIN_P_COST..=MAX_P_COST).contains(&self.p_cost) {
            anyhow::bail!("argon2 p_cost {} out of bounds [{}..={}]", self.p_cost, MIN_P_COST, MAX_P_COST);
        }
        Ok(())
    }
}

/// El keystore V2 en disco (serde JSON). El `ct` cifra el blob canónico del
/// keypair; el `counter`/params/salt/nonce están AUTENTICADOS en el AAD del AEAD
/// (un tamper de cualquiera de ellos rompe el tag).
#[derive(Clone, Serialize, Deserialize)]
pub struct KeystoreV2 {
    /// Debe ser `KEYSTORE_MAGIC`.
    pub magic: String,
    /// Debe ser `KEYSTORE_VERSION`.
    pub version: u16,
    /// KDF usada — siempre `"argon2id"`.
    pub kdf: String,
    /// Memoria de Argon2 (KiB).
    pub m_cost_kib: u32,
    /// Pasadas de Argon2.
    pub t_cost: u32,
    /// Lanes de Argon2.
    pub p_cost: u32,
    /// Salt aleatorio de 16 B.
    pub salt: Vec<u8>,
    /// Contador monotónico anti-rollback (autenticado en AAD).
    pub counter: u64,
    /// Nonce XChaCha20-Poly1305 de 24 B (aleatorio por cifrado).
    pub nonce: Vec<u8>,
    /// Ciphertext + tag sobre el blob canónico del keypair.
    pub ct: Vec<u8>,
}

impl KeystoreV2 {
    fn params(&self) -> KeystoreParams {
        KeystoreParams { m_cost_kib: self.m_cost_kib, t_cost: self.t_cost, p_cost: self.p_cost }
    }
}

/// Derivación de una sub-clave por HKDF-SHA3 (expand domain-separada) desde la
/// clave MAESTRA (la salida uniforme de Argon2id). SHA3 es resistente a extensión
/// de longitud, así que `SHA3-256(dominio ‖ master ‖ len(label) ‖ label)` es un
/// PRF-expand sólido para un PRK uniforme — el MISMO patrón que `generate_from_seed`.
/// `b"enc"` es la clave de cifrado del keystore; usar etiquetas distintas
/// (`b"role/consensus"`, `b"role/operator"`, …) da claves independientes por rol,
/// jerárquicas, sin re-correr Argon2.
pub fn derive_subkey(master: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(domains::KEYSTORE_HKDF_V2);
    h.update(master);
    h.update((label.len() as u32).to_le_bytes());
    h.update(label);
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Deriva una sub-clave POR ROL de forma jerárquica (KM#8 — HKDF jerárquico).
/// `derive_role_subkey(master, "consensus")` ≠ `..("operator")` ≠ la clave `enc`.
pub fn derive_role_subkey(master: &[u8; 32], role: &str) -> [u8; 32] {
    let label = format!("role/{role}");
    derive_subkey(master, label.as_bytes())
}

/// Corre Argon2id (tras validar las cotas) para derivar la clave maestra de 32 B.
fn derive_master(passphrase: &[u8], salt: &[u8], params: KeystoreParams) -> anyhow::Result<[u8; 32]> {
    params.validate()?; // ANTES de asignar memoria (anti-OOM).
    let a2_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("bad argon2 params: {e}"))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, a2_params);
    let mut master = [0u8; 32];
    a2.hash_password_into(passphrase, salt, &mut master)
        .map_err(|e| anyhow::anyhow!("argon2id derivation failed: {e}"))?;
    Ok(master)
}

/// AAD autenticada por el AEAD: TODOS los campos del header (magic/version/params/
/// salt/counter/nonce), en un orden fijo. Un tamper de cualquiera rompe el tag —
/// esto es lo que hace inmutables el `counter` (anti-rollback) y los params de
/// Argon2 (anti-downgrade a un KDF débil).
fn aad_bytes(version: u16, params: KeystoreParams, salt: &[u8], counter: u64, nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(KEYSTORE_MAGIC.len() + 2 + 12 + salt.len() + 8 + nonce.len());
    aad.extend_from_slice(KEYSTORE_MAGIC.as_bytes());
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(&params.m_cost_kib.to_le_bytes());
    aad.extend_from_slice(&params.t_cost.to_le_bytes());
    aad.extend_from_slice(&params.p_cost.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(&counter.to_le_bytes());
    aad.extend_from_slice(nonce);
    aad
}

/// Cifra un `Keypair` a un keystore V2 con la `passphrase` dada. `counter` es el
/// contador monotónico anti-rollback (el que cifra lo incrementa en cada
/// re-cifrado; un keystore recién creado usa 1).
pub fn encrypt_keystore(
    keypair: &Keypair,
    passphrase: &[u8],
    params: KeystoreParams,
    counter: u64,
) -> anyhow::Result<KeystoreV2> {
    if passphrase.is_empty() {
        anyhow::bail!("refusing to encrypt with an empty passphrase");
    }
    params.validate()?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow::anyhow!("cannot get salt randomness: {e}"))?;
    getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("cannot get nonce randomness: {e}"))?;

    let mut master = derive_master(passphrase, &salt, params)?;
    let mut enc_key = derive_subkey(&master, b"enc");
    master.zeroize();

    let mut plaintext = keypair_to_canonical_bytes(keypair);
    let aad = aad_bytes(KEYSTORE_VERSION, params, &salt, counter, &nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&enc_key));
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| anyhow::anyhow!("keystore encryption failed"))?;
    enc_key.zeroize();
    plaintext.zeroize();

    Ok(KeystoreV2 {
        magic: KEYSTORE_MAGIC.to_string(),
        version: KEYSTORE_VERSION,
        kdf: "argon2id".to_string(),
        m_cost_kib: params.m_cost_kib,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
        salt: salt.to_vec(),
        counter,
        nonce: nonce.to_vec(),
        ct,
    })
}

/// Descifra un keystore V2 con la `passphrase`. Valida el formato + las cotas de
/// Argon2 ANTES de derivar (anti-OOM), reconstruye la AAD (así un tamper del
/// counter/params/salt/nonce rompe el tag), y devuelve el `Keypair`.
pub fn decrypt_keystore(ks: &KeystoreV2, passphrase: &[u8]) -> anyhow::Result<Keypair> {
    if ks.magic != KEYSTORE_MAGIC {
        anyhow::bail!("not a qchain keystore v2 (bad magic)");
    }
    if ks.version != KEYSTORE_VERSION {
        anyhow::bail!("unsupported keystore version {}", ks.version);
    }
    if ks.kdf != "argon2id" {
        anyhow::bail!("unsupported keystore kdf {}", ks.kdf);
    }
    if ks.salt.len() != SALT_LEN {
        anyhow::bail!("bad keystore salt length {} (expected {SALT_LEN})", ks.salt.len());
    }
    if ks.nonce.len() != NONCE_LEN {
        anyhow::bail!("bad keystore nonce length {} (expected {NONCE_LEN})", ks.nonce.len());
    }
    let params = ks.params();
    params.validate()?; // ANTES de asignar la memoria de Argon2 (anti-OOM).

    let mut master = derive_master(passphrase, &ks.salt, params)?;
    let mut enc_key = derive_subkey(&master, b"enc");
    master.zeroize();

    let aad = aad_bytes(ks.version, params, &ks.salt, ks.counter, &ks.nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&enc_key));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&ks.nonce), Payload { msg: &ks.ct, aad: &aad })
        .map_err(|_| anyhow::anyhow!("keystore decryption failed — wrong passphrase or tampered file"))?;
    enc_key.zeroize();

    let keypair = keypair_from_canonical_bytes(&plaintext);
    let mut plaintext = plaintext;
    plaintext.zeroize();
    keypair
}

/// ¿El archivo en `path` es un keystore V2 cifrado (vs un `keypair.json` en texto
/// plano)? Un keystore es un objeto JSON con `"magic": "qchain-keystore-v2"`; un
/// keypair plano es un array JSON de bytes.
pub fn is_keystore_file(path: &std::path::Path) -> bool {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<KeystoreV2>(&bytes).map(|k| k.magic == KEYSTORE_MAGIC).unwrap_or(false),
        Err(_) => false,
    }
}

/// Lee el keystore V2 de `path`.
pub fn read_keystore_file(path: &std::path::Path) -> anyhow::Result<KeystoreV2> {
    let bytes = std::fs::read(path)?;
    let ks: KeystoreV2 = serde_json::from_slice(&bytes)?;
    if ks.magic != KEYSTORE_MAGIC {
        anyhow::bail!("not a qchain keystore v2 file: {}", path.display());
    }
    Ok(ks)
}

/// Escribe un keystore V2 a disco 0600 (no lleva secretos en claro, pero el
/// archivo autoriza descifrar con la passphrase → mismo cuidado de permisos).
pub fn write_keystore_file(ks: &KeystoreV2, path: &std::path::Path) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(ks)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(&bytes)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &bytes)?;
    }
    Ok(())
}

/// **Carga un keypair de un archivo, auto-detectando keystore V2 vs texto plano**
/// (compatibilidad hacia atrás, KM#8). Si el archivo es un keystore cifrado exige
/// la `passphrase` (error claro si falta); si es un `keypair.json` en texto plano
/// lo lee directo (la passphrase se ignora). Es el punto de entrada que reemplaza
/// a `read_keypair_file` en los cargadores (daemon/nodo) sin romper nada.
pub fn read_keypair_or_keystore(path: &std::path::Path, passphrase: Option<&[u8]>) -> anyhow::Result<Keypair> {
    if is_keystore_file(path) {
        let ks = read_keystore_file(path)?;
        let pass = passphrase
            .ok_or_else(|| anyhow::anyhow!("{} is an encrypted keystore but no passphrase was provided", path.display()))?;
        decrypt_keystore(&ks, pass)
    } else {
        crate::read_keypair_file(path)
    }
}

/// Lee el `counter` de un keystore sin descifrarlo (para la RollbackGuard). No
/// autentica el counter — el AEAD lo hace al descifrar; esto es sólo para la
/// comparación monotónica ANTES de gastar Argon2.
pub fn keystore_counter(path: &std::path::Path) -> anyhow::Result<u64> {
    Ok(read_keystore_file(path)?.counter)
}

/// **Guardia anti-rollback del keystore.** Persiste el `counter` más alto visto;
/// rechaza cargar un keystore cuyo contador sea ESTRICTAMENTE menor (un atacante
/// que guardó una copia vieja del archivo no puede re-insertarla tras una
/// rotación). Persiste con fsync + rename atómico (crash-safe), misma postura que
/// la `DoubleSignGuard` del firmante remoto.
pub struct RollbackGuard {
    path: std::path::PathBuf,
    highest: Option<u64>,
}

impl RollbackGuard {
    /// Carga la guardia desde `path` (un archivo con el counter en texto). Si no
    /// existe, arranca vacía (cualquier counter ≥ 0 es aceptable la primera vez).
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let highest = match std::fs::read_to_string(path) {
            Ok(s) => {
                let t = s.trim();
                if t.is_empty() {
                    None
                } else {
                    Some(t.parse::<u64>().map_err(|e| anyhow::anyhow!("corrupt rollback guard {}: {e}", path.display()))?)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(anyhow::anyhow!("cannot read rollback guard {}: {e}", path.display())),
        };
        Ok(Self { path: path.to_path_buf(), highest })
    }

    /// El counter más alto registrado (None si nunca se registró ninguno).
    pub fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Verifica que `counter` no sea un rollback (≥ el más alto visto) y, si es
    /// mayor, lo persiste como el nuevo tope. Un counter igual al tope es
    /// idempotente (recargar el MISMO keystore). Un counter menor se RECHAZA.
    pub fn check_and_record(&mut self, counter: u64) -> anyhow::Result<()> {
        if let Some(hi) = self.highest {
            if counter < hi {
                anyhow::bail!(
                    "keystore rollback detected: counter {counter} is lower than the highest seen {hi} — refusing to load an old keystore copy"
                );
            }
            if counter == hi {
                return Ok(()); // mismo keystore, idempotente.
            }
        }
        self.persist(counter)?;
        self.highest = Some(counter);
        Ok(())
    }

    /// Escribe el counter con fsync + rename atómico (crash-safe): un corte no
    /// puede dejar la guardia con menos memoria que el keystore ya aceptado.
    fn persist(&self, counter: u64) -> anyhow::Result<()> {
        let tmp = self.path.with_extension("tmp");
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(counter.to_string().as_bytes())?;
            f.sync_all()?; // fsync del archivo
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            std::fs::rename(&tmp, &self.path)?; // rename atómico
                                                // fsync del directorio para que el rename sea durable.
            if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all();
                }
            }
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, counter.to_string().as_bytes())?;
            std::fs::rename(&tmp, &self.path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify;

    // Params baratos para tests (no queremos 19 MiB × muchos tests). Siguen
    // dentro de las cotas válidas.
    fn cheap() -> KeystoreParams {
        KeystoreParams { m_cost_kib: 64, t_cost: 1, p_cost: 1 }
    }

    fn a_keypair() -> Keypair {
        // Semilla determinista → la clave es reproducible en el `pure` backend;
        // en `liboqs` usamos generate() (aleatoria) porque no hay keygen sembrada.
        #[cfg(feature = "liboqs")]
        {
            Keypair::generate().unwrap()
        }
        #[cfg(all(feature = "pure", not(feature = "liboqs")))]
        {
            Keypair::generate_from_seed(&[7u8; 32]).unwrap()
        }
    }

    #[test]
    fn keystore_roundtrip_recovers_the_exact_keypair() {
        let kp = a_keypair();
        let addr = kp.public_key_bundle().to_address();
        let msg = b"km8 keystore roundtrip";
        let sig = kp.sign(msg).unwrap();

        let ks = encrypt_keystore(&kp, b"correct horse battery staple", cheap(), 1).unwrap();
        let back = decrypt_keystore(&ks, b"correct horse battery staple").unwrap();

        // Misma dirección + la firma original verifica bajo el bundle recuperado.
        assert_eq!(back.public_key_bundle().to_address(), addr);
        assert!(verify(&back.public_key_bundle(), msg, &sig));
        // Y el keypair recuperado firma algo nuevo que verifica.
        let sig2 = back.sign(msg).unwrap();
        assert!(verify(&back.public_key_bundle(), msg, &sig2));
    }

    #[test]
    fn keystore_wrong_passphrase_is_rejected() {
        let kp = a_keypair();
        let ks = encrypt_keystore(&kp, b"right-pass", cheap(), 1).unwrap();
        assert!(decrypt_keystore(&ks, b"wrong-pass").is_err(), "a wrong passphrase must fail the AEAD tag");
    }

    #[test]
    fn keystore_tampered_ciphertext_is_rejected() {
        let kp = a_keypair();
        let mut ks = encrypt_keystore(&kp, b"pass", cheap(), 1).unwrap();
        ks.ct[0] ^= 0x01; // flip un byte del ciphertext
        assert!(decrypt_keystore(&ks, b"pass").is_err(), "a tampered ciphertext must fail the tag");
    }

    #[test]
    fn keystore_tampered_header_counter_and_params_are_rejected() {
        let kp = a_keypair();
        // El counter está en el AAD → bajarlo (rollback) rompe el tag.
        let mut ks = encrypt_keystore(&kp, b"pass", cheap(), 5).unwrap();
        ks.counter = 4;
        assert!(decrypt_keystore(&ks, b"pass").is_err(), "tampering the counter (authenticated in AAD) must fail");

        // Los params de Argon2 también están en el AAD → un downgrade rompe el tag.
        let mut ks2 = encrypt_keystore(&kp, b"pass", cheap(), 1).unwrap();
        ks2.t_cost = MIN_T_COST; // dentro de cotas pero != el original (cheap t=1 ya es min; usar m)
        ks2.m_cost_kib = MIN_M_COST_KIB;
        assert!(decrypt_keystore(&ks2, b"pass").is_err(), "downgrading the argon2 params (in AAD) must fail");
    }

    #[test]
    fn out_of_bounds_argon2_params_are_rejected_before_running() {
        let kp = a_keypair();
        let mut ks = encrypt_keystore(&kp, b"pass", cheap(), 1).unwrap();
        // Un keystore hostil declara 4 GiB de memoria → rechazado por la cota,
        // SIN correr Argon2 (anti-OOM).
        ks.m_cost_kib = MAX_M_COST_KIB + 1;
        match decrypt_keystore(&ks, b"pass") {
            Err(e) => assert!(e.to_string().contains("out of bounds"), "must reject out-of-bounds m_cost before Argon2, got: {e}"),
            Ok(_) => panic!("out-of-bounds m_cost must be rejected"),
        }

        // t_cost fuera de rango.
        let mut ks2 = encrypt_keystore(&kp, b"pass", cheap(), 1).unwrap();
        ks2.t_cost = MAX_T_COST + 1;
        assert!(decrypt_keystore(&ks2, b"pass").is_err());

        // p_cost = 0 (inválido).
        let mut ks3 = encrypt_keystore(&kp, b"pass", cheap(), 1).unwrap();
        ks3.p_cost = 0;
        assert!(decrypt_keystore(&ks3, b"pass").is_err());

        // Y encrypt con params fuera de rango también se rechaza.
        assert!(encrypt_keystore(&kp, b"pass", KeystoreParams { m_cost_kib: 1, t_cost: 1, p_cost: 1 }, 1).is_err());
        // Passphrase vacía se rechaza al cifrar.
        assert!(encrypt_keystore(&kp, b"", cheap(), 1).is_err());
    }

    #[test]
    fn derive_subkey_is_domain_separated_and_deterministic() {
        let master = [3u8; 32];
        let enc = derive_subkey(&master, b"enc");
        let enc2 = derive_subkey(&master, b"enc");
        assert_eq!(enc, enc2, "determinista para el mismo label");
        let consensus = derive_role_subkey(&master, "consensus");
        let operator = derive_role_subkey(&master, "operator");
        assert_ne!(enc, consensus, "enc != rol");
        assert_ne!(consensus, operator, "roles distintos dan claves distintas");
        // Una maestra distinta da claves distintas.
        assert_ne!(derive_subkey(&[4u8; 32], b"enc"), enc);
        // La derivación NO es un simple hash del label (el dominio + master están dentro).
        assert_ne!(consensus, derive_subkey(&master, b"role/operator"));
    }

    #[test]
    fn plaintext_keypair_and_keystore_are_distinguished() {
        let dir = std::env::temp_dir().join(format!("qchain-km8-detect-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let plain_path = dir.join("keypair.json");
        let ks_path = dir.join("keystore.json");

        let kp = a_keypair();
        let addr = kp.public_key_bundle().to_address();
        crate::write_keypair_file(&kp, &plain_path).unwrap();
        let ks = encrypt_keystore(&kp, b"pass", cheap(), 1).unwrap();
        write_keystore_file(&ks, &ks_path).unwrap();

        // Detección.
        assert!(!is_keystore_file(&plain_path), "plaintext keypair.json is NOT a keystore");
        assert!(is_keystore_file(&ks_path), "the keystore file IS detected");

        // read_keypair_or_keystore: plano sin passphrase OK (passphrase ignorada).
        let back_plain = read_keypair_or_keystore(&plain_path, None).unwrap();
        assert_eq!(back_plain.public_key_bundle().to_address(), addr);
        let back_plain2 = read_keypair_or_keystore(&plain_path, Some(b"ignored")).unwrap();
        assert_eq!(back_plain2.public_key_bundle().to_address(), addr);
        // keystore CON passphrase OK.
        let back_ks = read_keypair_or_keystore(&ks_path, Some(b"pass")).unwrap();
        assert_eq!(back_ks.public_key_bundle().to_address(), addr);
        // keystore SIN passphrase → error claro.
        match read_keypair_or_keystore(&ks_path, None) {
            Err(e) => assert!(e.to_string().contains("encrypted keystore"), "must ask for a passphrase, got: {e}"),
            Ok(_) => panic!("a keystore without a passphrase must error"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_guard_rejects_a_lower_counter_and_persists_the_high_water_mark() {
        let dir = std::env::temp_dir().join(format!("qchain-km8-guard-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let guard_path = dir.join("keystore.counter-guard");

        // Cargar counter 5 → registrado.
        let mut g = RollbackGuard::load(&guard_path).unwrap();
        assert_eq!(g.highest(), None);
        g.check_and_record(5).unwrap();
        assert_eq!(g.highest(), Some(5));
        // El mismo counter (5) es idempotente.
        g.check_and_record(5).unwrap();
        // Un counter menor (3) es RECHAZADO.
        assert!(g.check_and_record(3).is_err(), "a lower counter is a rollback");
        // Un counter mayor (6) se acepta y sube el tope.
        g.check_and_record(6).unwrap();
        assert_eq!(g.highest(), Some(6));

        // Persiste entre reinicios: una guardia recargada del disco recuerda 6.
        let mut g2 = RollbackGuard::load(&guard_path).unwrap();
        assert_eq!(g2.highest(), Some(6));
        assert!(g2.check_and_record(4).is_err(), "rollback survives a reload");
        g2.check_and_record(7).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }
}
