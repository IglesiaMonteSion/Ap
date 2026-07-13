//! Password-encrypted wallet backups ("keystore"), same idea as Ethereum's
//! keystore V3: the raw key file is encrypted with a key derived from the
//! user's password, so the downloaded backup is useless to anyone who doesn't
//! know the password. A real second layer of security on the `.json` backup.
//!
//! - KDF: Argon2id (memory-hard, deliberately slow - resists brute force).
//! - Cipher: AES-256-GCM (authenticated - a wrong password / tampered file
//!   fails to decrypt instead of silently returning garbage).
//!
//! Done server-side here so it works over plain HTTP on today's testnet
//! deployment; in the planned browser-WASM phase this moves client-side
//! (WebCrypto) so the password never leaves the device. Note: this protects
//! the *file that leaves the server*; in the current custodial model the
//! server still holds the raw key on disk - the non-custodial WASM phase is
//! what removes that.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use base64::Engine;
use rand::RngCore;
use serde_json::{json, Value};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn ub64(s: &str) -> anyhow::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| anyhow::anyhow!("base64 inválido: {e}"))
}

/// Derive a 32-byte AES key from the password and salt via Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("derivación de clave falló: {e}"))?;
    Ok(key)
}

/// Encrypt a raw keypair-file's contents under `password`, returning a
/// self-describing keystore JSON (salt + nonce + ciphertext + params).
pub fn encrypt(plaintext: &str, password: &str) -> anyhow::Result<String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("cifrado falló: {e}"))?;
    Ok(json!({
        "qchain_keystore": 1,
        "kdf": "argon2id",
        "cipher": "aes-256-gcm",
        "salt": b64(&salt),
        "nonce": b64(&nonce),
        "ciphertext": b64(&ct),
    })
    .to_string())
}

/// Decrypt a keystore JSON back to the raw keypair-file contents. A wrong
/// password (or a tampered file) fails here rather than returning garbage,
/// because AES-GCM is authenticated.
pub fn decrypt(obj: &Value, password: &str) -> anyhow::Result<String> {
    let get = |k: &str| -> anyhow::Result<Vec<u8>> {
        ub64(obj[k].as_str().ok_or_else(|| anyhow::anyhow!("keystore sin campo '{k}'"))?)
    };
    let salt = get("salt")?;
    let nonce = get("nonce")?;
    let ct = get("ciphertext")?;
    if nonce.len() != 12 {
        anyhow::bail!("nonce de tamaño inválido");
    }
    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
        .map_err(|_| anyhow::anyhow!("contraseña incorrecta o archivo dañado"))?;
    String::from_utf8(pt).map_err(|_| anyhow::anyhow!("el contenido descifrado no es texto válido"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_with_the_right_password() {
        let secret = r#"{"key":"super-secret-keypair"}"#;
        let ks = encrypt(secret, "clave-fuerte-123").unwrap();
        let obj: Value = serde_json::from_str(&ks).unwrap();
        assert_eq!(obj["qchain_keystore"], 1);
        assert!(!ks.contains("super-secret")); // el secreto no aparece en claro
        let back = decrypt(&obj, "clave-fuerte-123").unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let ks = encrypt("secreto", "correcta").unwrap();
        let obj: Value = serde_json::from_str(&ks).unwrap();
        assert!(decrypt(&obj, "incorrecta").is_err());
    }
}
