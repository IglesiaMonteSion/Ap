//! Known-Answer Tests (KAT) — tarea #189.
//!
//! Vectores OFICIALES donde se pueden fijar con certeza (SHA-3 / FIPS 202), y
//! pines de regresión deterministas para el resto (Ed25519 es determinista por
//! RFC 8032; ML-DSA/SLH-DSA keygen-desde-semilla es determinista en el backend
//! `pure`). Objetivo: atrapar un cambio de backend/encoding que rompa la
//! interoperabilidad en silencio. **Los vectores CAVP/ACVP completos de NIST
//! para ML-KEM/ML-DSA/SLH-DSA (megabytes) siguen pendientes — ver #189.**

use sha3::{Digest, Sha3_256};

/// SHA3-256 — vectores OFICIALES de FIPS 202.
#[test]
fn kat_sha3_256_official_vectors() {
    // SHA3-256("") — FIPS 202.
    let empty: [u8; 32] = Sha3_256::digest(b"").into();
    assert_eq!(
        hex::encode(empty),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "SHA3-256 del mensaje vacío debe coincidir con FIPS 202"
    );
    // SHA3-256("abc") — FIPS 202.
    let abc: [u8; 32] = Sha3_256::digest(b"abc").into();
    assert_eq!(
        hex::encode(abc),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "SHA3-256(\"abc\") debe coincidir con FIPS 202"
    );
}

/// Ed25519 — determinismo (RFC 8032) + pin de regresión de la firma. La misma
/// clave + mensaje SIEMPRE producen la MISMA firma (propiedad de RFC 8032). El
/// pin atrapa un cambio de comportamiento/encoding de ed25519-dalek.
#[test]
fn kat_ed25519_deterministic_signature_pin() {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let msg = b"qchain kat vector v1";
    let sig1 = sk.sign(msg).to_bytes();
    let sig2 = sk.sign(msg).to_bytes();
    assert_eq!(sig1, sig2, "Ed25519 debe ser determinista (RFC 8032)");
    // Pin de la clave pública derivada de la semilla [1;32] (determinista).
    assert_eq!(
        hex::encode(sk.verifying_key().to_bytes()),
        "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        "la clave pública Ed25519 derivada de la semilla [1;32] no debe cambiar"
    );
    // Pin de la firma (determinista para esta clave + mensaje).
    assert_eq!(
        hex::encode(sig1),
        "9b3fd123d6f86675704976905f3fe2b199799a73e6835f6b77560d480b5fc5f3ccbfab48106e148d53fda8130dd917cb35ad8315e119bb6185dd6a3045c78f0d",
        "la firma Ed25519 de un vector fijo no debe cambiar"
    );
}
