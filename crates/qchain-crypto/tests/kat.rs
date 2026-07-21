//! Known-Answer Tests (KAT) — tarea #189.
//!
//! Vectores OFICIALES: SHA-3 (FIPS 202), Ed25519 (RFC 8032, determinista), y
//! **vectores REALES `sigVer` del NIST ACVP-Server** para las dos firmas PQC —
//! **ML-DSA-65** (FIPS 204) y **SLH-DSA-SHA2-256s** (FIPS 205) — que exigen que
//! `verify_*` coincida con el `testPassed` oficial de NIST (ver
//! `kat_pqc_acvp_official_sigver_vectors`). Objetivo: atrapar un cambio de
//! backend/param-set/encoding que rompa la interoperabilidad con la referencia
//! NIST en silencio.
//!
//! **Gap honesto que queda (#189):** los vectores de **ML-KEM** (`encapDecap`)
//! entregan la clave de decapsulación como semilla `(d,z)`, y el crate `oqs` no
//! expone keygen determinista desde semilla ni `dk`-desde-semilla, así que no
//! son ejecutables contra nuestra API byte-orientada sin reimplementar el keygen
//! de FIPS 203. Se documenta como diferido; ML-KEM sí está cubierto por el
//! round-trip funcional (`kem` tests) + los KAT propios de liboqs upstream.

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

/// Vectores OFICIALES CAVP/ACVP de NIST para las firmas PQC — tarea #189, cierra
/// (parcialmente) el pendiente 'los vectores CAVP/ACVP completos siguen abiertos'.
/// Se fijan vectores REALES de `sigVer` del NIST ACVP-Server (interfaz EXTERNAL,
/// `preHash=pure`, contexto VACÍO — el modo exacto que implementa la API plana de
/// liboqs), y se exige que `verify_*` coincida con el `testPassed` oficial de NIST:
/// un vector VÁLIDO verifica `true` y uno DELIBERADAMENTE inválido verifica
/// `false`. Atrapa cualquier cambio de backend/param-set/encoding que rompa la
/// interoperabilidad con la referencia NIST en silencio.
///
/// Cubre **ML-DSA-65** (FIPS 204, la firma PQC principal del combo) y
/// **SLH-DSA-SHA2-256s** (FIPS 205, = `SPHINCS+-SHA2-256s-simple` de liboqs, el
/// 3er factor opt-in). **Límite honesto:** los vectores de **ML-KEM** (`encapDecap`)
/// entregan la clave como semilla `(d,z)` y el crate `oqs` no expone keygen
/// determinista desde semilla ni `dk`-desde-semilla, así que no son ejecutables
/// contra nuestra API byte-orientada sin reimplementar el keygen de FIPS 203 —
/// quedan documentados como gap. El vector completo se versiona en
/// `tests/kat_pqc_acvp_vectors.txt`.
#[test]
fn kat_pqc_acvp_official_sigver_vectors() {
    let raw = include_str!("kat_pqc_acvp_vectors.txt");
    let mut fields = std::collections::HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            // Los `_pass` son texto ("true"/"false"), no hex — se leen aparte.
            if k.ends_with("_pass") {
                continue;
            }
            fields.insert(k.to_string(), hex::decode(v.trim()).expect("fixture hex decodes"));
        }
    }
    let bytes = |k: &str| -> Vec<u8> { fields.get(k).unwrap_or_else(|| panic!("missing fixture field {k}")).clone() };
    // El `testPassed` oficial se relee del texto crudo del fixture.
    let pass_flag = |prefix: &str| -> bool {
        raw.lines().any(|l| l.trim() == format!("{prefix}_pass=true"))
    };

    // --- ML-DSA-65 (FIPS 204, sigVer external/pure, ctx vacío) ---
    let mldsa_ok = qchain_crypto::verify_ml_dsa_65_component(
        &bytes("mldsa65_pk"),
        &bytes("mldsa65_msg"),
        &bytes("mldsa65_sig"),
    );
    assert_eq!(
        mldsa_ok,
        pass_flag("mldsa65"),
        "ML-DSA-65 verify debe coincidir con el testPassed oficial de NIST ACVP (vector sigVer)"
    );

    // --- SLH-DSA-SHA2-256s (FIPS 205, sigVer external/pure, ctx vacío) ---
    let slh_ok = qchain_crypto::verify_slh_dsa_component(
        &bytes("slhdsa256s_pk"),
        &bytes("slhdsa256s_msg"),
        &bytes("slhdsa256s_sig"),
    );
    assert_eq!(
        slh_ok,
        pass_flag("slhdsa256s"),
        "SLH-DSA-SHA2-256s verify debe coincidir con el testPassed oficial de NIST ACVP (vector sigVer)"
    );
}
