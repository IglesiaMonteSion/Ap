//! Phase-2 (browser/WASM self-custody) feasibility check.
//!
//! The node verifies ML-DSA-65 signatures with liboqs (the C library, via the
//! `oqs` crate), which does NOT compile to WebAssembly. For a self-custody
//! wallet the signing must happen in the user's browser, i.e. in WASM. The
//! only realistic way is a *pure-Rust* ML-DSA implementation (RustCrypto's
//! `ml-dsa` crate, which does compile to wasm32) instead of liboqs.
//!
//! Everything hinges on one question: are the two implementations
//! byte-compatible? Both claim FIPS-204 (ML-DSA-65), and the key/signature
//! sizes already match exactly (pk 1952, sig 3309, sk 4032). These tests prove
//! it end to end by CROSS-verifying:
//!   1. sign with RustCrypto (what the browser would do)  -> verify with liboqs
//!      (what the node does). This is the direction that actually matters.
//!   2. sign with liboqs (the node) -> verify with RustCrypto (a WASM light
//!      client could then check node-produced signatures too).
//!
//! Verification is independent of how the signature was produced (deterministic
//! vs hedged) as long as the encoding and the (empty) context string match, so
//! cross-verification is the correct compatibility test. If both pass, signing
//! qchain transactions in the browser via pure-Rust WASM is viable.

use ml_dsa::{Generate, Keypair, MlDsa65, Signer, Verifier};
use ml_dsa::{EncodedVerifyingKey, Signature, SigningKey, VerifyingKey};

const MSG: &[u8] = b"qchain phase-2 wasm self-custody feasibility probe";

/// Direction that matters: a signature made by the pure-Rust `ml-dsa` crate
/// (the browser side) is accepted by liboqs (the node side).
#[test]
fn rustcrypto_signature_is_accepted_by_liboqs_node() {
    let sk = SigningKey::<MlDsa65>::generate();
    let vk = sk.verifying_key();
    let sig = sk.sign(MSG); // deterministic, empty context (FIPS-204 default)

    let vk_bytes = vk.encode();
    let sig_bytes = sig.encode();
    assert_eq!(vk_bytes.as_slice().len(), 1952, "ML-DSA-65 public key size");
    assert_eq!(sig_bytes.as_slice().len(), 3309, "ML-DSA-65 signature size");

    // `verify_ml_dsa_65_component` is exactly what the node uses (liboqs).
    let accepted =
        qchain_crypto::verify_ml_dsa_65_component(vk_bytes.as_slice(), MSG, sig_bytes.as_slice());
    assert!(accepted, "liboqs must accept a RustCrypto ML-DSA-65 signature");

    // And it must reject a tampered message (sanity: it's really verifying).
    let rejected =
        qchain_crypto::verify_ml_dsa_65_component(vk_bytes.as_slice(), b"other message", sig_bytes.as_slice());
    assert!(!rejected, "liboqs must reject the signature over a different message");
}

/// End-to-end: a keypair derived from a 32-byte master seed exactly the way
/// the browser build's `Keypair::generate_from_seed` does it (domain-separated
/// SHA3-256 sub-seeds -> Ed25519 from bytes + ML-DSA from seed) produces both
/// component signatures that the NODE accepts. This is the real proof that a
/// wallet whose keys are born in the browser (from `crypto.getRandomValues`)
/// can transact against the live network.
#[test]
fn seed_derived_browser_keys_verify_under_the_node() {
    use ed25519_dalek::{Signer as EdSigner, SigningKey as EdKey};
    use sha3::{Digest, Sha3_256};

    let master_seed = [7u8; 32];
    // Same derivation as `Keypair::generate_from_seed`.
    let ed_seed: [u8; 32] = Sha3_256::new()
        .chain_update(b"qchain-ed25519-v1")
        .chain_update(master_seed)
        .finalize()
        .into();
    let mldsa_seed: [u8; 32] = Sha3_256::new()
        .chain_update(b"qchain-ml-dsa-65-v1")
        .chain_update(master_seed)
        .finalize()
        .into();

    // Ed25519 half.
    let ed = EdKey::from_bytes(&ed_seed);
    let ed_sig = ed.sign(MSG).to_bytes();
    let ed_pk = ed.verifying_key().to_bytes();
    assert!(
        qchain_crypto::verify_ed25519_component(&ed_pk, MSG, &ed_sig),
        "node must accept the seed-derived Ed25519 signature"
    );

    // ML-DSA-65 half (pure-Rust, as WASM would do it).
    let ms = ml_dsa::B32::try_from(&mldsa_seed[..]).unwrap();
    let msk = SigningKey::<MlDsa65>::from_seed(&ms);
    let mvk = msk.verifying_key().encode();
    let msig = msk.sign(MSG).encode();
    assert!(
        qchain_crypto::verify_ml_dsa_65_component(mvk.as_slice(), MSG, msig.as_slice()),
        "node must accept the seed-derived ML-DSA-65 signature"
    );
}

/// Reverse direction: a signature made by liboqs (the node) is accepted by the
/// pure-Rust `ml-dsa` crate (so a WASM light client could verify node output).
#[test]
fn liboqs_signature_is_accepted_by_rustcrypto() {
    oqs::init();
    let alg = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).expect("liboqs ML-DSA-65");
    let (pk, sk) = alg.keypair().expect("liboqs keygen");
    let signature = alg.sign(MSG, &sk).expect("liboqs sign");

    let vk = VerifyingKey::<MlDsa65>::decode(
        &EncodedVerifyingKey::<MlDsa65>::try_from(pk.as_ref()).expect("pk bytes -> encoded vk"),
    );
    let sig = Signature::<MlDsa65>::try_from(signature.as_ref()).expect("sig bytes -> Signature");

    assert!(
        vk.verify(MSG, &sig).is_ok(),
        "RustCrypto ml-dsa must accept a liboqs ML-DSA-65 signature"
    );
}
