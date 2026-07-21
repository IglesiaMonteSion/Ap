//! Real SLH-DSA (SPHINCS+) support via liboqs - registered as
//! `ALGORITHM_SLH_DSA` in `registry.rs`, and a real, selectable third
//! factor via `COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA`
//! (`Keypair::generate_with_slh_dsa`). `Transaction`/consensus vote
//! verification (`qchain_crypto::verify`, via the generic
//! `PublicKeyBundle`/`MultiSignature` types) and `Ledger::apply_transaction`
//! (which checks the live on-chain registry's status for every component of
//! the resolved combo) both actually accept it now - see
//! `project-lessons-learned` for the finding that motivated wiring this in,
//! and `registry::combo_components`/`verify`'s docs for exactly how.
//!
//! Parameter set: `SPHINCS+-SHA2-256s-simple` - NIST security level 5 (the
//! highest available), "s" (small-signature, slower-signing) variant. Per
//! the `pqc-cryptography` skill, SLH-DSA's role in this project is the
//! conservative opt-in fallback for high-value/long-lived accounts
//! (treasury, validator root keys, cold storage) where a slower signing
//! path is an acceptable trade for hash-based security's more conservative
//! assumption and for keeping the (already large) signature as small as
//! this scheme allows.
//!
//! Backend: liboqs (the `liboqs` feature). SLH-DSA is deliberately NOT ported
//! to the pure-Rust/WASM backend - it is an opt-in factor the mandatory hybrid
//! combo doesn't use, so the browser wallet doesn't need it. Under the `pure`
//! (wasm) build this module is a stub whose type/method signatures still exist
//! (so `Keypair` and the keypair-file code compile unchanged) but whose
//! operations are unavailable (generate/sign return an error, verify returns
//! false).

/// A standalone SLH-DSA keypair - deliberately not merged into the hybrid
/// `Keypair` type, since this scheme is opt-in, not part of the mandatory
/// pair every account must have.
pub struct SlhDsaKeypair {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

// QCH-3.1 (tarea #188): borrar la clave secreta SLH-DSA de memoria al dropear.
impl Drop for SlhDsaKeypair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.sk.zeroize();
    }
}

impl SlhDsaKeypair {
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.pk
    }

    pub fn secret_key_bytes(&self) -> &[u8] {
        &self.sk
    }

    /// Reconstructs a keypair from raw key material - used when loading a
    /// persisted keypair file (liboqs can't re-derive the public key from
    /// the secret key alone, so both must round-trip together).
    pub fn from_raw_parts(pk: Vec<u8>, sk: Vec<u8>) -> Self {
        SlhDsaKeypair { pk, sk }
    }
}

// --------------------------------------------------------------------------
// liboqs backend (native / node)
// --------------------------------------------------------------------------
#[cfg(feature = "liboqs")]
mod imp {
    use super::SlhDsaKeypair;
    use crate::ensure_oqs_init;
    use oqs::sig::{Algorithm as OqsAlgorithm, Sig};

    fn slh_dsa_sig() -> anyhow::Result<Sig> {
        ensure_oqs_init();
        Sig::new(OqsAlgorithm::SphincsSha2256sSimple)
            .map_err(|e| anyhow::anyhow!("liboqs SLH-DSA (SHA2-256s-simple) unavailable: {e}"))
    }

    impl SlhDsaKeypair {
        pub fn generate() -> anyhow::Result<Self> {
            let sig_alg = slh_dsa_sig()?;
            let (pk, sk) = sig_alg.keypair().map_err(|e| anyhow::anyhow!("SLH-DSA keygen failed: {e}"))?;
            Ok(SlhDsaKeypair { pk: pk.into_vec(), sk: sk.into_vec() })
        }

        pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
            let sig_alg = slh_dsa_sig()?;
            let sk_ref = sig_alg
                .secret_key_from_bytes(&self.sk)
                .ok_or_else(|| anyhow::anyhow!("corrupt SLH-DSA secret key"))?;
            let sig = sig_alg.sign(msg, sk_ref).map_err(|e| anyhow::anyhow!("SLH-DSA signing failed: {e}"))?;
            Ok(sig.into_vec())
        }
    }

    pub fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let Ok(sig_alg) = slh_dsa_sig() else { return false };
        let Some(pk_ref) = sig_alg.public_key_from_bytes(pubkey) else {
            return false;
        };
        let Some(sig_ref) = sig_alg.signature_from_bytes(sig) else {
            return false;
        };
        sig_alg.verify(msg, sig_ref, pk_ref).is_ok()
    }
}

// --------------------------------------------------------------------------
// pure/wasm stub (SLH-DSA not available in the browser build)
// --------------------------------------------------------------------------
#[cfg(not(feature = "liboqs"))]
mod imp {
    use super::SlhDsaKeypair;

    impl SlhDsaKeypair {
        pub fn generate() -> anyhow::Result<Self> {
            anyhow::bail!("SLH-DSA is not available in the pure/wasm build")
        }
        pub fn sign(&self, _msg: &[u8]) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("SLH-DSA is not available in the pure/wasm build")
        }
    }

    pub fn verify(_pubkey: &[u8], _msg: &[u8], _sig: &[u8]) -> bool {
        false
    }
}

/// Verify a standalone SLH-DSA signature. Mirrors
/// `verify_ml_dsa_65_component`'s shape/failure-mode (returns `false` rather
/// than erroring on any malformed input). In the pure/wasm build this always
/// returns `false` (SLH-DSA unavailable there).
pub fn verify_slh_dsa_component(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    imp::verify(pubkey, msg, sig)
}

#[cfg(all(test, feature = "liboqs"))]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = SlhDsaKeypair::generate().unwrap();
        let msg = b"hello qchain, slh-dsa opt-in";
        let sig = kp.sign(msg).unwrap();
        assert!(verify_slh_dsa_component(kp.public_key_bytes(), msg, &sig));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let kp = SlhDsaKeypair::generate().unwrap();
        let sig = kp.sign(b"hello qchain").unwrap();
        assert!(!verify_slh_dsa_component(kp.public_key_bytes(), b"goodbye qchain", &sig));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let kp = SlhDsaKeypair::generate().unwrap();
        let other = SlhDsaKeypair::generate().unwrap();
        let sig = kp.sign(b"hello qchain").unwrap();
        assert!(!verify_slh_dsa_component(other.public_key_bytes(), b"hello qchain", &sig));
    }

    #[test]
    fn tampered_signature_bytes_fail_verification() {
        let kp = SlhDsaKeypair::generate().unwrap();
        let msg = b"hello qchain";
        let mut sig = kp.sign(msg).unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 0xFF;
        assert!(!verify_slh_dsa_component(kp.public_key_bytes(), msg, &sig));
    }

    #[test]
    fn real_key_and_signature_sizes_match_the_sha2_256s_simple_parameter_set() {
        let kp = SlhDsaKeypair::generate().unwrap();
        let sig = kp.sign(b"size probe").unwrap();
        assert_eq!(kp.public_key_bytes().len(), 64);
        assert_eq!(sig.len(), 29_792);
    }
}
