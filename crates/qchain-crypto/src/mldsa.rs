//! Pluggable ML-DSA-65 backend.
//!
//! The validator node signs/verifies with **liboqs** (C, via the `oqs` crate).
//! The browser/WASM self-custody wallet can't use liboqs (C doesn't compile to
//! wasm), so it uses the pure-Rust RustCrypto **`ml-dsa`** crate instead.
//!
//! Both are FIPS-204 ML-DSA-65 and are byte-compatible for verification (proven
//! end-to-end in `tests/wasm_feasibility.rs`): a signature made by one is
//! accepted by the other. That is exactly what lets a transaction signed in the
//! browser (pure backend) be verified by the node (liboqs backend).
//!
//! Selected by Cargo feature: `liboqs` (default, native) or `pure` (wasm).
//! The public API each backend exposes:
//!   - `sign(sk, msg) -> Vec<u8>` and `verify(pk, msg, sig) -> bool` (both)
//!   - `keypair() -> (pk, sk)` random (liboqs / node only)
//!   - `keypair_from_seed(&[u8;32]) -> (pk, sk)` deterministic (pure / browser),
//!     where the stored "sk" is the 32-byte seed itself - the smallest possible
//!     secret to hold and back up.

/// ML-DSA-65 public-key length (FIPS-204), identical across both backends.
#[allow(dead_code)]
pub const PK_LEN: usize = 1952;
/// ML-DSA-65 signature length (FIPS-204), identical across both backends.
#[allow(dead_code)]
pub const SIG_LEN: usize = 3309;

// --------------------------------------------------------------------------
// liboqs backend (native / validator node)
// --------------------------------------------------------------------------
#[cfg(feature = "liboqs")]
mod backend {
    use oqs::sig::{Algorithm, Sig};
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn alg() -> anyhow::Result<Sig> {
        INIT.call_once(oqs::init);
        Sig::new(Algorithm::MlDsa65).map_err(|e| anyhow::anyhow!("liboqs ML-DSA-65 unavailable: {e}"))
    }

    /// A fresh random keypair, `(public_key, secret_key)` in liboqs's own
    /// secret-key encoding.
    pub fn keypair() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let a = alg()?;
        let (pk, sk) = a.keypair().map_err(|e| anyhow::anyhow!("ML-DSA-65 keygen failed: {e}"))?;
        Ok((pk.into_vec(), sk.into_vec()))
    }

    pub fn sign(sk: &[u8], msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let a = alg()?;
        let sk_ref = a
            .secret_key_from_bytes(sk)
            .ok_or_else(|| anyhow::anyhow!("corrupt ML-DSA-65 secret key"))?;
        Ok(a.sign(msg, sk_ref)
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {e}"))?
            .into_vec())
    }

    pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let Ok(a) = alg() else { return false };
        let (Some(pk_ref), Some(sig_ref)) =
            (a.public_key_from_bytes(pk), a.signature_from_bytes(sig))
        else {
            return false;
        };
        a.verify(msg, sig_ref, pk_ref).is_ok()
    }
}

// --------------------------------------------------------------------------
// pure-Rust backend (wasm / browser wallet)
// --------------------------------------------------------------------------
#[cfg(all(not(feature = "liboqs"), feature = "pure"))]
mod backend {
    use ml_dsa::{
        signature::{Signer, Verifier},
        EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey, VerifyingKey, B32,
    };

    /// Deterministic keypair from a 32-byte seed. The browser supplies real
    /// entropy (`crypto.getRandomValues`); we store the seed itself as the
    /// secret. Returns `(public_key, seed)`.
    pub fn keypair_from_seed(seed: &[u8; 32]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let s = B32::try_from(&seed[..]).map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))?;
        let sk = SigningKey::<MlDsa65>::from_seed(&s);
        let pk = sk.verifying_key().encode().as_slice().to_vec();
        Ok((pk, seed.to_vec()))
    }

    pub fn sign(sk_seed: &[u8], msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let seed: [u8; 32] = sk_seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("ML-DSA-65 secret must be a 32-byte seed"))?;
        let s = B32::try_from(&seed[..]).map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))?;
        let sk = SigningKey::<MlDsa65>::from_seed(&s);
        // FIPS-204 deterministic signing, empty context - matches liboqs.
        Ok(sk.sign(msg).encode().as_slice().to_vec())
    }

    pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let Ok(enc) = EncodedVerifyingKey::<MlDsa65>::try_from(pk) else {
            return false;
        };
        let vk = VerifyingKey::<MlDsa65>::decode(&enc);
        let Ok(sig) = Signature::<MlDsa65>::try_from(sig) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }
}

#[cfg(all(not(feature = "liboqs"), not(feature = "pure")))]
compile_error!("qchain-crypto: enable feature `liboqs` (native/node) or `pure` (wasm)");

pub use backend::{sign, verify};

#[cfg(feature = "liboqs")]
pub use backend::keypair;

#[cfg(all(not(feature = "liboqs"), feature = "pure"))]
pub use backend::keypair_from_seed;
