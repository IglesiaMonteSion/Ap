//! ML-KEM-768 (FIPS 203) key encapsulation for the optional **encrypted** P2P
//! channel (see `qchain-network::session`). Node-only: the browser/WASM wallet
//! never runs the P2P transport, so this is gated on the `liboqs` feature and
//! absent from the `pure` (wasm32) build.
//!
//! Post-quantum by construction — ML-KEM (the NIST-standardized lattice KEM,
//! ex-Kyber), never X25519/ECDH (broken by Shor, the same reason this project
//! excludes BLS/Verkle+KZG). Real liboqs, never hand-rolled lattice math (the
//! `pqc-cryptography` skill's rule).
//!
//! The API is deliberately byte-oriented (`Vec<u8>` in/out) so callers never
//! touch an `oqs` type: the public key and ciphertext travel on the wire as
//! raw bytes inside the handshake frames, and the 32-byte shared secret feeds
//! a SHA3 KDF. Keys here are **ephemeral per connection** — a fresh keypair is
//! generated for each dial, so there is no long-term KEM key to persist or
//! leak (forward secrecy for the channel is out of scope for this increment
//! but the ephemerality is the groundwork for it).

#[cfg(feature = "liboqs")]
mod backend {
    use oqs::kem::{Algorithm, Kem};
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn kem() -> anyhow::Result<Kem> {
        INIT.call_once(oqs::init);
        Kem::new(Algorithm::MlKem768).map_err(|e| anyhow::anyhow!("liboqs ML-KEM-768 unavailable: {e}"))
    }

    /// A fresh ephemeral ML-KEM-768 keypair as raw bytes `(public, secret)`.
    pub fn keypair() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let k = kem()?;
        let (pk, sk) = k.keypair().map_err(|e| anyhow::anyhow!("ML-KEM keygen failed: {e}"))?;
        Ok((pk.as_ref().to_vec(), sk.as_ref().to_vec()))
    }

    /// Encapsulate to a peer's public key, returning `(ciphertext, shared_secret)`.
    /// The ciphertext is sent to the peer; the shared secret stays local.
    pub fn encapsulate(peer_pk: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let k = kem()?;
        let pk = k
            .public_key_from_bytes(peer_pk)
            .ok_or_else(|| anyhow::anyhow!("ML-KEM public key has the wrong length ({} bytes)", peer_pk.len()))?;
        let (ct, ss) = k.encapsulate(pk).map_err(|e| anyhow::anyhow!("ML-KEM encapsulate failed: {e}"))?;
        Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
    }

    /// Decapsulate a peer's ciphertext with our secret key, returning the
    /// shared secret — identical to the peer's `encapsulate` output.
    pub fn decapsulate(our_sk: &[u8], ct: &[u8]) -> anyhow::Result<Vec<u8>> {
        let k = kem()?;
        let sk = k
            .secret_key_from_bytes(our_sk)
            .ok_or_else(|| anyhow::anyhow!("ML-KEM secret key has the wrong length ({} bytes)", our_sk.len()))?;
        let ct = k
            .ciphertext_from_bytes(ct)
            .ok_or_else(|| anyhow::anyhow!("ML-KEM ciphertext has the wrong length ({} bytes)", ct.len()))?;
        let ss = k.decapsulate(sk, ct).map_err(|e| anyhow::anyhow!("ML-KEM decapsulate failed: {e}"))?;
        Ok(ss.as_ref().to_vec())
    }
}

#[cfg(feature = "liboqs")]
pub use backend::{decapsulate, encapsulate, keypair};

#[cfg(all(test, feature = "liboqs"))]
mod tests {
    /// A round trip: a keypair, encapsulation to its public key, and
    /// decapsulation of the resulting ciphertext must recover the identical
    /// 32-byte shared secret — the core KEM correctness property the encrypted
    /// channel relies on.
    #[test]
    fn ml_kem_round_trip_recovers_the_same_shared_secret() {
        let (pk, sk) = super::keypair().unwrap();
        let (ct, ss_a) = super::encapsulate(&pk).unwrap();
        let ss_b = super::decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_a, ss_b, "encapsulate and decapsulate must agree on the shared secret");
        assert_eq!(ss_a.len(), 32, "ML-KEM-768 shared secret is 32 bytes");
        assert!(!pk.is_empty() && !ct.is_empty());
    }

    /// Decapsulating with the wrong secret key must NOT recover the shared
    /// secret (ML-KEM is IND-CCA2: a mismatched key yields an unrelated value,
    /// implicit rejection), so a relay that substitutes its own keypair can't
    /// derive the real channel key.
    #[test]
    fn decapsulating_with_a_foreign_key_does_not_recover_the_secret() {
        let (pk, _sk) = super::keypair().unwrap();
        let (ct, ss_a) = super::encapsulate(&pk).unwrap();
        let (_pk2, sk2) = super::keypair().unwrap();
        let ss_wrong = super::decapsulate(&sk2, &ct).unwrap();
        assert_ne!(ss_a, ss_wrong, "a foreign secret key must not recover the shared secret");
    }
}
