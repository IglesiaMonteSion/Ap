//! Hybrid classical + post-quantum signatures for this L1, backed by real
//! liboqs (via the `oqs` crate) for the ML-DSA-65 half - see the
//! `pqc-cryptography` skill for why liboqs specifically, and never
//! hand-rolled math. Design and policy: `ARCHITECTURE.md` §2.
//!
//! Every account key is a **hybrid** key: an Ed25519 keypair plus an
//! ML-DSA-65 keypair. A signature is only valid if **both** halves verify -
//! this is a binding policy, not a convenience default (see `verify`).
//!
//! Addresses (`Pubkey`) are a 32-byte hash of the full dual-key bundle, kept
//! constant-size regardless of the (much larger) ML-DSA-65 public key. The
//! full bundle only needs to travel with a transaction, not live in the
//! address itself - the same "reveal the key at spend time" pattern Bitcoin
//! uses for P2PKH, reused here for the same reason: keeping every address
//! the same size no matter which registry entries it uses.

pub mod registry;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use oqs::sig::{Algorithm as OqsAlgorithm, Sig};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::str::FromStr;
use std::sync::Once;

pub use registry::{
    AlgorithmId, AlgorithmStatus, RegistryEntry, ALGORITHM_ED25519, ALGORITHM_ML_DSA_65,
    COMBO_HYBRID_ED25519_ML_DSA_65,
};

static OQS_INIT: Once = Once::new();

fn ensure_oqs_init() {
    OQS_INIT.call_once(oqs::init);
}

fn ml_dsa_65() -> anyhow::Result<Sig> {
    ensure_oqs_init();
    Sig::new(OqsAlgorithm::MlDsa65).map_err(|e| anyhow::anyhow!("liboqs ML-DSA-65 unavailable: {e}"))
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <String as Deserialize>::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub struct Pubkey(pub [u8; 32]);

impl Pubkey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Pubkey(bytes)
    }

    /// Sentinel address for the built-in System Program (never has a real
    /// keypair behind it).
    pub const fn system_program_id() -> Self {
        Pubkey([0u8; 32])
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl Serialize for Pubkey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Pubkey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(d)?;
        Pubkey::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pubkey({self})")
    }
}

impl FromStr for Pubkey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec()?;
        if bytes.len() != 32 {
            anyhow::bail!("invalid pubkey: expected 32 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Pubkey(arr))
    }
}

/// ed25519 signature, hex-encoded for serde (serde's built-in array support
/// only goes up to 32 bytes; this is 64).
#[derive(Clone, Copy)]
pub struct Signature(pub [u8; 64]);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", hex::encode(self.0))
    }
}

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!("expected 64 bytes, got {}", bytes.len())));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature(arr))
    }
}

/// The raw dual public keys behind an address. A `Pubkey` is only
/// `sha3_256(ed25519 || mldsa)`; validators recompute that hash from the
/// bundle to confirm it matches the claimed sender before trusting either
/// signature half.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct PublicKeyBundle {
    pub ed25519: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub mldsa: Vec<u8>,
}

impl PublicKeyBundle {
    pub fn to_address(&self) -> Pubkey {
        let mut hasher = Sha3_256::new();
        hasher.update(self.ed25519);
        hasher.update(&self.mldsa);
        Pubkey(hasher.finalize().into())
    }
}

/// A signature covering both registered schemes. Both halves must verify -
/// see the module docs and `ARCHITECTURE.md` §2 for why this is mandatory,
/// not optional.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HybridSignature {
    pub ed25519: Signature,
    #[serde(with = "hex_bytes")]
    pub mldsa: Vec<u8>,
}

pub struct Keypair {
    ed25519: SigningKey,
    mldsa_pk: Vec<u8>,
    mldsa_sk: Vec<u8>,
}

impl Keypair {
    pub fn generate() -> anyhow::Result<Self> {
        let mut csprng = OsRng;
        let ed25519 = SigningKey::generate(&mut csprng);
        let sig_alg = ml_dsa_65()?;
        let (pk, sk) = sig_alg.keypair().map_err(|e| anyhow::anyhow!("ML-DSA-65 keygen failed: {e}"))?;
        Ok(Keypair {
            ed25519,
            mldsa_pk: pk.into_vec(),
            mldsa_sk: sk.into_vec(),
        })
    }

    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            ed25519: self.ed25519.verifying_key().to_bytes(),
            mldsa: self.mldsa_pk.clone(),
        }
    }

    pub fn pubkey(&self) -> Pubkey {
        self.public_key_bundle().to_address()
    }

    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<HybridSignature> {
        let ed_sig: DalekSignature = self.ed25519.sign(msg);
        let sig_alg = ml_dsa_65()?;
        let sk_ref = sig_alg
            .secret_key_from_bytes(&self.mldsa_sk)
            .ok_or_else(|| anyhow::anyhow!("corrupt ML-DSA-65 secret key"))?;
        let mldsa_sig = sig_alg
            .sign(msg, sk_ref)
            .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {e}"))?;
        Ok(HybridSignature {
            ed25519: Signature(ed_sig.to_bytes()),
            mldsa: mldsa_sig.into_vec(),
        })
    }
}

/// Verify a hybrid signature: **both** the ed25519 and ML-DSA-65 halves
/// must be valid for `msg` under the keys in `bundle`. Callers are
/// responsible for separately checking that `bundle` actually hashes to the
/// address it claims to represent (`PublicKeyBundle::to_address`).
pub fn verify(bundle: &PublicKeyBundle, msg: &[u8], signature: &HybridSignature) -> bool {
    verify_ed25519_component(&bundle.ed25519, msg, &signature.ed25519.0)
        && verify_ml_dsa_65_component(&bundle.mldsa, msg, &signature.mldsa)
}

/// Verify just the Ed25519 half against a raw 32-byte public key. Exposed
/// standalone (not just via the hybrid `verify`) because contracts doing
/// custom authorization logic (e.g. a smart-contract multisig) may need to
/// check one registered scheme's signature at a time - see the
/// `host_verify_signature` syscall in `qchain-execution` and
/// `ARCHITECTURE.md` §4.
pub fn verify_ed25519_component(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => {
            let dsig = DalekSignature::from_bytes(sig);
            vk.verify(msg, &dsig).is_ok()
        }
        Err(_) => false,
    }
}

/// Verify just the ML-DSA-65 half against a raw public key. See
/// `verify_ed25519_component` docs for why this is exposed standalone.
pub fn verify_ml_dsa_65_component(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig_alg) = ml_dsa_65() else { return false };
    let Some(pk_ref) = sig_alg.public_key_from_bytes(pubkey) else {
        return false;
    };
    let Some(sig_ref) = sig_alg.signature_from_bytes(sig) else {
        return false;
    };
    sig_alg.verify(msg, sig_ref, pk_ref).is_ok()
}

/// Length-prefixed encoding: `[u32 LE len][bytes] [u32 LE len][bytes] ...`.
/// Used for the keypair file format below, where ML-DSA-65 key/secret
/// lengths aren't a compile-time constant (they come from liboqs at
/// runtime), so a fixed-offset layout isn't an option.
fn encode_length_prefixed(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_le_bytes());
        out.extend_from_slice(field);
    }
    out
}

fn decode_length_prefixed(mut bytes: &[u8], count: usize) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        if bytes.len() < 4 {
            anyhow::bail!("truncated keypair data");
        }
        let (len_bytes, rest) = bytes.split_at(4);
        let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
        if rest.len() < len {
            anyhow::bail!("truncated keypair data");
        }
        let (field, rest) = rest.split_at(len);
        fields.push(field.to_vec());
        bytes = rest;
    }
    Ok(fields)
}

/// Keypair file layout: JSON array of bytes, length-prefixed fields (ed25519
/// keypair [64 bytes], ML-DSA-65 secret key, ML-DSA-65 public key) - fully
/// self-contained, since liboqs can't re-derive the ML-DSA public key from
/// the secret key alone.
pub fn write_keypair_file(keypair: &Keypair, path: &std::path::Path) -> anyhow::Result<()> {
    let ed_bytes = keypair.ed25519.to_keypair_bytes();
    let encoded = encode_length_prefixed(&[&ed_bytes, &keypair.mldsa_sk, &keypair.mldsa_pk]);
    std::fs::write(path, serde_json::to_vec(&encoded)?)?;
    Ok(())
}

pub fn read_keypair_file(path: &std::path::Path) -> anyhow::Result<Keypair> {
    let contents = std::fs::read(path)?;
    let encoded: Vec<u8> = serde_json::from_slice(&contents)?;
    let fields = decode_length_prefixed(&encoded, 3)?;
    let ed_bytes: [u8; 64] = fields[0]
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ed25519 keypair length"))?;
    let ed25519 = SigningKey::from_keypair_bytes(&ed_bytes).map_err(|e| anyhow::anyhow!("invalid ed25519 bytes: {e}"))?;
    Ok(Keypair {
        ed25519,
        mldsa_sk: fields[1].clone(),
        mldsa_pk: fields[2].clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let msg = b"hello qchain";
        let sig = kp.sign(msg).unwrap();
        assert!(verify(&kp.public_key_bundle(), msg, &sig));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign(b"hello qchain").unwrap();
        assert!(!verify(&kp.public_key_bundle(), b"goodbye qchain", &sig));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let kp = Keypair::generate().unwrap();
        let other = Keypair::generate().unwrap();
        let sig = kp.sign(b"hello qchain").unwrap();
        assert!(!verify(&other.public_key_bundle(), b"hello qchain", &sig));
    }

    #[test]
    fn address_is_bound_to_both_public_keys() {
        let kp = Keypair::generate().unwrap();
        let mut bundle = kp.public_key_bundle();
        bundle.ed25519[0] ^= 0xFF;
        assert_ne!(bundle.to_address(), kp.pubkey());
    }

    #[test]
    fn pubkey_display_and_parse_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let s = kp.pubkey().to_string();
        let parsed: Pubkey = s.parse().unwrap();
        assert_eq!(kp.pubkey(), parsed);
    }

    #[test]
    fn keypair_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("qchain-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id.json");
        let kp = Keypair::generate().unwrap();
        write_keypair_file(&kp, &path).unwrap();
        let kp2 = read_keypair_file(&path).unwrap();
        assert_eq!(kp.pubkey(), kp2.pubkey());
        let sig = kp2.sign(b"roundtrip").unwrap();
        assert!(verify(&kp2.public_key_bundle(), b"roundtrip", &sig));
        std::fs::remove_file(&path).ok();
    }
}
