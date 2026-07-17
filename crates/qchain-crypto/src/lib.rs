//! Classical + post-quantum signatures for this L1, backed by real liboqs
//! (via the `oqs` crate) for the ML-DSA-65 and SLH-DSA halves - see the
//! `pqc-cryptography` skill for why liboqs specifically, and never
//! hand-rolled math. Design and policy: `ARCHITECTURE.md` §2.
//!
//! Every account key is a **combo** of individually-registered scheme
//! components (`registry::combo_components`) - phase 1's default is the
//! mandatory Ed25519+ML-DSA-65 hybrid, with an opt-in Ed25519+ML-DSA-65+
//! SLH-DSA triple combo also available (`Keypair::generate_with_slh_dsa`).
//! A signature is only valid if **every** component of the resolved combo
//! verifies - this is a binding policy, not a convenience default (see
//! `verify`). This generality is what makes the on-chain algorithm registry
//! real rather than bookkeeping: `verify` resolves which combo a bundle
//! claims from its components (`registry::combo_from_components`), so an
//! attacker can't drop/substitute a mandatory factor and still pass -
//! doing so simply resolves to no known combo, and `verify` rejects
//! outright. See `project-lessons-learned` for the finding that motivated
//! this (the registry previously gated nothing at signature-verification
//! time, no matter what governance had "activated").
//!
//! Addresses (`Pubkey`) are a 32-byte hash of the full key bundle (every
//! component's scheme id and bytes, in combo order), kept constant-size
//! regardless of how many/how large the underlying component keys are. The
//! full bundle only needs to travel with a transaction, not live in the
//! address itself - the same "reveal the key at spend time" pattern Bitcoin
//! uses for P2PKH, reused here for the same reason: keeping every address
//! the same size no matter which registry entries it uses. Binding the
//! scheme id (not just the raw bytes) into the address hash matters too -
//! without it, two different combos that happened to produce
//! same-length/same-byte component keys could collide.

pub mod registry;
pub mod slh_dsa;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, VerifyingKey};
#[cfg(feature = "liboqs")]
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use std::str::FromStr;

mod mldsa;

pub use registry::{
    combo_components, combo_from_components, slh_dsa_registry_entry, AlgorithmId, AlgorithmStatus, RegistryEntry,
    ALGORITHM_ED25519, ALGORITHM_ML_DSA_65, ALGORITHM_SLH_DSA, COMBO_HYBRID_ED25519_ML_DSA_65,
    COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA,
};
pub use slh_dsa::{verify_slh_dsa_component, SlhDsaKeypair};

/// One-time liboqs init, used by the liboqs-backed halves (`mldsa`'s liboqs
/// backend has its own; this one serves `slh_dsa`). No-op concept in the pure
/// build, which has no liboqs.
#[cfg(feature = "liboqs")]
fn ensure_oqs_init() {
    use std::sync::Once;
    static OQS_INIT: Once = Once::new();
    OQS_INIT.call_once(oqs::init);
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

/// One scheme component of a key bundle or signature: which registered
/// scheme, and its raw bytes. `PublicKeyBundle`/`MultiSignature` are each
/// just an ordered list of these - the order (and which schemes appear)
/// must exactly match a known combo (`registry::combo_components`) or
/// `verify` rejects outright.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct KeyComponent {
    pub scheme: AlgorithmId,
    #[serde(with = "hex_bytes")]
    pub bytes: Vec<u8>,
}

/// The raw public keys behind an address, one component per scheme in the
/// account's combo. A `Pubkey` is `sha3_256` of every component's scheme id
/// and bytes, in order; validators recompute that hash from the bundle to
/// confirm it matches the claimed sender before trusting any signature
/// component.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct PublicKeyBundle {
    pub components: Vec<KeyComponent>,
}

impl PublicKeyBundle {
    pub fn to_address(&self) -> Pubkey {
        let mut hasher = Sha3_256::new();
        for component in &self.components {
            hasher.update(component.scheme.0.to_le_bytes());
            hasher.update(&component.bytes);
        }
        Pubkey(hasher.finalize().into())
    }
}

/// A signature covering every component of a combo. **Every** component
/// must verify - see the module docs and `ARCHITECTURE.md` §2 for why this
/// is mandatory, not optional.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct MultiSignature {
    pub components: Vec<KeyComponent>,
}

pub struct Keypair {
    combo: AlgorithmId,
    ed25519: SigningKey,
    mldsa_pk: Vec<u8>,
    mldsa_sk: Vec<u8>,
    slh_dsa: Option<SlhDsaKeypair>,
}

impl Keypair {
    /// Generates a keypair under the phase-1 default combo (Ed25519 +
    /// ML-DSA-65, both mandatory). Random generation - the validator/CLI path;
    /// available only in the `liboqs` build (needs system randomness and
    /// liboqs keygen). The browser/WASM build uses `generate_from_seed`.
    #[cfg(feature = "liboqs")]
    pub fn generate() -> anyhow::Result<Self> {
        Self::generate_ed25519_ml_dsa(None)
    }

    /// Generates a keypair under the opt-in triple combo (Ed25519 +
    /// ML-DSA-65 + SLH-DSA) - see `registry::COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA`'s
    /// docs for the tradeoff (much larger signatures, higher fees, for
    /// high-value/long-lived accounts).
    #[cfg(feature = "liboqs")]
    pub fn generate_with_slh_dsa() -> anyhow::Result<Self> {
        let slh_dsa = SlhDsaKeypair::generate()?;
        Self::generate_ed25519_ml_dsa(Some(slh_dsa))
    }

    #[cfg(feature = "liboqs")]
    fn generate_ed25519_ml_dsa(slh_dsa: Option<SlhDsaKeypair>) -> anyhow::Result<Self> {
        let mut csprng = OsRng;
        let ed25519 = SigningKey::generate(&mut csprng);
        let (mldsa_pk, mldsa_sk) = mldsa::keypair()?;
        let combo = if slh_dsa.is_some() {
            COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA
        } else {
            COMBO_HYBRID_ED25519_ML_DSA_65
        };
        Ok(Keypair {
            combo,
            ed25519,
            mldsa_pk,
            mldsa_sk,
            slh_dsa,
        })
    }

    /// Deterministically derives the mandatory Ed25519 + ML-DSA-65 keypair from
    /// a single 32-byte master seed. This is the browser/WASM entry point: the
    /// browser supplies real entropy (`crypto.getRandomValues`) as the seed and
    /// keeps only it (nothing leaves the device). Two independent sub-seeds are
    /// derived from the master via domain-separated SHA3-256 so the two schemes
    /// don't share key material. Available in the `pure` build; also compiled in
    /// the `liboqs` build for cross-testing, where it errors (liboqs has no
    /// seeded ML-DSA keygen) - the node never uses it.
    #[cfg(feature = "pure")]
    pub fn generate_from_seed(master_seed: &[u8; 32]) -> anyhow::Result<Self> {
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
        let ed25519 = SigningKey::from_bytes(&ed_seed);
        let (mldsa_pk, mldsa_sk) = mldsa::keypair_from_seed(&mldsa_seed)?;
        Ok(Keypair {
            combo: COMBO_HYBRID_ED25519_ML_DSA_65,
            ed25519,
            mldsa_pk,
            mldsa_sk,
            slh_dsa: None,
        })
    }

    pub fn combo(&self) -> AlgorithmId {
        self.combo
    }

    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        let mut components = vec![
            KeyComponent { scheme: ALGORITHM_ED25519, bytes: self.ed25519.verifying_key().to_bytes().to_vec() },
            KeyComponent { scheme: ALGORITHM_ML_DSA_65, bytes: self.mldsa_pk.clone() },
        ];
        if let Some(slh_dsa) = &self.slh_dsa {
            components.push(KeyComponent { scheme: ALGORITHM_SLH_DSA, bytes: slh_dsa.public_key_bytes().to_vec() });
        }
        PublicKeyBundle { components }
    }

    pub fn pubkey(&self) -> Pubkey {
        self.public_key_bundle().to_address()
    }

    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<MultiSignature> {
        let ed_sig: DalekSignature = self.ed25519.sign(msg);
        let mldsa_sig = mldsa::sign(&self.mldsa_sk, msg)?;
        let mut components = vec![
            KeyComponent { scheme: ALGORITHM_ED25519, bytes: ed_sig.to_bytes().to_vec() },
            KeyComponent { scheme: ALGORITHM_ML_DSA_65, bytes: mldsa_sig },
        ];
        if let Some(slh_dsa) = &self.slh_dsa {
            components.push(KeyComponent { scheme: ALGORITHM_SLH_DSA, bytes: slh_dsa.sign(msg)? });
        }
        Ok(MultiSignature { components })
    }
}

/// Verify a multi-scheme signature: resolves which combo `bundle` claims
/// from the sequence of schemes in its components
/// (`registry::combo_from_components`) and rejects outright if none match -
/// this is what stops an attacker from dropping/substituting/reordering a
/// mandatory factor and still passing (see module docs). If a combo
/// resolves, **every** component of that combo must independently verify.
/// Callers are still responsible for separately checking that `bundle`
/// actually hashes to the address it claims to represent
/// (`PublicKeyBundle::to_address`).
pub fn verify(bundle: &PublicKeyBundle, msg: &[u8], signature: &MultiSignature) -> bool {
    let schemes: Vec<AlgorithmId> = bundle.components.iter().map(|c| c.scheme).collect();
    let Some(_combo) = combo_from_components(&schemes) else { return false };
    if signature.components.len() != bundle.components.len() {
        return false;
    }
    for (pk_comp, sig_comp) in bundle.components.iter().zip(signature.components.iter()) {
        if pk_comp.scheme != sig_comp.scheme {
            return false;
        }
        let ok = if pk_comp.scheme == ALGORITHM_ED25519 {
            let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk_comp.bytes.as_slice()), <[u8; 64]>::try_from(sig_comp.bytes.as_slice()))
            else {
                return false;
            };
            verify_ed25519_component(&pk, msg, &sig)
        } else if pk_comp.scheme == ALGORITHM_ML_DSA_65 {
            verify_ml_dsa_65_component(&pk_comp.bytes, msg, &sig_comp.bytes)
        } else if pk_comp.scheme == ALGORITHM_SLH_DSA {
            verify_slh_dsa_component(&pk_comp.bytes, msg, &sig_comp.bytes)
        } else {
            // A known combo can only be built from schemes this crate
            // knows how to verify (see `combo_components`) - reaching
            // here would mean the registry and this match fell out of
            // sync, so fail closed rather than silently accept.
            false
        };
        if !ok {
            return false;
        }
    }
    true
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
            // `verify_strict`, not `verify`: the non-strict path accepts
            // non-canonical `S`/`R` encodings, which makes ed25519 signatures
            // malleable - an observer of a pending transaction could produce
            // a variant signature that still verifies, changing the
            // transaction's own hash (its Narwhal batch digest and RPC txid)
            // without the payer's involvement. Nonce-based replay protection
            // means this can't double-spend, but a stable txid is a real
            // client-facing promise, and consensus vote/certificate digests
            // should likewise not be third-party-malleable. `verify_strict`
            // rejects the non-canonical encodings, closing it.
            vk.verify_strict(msg, &dsig).is_ok()
        }
        Err(_) => false,
    }
}

/// Verify just the ML-DSA-65 half against a raw public key. See
/// `verify_ed25519_component` docs for why this is exposed standalone.
pub fn verify_ml_dsa_65_component(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    mldsa::verify(pubkey, msg, sig)
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

/// Keypair file layout: JSON array of bytes, length-prefixed fields -
/// ed25519 keypair [64 bytes], ML-DSA-65 secret key, ML-DSA-65 public key,
/// combo id [2 bytes LE], then (only if the combo includes SLH-DSA)
/// SLH-DSA secret key, SLH-DSA public key - fully self-contained, since
/// liboqs can't re-derive a public key from its secret key alone for
/// either PQC scheme.
pub fn write_keypair_file(keypair: &Keypair, path: &std::path::Path) -> anyhow::Result<()> {
    let ed_bytes = keypair.ed25519.to_keypair_bytes();
    let combo_bytes = keypair.combo.0.to_le_bytes();
    let mut fields: Vec<&[u8]> = vec![&ed_bytes, &keypair.mldsa_sk, &keypair.mldsa_pk, &combo_bytes];
    if let Some(slh_dsa) = &keypair.slh_dsa {
        fields.push(slh_dsa.secret_key_bytes());
        fields.push(slh_dsa.public_key_bytes());
    }
    let encoded = encode_length_prefixed(&fields);
    let bytes = serde_json::to_vec(&encoded)?;
    // This file holds the RAW secret keys (Ed25519 + ML-DSA-65 + optional
    // SLH-DSA). `std::fs::write` would create it 0644 (world-readable under the
    // usual umask), leaking the private key to any local user / co-located
    // service / container-mount reader. Write it 0600 atomically in the shared
    // primitive so EVERY caller (CLI keygen, faucet keygen, the custodial web
    // wallet) is covered, not just the three files the installer chmods after
    // the fact (which also left a create->chmod race).
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(&bytes)?;
        // `mode(0o600)` only applies on creation; force it for an overwrite of
        // a pre-existing (possibly 0644) file too.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &bytes)?;
    }
    Ok(())
}

pub fn read_keypair_file(path: &std::path::Path) -> anyhow::Result<Keypair> {
    let contents = std::fs::read(path)?;
    let encoded: Vec<u8> = serde_json::from_slice(&contents)?;
    // Decode the always-present 4 fields first to learn the combo, then
    // (only if it needs SLH-DSA) decode again from the same in-memory
    // bytes with the extra 2 fields included.
    let fields = decode_length_prefixed(&encoded, 4)?;
    let ed_bytes: [u8; 64] = fields[0]
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ed25519 keypair length"))?;
    let ed25519 = SigningKey::from_keypair_bytes(&ed_bytes).map_err(|e| anyhow::anyhow!("invalid ed25519 bytes: {e}"))?;
    let combo_bytes: [u8; 2] = fields[3].as_slice().try_into().map_err(|_| anyhow::anyhow!("invalid combo id length"))?;
    let combo = AlgorithmId(u16::from_le_bytes(combo_bytes));
    let required = combo_components(combo).ok_or_else(|| anyhow::anyhow!("unknown combo id in keypair file: {combo:?}"))?;
    let slh_dsa = if required.contains(&ALGORITHM_SLH_DSA) {
        let all_fields = decode_length_prefixed(&encoded, 6)?;
        Some(SlhDsaKeypair::from_raw_parts(all_fields[5].clone(), all_fields[4].clone()))
    } else {
        None
    };
    Ok(Keypair {
        combo,
        ed25519,
        mldsa_sk: fields[1].clone(),
        mldsa_pk: fields[2].clone(),
        slh_dsa,
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
    fn address_is_bound_to_every_component() {
        let kp = Keypair::generate().unwrap();
        let mut bundle = kp.public_key_bundle();
        bundle.components[0].bytes[0] ^= 0xFF;
        assert_ne!(bundle.to_address(), kp.pubkey());
    }

    #[test]
    fn dropping_a_mandatory_component_is_rejected_not_silently_accepted() {
        // An attacker can't just omit the ML-DSA-65 half and pass with a
        // bare Ed25519 signature - the dropped bundle resolves to no known
        // combo, so `verify` rejects outright regardless of whether the
        // remaining Ed25519 component genuinely verifies.
        let kp = Keypair::generate().unwrap();
        let msg = b"hello qchain";
        let mut sig = kp.sign(msg).unwrap();
        let mut bundle = kp.public_key_bundle();
        bundle.components.truncate(1);
        sig.components.truncate(1);
        assert!(!verify(&bundle, msg, &sig));
    }

    #[test]
    fn triple_combo_with_slh_dsa_signs_and_verifies() {
        let kp = Keypair::generate_with_slh_dsa().unwrap();
        assert_eq!(kp.combo(), COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA);
        let msg = b"hello qchain, triple hybrid";
        let sig = kp.sign(msg).unwrap();
        let bundle = kp.public_key_bundle();
        assert_eq!(bundle.components.len(), 3);
        assert_eq!(sig.components.len(), 3);
        assert!(verify(&bundle, msg, &sig));
    }

    #[test]
    fn triple_combo_signature_is_rejected_if_the_slh_dsa_component_is_tampered() {
        let kp = Keypair::generate_with_slh_dsa().unwrap();
        let msg = b"hello qchain";
        let mut sig = kp.sign(msg).unwrap();
        let last = sig.components.len() - 1;
        sig.components[last].bytes[0] ^= 0xFF;
        assert!(!verify(&kp.public_key_bundle(), msg, &sig));
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
        assert_eq!(kp2.combo(), COMBO_HYBRID_ED25519_ML_DSA_65);
        let sig = kp2.sign(b"roundtrip").unwrap();
        assert!(verify(&kp2.public_key_bundle(), b"roundtrip", &sig));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn keypair_file_roundtrip_preserves_the_slh_dsa_triple_combo() {
        let dir = std::env::temp_dir().join(format!("qchain-test-slhdsa-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("id.json");
        let kp = Keypair::generate_with_slh_dsa().unwrap();
        write_keypair_file(&kp, &path).unwrap();
        let kp2 = read_keypair_file(&path).unwrap();
        assert_eq!(kp.pubkey(), kp2.pubkey());
        assert_eq!(kp2.combo(), COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA);
        let sig = kp2.sign(b"roundtrip").unwrap();
        assert!(verify(&kp2.public_key_bundle(), b"roundtrip", &sig));
        std::fs::remove_file(&path).ok();
    }
}
