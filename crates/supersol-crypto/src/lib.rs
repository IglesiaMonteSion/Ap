//! Cryptographic primitives for SuperSol: keypairs, addresses and hybrid
//! classical + post-quantum signatures.
//!
//! Every SuperSol key is a **hybrid** key: an ed25519 keypair (fast, small,
//! battle-tested) paired with an ML-DSA-65 keypair (NIST FIPS 204,
//! "Module-Lattice-Based Digital Signature Standard" - the standardized
//! successor to CRYSTALS-Dilithium, believed hard to break even for an
//! attacker with a large quantum computer). A transaction is only valid if
//! **both** signatures verify. This defense-in-depth is deliberate: if either
//! scheme is ever broken (a cryptanalytic break of ed25519, or a flaw found
//! in this still-young PQ standard), funds stay safe as long as the *other*
//! scheme holds.
//!
//! Addresses (`Pubkey`) stay a compact 32-byte hash of both public keys
//! (`sha256(ed25519_pubkey || mldsa_pubkey)`), base58-encoded exactly like a
//! Solana address, rather than exposing the much larger raw ML-DSA public
//! key (1952 bytes) in every address. The full key material only needs to
//! travel alongside a transaction, at spend time - the same "reveal the key
//! only when you spend" pattern Bitcoin uses for P2PKH addresses.

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as MlDsaSigner, Verifier as MlDsaVerifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

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

// Serialized as its base58 string (not the raw byte array) so pubkeys read
// naturally in JSON-RPC payloads, matching what Solana users expect.
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

impl Pubkey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Pubkey(bytes)
    }

    /// The all-zero pubkey, used as the id of the built-in System Program.
    pub const fn system_program_id() -> Self {
        Pubkey([0u8; 32])
    }

    /// The fixed-supply treasury account: holds the entire genesis mint
    /// until it's disbursed (e.g. via a devnet faucet). No keypair hashes to
    /// this address - it is a hardcoded sentinel, not derived from any real
    /// ed25519/ML-DSA key pair - so it can never be the payer of an ordinary
    /// signed transaction. The only way funds leave it is through whatever
    /// explicit, policy-controlled disbursement path a validator chooses to
    /// run (see `Ledger::disburse_from_treasury`), never a forged signature.
    pub const fn treasury() -> Self {
        Pubkey([
            0x54, 0x52, 0x45, 0x41, 0x53, 0x55, 0x52, 0x59, // "TREASURY"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
    }

    /// The staking-rewards reserve: a fixed slice of the genesis supply set
    /// aside to fund staking rewards without inflating past the 700M cap.
    /// Like the treasury, this is a hardcoded sentinel with no corresponding
    /// keypair - only the protocol's own reward-distribution logic
    /// (`Ledger::distribute_staking_rewards`) can move funds out of it.
    pub const fn staking_rewards_pool() -> Self {
        Pubkey([
            0x53, 0x54, 0x41, 0x4B, 0x45, 0x50, 0x4F, 0x4F, 0x4C, // "STAKEPOOL"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pubkey({})", self)
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

/// ed25519 signatures are 64 bytes, longer than serde's built-in array
/// support (which only covers arrays up to 32 elements), so we (de)serialize
/// as a hex string instead - this also happens to make it readable in
/// JSON-RPC payloads.
#[derive(Clone, Copy)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
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
            return Err(serde::de::Error::custom(format!(
                "invalid signature length: expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature(arr))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self)
    }
}

/// The raw dual public keys behind an address. A `Pubkey` is only
/// `sha256(ed25519 || mldsa)`; this bundle is what a transaction actually
/// carries so a validator can recompute that hash (proving the bundle really
/// belongs to the claimed address) and verify both signatures against it.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct PublicKeyBundle {
    pub ed25519: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub mldsa: Vec<u8>,
}

impl PublicKeyBundle {
    pub fn to_address(&self) -> Pubkey {
        let mut hasher = Sha256::new();
        hasher.update(self.ed25519);
        hasher.update(&self.mldsa);
        Pubkey(hasher.finalize().into())
    }
}

/// A signature covering both schemes. Both parts must verify for the
/// signature as a whole to be considered valid.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct HybridSignature {
    pub ed25519: Signature,
    #[serde(with = "hex_bytes")]
    pub mldsa: Vec<u8>,
}

/// A keypair identifying a wallet or a validator: an ed25519 keypair plus an
/// ML-DSA-65 (post-quantum) keypair, used together for every signature.
pub struct Keypair {
    ed25519: SigningKey,
    mldsa_sk_bytes: [u8; ml_dsa_65::SK_LEN],
    mldsa_pk_bytes: [u8; ml_dsa_65::PK_LEN],
}

impl Keypair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let ed25519 = SigningKey::generate(&mut csprng);
        let (mldsa_pk, mldsa_sk) = ml_dsa_65::KG::try_keygen().expect("ML-DSA-65 key generation failed");
        Keypair {
            ed25519,
            mldsa_sk_bytes: mldsa_sk.into_bytes(),
            mldsa_pk_bytes: mldsa_pk.into_bytes(),
        }
    }

    /// Load from the (ed25519 keypair bytes || ML-DSA-65 secret key bytes)
    /// layout written by `write_keypair_file`.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let expected_len = 64 + ml_dsa_65::SK_LEN;
        if bytes.len() != expected_len {
            anyhow::bail!("invalid keypair: expected {expected_len} bytes, got {}", bytes.len());
        }
        let mut ed_bytes = [0u8; 64];
        ed_bytes.copy_from_slice(&bytes[..64]);
        let ed25519 = SigningKey::from_keypair_bytes(&ed_bytes)
            .map_err(|e| anyhow::anyhow!("invalid ed25519 keypair bytes: {e}"))?;

        let mut mldsa_sk_bytes = [0u8; ml_dsa_65::SK_LEN];
        mldsa_sk_bytes.copy_from_slice(&bytes[64..]);
        let mldsa_sk = ml_dsa_65::PrivateKey::try_from_bytes(mldsa_sk_bytes)
            .map_err(|e| anyhow::anyhow!("invalid ML-DSA-65 secret key: {e}"))?;
        let mldsa_pk_bytes = mldsa_sk.get_public_key().into_bytes();

        Ok(Keypair {
            ed25519,
            mldsa_sk_bytes,
            mldsa_pk_bytes,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + ml_dsa_65::SK_LEN);
        out.extend_from_slice(&self.ed25519.to_keypair_bytes());
        out.extend_from_slice(&self.mldsa_sk_bytes);
        out
    }

    pub fn public_key_bundle(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            ed25519: self.ed25519.verifying_key().to_bytes(),
            mldsa: self.mldsa_pk_bytes.to_vec(),
        }
    }

    pub fn pubkey(&self) -> Pubkey {
        self.public_key_bundle().to_address()
    }

    pub fn sign(&self, msg: &[u8]) -> HybridSignature {
        let ed_sig: DalekSignature = self.ed25519.sign(msg);
        let mldsa_sk = ml_dsa_65::PrivateKey::try_from_bytes(self.mldsa_sk_bytes)
            .expect("keypair was constructed with a valid ML-DSA-65 secret key");
        let mldsa_sig = mldsa_sk
            .try_sign(msg, &[])
            .expect("ML-DSA-65 signing failed");
        HybridSignature {
            ed25519: Signature(ed_sig.to_bytes()),
            mldsa: mldsa_sig.to_vec(),
        }
    }
}

/// Write a keypair to disk as a JSON array of bytes: ed25519 keypair (64
/// bytes, secret || public - the same layout Solana's `solana-keygen` uses)
/// followed by the ML-DSA-65 secret key.
pub fn write_keypair_file(keypair: &Keypair, path: &std::path::Path) -> anyhow::Result<()> {
    let bytes = keypair.to_bytes();
    let json = serde_json::to_vec(&bytes)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn read_keypair_file(path: &std::path::Path) -> anyhow::Result<Keypair> {
    let contents = std::fs::read(path)?;
    let bytes: Vec<u8> = serde_json::from_slice(&contents)?;
    Keypair::from_bytes(&bytes)
}

/// Verify a hybrid signature: both the ed25519 and the ML-DSA-65 parts must
/// be valid for `msg` under the keys in `bundle`. Callers are responsible for
/// separately checking that `bundle` actually hashes to the address it
/// claims to represent (see `PublicKeyBundle::to_address`).
pub fn verify(bundle: &PublicKeyBundle, msg: &[u8], signature: &HybridSignature) -> bool {
    let ed_ok = match VerifyingKey::from_bytes(&bundle.ed25519) {
        Ok(vk) => {
            let dsig = DalekSignature::from_bytes(&signature.ed25519.0);
            vk.verify(msg, &dsig).is_ok()
        }
        Err(_) => false,
    };
    if !ed_ok {
        return false;
    }

    let Ok(pk_bytes) = <[u8; ml_dsa_65::PK_LEN]>::try_from(bundle.mldsa.as_slice()) else {
        return false;
    };
    let Ok(pk) = ml_dsa_65::PublicKey::try_from_bytes(pk_bytes) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; ml_dsa_65::SIG_LEN]>::try_from(signature.mldsa.as_slice()) else {
        return false;
    };
    pk.verify(msg, &sig_bytes, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate();
        let msg = b"hello supersol";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_key_bundle(), msg, &sig));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"hello supersol");
        assert!(!verify(&kp.public_key_bundle(), b"goodbye supersol", &sig));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let kp = Keypair::generate();
        let other = Keypair::generate();
        let sig = kp.sign(b"hello supersol");
        assert!(!verify(&other.public_key_bundle(), b"hello supersol", &sig));
    }

    #[test]
    fn keypair_bytes_roundtrip() {
        let kp = Keypair::generate();
        let bytes = kp.to_bytes();
        let kp2 = Keypair::from_bytes(&bytes).unwrap();
        assert_eq!(kp.pubkey(), kp2.pubkey());
        // The reloaded keypair must still be able to produce valid signatures.
        let sig = kp2.sign(b"hello supersol");
        assert!(verify(&kp2.public_key_bundle(), b"hello supersol", &sig));
    }

    #[test]
    fn pubkey_display_and_parse_roundtrip() {
        let kp = Keypair::generate();
        let s = kp.pubkey().to_string();
        let parsed: Pubkey = s.parse().unwrap();
        assert_eq!(kp.pubkey(), parsed);
    }

    #[test]
    fn address_is_bound_to_both_public_keys() {
        let kp = Keypair::generate();
        let mut bundle = kp.public_key_bundle();
        bundle.ed25519[0] ^= 0xFF;
        assert_ne!(bundle.to_address(), kp.pubkey());
    }

    /// Not a correctness test - a throughput measurement, run explicitly with
    /// `cargo test --release -p supersol-crypto -- --ignored --nocapture`.
    /// Grounds the README's TPS estimate in a real number instead of a
    /// guess: this is the single-core cost of verifying one transaction's
    /// signature, which is the dominant per-transaction cost in this engine.
    #[test]
    #[ignore]
    fn bench_hybrid_verify_throughput() {
        use std::time::Instant;

        let kp = Keypair::generate();
        let msg = b"benchmark message payload, roughly transaction-sized-ish";
        let sig = kp.sign(msg);
        let bundle = kp.public_key_bundle();
        assert!(verify(&bundle, msg, &sig));

        const ITERS: u32 = 2_000;

        let start = Instant::now();
        for _ in 0..ITERS {
            std::hint::black_box(verify(&bundle, msg, &sig));
        }
        let hybrid_elapsed = start.elapsed();

        let ed_vk = VerifyingKey::from_bytes(&bundle.ed25519).unwrap();
        let ed_dsig = DalekSignature::from_bytes(&sig.ed25519.0);
        let start = Instant::now();
        for _ in 0..ITERS {
            std::hint::black_box(ed_vk.verify(msg, &ed_dsig).is_ok());
        }
        let ed25519_elapsed = start.elapsed();

        println!(
            "hybrid verify:  {:>8.2} ops/sec ({:>6.2} us/op)",
            ITERS as f64 / hybrid_elapsed.as_secs_f64(),
            hybrid_elapsed.as_secs_f64() * 1_000_000.0 / ITERS as f64
        );
        println!(
            "ed25519 verify: {:>8.2} ops/sec ({:>6.2} us/op) - included above, shown for comparison",
            ITERS as f64 / ed25519_elapsed.as_secs_f64(),
            ed25519_elapsed.as_secs_f64() * 1_000_000.0 / ITERS as f64
        );
    }

    #[test]
    #[ignore]
    fn bench_hybrid_sign_throughput() {
        use std::time::Instant;

        let kp = Keypair::generate();
        let msg = b"benchmark message payload, roughly transaction-sized-ish";

        const ITERS: u32 = 2_000;
        let start = Instant::now();
        for _ in 0..ITERS {
            std::hint::black_box(kp.sign(msg));
        }
        let elapsed = start.elapsed();
        println!(
            "hybrid sign:    {:>8.2} ops/sec ({:>6.2} us/op)",
            ITERS as f64 / elapsed.as_secs_f64(),
            elapsed.as_secs_f64() * 1_000_000.0 / ITERS as f64
        );
    }
}
