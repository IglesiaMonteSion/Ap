//! A hash-based sparse Merkle tree over 256-bit account addresses -
//! explicitly not a Verkle tree (see `ARCHITECTURE.md` §3 and the
//! `stark-proofs-and-hash-commitments` skill for why: Verkle's practical
//! instantiation depends on KZG, which is pairing-based and broken by
//! Shor's algorithm exactly like BLS aggregation is). Every hash in this
//! module is SHA3-256 - no elliptic curve operation anywhere in the state
//! commitment path.
//!
//! Simplification flagged explicitly: this implementation recomputes the
//! root from the full populated-leaf set on every `root()`/`prove()` call
//! (`O(accounts × 256)`) rather than maintaining an always-live incremental
//! tree, and proofs always walk the full 256 levels rather than compressing
//! empty-subtree runs into extension nodes. Both are legitimate phase-2
//! optimizations once account counts grow past what recomputation handles
//! comfortably - correctness doesn't depend on either optimization, so
//! deferring them doesn't compromise the commitment's soundness, only its
//! performance at scale.

use crate::store::StateStore;
use qchain_core::Account;
use qchain_crypto::Pubkey;
use sha3::{Digest, Sha3_256};

pub const KEY_BITS: usize = 256;

/// Real leaf-hashing function for the state tree - `SHA3-256` of a domain
/// separator plus the full borsh-encoded `Account`. Exposed `pub` (not
/// just crate-internal) so external verifiers that need to bind a claim
/// about an account's contents to a real Merkle root - e.g.
/// `qchain-stark`'s state-tie-in - can compute the exact same leaf hash
/// this tree itself uses, rather than reimplementing (and risking
/// drifting from) this logic in a second place.
pub fn hash_leaf(account: &Account) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update([0x00]); // domain separator: leaf
    if let Ok(bytes) = borsh::to_vec(account) {
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

fn hash_internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update([0x01]); // domain separator: internal node
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn bit_at(key: &[u8; 32], depth: usize) -> bool {
    let byte = key[depth / 8];
    let bit_index = 7 - (depth % 8);
    (byte >> bit_index) & 1 == 1
}

/// `empty_hashes()[d]` is the root hash of an empty subtree covering `d`
/// levels (`d = 0` is an empty leaf, `d = KEY_BITS` is the whole empty
/// tree). Precomputed once; every empty region of the tree at a given depth
/// shares this same hash, which is what lets a sparse tree avoid ever
/// materializing the (astronomically many) actually-empty nodes.
pub fn empty_hashes() -> Vec<[u8; 32]> {
    let mut hashes = Vec::with_capacity(KEY_BITS + 1);
    let mut hasher = Sha3_256::new();
    hasher.update([0x00]);
    hashes.push(hasher.finalize().into());
    for d in 1..=KEY_BITS {
        let prev = hashes[d - 1];
        hashes.push(hash_internal(&prev, &prev));
    }
    hashes
}

type Leaf = ([u8; 32], [u8; 32]);

fn partition(leaves: &[Leaf], depth: usize) -> (Vec<Leaf>, Vec<Leaf>) {
    let mut left = Vec::new();
    let mut right = Vec::new();
    for &(k, v) in leaves {
        if bit_at(&k, depth) {
            right.push((k, v));
        } else {
            left.push((k, v));
        }
    }
    (left, right)
}

fn compute_root(leaves: &[Leaf], depth: usize, empty: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty[KEY_BITS - depth];
    }
    if depth == KEY_BITS {
        return leaves[0].1;
    }
    let (left, right) = partition(leaves, depth);
    let lh = compute_root(&left, depth + 1, empty);
    let rh = compute_root(&right, depth + 1, empty);
    hash_internal(&lh, &rh)
}

/// Returns (leaf value hash - `empty[0]` if the key is absent, proving
/// exclusion, siblings ordered leaf-to-root).
fn compute_proof(leaves: &[Leaf], depth: usize, target: &[u8; 32], empty: &[[u8; 32]], siblings: &mut Vec<[u8; 32]>) -> [u8; 32] {
    if depth == KEY_BITS {
        return leaves.iter().find(|(k, _)| k == target).map(|(_, v)| *v).unwrap_or(empty[0]);
    }
    let (left, right) = partition(leaves, depth);
    let target_right = bit_at(target, depth);
    let (same_side, other_side) = if target_right { (&right, &left) } else { (&left, &right) };
    let other_hash = compute_root(other_side, depth + 1, empty);
    let leaf_hash = compute_proof(same_side, depth + 1, target, empty, siblings);
    siblings.push(other_hash);
    leaf_hash
}

/// Serialize/Deserialize added for real transport - a light client
/// receiving a `qchain-stark` state-bound proof over RPC needs these
/// over the wire, not just in-process.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    pub key: [u8; 32],
    /// `None` if this proves the account does *not* exist (exclusion
    /// proof) - the sparse tree makes both kinds of proof equally cheap.
    pub leaf_value_hash: Option<[u8; 32]>,
    /// Sibling hashes, ordered leaf-to-root, always `KEY_BITS` long.
    pub siblings: Vec<[u8; 32]>,
}

pub fn verify_proof(root: [u8; 32], proof: &MerkleProof, empty_leaf_hash: [u8; 32]) -> bool {
    if proof.siblings.len() != KEY_BITS {
        return false;
    }
    let mut current = proof.leaf_value_hash.unwrap_or(empty_leaf_hash);
    for (i, sibling) in proof.siblings.iter().enumerate() {
        let depth = KEY_BITS - 1 - i;
        let bit = bit_at(&proof.key, depth);
        current = if bit {
            hash_internal(sibling, &current)
        } else {
            hash_internal(&current, sibling)
        };
    }
    current == root
}

/// Computes the tree root and proofs over whatever a `StateStore`
/// currently holds. Stateless itself (other than the precomputed empty
/// hash table) - the store is always the source of truth.
pub struct StateTree {
    empty: Vec<[u8; 32]>,
}

impl Default for StateTree {
    fn default() -> Self {
        Self::new()
    }
}

impl StateTree {
    pub fn new() -> Self {
        StateTree { empty: empty_hashes() }
    }

    pub fn empty_leaf_hash(&self) -> [u8; 32] {
        self.empty[0]
    }

    fn leaves(&self, store: &dyn StateStore) -> Vec<Leaf> {
        store.iter().map(|(pk, acc)| (pk.to_bytes(), hash_leaf(&acc))).collect()
    }

    pub fn root(&self, store: &dyn StateStore) -> [u8; 32] {
        compute_root(&self.leaves(store), 0, &self.empty)
    }

    pub fn prove(&self, store: &dyn StateStore, key: &Pubkey) -> MerkleProof {
        let leaves = self.leaves(store);
        let target = key.to_bytes();
        let mut siblings = Vec::with_capacity(KEY_BITS);
        let leaf_hash = compute_proof(&leaves, 0, &target, &self.empty, &mut siblings);
        let leaf_value_hash = if leaf_hash == self.empty[0] { None } else { Some(leaf_hash) };
        MerkleProof {
            key: target,
            leaf_value_hash,
            siblings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;
    use qchain_crypto::Keypair;

    fn wallet(balance: u64) -> Account {
        Account {
            balance,
            nonce: 0,
            algorithm_id: qchain_crypto::COMBO_HYBRID_ED25519_ML_DSA_65,
            owner: Pubkey::system_program_id(),
            code_hash: [0u8; 32],
            data: vec![],
        }
    }

    #[test]
    fn empty_store_root_matches_empty_hash() {
        let store = InMemoryStore::new();
        let tree = StateTree::new();
        assert_eq!(tree.root(&store), tree.empty[KEY_BITS]);
    }

    #[test]
    fn inclusion_proof_verifies_against_the_real_root() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));
        store.set(bob, wallet(2_000));

        let tree = StateTree::new();
        let root = tree.root(&store);
        let proof = tree.prove(&store, &alice);

        assert!(proof.leaf_value_hash.is_some());
        assert!(verify_proof(root, &proof, tree.empty_leaf_hash()));
    }

    #[test]
    fn exclusion_proof_verifies_for_an_absent_account() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let ghost = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));

        let tree = StateTree::new();
        let root = tree.root(&store);
        let proof = tree.prove(&store, &ghost);

        assert!(proof.leaf_value_hash.is_none());
        assert!(verify_proof(root, &proof, tree.empty_leaf_hash()));
    }

    #[test]
    fn tampered_proof_fails_verification() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));

        let tree = StateTree::new();
        let root = tree.root(&store);
        let mut proof = tree.prove(&store, &alice);
        proof.siblings[0][0] ^= 0xFF;

        assert!(!verify_proof(root, &proof, tree.empty_leaf_hash()));
    }

    #[test]
    fn root_changes_when_a_balance_changes() {
        let mut store = InMemoryStore::new();
        let alice = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));
        let tree = StateTree::new();
        let root1 = tree.root(&store);

        store.set(alice, wallet(999));
        let root2 = tree.root(&store);

        assert_ne!(root1, root2);
    }
}
