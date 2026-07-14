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
    // Fail-loud, deliberately (same philosophy as `SledStore` refusing to
    // run on corrupt data): a silent `if let Ok(...)` would, on a
    // serialization failure, hash *only* the domain separator - producing
    // exactly `Sha3(0x00)`, which is `empty_hashes()[0]`, the hash of an
    // *absent* leaf. That would make a real account collide with "no
    // account here", letting an exclusion proof validate against a
    // populated slot (mint/erase value). Borsh encoding of an in-memory
    // `Account` (fixed-size + `Vec<u8>` fields) has no realistic failure
    // mode, so this `expect` is a theoretical-collision backstop, not a
    // hot path that ever fires.
    let bytes = borsh::to_vec(account).expect("borsh encoding of an Account cannot fail");
    hasher.update(bytes);
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// `mask_prefix(key, d)` zeroes every bit at index `>= d`, leaving only
/// the `d` bits that address a subtree rooted at depth `d` - the
/// canonical form `IncrementalStateTree`'s cache keys on, so two calls
/// that mean "the same subtree" always produce the same cache key
/// regardless of what garbage lives in the tail bits of whatever `key`
/// happened to be passed in.
fn mask_prefix(key: &[u8; 32], depth: usize) -> [u8; 32] {
    let mut out = *key;
    if depth >= KEY_BITS {
        return out;
    }
    let full_bytes = depth / 8;
    let rem_bits = depth % 8;
    if rem_bits != 0 {
        out[full_bytes] &= 0xFFu8 << (8 - rem_bits);
        for b in &mut out[full_bytes + 1..] {
            *b = 0;
        }
    } else {
        for b in &mut out[full_bytes..] {
            *b = 0;
        }
    }
    out
}

fn prefix_with_bit(key: &[u8; 32], depth: usize, bit_value: bool) -> [u8; 32] {
    let mut out = mask_prefix(key, depth + 1);
    let byte_idx = depth / 8;
    let bit_idx = 7 - (depth % 8);
    if bit_value {
        out[byte_idx] |= 1 << bit_idx;
    } else {
        out[byte_idx] &= !(1 << bit_idx);
    }
    out
}

/// A real incremental sparse Merkle tree - the "always-live incremental
/// tree" this module's own doc comment names as the deferred phase-2
/// optimization over the plain `StateTree` above, which recomputes the
/// entire root from every populated leaf on every single call
/// (`O(accounts × 256)`). Measured live (not estimated) against a real
/// validator under real sustained transfer load: that recompute cost -
/// not post-quantum signature verification, the initially reasonable
/// suspicion - was the dominant driver of a single node saturating a
/// full CPU core at a quite modest real transaction rate (`Ledger`
/// calls `root()`/`prove()` up to six times per single-instruction
/// `Transfer`, for the before/after receipt capture alone). See
/// `project-lessons-learned` for the full measurement.
///
/// Caches, per materialized (non-empty) subtree, `(depth, masked
/// prefix) -> subtree hash` - `note_set` updates exactly the `KEY_BITS`
/// (256) cache entries on the changed leaf's own root-to-leaf path,
/// independent of how many other accounts exist; `root()` is then an
/// `O(1)` cache read and `prove()` an `O(KEY_BITS)` walk of direct cache
/// lookups, neither of which re-touches any other leaf. This trades
/// `StateTree`'s "no memory beyond the store itself" property for real
/// memory proportional to `accounts × KEY_BITS` cache entries (the same
/// order `StateTree` used to *recompute* on every call, just paid once
/// as memory instead of repeatedly as CPU) - a real, quantifiable,
/// worthwhile trade for a validator that queries its own root far more
/// often than accounts are created.
///
/// Deliberately **not** a drop-in replacement for `StateTree`'s API:
/// `StateTree` stays exactly as-is (still the correctness reference
/// every test in this module and `qchain-stark` compares against) and
/// stays the only implementation used against an arbitrary, possibly
/// third-party `&dyn StateStore` (there is no way to keep an incremental
/// cache in sync with a store this type never observes mutations on).
/// `IncrementalStateTree` is for exactly one situation: a long-lived
/// owner (`Ledger`) that itself performs every mutation and can
/// therefore call `note_set` at each one - see `Ledger`'s doc comments
/// for the enumerated call sites that make this invariant hold.
///
/// Only ever needs `note_set`, never a matching "note removed": this
/// project's own execution model never deletes a `StateStore` row (a
/// closed stake account is zeroed, not removed - see `staking.rs`'s
/// module docs), so nothing in real `Ledger` operation ever needs the
/// tree to forget a key it once saw. A hypothetical caller that *did*
/// need real removal would have to extend this type - not silently
/// mishandled, just genuinely out of scope for what `Ledger` needs.
#[derive(Clone)]
pub struct IncrementalStateTree {
    empty: Vec<[u8; 32]>,
    cache: std::collections::HashMap<(u16, [u8; 32]), [u8; 32]>,
}

impl Default for IncrementalStateTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalStateTree {
    pub fn new() -> Self {
        IncrementalStateTree { empty: empty_hashes(), cache: std::collections::HashMap::new() }
    }

    pub fn empty_leaf_hash(&self) -> [u8; 32] {
        self.empty[0]
    }

    fn cached_or_empty(&self, depth: usize, prefix: [u8; 32]) -> [u8; 32] {
        self.cache.get(&(depth as u16, prefix)).copied().unwrap_or(self.empty[KEY_BITS - depth])
    }

    /// Must be called for every real committed `StateStore::set` this
    /// tree is tracking, with the account's *new* contents - see the
    /// struct docs for why this project never needs a removal
    /// counterpart. `O(KEY_BITS)`, independent of how many other
    /// accounts exist.
    pub fn note_set(&mut self, key: &Pubkey, account: &Account) {
        let full_key = key.to_bytes();
        let mut current = hash_leaf(account);
        self.cache.insert((KEY_BITS as u16, full_key), current);
        for depth in (0..KEY_BITS).rev() {
            let bit = bit_at(&full_key, depth);
            let sibling = self.cached_or_empty(depth + 1, prefix_with_bit(&full_key, depth, !bit));
            current = if bit { hash_internal(&sibling, &current) } else { hash_internal(&current, &sibling) };
            self.cache.insert((depth as u16, mask_prefix(&full_key, depth)), current);
        }
    }

    /// The tracked root - an `O(1)` cache read, not a recompute.
    pub fn root(&self) -> [u8; 32] {
        self.cached_or_empty(0, [0u8; 32])
    }

    /// A real inclusion/exclusion proof against the tracked state -
    /// `O(KEY_BITS)` direct cache lookups, never touches any other
    /// account's data.
    pub fn prove(&self, key: &Pubkey) -> MerkleProof {
        let target = key.to_bytes();
        let mut siblings = Vec::with_capacity(KEY_BITS);
        for depth in (0..KEY_BITS).rev() {
            siblings.push(self.cached_or_empty(depth + 1, prefix_with_bit(&target, depth, !bit_at(&target, depth))));
        }
        let leaf_hash = self.cache.get(&(KEY_BITS as u16, target)).copied().unwrap_or(self.empty[0]);
        let leaf_value_hash = if leaf_hash == self.empty[0] { None } else { Some(leaf_hash) };
        MerkleProof { key: target, leaf_value_hash, siblings }
    }

    /// What `root()` would become if `changes` (a small, bounded set -
    /// in practice one transaction's working set, not the whole account
    /// universe) were applied on top of the tracked state, without
    /// mutating this tree - `O(changes.len() × KEY_BITS)`: any subtree
    /// with no pending change underneath it is read straight from the
    /// existing cache instead of being walked. This is what lets
    /// `Ledger`'s pre-commit "what would the root become" receipt
    /// capture (see `ledger.rs`'s `pre_capture`/`root_after`) stay cheap
    /// too, not just the already-committed `root()`/`prove()` above.
    pub fn root_with_pending(&self, changes: &[(Pubkey, Account)]) -> [u8; 32] {
        let leaves: Vec<Leaf> = changes.iter().map(|(k, a)| (k.to_bytes(), hash_leaf(a))).collect();
        self.pending_root(0, [0u8; 32], &leaves)
    }

    /// Same idea as `root_with_pending`, for a single key's
    /// inclusion/exclusion proof against the hypothetical post-`changes`
    /// state.
    pub fn prove_with_pending(&self, key: &Pubkey, changes: &[(Pubkey, Account)]) -> MerkleProof {
        let leaves: Vec<Leaf> = changes.iter().map(|(k, a)| (k.to_bytes(), hash_leaf(a))).collect();
        let target = key.to_bytes();
        let mut siblings = Vec::with_capacity(KEY_BITS);
        let leaf_hash = self.pending_proof(0, [0u8; 32], &target, &leaves, &mut siblings);
        let leaf_value_hash = if leaf_hash == self.empty[0] { None } else { Some(leaf_hash) };
        MerkleProof { key: target, leaf_value_hash, siblings }
    }

    fn pending_root(&self, depth: usize, prefix: [u8; 32], leaves: &[Leaf]) -> [u8; 32] {
        if leaves.is_empty() {
            return self.cached_or_empty(depth, prefix);
        }
        if depth == KEY_BITS {
            return leaves[0].1;
        }
        let (left, right) = partition(leaves, depth);
        let lh = self.pending_root(depth + 1, prefix, &left);
        let rh = self.pending_root(depth + 1, prefix_with_bit(&prefix, depth, true), &right);
        hash_internal(&lh, &rh)
    }

    fn pending_proof(&self, depth: usize, prefix: [u8; 32], target: &[u8; 32], leaves: &[Leaf], siblings: &mut Vec<[u8; 32]>) -> [u8; 32] {
        if depth == KEY_BITS {
            return leaves.iter().find(|(k, _)| k == target).map(|(_, v)| *v).unwrap_or_else(|| self.cached_or_empty(depth, prefix));
        }
        let (left, right) = partition(leaves, depth);
        let target_right = bit_at(target, depth);
        let (same_side, other_side) = if target_right { (&right, &left) } else { (&left, &right) };
        let other_prefix = prefix_with_bit(&prefix, depth, !target_right);
        let other_hash = if other_side.is_empty() { self.cached_or_empty(depth + 1, other_prefix) } else { self.pending_root(depth + 1, other_prefix, other_side) };
        let same_prefix = prefix_with_bit(&prefix, depth, target_right);
        let leaf_hash = self.pending_proof(depth + 1, same_prefix, target, same_side, siblings);
        siblings.push(other_hash);
        leaf_hash
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

    /// `IncrementalStateTree` is a real rewrite of a security-relevant
    /// primitive (the state commitment `qchain-stark` and light clients
    /// both bind to) purely for performance - so every one of its outputs
    /// is checked step by step against `StateTree`, the simple,
    /// obviously-correct reference this module already trusted, over a
    /// real sequence of inserts/updates across several accounts. Any
    /// divergence here would mean a validator computing a root/proof
    /// that disagrees with what the same state "really" hashes to -
    /// exactly the class of bug worth a dedicated equivalence test, not
    /// just "it compiles and returns *a* hash."
    #[test]
    fn incremental_tree_matches_the_reference_tree_after_every_insert_and_update() {
        let mut store = InMemoryStore::new();
        let reference = StateTree::new();
        let mut incremental = IncrementalStateTree::new();
        let keys: Vec<Pubkey> = (0..5).map(|_| Keypair::generate().unwrap().pubkey()).collect();

        assert_eq!(incremental.root(), reference.root(&store));

        for (i, key) in keys.iter().enumerate() {
            let account = wallet(1_000 + i as u64);
            store.set(*key, account.clone());
            incremental.note_set(key, &account);
            assert_eq!(incremental.root(), reference.root(&store), "root diverged after inserting account {i}");
            for k in &keys {
                assert_eq!(incremental.prove(k), reference.prove(&store, k), "proof for a known key diverged after inserting account {i}");
            }
        }

        // A ghost key never inserted must still prove exclusion identically.
        let ghost = Keypair::generate().unwrap().pubkey();
        assert_eq!(incremental.prove(&ghost), reference.prove(&store, &ghost));

        // Updating an existing account's balance must move both trees
        // identically, not just "insert" behavior.
        let updated = wallet(50_000);
        store.set(keys[2], updated.clone());
        incremental.note_set(&keys[2], &updated);
        assert_eq!(incremental.root(), reference.root(&store));
        assert_eq!(incremental.prove(&keys[2]), reference.prove(&store, &keys[2]));
    }

    /// `root_with_pending`/`prove_with_pending` model `Ledger`'s
    /// "what would the root become if this transaction's working set
    /// were applied" query (`ledger.rs`'s `root_after`) - checked against
    /// actually applying the same changes to a real store and asking the
    /// slow, trusted `StateTree` for the answer, without ever calling
    /// `note_set` on the incremental tree for those pending changes
    /// (they're hypothetical, not yet committed).
    #[test]
    fn pending_root_and_proof_match_actually_applying_the_change() {
        let mut store = InMemoryStore::new();
        let mut incremental = IncrementalStateTree::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let bob = Keypair::generate().unwrap().pubkey();
        let carol = Keypair::generate().unwrap().pubkey(); // never touched - must still prove correctly

        for (k, balance) in [(alice, 5_000), (bob, 2_000), (carol, 9_000)] {
            let account = wallet(balance);
            store.set(k, account.clone());
            incremental.note_set(&k, &account);
        }

        let pending = vec![(alice, wallet(4_000)), (bob, wallet(3_000))];

        let pending_root = incremental.root_with_pending(&pending);
        let pending_proof_alice = incremental.prove_with_pending(&alice, &pending);
        let pending_proof_carol = incremental.prove_with_pending(&carol, &pending);

        // Actually apply the same change to an independent store and ask
        // the trusted, slow reference tree what the real answer is.
        let mut applied_store = InMemoryStore::new();
        applied_store.set(alice, wallet(5_000));
        applied_store.set(bob, wallet(2_000));
        applied_store.set(carol, wallet(9_000));
        for (k, v) in &pending {
            applied_store.set(*k, v.clone());
        }
        let reference = StateTree::new();

        assert_eq!(pending_root, reference.root(&applied_store));
        assert_eq!(pending_proof_alice, reference.prove(&applied_store, &alice));
        assert_eq!(pending_proof_carol, reference.prove(&applied_store, &carol), "an untouched account's proof must still reflect real committed state, not empty");

        // The real, committed tree must be untouched by a pending query.
        assert_ne!(incremental.root(), pending_root);
    }

    #[test]
    fn pending_root_of_a_brand_new_account_proves_correctly() {
        let mut store = InMemoryStore::new();
        let mut incremental = IncrementalStateTree::new();
        let alice = Keypair::generate().unwrap().pubkey();
        let new_account_key = Keypair::generate().unwrap().pubkey();
        store.set(alice, wallet(1_000));
        incremental.note_set(&alice, &wallet(1_000));

        let pending = vec![(new_account_key, wallet(777))];
        let pending_root = incremental.root_with_pending(&pending);
        let pending_proof = incremental.prove_with_pending(&new_account_key, &pending);

        let mut applied_store = InMemoryStore::new();
        applied_store.set(alice, wallet(1_000));
        applied_store.set(new_account_key, wallet(777));
        let reference = StateTree::new();

        assert_eq!(pending_root, reference.root(&applied_store));
        assert_eq!(pending_proof, reference.prove(&applied_store, &new_account_key));
    }
}
