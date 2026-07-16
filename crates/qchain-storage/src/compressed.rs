//! Path-compressed sparse Merkle tree (Jellyfish/patricia style) over 256-bit
//! account addresses - the O(log n) replacement for the fixed 256-deep
//! `tree::StateTree`/`IncrementalStateTree`, whose every account write folds a
//! leaf through all 256 levels (measured: ~82% of `apply_transaction`'s cost is
//! these tree-write hashes; shrinking the depth 256->32 as a probe took apply
//! from 712 to 3162 tx/s, a 4.4x speedup).
//!
//! The idea: a lone leaf deep in the tree is represented by *just its leaf
//! hash*, with the long single-child chain of empty siblings above it
//! **compressed away** (never hashed). Only genuine branch points - depths where
//! two populated subtrees diverge - cost a hash. For n random accounts a leaf's
//! path branches within ~log2(n) levels of the root, so a write hashes ~log2(n)
//! nodes instead of 256.
//!
//! **This changes the state root.** It is a deliberately different commitment
//! from `tree.rs` (different domain separators, compressed shape), so a network
//! adopting it needs a fresh genesis - it is NOT an in-place upgrade of an
//! existing chain. `tree.rs` stays as the untouched reference/legacy tree.
//!
//! Security (same bar as the 256-deep tree):
//! - A leaf node commits to its **full key** (`H(0x03 || key || value_hash)`),
//!   so a leaf cannot be moved to a different position, and an exclusion proof
//!   that terminates at a *different* leaf is unambiguous (the verifier checks
//!   the terminal leaf's key != the queried key).
//! - Distinct domain separators for leaf (`0x03`), internal (`0x04`), and the
//!   single empty-subtree constant (`0x05`) make a leaf, an internal node, and
//!   an empty subtree mutually non-collidable - closing the "a leaf could be
//!   read as a subtree" class of bug that plagues naive compressed trees.
//! - Every hash is SHA3-256 - no elliptic-curve / pairing operation anywhere,
//!   same post-quantum-conservative choice as `tree.rs`.

use qchain_core::Account;
use qchain_crypto::Pubkey;
use sha3::{Digest, Sha3_256};

use crate::tree::hash_leaf;

/// Hash of an empty subtree. A single constant suffices (unlike the 256-deep
/// tree's per-depth `empty_hashes()`): compression means an empty region is
/// always a terminal, never an intermediate node whose value depends on its
/// height.
pub fn empty_node() -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update([0x05]); // domain separator: empty subtree
    h.finalize().into()
}

/// Node hash of a leaf: `SHA3(0x03 || key || value_hash)`, where `value_hash`
/// is the SAME per-account value hash the legacy tree uses (`tree::hash_leaf`).
/// Committing to the full key is what makes a compressed leaf's position
/// unambiguous.
pub fn leaf_node(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update([0x03]); // domain separator: leaf
    h.update(key);
    h.update(value_hash);
    h.finalize().into()
}

fn internal_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update([0x04]); // domain separator: internal
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn bit_at(key: &[u8; 32], depth: usize) -> bool {
    let byte = key[depth / 8];
    let bit_index = 7 - (depth % 8);
    (byte >> bit_index) & 1 == 1
}

type Leaf = ([u8; 32], [u8; 32]); // (key, value_hash)

fn partition(leaves: &[Leaf], depth: usize) -> (Vec<Leaf>, Vec<Leaf>) {
    let mut left = Vec::new();
    let mut right = Vec::new();
    for &l in leaves {
        if bit_at(&l.0, depth) {
            right.push(l);
        } else {
            left.push(l);
        }
    }
    (left, right)
}

/// Root of the subtree covering the leaves that share the first `depth` bits.
/// Compression: a single-child subtree descends WITHOUT hashing (the empty
/// sibling contributes nothing to a compressed commitment); a lone leaf is just
/// its leaf hash; an empty set is the empty constant.
fn compute_root(leaves: &[Leaf], depth: usize) -> [u8; 32] {
    match leaves.len() {
        0 => empty_node(),
        1 => leaf_node(&leaves[0].0, &leaves[0].1),
        _ => {
            let (left, right) = partition(leaves, depth);
            if left.is_empty() {
                compute_root(&right, depth + 1)
            } else if right.is_empty() {
                compute_root(&left, depth + 1)
            } else {
                internal_node(&compute_root(&left, depth + 1), &compute_root(&right, depth + 1))
            }
        }
    }
}

/// One step of a proof: the sibling subtree hash and the branch depth at which
/// it sits. The verifier folds these leaf-to-root, combining with the query key's
/// bit at each `depth`. Only real branch points appear (compressed levels are
/// absent), so the list is ~log2(n) long, not 256.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ProofStep {
    pub depth: u16,
    pub sibling: [u8; 32],
}

/// What a lookup terminates at: the key's own leaf (inclusion), a *different*
/// leaf occupying the compressed slot (exclusion), or an empty subtree
/// (exclusion). Carries exactly what the verifier needs to recompute the
/// terminal node hash and to confirm non-membership.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum Terminal {
    /// The queried key's own leaf value hash (inclusion proof).
    Leaf { value_hash: [u8; 32] },
    /// A different key's leaf sits where the query would go (exclusion).
    OtherLeaf { key: [u8; 32], value_hash: [u8; 32] },
    /// The query lands in an empty subtree (exclusion).
    Empty,
}

/// A compressed inclusion OR exclusion proof for one key. Bound to a root by
/// `verify_proof`. `steps` are ordered LEAF-TO-ROOT.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CompressedProof {
    pub key: [u8; 32],
    pub terminal: Terminal,
    pub steps: Vec<ProofStep>,
}

impl CompressedProof {
    /// Whether this proves the key is PRESENT (vs an exclusion proof).
    pub fn is_inclusion(&self) -> bool {
        matches!(self.terminal, Terminal::Leaf { .. })
    }
    /// The proven value hash if this is an inclusion proof.
    pub fn value_hash(&self) -> Option<[u8; 32]> {
        match self.terminal {
            Terminal::Leaf { value_hash } => Some(value_hash),
            _ => None,
        }
    }
}

fn compute_proof(leaves: &[Leaf], depth: usize, target: &[u8; 32], steps: &mut Vec<ProofStep>) -> Terminal {
    match leaves.len() {
        0 => Terminal::Empty,
        1 => {
            let (k, v) = leaves[0];
            if &k == target {
                Terminal::Leaf { value_hash: v }
            } else {
                Terminal::OtherLeaf { key: k, value_hash: v }
            }
        }
        _ => {
            let (left, right) = partition(leaves, depth);
            if left.is_empty() {
                compute_proof(&right, depth + 1, target, steps)
            } else if right.is_empty() {
                compute_proof(&left, depth + 1, target, steps)
            } else {
                let target_right = bit_at(target, depth);
                let (same, other) = if target_right { (&right, &left) } else { (&left, &right) };
                let other_hash = compute_root(other, depth + 1);
                let terminal = compute_proof(same, depth + 1, target, steps);
                // Pushed AFTER the recursion, so `steps` ends up leaf-to-root.
                steps.push(ProofStep { depth: depth as u16, sibling: other_hash });
                terminal
            }
        }
    }
}

/// Verify a compressed proof against `root`. For an inclusion proof, also
/// checks the terminal is the queried key's leaf; for an exclusion proof, checks
/// the terminal is empty or a DIFFERENT key's leaf. Folding uses only the
/// branch steps, so it is O(steps) = ~O(log n), never 256.
pub fn verify_proof(root: [u8; 32], proof: &CompressedProof) -> bool {
    let mut current = match &proof.terminal {
        Terminal::Leaf { value_hash } => leaf_node(&proof.key, value_hash),
        Terminal::OtherLeaf { key, value_hash } => {
            // An exclusion proof that terminates at another leaf must be a
            // genuinely different key, or it proves nothing.
            if key == &proof.key {
                return false;
            }
            leaf_node(key, value_hash)
        }
        Terminal::Empty => empty_node(),
    };
    for step in &proof.steps {
        let d = step.depth as usize;
        current = if bit_at(&proof.key, d) {
            internal_node(&step.sibling, &current)
        } else {
            internal_node(&current, &step.sibling)
        };
    }
    current == root
}

/// Builds a compressed tree root and proofs from a full leaf set - the
/// reference/functional form (the incremental owner-maintained form is
/// `IncrementalCompressedTree`). Stateless beyond its inputs.
pub struct CompressedStateTree;

impl CompressedStateTree {
    pub fn root(leaves: &[Leaf]) -> [u8; 32] {
        compute_root(leaves, 0)
    }

    pub fn root_from_accounts<'a>(accounts: impl Iterator<Item = (&'a Pubkey, &'a Account)>) -> [u8; 32] {
        let leaves: Vec<Leaf> = accounts.map(|(k, a)| (k.to_bytes(), hash_leaf(a))).collect();
        Self::root(&leaves)
    }

    pub fn prove(leaves: &[Leaf], key: &[u8; 32]) -> CompressedProof {
        let mut steps = Vec::new();
        let terminal = compute_proof(leaves, 0, key, &mut steps);
        CompressedProof { key: *key, terminal, steps }
    }
}

fn first_diff_bit(a: &[u8; 32], b: &[u8; 32]) -> usize {
    for d in 0..256 {
        if bit_at(a, d) != bit_at(b, d) {
            return d;
        }
    }
    256 // equal keys
}

/// Owner-maintained incremental compressed tree - the O(log n)-per-write
/// counterpart of `tree::IncrementalStateTree` (which is O(256) per write). A
/// single `insert` touches only the nodes on the changed leaf's branch path
/// (~log2(n) of them), recomputing exactly those node hashes. `root()` is O(1)
/// (the root node's cached hash) and `prove()` an O(log n) walk. Same use model
/// as `IncrementalStateTree`: a single owner (`Ledger`) that performs every
/// mutation calls `insert` at each one.
#[derive(Clone, Debug)]
enum CNode {
    Empty,
    Leaf { key: [u8; 32], value: [u8; 32], hash: [u8; 32] },
    /// Branches at bit `depth`; `rep` is a representative key of some leaf in
    /// this subtree (all leaves here agree on bits `[0, depth)`).
    Internal { depth: usize, rep: [u8; 32], left: Box<CNode>, right: Box<CNode>, hash: [u8; 32] },
}

impl CNode {
    fn hash(&self) -> [u8; 32] {
        match self {
            CNode::Empty => empty_node(),
            CNode::Leaf { hash, .. } => *hash,
            CNode::Internal { hash, .. } => *hash,
        }
    }

    fn leaf(key: [u8; 32], value: [u8; 32]) -> CNode {
        CNode::Leaf { key, value, hash: leaf_node(&key, &value) }
    }

    fn branch(depth: usize, rep: [u8; 32], left: CNode, right: CNode) -> CNode {
        let hash = internal_node(&left.hash(), &right.hash());
        CNode::Internal { depth, rep, left: Box::new(left), right: Box::new(right), hash }
    }

    fn insert(self, key: [u8; 32], value: [u8; 32]) -> CNode {
        match self {
            CNode::Empty => CNode::leaf(key, value),
            CNode::Leaf { key: k, value: v, .. } => {
                if k == key {
                    CNode::leaf(key, value) // update in place
                } else {
                    let d = first_diff_bit(&k, &key);
                    let existing = CNode::leaf(k, v);
                    let fresh = CNode::leaf(key, value);
                    if bit_at(&key, d) {
                        CNode::branch(d, k, existing, fresh)
                    } else {
                        CNode::branch(d, k, fresh, existing)
                    }
                }
            }
            CNode::Internal { depth, rep, left, right, .. } => {
                let d = first_diff_bit(&key, &rep);
                if d < depth {
                    // The new key diverges from this whole subtree above its
                    // branch point - split here, with the existing subtree on
                    // one side and the new leaf on the other.
                    let existing = CNode::Internal { depth, rep, left, right, hash: [0; 32] }.rehash();
                    let fresh = CNode::leaf(key, value);
                    if bit_at(&key, d) {
                        CNode::branch(d, rep, existing, fresh)
                    } else {
                        CNode::branch(d, rep, fresh, existing)
                    }
                } else {
                    // Shares the prefix - descend into the matching child.
                    if bit_at(&key, depth) {
                        let nr = right.insert(key, value);
                        CNode::branch(depth, rep, *left, nr)
                    } else {
                        let nl = left.insert(key, value);
                        CNode::branch(depth, rep, nl, *right)
                    }
                }
            }
        }
    }

    fn rehash(self) -> CNode {
        match self {
            CNode::Internal { depth, rep, left, right, .. } => {
                let hash = internal_node(&left.hash(), &right.hash());
                CNode::Internal { depth, rep, left, right, hash }
            }
            other => other,
        }
    }

    fn prove(&self, target: &[u8; 32], steps: &mut Vec<ProofStep>) -> Terminal {
        match self {
            CNode::Empty => Terminal::Empty,
            CNode::Leaf { key, value, .. } => {
                if key == target {
                    Terminal::Leaf { value_hash: *value }
                } else {
                    Terminal::OtherLeaf { key: *key, value_hash: *value }
                }
            }
            CNode::Internal { depth, left, right, .. } => {
                let (same, other): (&CNode, &CNode) = if bit_at(target, *depth) { (right, left) } else { (left, right) };
                let other_hash = other.hash();
                let terminal = same.prove(target, steps);
                steps.push(ProofStep { depth: *depth as u16, sibling: other_hash });
                terminal
            }
        }
    }
}

/// Incremental compressed state tree (see `CNode`). Same role as
/// `tree::IncrementalStateTree`, O(log n) instead of O(256) per write.
#[derive(Clone)]
pub struct IncrementalCompressedTree {
    root: CNode,
}

impl Default for IncrementalCompressedTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalCompressedTree {
    pub fn new() -> Self {
        IncrementalCompressedTree { root: CNode::Empty }
    }

    /// Insert or update an account. Must be called for every committed
    /// `StateStore::set` this tree tracks (same contract as
    /// `IncrementalStateTree::note_set`).
    pub fn note_set(&mut self, key: &Pubkey, account: &Account) {
        let k = key.to_bytes();
        let v = hash_leaf(account);
        let root = std::mem::replace(&mut self.root, CNode::Empty);
        self.root = root.insert(k, v);
    }

    pub fn root(&self) -> [u8; 32] {
        self.root.hash()
    }

    pub fn prove(&self, key: &Pubkey) -> CompressedProof {
        let target = key.to_bytes();
        let mut steps = Vec::new();
        let terminal = self.root.prove(&target, &mut steps);
        CompressedProof { key: target, terminal, steps }
    }

    /// What `root()` would become if `changes` (a small, bounded set - in
    /// practice one transaction's working set, not the whole account universe)
    /// were applied on top of the committed tree, WITHOUT mutating it. The
    /// compressed-tree counterpart of `IncrementalStateTree::root_with_pending`,
    /// and what lets `Ledger`'s STARK receipt capture (`pre_capture`/`root_after`)
    /// stay cheap in compressed mode too. Cost is `O(changes × log n)`: any
    /// committed subtree with no pending change underneath it is read straight
    /// from its cached node hash in `O(1)` (the `pending.is_empty()` short
    /// circuit in `merged_hash`), never walked.
    pub fn root_with_pending(&self, changes: &[(Pubkey, Account)]) -> [u8; 32] {
        let leaves: Vec<Leaf> = changes.iter().map(|(k, a)| (k.to_bytes(), hash_leaf(a))).collect();
        merged_hash(&self.root, &leaves, 0)
    }

    /// Same idea as `root_with_pending`, for a single key's inclusion/exclusion
    /// proof against the hypothetical post-`changes` state. A sibling subtree
    /// untouched by any pending change contributes its committed node hash in
    /// `O(1)`; only the target's path and the paths of the pending changes are
    /// walked.
    pub fn prove_with_pending(&self, key: &Pubkey, changes: &[(Pubkey, Account)]) -> CompressedProof {
        let leaves: Vec<Leaf> = changes.iter().map(|(k, a)| (k.to_bytes(), hash_leaf(a))).collect();
        let target = key.to_bytes();
        let mut steps = Vec::new();
        let terminal = merged_prove(&self.root, &leaves, 0, &target, &mut steps);
        CompressedProof { key: target, terminal, steps }
    }
}

/// Hash of the subtree represented by `node` with `pending` leaves additionally
/// inserted, where every leaf under `node` and every `pending` key share the
/// first `depth` bits (the invariant the recursion maintains as it descends).
/// `pending` empty ⇒ the committed `node.hash()` verbatim, in `O(1)` - the whole
/// point, so an untouched subtree costs nothing.
fn merged_hash(node: &CNode, pending: &[Leaf], depth: usize) -> [u8; 32] {
    if pending.is_empty() {
        return node.hash();
    }
    match node {
        CNode::Empty => compute_root(pending, depth),
        CNode::Leaf { key, value, .. } => {
            // The existing lone leaf, plus the pending leaves (a pending change
            // to the same key overrides it). Order-independent `compute_root`
            // gives the canonical compressed shape for this small leaf set.
            let mut set: Vec<Leaf> = pending.to_vec();
            if !pending.iter().any(|(k, _)| k == key) {
                set.push((*key, *value));
            }
            compute_root(&set, depth)
        }
        CNode::Internal { depth: nd, rep, left, right, .. } => {
            let nd = *nd;
            // The earliest bit (within [depth, nd)) at which any pending key
            // diverges from this whole subtree's shared prefix. `>= nd` means
            // every pending key belongs INSIDE the node (routed by bit `nd`).
            let mut min_div = nd;
            for (k, _) in pending {
                let b = first_diff_bit(k, rep);
                if b < min_div {
                    min_div = b;
                }
            }
            if min_div >= nd {
                let (pl, pr) = partition(pending, nd);
                let lh = merged_hash(left, &pl, nd + 1);
                let rh = merged_hash(right, &pr, nd + 1);
                internal_node(&lh, &rh)
            } else {
                // A new branch appears at `min_div`, above this internal node:
                // the entire existing node sits on `rep`'s side (all its leaves
                // agree with `rep` through bit `nd-1 >= min_div`), pending splits
                // by bit `min_div`.
                let rep_bit = bit_at(rep, min_div);
                let (pl, pr) = partition(pending, min_div);
                let (rep_pending, other_pending) = if rep_bit { (pr, pl) } else { (pl, pr) };
                let rep_hash = merged_hash(node, &rep_pending, min_div + 1);
                let other_hash = compute_root(&other_pending, min_div + 1);
                let (lh, rh) = if rep_bit { (other_hash, rep_hash) } else { (rep_hash, other_hash) };
                internal_node(&lh, &rh)
            }
        }
    }
}

/// Inclusion/exclusion proof for `target` against the hypothetical post-`pending`
/// state, mirroring `merged_hash`'s structure. A sibling subtree with no pending
/// change is folded in via its committed hash (through the `pending.is_empty()`
/// short circuit inside `merged_hash`), so only the target's path and the pending
/// paths are walked. Same invariant: `target` and every leaf under `node` share
/// the first `depth` bits.
fn merged_prove(node: &CNode, pending: &[Leaf], depth: usize, target: &[u8; 32], steps: &mut Vec<ProofStep>) -> Terminal {
    if pending.is_empty() {
        return node.prove(target, steps);
    }
    match node {
        CNode::Empty => compute_proof(pending, depth, target, steps),
        CNode::Leaf { key, value, .. } => {
            let mut set: Vec<Leaf> = pending.to_vec();
            if !pending.iter().any(|(k, _)| k == key) {
                set.push((*key, *value));
            }
            compute_proof(&set, depth, target, steps)
        }
        CNode::Internal { depth: nd, rep, left, right, .. } => {
            let nd = *nd;
            let mut min_div = nd;
            for (k, _) in pending {
                let b = first_diff_bit(k, rep);
                if b < min_div {
                    min_div = b;
                }
            }
            if min_div >= nd {
                let (pl, pr) = partition(pending, nd);
                if bit_at(target, nd) {
                    let other_hash = merged_hash(left, &pl, nd + 1);
                    let terminal = merged_prove(right, &pr, nd + 1, target, steps);
                    steps.push(ProofStep { depth: nd as u16, sibling: other_hash });
                    terminal
                } else {
                    let other_hash = merged_hash(right, &pr, nd + 1);
                    let terminal = merged_prove(left, &pl, nd + 1, target, steps);
                    steps.push(ProofStep { depth: nd as u16, sibling: other_hash });
                    terminal
                }
            } else {
                let rep_bit = bit_at(rep, min_div);
                let (pl, pr) = partition(pending, min_div);
                let (rep_pending, other_pending) = if rep_bit { (pr, pl) } else { (pl, pr) };
                if bit_at(target, min_div) == rep_bit {
                    // Target descends with the existing node; sibling is the
                    // pending-only other side.
                    let other_hash = compute_root(&other_pending, min_div + 1);
                    let terminal = merged_prove(node, &rep_pending, min_div + 1, target, steps);
                    steps.push(ProofStep { depth: min_div as u16, sibling: other_hash });
                    terminal
                } else {
                    // Target descends into the pending-only other side; sibling
                    // is the existing node merged with its share of pending.
                    let rep_hash = merged_hash(node, &rep_pending, min_div + 1);
                    let terminal = compute_proof(&other_pending, min_div + 1, target, steps);
                    steps.push(ProofStep { depth: min_div as u16, sibling: rep_hash });
                    terminal
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::hash_leaf;
    use qchain_core::Account;

    fn acct(balance: u64) -> Account {
        Account { balance, ..Account::new_wallet(Pubkey::system_program_id()) }
    }

    fn key(seed: u8) -> [u8; 32] {
        // Distinct, deterministic keys with varied bit patterns.
        let mut h = Sha3_256::new();
        h.update([seed]);
        h.finalize().into()
    }

    fn leaves_of(items: &[(u8, u64)]) -> Vec<Leaf> {
        items.iter().map(|&(s, b)| (key(s), hash_leaf(&acct(b)))).collect()
    }

    #[test]
    fn empty_tree_root_is_the_empty_constant() {
        assert_eq!(CompressedStateTree::root(&[]), empty_node());
    }

    #[test]
    fn single_leaf_root_is_just_its_leaf_hash_regardless_of_key() {
        for s in 0..8u8 {
            let l = leaves_of(&[(s, 100)]);
            assert_eq!(CompressedStateTree::root(&l), leaf_node(&l[0].0, &l[0].1));
        }
    }

    #[test]
    fn root_is_order_independent() {
        let a = leaves_of(&[(1, 10), (2, 20), (3, 30), (9, 90), (200, 5)]);
        let mut b = a.clone();
        b.reverse();
        let mut c = a.clone();
        c.rotate_left(2);
        assert_eq!(CompressedStateTree::root(&a), CompressedStateTree::root(&b));
        assert_eq!(CompressedStateTree::root(&a), CompressedStateTree::root(&c));
    }

    #[test]
    fn inclusion_proofs_verify_for_every_present_key() {
        let items: Vec<(u8, u64)> = (0..40u8).map(|s| (s, (s as u64 + 1) * 7)).collect();
        let leaves = leaves_of(&items);
        let root = CompressedStateTree::root(&leaves);
        for &(s, _) in &items {
            let p = CompressedStateTree::prove(&leaves, &key(s));
            assert!(p.is_inclusion(), "key {s} must prove present");
            assert!(verify_proof(root, &p), "inclusion proof for key {s} must verify");
        }
    }

    #[test]
    fn exclusion_proofs_verify_for_absent_keys() {
        let items: Vec<(u8, u64)> = (0..30u8).map(|s| (s, s as u64 + 1)).collect();
        let leaves = leaves_of(&items);
        let root = CompressedStateTree::root(&leaves);
        for s in 100..140u8 {
            let p = CompressedStateTree::prove(&leaves, &key(s));
            assert!(!p.is_inclusion(), "key {s} must prove absent");
            assert!(verify_proof(root, &p), "exclusion proof for key {s} must verify");
        }
    }

    #[test]
    fn a_tampered_value_breaks_the_inclusion_proof() {
        let leaves = leaves_of(&[(1, 10), (2, 20), (3, 30)]);
        let root = CompressedStateTree::root(&leaves);
        let mut p = CompressedStateTree::prove(&leaves, &key(2));
        // Flip the proven value hash.
        if let Terminal::Leaf { value_hash } = &mut p.terminal {
            value_hash[0] ^= 0xFF;
        }
        assert!(!verify_proof(root, &p), "a tampered value must not verify against the real root");
    }

    #[test]
    fn an_exclusion_proof_cannot_be_forged_for_a_present_key() {
        // Take a present key's inclusion proof and try to pass it off as an
        // exclusion by relabeling the terminal as OtherLeaf with the SAME key.
        let leaves = leaves_of(&[(1, 10), (2, 20), (3, 30)]);
        let root = CompressedStateTree::root(&leaves);
        let p = CompressedStateTree::prove(&leaves, &key(2));
        let forged = CompressedProof {
            key: p.key,
            terminal: Terminal::OtherLeaf { key: p.key, value_hash: p.value_hash().unwrap() },
            steps: p.steps.clone(),
        };
        assert!(!verify_proof(root, &forged), "OtherLeaf with the queried key must be rejected");
    }

    #[test]
    fn a_sibling_swap_breaks_the_proof() {
        let leaves = leaves_of(&[(1, 10), (2, 20), (3, 30), (4, 40)]);
        let root = CompressedStateTree::root(&leaves);
        let mut p = CompressedStateTree::prove(&leaves, &key(1));
        if let Some(s) = p.steps.first_mut() {
            s.sibling[0] ^= 0xFF;
        }
        assert!(!verify_proof(root, &p), "a corrupted sibling must not verify");
    }

    /// The whole point: a leaf's proof has ~log2(n) steps, not 256.
    #[test]
    fn proof_length_is_logarithmic_not_256() {
        let items: Vec<(u8, u64)> = (0..64u8).map(|s| (s, 1)).collect();
        let leaves = leaves_of(&items);
        for &(s, _) in &items {
            let p = CompressedStateTree::prove(&leaves, &key(s));
            assert!(p.steps.len() < 32, "a compressed proof over 64 leaves should be <32 steps, got {}", p.steps.len());
        }
    }

    fn wide_key(seed: u32) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(seed.to_le_bytes());
        h.finalize().into()
    }

    /// The incremental tree MUST agree with the functional reference on every
    /// root - inserts AND in-place updates, in any order. This is the
    /// correctness anchor that makes the fast path trustworthy.
    #[test]
    fn incremental_matches_the_functional_reference_root() {
        let mut inc = IncrementalCompressedTree::new();
        let mut leaves: std::collections::BTreeMap<[u8; 32], [u8; 32]> = std::collections::BTreeMap::new();
        // 300 inserts, then updates to a third of them.
        for i in 0..300u32 {
            let pk = Pubkey::new(wide_key(i));
            let a = acct((i as u64 + 1) * 13);
            inc.note_set(&pk, &a);
            leaves.insert(wide_key(i), hash_leaf(&a));
            let set: Vec<Leaf> = leaves.iter().map(|(k, v)| (*k, *v)).collect();
            assert_eq!(inc.root(), CompressedStateTree::root(&set), "root diverged after insert {i}");
        }
        for i in (0..300u32).step_by(3) {
            let pk = Pubkey::new(wide_key(i));
            let a = acct(999_000 + i as u64);
            inc.note_set(&pk, &a);
            leaves.insert(wide_key(i), hash_leaf(&a));
            let set: Vec<Leaf> = leaves.iter().map(|(k, v)| (*k, *v)).collect();
            assert_eq!(inc.root(), CompressedStateTree::root(&set), "root diverged after update {i}");
        }
    }

    #[test]
    fn incremental_proofs_verify_inclusion_and_exclusion() {
        let mut inc = IncrementalCompressedTree::new();
        for i in 0..128u32 {
            inc.note_set(&Pubkey::new(wide_key(i)), &acct(i as u64 + 1));
        }
        let root = inc.root();
        for i in 0..128u32 {
            let p = inc.prove(&Pubkey::new(wide_key(i)));
            assert!(p.is_inclusion() && verify_proof(root, &p), "present key {i} must prove+verify");
        }
        for i in 1000..1064u32 {
            let p = inc.prove(&Pubkey::new(wide_key(i)));
            assert!(!p.is_inclusion() && verify_proof(root, &p), "absent key {i} must prove exclusion+verify");
        }
    }

    /// `root_with_pending`/`prove_with_pending` must agree, for BOTH the root
    /// and every key's proof, with the ground truth: collect the committed leaf
    /// set, overlay the pending changes, and ask the order-independent functional
    /// reference. This is the correctness anchor that makes the efficient merged
    /// walk (which reads untouched subtrees straight from cached node hashes)
    /// trustworthy - exactly the equivalence test the legacy tree has for its own
    /// `pending` path. Covered: a pending update to an existing key, a pending
    /// brand-new key, an untouched key's proof, and an absent key's exclusion.
    #[test]
    fn pending_root_and_proofs_match_the_functional_overlay() {
        let mut inc = IncrementalCompressedTree::new();
        let mut committed: std::collections::BTreeMap<[u8; 32], [u8; 32]> = std::collections::BTreeMap::new();
        for i in 0..200u32 {
            let pk = Pubkey::new(wide_key(i));
            let a = acct((i as u64 + 1) * 11);
            inc.note_set(&pk, &a);
            committed.insert(wide_key(i), hash_leaf(&a));
        }

        // Pending working set: update an existing account, add a brand-new one.
        let updated_key = Pubkey::new(wide_key(37));
        let updated_acct = acct(500_000);
        let new_key = Pubkey::new(wide_key(9_999));
        let new_acct = acct(777_777);
        let pending = vec![(updated_key, updated_acct.clone()), (new_key, new_acct.clone())];

        // Ground truth: committed leaves with the pending overlay applied.
        let mut overlay = committed.clone();
        overlay.insert(updated_key.to_bytes(), hash_leaf(&updated_acct));
        overlay.insert(new_key.to_bytes(), hash_leaf(&new_acct));
        let overlay_leaves: Vec<Leaf> = overlay.iter().map(|(k, v)| (*k, *v)).collect();
        let truth_root = CompressedStateTree::root(&overlay_leaves);

        assert_eq!(inc.root_with_pending(&pending), truth_root, "pending root must match the functional overlay");
        // The committed tree must be untouched by a pending query.
        assert_ne!(inc.root(), truth_root);

        // Proofs for: the updated key, the brand-new key, an untouched key, and
        // an absent key - each against the hypothetical post-pending state.
        for probe in [updated_key, new_key, Pubkey::new(wide_key(120)), Pubkey::new(wide_key(50_000))] {
            let p = inc.prove_with_pending(&probe, &pending);
            let truth = CompressedStateTree::prove(&overlay_leaves, &probe.to_bytes());
            assert_eq!(p, truth, "pending proof for a probed key must match the functional overlay");
            assert!(verify_proof(truth_root, &p), "pending proof must verify against the pending root");
        }
    }

    /// A pending change on an empty tree, and pending changes that force a NEW
    /// branch point above an existing internal node (keys sharing a long prefix
    /// with a committed key), exercise the merged walk's Empty/Leaf and
    /// `min_div < nd` branches respectively.
    #[test]
    fn pending_merge_handles_empty_tree_and_new_branch_points() {
        // Empty tree: pending root/proof must equal a fresh functional tree.
        let empty = IncrementalCompressedTree::new();
        let k0 = Pubkey::new(wide_key(1));
        let a0 = acct(42);
        let pending0 = vec![(k0, a0.clone())];
        let leaves0 = vec![(k0.to_bytes(), hash_leaf(&a0))];
        assert_eq!(empty.root_with_pending(&pending0), CompressedStateTree::root(&leaves0));
        assert_eq!(empty.prove_with_pending(&k0, &pending0), CompressedStateTree::prove(&leaves0, &k0.to_bytes()));

        // Force a new branch: commit one key, then a pending key crafted to
        // share a prefix and diverge partway - and a couple of ordinary keys.
        let mut inc = IncrementalCompressedTree::new();
        let mut committed: std::collections::BTreeMap<[u8; 32], [u8; 32]> = std::collections::BTreeMap::new();
        for i in 0..8u32 {
            let pk = Pubkey::new(wide_key(i));
            let a = acct(i as u64 + 1);
            inc.note_set(&pk, &a);
            committed.insert(wide_key(i), hash_leaf(&a));
        }
        // A pending key that equals a committed key in its first byte but not
        // after - lands near an existing leaf, splitting deep.
        let base = wide_key(3);
        let mut near = base;
        near[16] ^= 0x01; // diverge in the middle
        let near_pk = Pubkey::new(near);
        let near_acct = acct(123_456);
        let pending = vec![(near_pk, near_acct.clone())];

        let mut overlay = committed.clone();
        overlay.insert(near, hash_leaf(&near_acct));
        let overlay_leaves: Vec<Leaf> = overlay.iter().map(|(k, v)| (*k, *v)).collect();
        let truth_root = CompressedStateTree::root(&overlay_leaves);
        assert_eq!(inc.root_with_pending(&pending), truth_root);
        for probe in [near_pk, Pubkey::new(base), Pubkey::new(wide_key(5))] {
            let p = inc.prove_with_pending(&probe, &pending);
            assert_eq!(p, CompressedStateTree::prove(&overlay_leaves, &probe.to_bytes()));
            assert!(verify_proof(truth_root, &p));
        }
    }

    /// Benchmark: per-write cost of the compressed tree vs the 256-deep
    /// `IncrementalStateTree`. Ignored by default (run with --ignored).
    #[test]
    #[ignore]
    fn bench_note_set_compressed_vs_256() {
        use crate::tree::IncrementalStateTree;
        const N: u32 = 5000;
        let keys: Vec<Pubkey> = (0..N).map(|i| Pubkey::new(wide_key(i))).collect();
        let accts: Vec<Account> = (0..N).map(|i| acct(i as u64 + 1)).collect();

        let mut old = IncrementalStateTree::new();
        let t = std::time::Instant::now();
        for i in 0..N as usize {
            old.note_set(&keys[i], &accts[i]);
        }
        let e_old = t.elapsed();

        let mut new = IncrementalCompressedTree::new();
        let t = std::time::Instant::now();
        for i in 0..N as usize {
            new.note_set(&keys[i], &accts[i]);
        }
        let e_new = t.elapsed();

        println!(
            "note_set x{N}:  256-deep {:?} ({:?}/write)  |  compressed {:?} ({:?}/write)  |  speedup {:.1}x",
            e_old, e_old / N, e_new, e_new / N, e_old.as_secs_f64() / e_new.as_secs_f64()
        );
    }
}
