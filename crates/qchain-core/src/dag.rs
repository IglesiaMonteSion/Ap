//! Pure data types for the Narwhal-Bullshark DAG (design:
//! `ARCHITECTURE.md` §1, full protocol detail in the `dag-consensus-design`
//! skill). The consensus *algorithm* (quorum tracking, round advancement,
//! leader-based ordering) lives in `qchain-consensus`; this module only
//! defines what a vertex/certificate/batch *is*, with no logic attached -
//! keeping it dependency-free of any I/O or network code, per the
//! `blockchain-core-rust` skill's "deterministic core, I/O pushed to the
//! edges" convention.

use crate::transaction::Transaction;
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_crypto::MultiSignature;
use qchain_crypto::Pubkey;
use serde::{Deserialize, Serialize};
use sha3::{Digest as _, Sha3_256};

pub type Round = u64;
/// A validator's identity is its address - the same hash-derived, 32-byte,
/// scheme-agnostic address every account has.
pub type ValidatorId = Pubkey;
pub type Digest = [u8; 32];
/// A primary runs several workers in parallel, each disseminating its own
/// batches over its own network path (`ARCHITECTURE.md` §2: this is
/// specifically what lets batch bandwidth scale across separate routes/cores
/// instead of serializing through one channel). Just an index a primary
/// assigns locally to its own worker lanes - not a cross-validator identity,
/// so it doesn't need to be a `Pubkey` like `ValidatorId`.
pub type WorkerId = u8;

/// A batch of transactions a worker disseminates. Narwhal's primaries
/// reference batch *digests* in vertices, never the batches themselves -
/// this is what keeps consensus-layer messages small even though the
/// underlying transaction data can be large (heavy with PQC signatures,
/// see `ARCHITECTURE.md` §2's bandwidth analysis).
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Batch {
    pub transactions: Vec<Transaction>,
}

impl Batch {
    pub fn digest(&self) -> Digest {
        let mut hasher = Sha3_256::new();
        // Length-prefix the transaction list so a batch's digest is an
        // unambiguous function of its exact contents - see `Vertex::digest`
        // for the full rationale (here the elements are fixed-size 32-byte
        // hashes so the risk is smaller, but framing it is free and keeps
        // every digest in this module consistently domain-separated).
        hasher.update((self.transactions.len() as u64).to_le_bytes());
        for tx in &self.transactions {
            hasher.update(tx.hash());
        }
        hasher.finalize().into()
    }
}

/// One validator's proposal for a DAG round: references to the batches its
/// own workers disseminated since its last vertex (one entry per worker
/// that had something ready - workers with nothing to say this round
/// contribute no entry, not an empty batch), plus references to 2f+1
/// certificates from the previous round (their "parents" in the DAG).
/// Round 0 vertices have no parents (genesis). `batch_digests` is the
/// author's own choice, carried as-is in whatever order it built it in -
/// unlike `parents` reachability (§`qchain-consensus`'s Bullshark), no
/// other validator ever needs to independently reconstruct this list, so
/// there's no canonical-ordering requirement to enforce here.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct Vertex {
    pub round: Round,
    pub author: ValidatorId,
    pub batch_digests: Vec<(WorkerId, Digest)>,
    pub parents: Vec<Digest>,
}

impl Vertex {
    /// Length-prefix each variable-length vector before hashing it. Without
    /// the prefixes, the boundary between `batch_digests` and `parents` is
    /// not encoded in the byte stream, so two different vertices could in
    /// principle hash the same input (e.g. a `(worker_id, digest)` entry vs.
    /// a `parents` digest that happen to line up across the boundary). Not
    /// exploitable in practice - `parents` are real certificate digests an
    /// attacker cannot freely choose - but a content-addressed identifier
    /// should be an unambiguous function of its contents regardless. Framing
    /// each vector with its length (and prefixing `Batch::digest` the same
    /// way) closes it. Format-breaking on purpose: this changes every
    /// certificate digest, so all validators must run a build that agrees on
    /// it - done pre-mainnet, before any long-lived chain depends on the old
    /// encoding. `chain_id` (a hash of genesis config, not of any vertex) is
    /// unaffected.
    pub fn digest(&self) -> Digest {
        let mut hasher = Sha3_256::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.author.to_bytes());
        hasher.update((self.batch_digests.len() as u64).to_le_bytes());
        for (worker_id, digest) in &self.batch_digests {
            hasher.update([*worker_id]);
            hasher.update(digest);
        }
        hasher.update((self.parents.len() as u64).to_le_bytes());
        for p in &self.parents {
            hasher.update(p);
        }
        hasher.finalize().into()
    }
}

/// A vertex plus a stake-weighted quorum (2f+1) of signatures over its
/// digest - what actually becomes a node in the DAG once certified.
/// Equivocation (two different vertices from the same author/round both
/// gathering a quorum) is impossible as long as honest validators only ever
/// sign one vertex per author per round; any pair of conflicting *signed*
/// vertices from the same author is self-contained slashable evidence (see
/// `blockchain-security-audit` #3).
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Certificate {
    pub vertex: Vertex,
    pub signatures: Vec<(ValidatorId, MultiSignature)>,
}

impl Certificate {
    pub fn digest(&self) -> Digest {
        self.vertex.digest()
    }
}

/// Self-contained proof that a validator equivocated - the "conflicting
/// *signed* vertices from the same author" this module's own doc comment
/// above already named as slashable, now actually constructible. Anyone can
/// verify it independently, with no other on-chain state needed: check
/// `author_bundle.to_address() == vertex_a.author == vertex_b.author`,
/// `vertex_a.round == vertex_b.round`, `vertex_a.digest() != vertex_b.digest()`,
/// and that both `signature_a`/`signature_b` verify under `author_bundle`
/// over their own vertex's digest (`qchain_crypto::verify`). See
/// `qchain-execution::staking::StakingInstruction::ReportEquivocation` for
/// where that verification actually runs, and `qchain-node::engine` for how
/// this gets constructed from two conflicting `VertexProposal`s.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct EquivocationEvidence {
    pub vertex_a: Vertex,
    pub signature_a: MultiSignature,
    pub vertex_b: Vertex,
    pub signature_b: MultiSignature,
    pub author_bundle: qchain_crypto::PublicKeyBundle,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vertex_digest_changes_with_parents() {
        let author = Pubkey::system_program_id();
        let v1 = Vertex {
            round: 1,
            author,
            batch_digests: vec![(0, [1u8; 32])],
            parents: vec![[2u8; 32]],
        };
        let mut v2 = v1.clone();
        v2.parents = vec![[3u8; 32]];
        assert_ne!(v1.digest(), v2.digest());
    }

    #[test]
    fn vertex_digest_changes_with_batch_digests() {
        let author = Pubkey::system_program_id();
        let v1 = Vertex { round: 1, author, batch_digests: vec![(0, [1u8; 32])], parents: vec![] };
        let mut v2 = v1.clone();
        v2.batch_digests = vec![(0, [1u8; 32]), (1, [9u8; 32])];
        assert_ne!(v1.digest(), v2.digest());

        let mut v3 = v1.clone();
        v3.batch_digests = vec![(1, [1u8; 32])];
        assert_ne!(v1.digest(), v3.digest(), "worker id must be part of the digest, not just the batch content");
    }

    #[test]
    fn empty_batch_digest_is_deterministic() {
        let b = Batch { transactions: vec![] };
        let b2 = Batch { transactions: vec![] };
        assert_eq!(b.digest(), b2.digest());
    }

    /// With the length prefixes, the split of content between `batch_digests`
    /// and `parents` is part of the digest, not just the concatenated bytes.
    /// Here both vertices carry the exact same two 32-byte values in the same
    /// order across the boundary (one as a worker-0 batch entry, one as a
    /// parent) - only the boundary differs. They must hash differently.
    #[test]
    fn vertex_digest_encodes_the_batch_parents_boundary_not_just_the_concatenation() {
        let author = Pubkey::system_program_id();
        let x = [4u8; 32];
        let y = [5u8; 32];
        let a = Vertex { round: 1, author, batch_digests: vec![(0, x), (0, y)], parents: vec![] };
        let b = Vertex { round: 1, author, batch_digests: vec![(0, x)], parents: vec![y] };
        assert_ne!(a.digest(), b.digest(), "moving a value from batch_digests to parents must change the digest");

        // Length framing also distinguishes "one parent" from "no parents"
        // even when the batch side would otherwise absorb the difference.
        let c = Vertex { round: 1, author, batch_digests: vec![], parents: vec![x, y] };
        let d = Vertex { round: 1, author, batch_digests: vec![], parents: vec![x] };
        assert_ne!(c.digest(), d.digest());
    }
}
