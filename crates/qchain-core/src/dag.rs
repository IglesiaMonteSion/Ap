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
    pub fn digest(&self) -> Digest {
        let mut hasher = Sha3_256::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.author.to_bytes());
        for (worker_id, digest) in &self.batch_digests {
            hasher.update([*worker_id]);
            hasher.update(digest);
        }
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
}
