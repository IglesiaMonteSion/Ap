//! In-memory store for certified DAG vertices (design: `ARCHITECTURE.md`
//! §1). A pure data structure - certificate *validity* (quorum, signatures)
//! is checked before insertion by callers (`verify_certificate` at this
//! crate's root), not by the store itself, so this type stays trivially
//! testable and reusable for both live nodes and simulations.

use qchain_core::{Certificate, Digest, Round, ValidatorId};
use std::collections::HashMap;

#[derive(Default)]
pub struct DagStore {
    by_digest: HashMap<Digest, Certificate>,
    by_round: HashMap<Round, HashMap<ValidatorId, Digest>>,
    highest_round: Round,
}

impl DagStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an already-verified certificate, returning its digest.
    /// Overwrites any prior certificate from the same author/round - honest
    /// authors never equivocate, and if one does, keeping the newest one
    /// observed is a phase-1 stand-in for the real evidence-and-slash path
    /// (`ARCHITECTURE.md` §7 / `blockchain-security-audit` skill).
    pub fn insert(&mut self, cert: Certificate) -> Digest {
        let digest = cert.digest();
        let round = cert.vertex.round;
        let author = cert.vertex.author;
        self.by_round.entry(round).or_default().insert(author, digest);
        self.by_digest.insert(digest, cert);
        if round > self.highest_round || self.by_digest.len() == 1 {
            self.highest_round = round;
        }
        digest
    }

    pub fn get(&self, digest: &Digest) -> Option<&Certificate> {
        self.by_digest.get(digest)
    }

    pub fn certificate_by_author(&self, round: Round, author: &ValidatorId) -> Option<&Certificate> {
        let digest = self.by_round.get(&round)?.get(author)?;
        self.by_digest.get(digest)
    }

    pub fn certificates_in_round(&self, round: Round) -> impl Iterator<Item = &Certificate> {
        self.by_round.get(&round).into_iter().flat_map(|m| m.values()).filter_map(move |d| self.by_digest.get(d))
    }

    pub fn highest_round(&self) -> Round {
        self.highest_round
    }

    /// The lowest round for which any certificate is still present. `0` for
    /// an empty store. After `prune_below(gc)` this is the real bottom of
    /// the retained window - the value a restarting node reads back to learn
    /// where its persisted (and now pruned) DAG actually starts, so it can
    /// set the same GC barrier the pruned rounds were finalized under (see
    /// `Bullshark`'s `gc_floor` and `ConsensusState::set_gc_floor`).
    pub fn lowest_round(&self) -> Round {
        self.by_round.keys().copied().min().unwrap_or(0)
    }

    /// Drop every certificate strictly below `round`, returning the digests
    /// removed (so a caller persisting the DAG can delete the same keys from
    /// its on-disk log). Only ever called with a `round` far below the
    /// consensus finalized floor (see `qchain-node::engine`'s
    /// `DAG_RETENTION_ROUNDS`): the rounds it removes are permanently
    /// committed history whose account effects already persisted, and no
    /// future leader's causal walk needs them once the matching GC barrier
    /// is set (`Bullshark::gc_floor`). `highest_round` is left untouched -
    /// pruning the old tail never lowers the frontier.
    pub fn prune_below(&mut self, round: Round) -> Vec<Digest> {
        let mut removed = Vec::new();
        let rounds_to_drop: Vec<Round> = self.by_round.keys().copied().filter(|r| *r < round).collect();
        for r in rounds_to_drop {
            if let Some(authors) = self.by_round.remove(&r) {
                for (_author, digest) in authors {
                    if self.by_digest.remove(&digest).is_some() {
                        removed.push(digest);
                    }
                }
            }
        }
        removed
    }

    pub fn contains(&self, digest: &Digest) -> bool {
        self.by_digest.contains_key(digest)
    }

    pub fn len(&self) -> usize {
        self.by_digest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_digest.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_core::Vertex;
    use qchain_crypto::Pubkey;

    fn cert(round: Round, author: ValidatorId, parents: Vec<Digest>) -> Certificate {
        Certificate { vertex: Vertex { round, author, batch_digests: vec![(0, [round as u8; 32])], parents }, signatures: vec![] }
    }

    #[test]
    fn round_tracking_finds_the_highest_inserted_round() {
        let mut dag = DagStore::new();
        let author = Pubkey::system_program_id();
        dag.insert(cert(0, author, vec![]));
        dag.insert(cert(3, author, vec![]));
        dag.insert(cert(1, author, vec![]));
        assert_eq!(dag.highest_round(), 3);
    }

    #[test]
    fn lookup_by_author_and_round_finds_the_right_certificate() {
        let mut dag = DagStore::new();
        let a1 = Pubkey::new([1u8; 32]);
        let a2 = Pubkey::new([2u8; 32]);
        let d1 = dag.insert(cert(0, a1, vec![]));
        dag.insert(cert(0, a2, vec![]));

        let found = dag.certificate_by_author(0, &a1).unwrap();
        assert_eq!(found.digest(), d1);
        assert_eq!(dag.certificates_in_round(0).count(), 2);
    }
}
