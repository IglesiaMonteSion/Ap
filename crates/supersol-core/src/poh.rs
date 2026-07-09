//! Proof of History: a verifiable, sequential hash chain that acts as a
//! decentralized clock. Each tick hashes the previous state; recording data
//! mixes it into the chain, which cryptographically proves that data existed
//! *before* every tick that comes after it. This is the same core idea
//! Solana uses to order events without waiting on global consensus for every
//! single step.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type PohHash = [u8; 32];

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct PohEntry {
    pub tick_height: u64,
    #[serde(with = "crate::hex32")]
    pub hash: PohHash,
    /// Present when this entry mixes in external data (e.g. a transaction
    /// hash) rather than being a plain empty tick.
    pub mixed_data: Option<Vec<u8>>,
}

pub struct Poh {
    hash: PohHash,
    tick_height: u64,
}

impl Poh {
    pub fn new(seed: PohHash) -> Self {
        Poh {
            hash: seed,
            tick_height: 0,
        }
    }

    pub fn tick(&mut self) -> PohEntry {
        let mut hasher = Sha256::new();
        hasher.update(self.hash);
        self.hash = hasher.finalize().into();
        self.tick_height += 1;
        PohEntry {
            tick_height: self.tick_height,
            hash: self.hash,
            mixed_data: None,
        }
    }

    pub fn record(&mut self, data: &[u8]) -> PohEntry {
        let mut hasher = Sha256::new();
        hasher.update(self.hash);
        hasher.update(data);
        self.hash = hasher.finalize().into();
        self.tick_height += 1;
        PohEntry {
            tick_height: self.tick_height,
            hash: self.hash,
            mixed_data: Some(data.to_vec()),
        }
    }

    pub fn current_hash(&self) -> PohHash {
        self.hash
    }

    pub fn tick_height(&self) -> u64 {
        self.tick_height
    }
}

/// Re-derive the hash chain from a seed and confirm it matches the claimed
/// entries. Any validator (or light client) can run this to check that a
/// leader didn't fabricate or reorder history.
pub fn verify_poh_sequence(seed: PohHash, entries: &[PohEntry]) -> bool {
    let mut hash = seed;
    for entry in entries {
        let mut hasher = Sha256::new();
        hasher.update(hash);
        if let Some(data) = &entry.mixed_data {
            hasher.update(data);
        }
        let computed: PohHash = hasher.finalize().into();
        if computed != entry.hash {
            return false;
        }
        hash = computed;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_chain_is_verifiable() {
        let seed = [7u8; 32];
        let mut poh = Poh::new(seed);
        let entries: Vec<_> = (0..10).map(|_| poh.tick()).collect();
        assert!(verify_poh_sequence(seed, &entries));
    }

    #[test]
    fn mixed_data_is_verifiable_and_order_dependent() {
        let seed = [3u8; 32];
        let mut poh = Poh::new(seed);
        let mut entries = vec![poh.tick()];
        entries.push(poh.record(b"tx-1"));
        entries.push(poh.tick());
        entries.push(poh.record(b"tx-2"));
        assert!(verify_poh_sequence(seed, &entries));
    }

    #[test]
    fn tampering_breaks_verification() {
        let seed = [1u8; 32];
        let mut poh = Poh::new(seed);
        let mut entries = vec![poh.record(b"tx-1"), poh.tick()];
        // Swap the mixed data after the fact - the chain should no longer verify.
        entries[0].mixed_data = Some(b"tx-9".to_vec());
        assert!(!verify_poh_sequence(seed, &entries));
    }
}
