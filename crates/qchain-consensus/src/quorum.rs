//! Stake-weighted validator set and quorum math (design: `ARCHITECTURE.md`
//! §1, `dag-consensus-design` skill). BFT assumption: at most `f` validators
//! (by stake) are Byzantine out of `n = 3f+1`; a quorum certificate needs
//! support from strictly more than 2/3 of total stake ("2f+1").

use qchain_core::ValidatorId;
use qchain_crypto::PublicKeyBundle;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct ValidatorInfo {
    pub id: ValidatorId,
    pub pubkey_bundle: PublicKeyBundle,
    pub stake: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ValidatorSet {
    validators: HashMap<ValidatorId, ValidatorInfo>,
    total_stake: u64,
}

impl ValidatorSet {
    pub fn new(validators: Vec<ValidatorInfo>) -> Self {
        let total_stake = validators.iter().map(|v| v.stake).sum();
        let validators = validators.into_iter().map(|v| (v.id, v)).collect();
        ValidatorSet { validators, total_stake }
    }

    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// Minimum stake a quorum certificate must carry: the smallest integer
    /// strictly greater than `2/3` of total stake (i.e. `2f+1` out of
    /// `n = 3f+1`).
    pub fn quorum_threshold(&self) -> u64 {
        (self.total_stake * 2) / 3 + 1
    }

    pub fn stake_of(&self, id: &ValidatorId) -> u64 {
        self.validators.get(id).map(|v| v.stake).unwrap_or(0)
    }

    pub fn get(&self, id: &ValidatorId) -> Option<&ValidatorInfo> {
        self.validators.get(id)
    }

    /// Deterministic ordering of validator ids - the basis for leader
    /// election, so every honest validator must compute the exact same
    /// sequence.
    pub fn ids_sorted(&self) -> Vec<ValidatorId> {
        let mut ids: Vec<ValidatorId> = self.validators.keys().copied().collect();
        ids.sort_by_key(|id| id.to_bytes());
        ids
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_crypto::Keypair;

    fn info(stake: u64) -> ValidatorInfo {
        let kp = Keypair::generate().unwrap();
        ValidatorInfo { id: kp.pubkey(), pubkey_bundle: kp.public_key_bundle(), stake }
    }

    #[test]
    fn quorum_threshold_is_strictly_more_than_two_thirds() {
        let set = ValidatorSet::new(vec![info(1), info(1), info(1), info(1)]);
        assert_eq!(set.total_stake(), 4);
        // 2/3 of 4 is 2.67; quorum must be 3, not 2.
        assert_eq!(set.quorum_threshold(), 3);
    }

    #[test]
    fn uneven_stake_is_respected() {
        let set = ValidatorSet::new(vec![info(7), info(1), info(1), info(1)]);
        assert_eq!(set.total_stake(), 10);
        assert_eq!(set.quorum_threshold(), 7);
    }

    #[test]
    fn ids_sorted_is_stable_regardless_of_insertion_order() {
        let a = info(1);
        let b = info(1);
        let set1 = ValidatorSet::new(vec![a.clone(), b.clone()]);
        let set2 = ValidatorSet::new(vec![b, a]);
        assert_eq!(set1.ids_sorted(), set2.ids_sorted());
    }
}
