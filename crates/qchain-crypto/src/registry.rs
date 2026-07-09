//! The on-chain algorithm registry (design: `ARCHITECTURE.md` §2). Phase 1
//! ships exactly two entries - Ed25519 (classical half) and ML-DSA-65 (PQC
//! half) - and every account's signature is the mandatory combination of
//! both (see `HybridSignature`/`verify`). The registry exists as a real,
//! extensible data structure from day one so that adding a scheme later
//! (SLH-DSA opt-in, ML-DSA-87 for higher-value accounts) or deprecating one
//! is a governance action over this table, not a protocol rewrite - that's
//! the whole point of "migración trivial, no hard fork."

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AlgorithmId(pub u16);

/// Classical half of the hybrid signature during the migration phase.
pub const ALGORITHM_ED25519: AlgorithmId = AlgorithmId(1);
/// PQC half - NIST FIPS 204, security level 3. See `pqc-cryptography` skill.
pub const ALGORITHM_ML_DSA_65: AlgorithmId = AlgorithmId(2);
// Ids 3-999 are reserved for individual signature scheme components,
// allocated by governance vote in later phases (SLH-DSA variants,
// ML-DSA-87, ...) - never reused once assigned, even after retirement.

/// Ids >= 1000 identify a *combination policy* an account can be under, not
/// a single scheme - what `Account.algorithm_id` actually stores. Phase 1
/// has exactly one: the mandatory Ed25519+ML-DSA-65 hybrid. The eventual
/// "migración completa a solo-PQC" governance vote (`ARCHITECTURE.md` §6)
/// activates a *new* combo id here (e.g. "ML-DSA-65 only") rather than
/// redefining this one - existing accounts keep working under the combo
/// they were created with until they migrate.
pub const COMBO_HYBRID_ED25519_ML_DSA_65: AlgorithmId = AlgorithmId(1000);

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum AlgorithmStatus {
    /// Usable by new accounts.
    Active,
    /// No new accounts may adopt it; existing accounts keep working until
    /// `retirement_epoch`, giving a real migration grace period.
    Deprecated { retirement_epoch: u64 },
    /// No longer valid for signing at all. Only ever reached after the
    /// deprecation grace period has fully elapsed.
    Retired,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RegistryEntry {
    pub id: AlgorithmId,
    pub name: String,
    pub pubkey_len: usize,
    pub max_sig_len: usize,
    pub status: AlgorithmStatus,
    pub activation_epoch: u64,
}

/// The registry state at genesis. A real deployment persists this table in
/// state (so it can change via governance); this function is the seed data,
/// not a hardcoded ceiling.
pub fn genesis_registry() -> Vec<RegistryEntry> {
    vec![
        RegistryEntry {
            id: ALGORITHM_ED25519,
            name: "Ed25519".to_string(),
            pubkey_len: 32,
            max_sig_len: 64,
            status: AlgorithmStatus::Active,
            activation_epoch: 0,
        },
        RegistryEntry {
            id: ALGORITHM_ML_DSA_65,
            name: "ML-DSA-65".to_string(),
            pubkey_len: 1_952,
            max_sig_len: 3_309,
            status: AlgorithmStatus::Active,
            activation_epoch: 0,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_registry_has_both_phase_1_schemes_active() {
        let reg = genesis_registry();
        assert_eq!(reg.len(), 2);
        assert!(reg.iter().all(|e| e.status == AlgorithmStatus::Active));
        assert!(reg.iter().any(|e| e.id == ALGORITHM_ED25519));
        assert!(reg.iter().any(|e| e.id == ALGORITHM_ML_DSA_65));
    }
}
