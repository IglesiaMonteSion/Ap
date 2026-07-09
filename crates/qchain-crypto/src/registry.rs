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
/// SLH-DSA (SPHINCS+) - NIST FIPS 205, security level 5, the
/// `sha2-256s-simple` parameter set (see `pqc-cryptography` skill for why
/// hash-based/"s" was chosen: conservative opt-in fallback for
/// high-value/long-lived accounts, where minimizing signature size matters
/// more than signing speed). Real keygen/sign/verify functions live in
/// `qchain_crypto::slh_dsa` - **not yet wired into `Transaction`, consensus
/// vote signatures, or the WASM `host_verify_signature` syscall**, all of
/// which still hardcode the Ed25519+ML-DSA-65 pair (see
/// `project-lessons-learned` for why "activating" this id via governance
/// today is bookkeeping only, not a change in what a validator accepts).
pub const ALGORITHM_SLH_DSA: AlgorithmId = AlgorithmId(3);
// Ids 4-999 are reserved for individual signature scheme components,
// allocated by governance vote in later phases (other SLH-DSA parameter
// sets, ML-DSA-87, ...) - never reused once assigned, even after
// retirement.

/// Ids >= 1000 identify a *combination policy* an account can be under, not
/// a single scheme - what `Account.algorithm_id` actually stores. Phase 1
/// has exactly one: the mandatory Ed25519+ML-DSA-65 hybrid. The eventual
/// "migración completa a solo-PQC" governance vote (`ARCHITECTURE.md` §6)
/// activates a *new* combo id here (e.g. "ML-DSA-65 only") rather than
/// redefining this one - existing accounts keep working under the combo
/// they were created with until they migrate.
pub const COMBO_HYBRID_ED25519_ML_DSA_65: AlgorithmId = AlgorithmId(1000);

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
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

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
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

/// A `RegistryEntry` for `ALGORITHM_SLH_DSA`, ready to use as the payload of
/// a real `ActivateAlgorithm` governance proposal - deliberately not part of
/// `genesis_registry()` (it's opt-in, not phase-1-active). `pubkey_len`/
/// `max_sig_len` are the real, measured liboqs sizes for
/// SPHINCS+-SHA2-256s-simple (see `qchain_crypto::slh_dsa`'s own size test),
/// not estimated from a published table.
pub fn slh_dsa_registry_entry(activation_epoch: u64) -> RegistryEntry {
    RegistryEntry {
        id: ALGORITHM_SLH_DSA,
        name: "SLH-DSA-SHA2-256s-simple".to_string(),
        pubkey_len: 64,
        max_sig_len: 29_792,
        status: AlgorithmStatus::Active,
        activation_epoch,
    }
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

    #[test]
    fn slh_dsa_is_not_part_of_the_phase_1_genesis_registry() {
        // It's opt-in (see ALGORITHM_SLH_DSA's doc comment) - genesis must
        // not silently activate it.
        let reg = genesis_registry();
        assert!(!reg.iter().any(|e| e.id == ALGORITHM_SLH_DSA));
    }

    #[test]
    fn slh_dsa_registry_entry_reports_the_real_measured_sizes() {
        let entry = slh_dsa_registry_entry(42);
        assert_eq!(entry.id, ALGORITHM_SLH_DSA);
        assert_eq!(entry.pubkey_len, 64);
        assert_eq!(entry.max_sig_len, 29_792);
        assert_eq!(entry.activation_epoch, 42);
        assert_eq!(entry.status, AlgorithmStatus::Active);
    }
}
