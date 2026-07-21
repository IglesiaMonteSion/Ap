//! The on-chain algorithm registry (design: `ARCHITECTURE.md` §2). Phase 1
//! ships exactly two entries - Ed25519 (classical half) and ML-DSA-65 (PQC
//! half) - and every account's signature is the mandatory combination of
//! both (see `MultiSignature`/`verify`). The registry exists as a real,
//! extensible data structure from day one so that adding a scheme later
//! (SLH-DSA opt-in, ML-DSA-87 for higher-value accounts) or deprecating one
//! is a governance action over this table, not a protocol rewrite - that's
//! the whole point of "migración trivial, no hard fork."
//!
//! A **combo** (`AlgorithmId >= 1000`) names an ordered, fixed list of
//! individual scheme components an account's key bundle must contain -
//! `combo_components`/`combo_from_components` are the real, load-bearing
//! link between the registry's `AlgorithmId`s and what `qchain_crypto::verify`
//! actually accepts (see that function's docs for exactly how).

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
/// `qchain_crypto::slh_dsa`, and it's a real, selectable third factor via
/// `COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA` - `Transaction`/consensus vote
/// verification actually accept it now (`qchain_crypto::verify` resolves the
/// combo from the bundle's components, see that function's docs), and
/// `Ledger::apply_transaction` (`qchain-execution`) rejects any transaction
/// whose combo includes a `Retired` component per the live on-chain
/// registry - "activating" this id via governance now has real teeth, not
/// just bookkeeping (see `project-lessons-learned` for the finding that led
/// here).
pub const ALGORITHM_SLH_DSA: AlgorithmId = AlgorithmId(3);
// Ids 4-999 are reserved for individual signature scheme components,
// allocated by governance vote in later phases (other SLH-DSA parameter
// sets, ML-DSA-87, ...) - never reused once assigned, even after
// retirement.

/// Ids >= 1000 identify a *combination policy* an account can be under, not
/// a single scheme - what `Account.algorithm_id` actually stores, and what
/// `qchain_crypto::verify` resolves a `PublicKeyBundle`/`MultiSignature`
/// pair against (see `combo_components`). Phase 1 ships exactly one: the
/// mandatory Ed25519+ML-DSA-65 hybrid. The eventual "migración completa a
/// solo-PQC" governance vote (`ARCHITECTURE.md` §6) activates a *new* combo
/// id here (e.g. "ML-DSA-65 only") rather than redefining this one -
/// existing accounts keep working under the combo they were created with
/// until they migrate.
pub const COMBO_HYBRID_ED25519_ML_DSA_65: AlgorithmId = AlgorithmId(1000);
/// Opt-in triple hybrid: the mandatory phase-1 pair, plus SLH-DSA as a third
/// mandatory factor - all three components must independently verify. For
/// high-value/long-lived accounts per `pqc-cryptography`'s SLH-DSA section;
/// not the default (`Keypair::generate()` still produces the phase-1 pair -
/// see `Keypair::generate_with_slh_dsa()` to opt in). Costs materially more
/// in fees (`byte_size()` sums every component's real length, and SLH-DSA's
/// signature alone is 29,792 bytes - see `qchain_crypto::slh_dsa`), which is
/// the accepted trade for the extra hash-based conservative margin.
pub const COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA: AlgorithmId = AlgorithmId(1001);

/// The ordered list of individual scheme components a combo requires, or
/// `None` if `id` isn't a known combo. Order matters: `verify` matches
/// components positionally against this list, and `Keypair::sign`/
/// `public_key_bundle` build components in this exact order.
pub fn combo_components(id: AlgorithmId) -> Option<&'static [AlgorithmId]> {
    if id == COMBO_HYBRID_ED25519_ML_DSA_65 {
        Some(&[ALGORITHM_ED25519, ALGORITHM_ML_DSA_65])
    } else if id == COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA {
        Some(&[ALGORITHM_ED25519, ALGORITHM_ML_DSA_65, ALGORITHM_SLH_DSA])
    } else {
        None
    }
}

/// Reverse lookup: which known combo (if any) requires exactly this
/// ordered list of schemes. This is the real gate against an attacker
/// self-declaring a bundle with a missing/extra/substituted component and
/// having it accepted - `qchain_crypto::verify` calls this on every
/// verification and rejects outright if no combo matches (see its docs).
pub fn combo_from_components(schemes: &[AlgorithmId]) -> Option<AlgorithmId> {
    [COMBO_HYBRID_ED25519_ML_DSA_65, COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA]
        .into_iter()
        .find(|&combo| combo_components(combo) == Some(schemes))
}

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

/// One algorithm's on-chain registry record — the **crypto-agility** unit
/// (tarea #201, QCH-S15). The four properties the audit asks to formalize map
/// onto this record + its live enforcement in `qchain-execution::Ledger`:
///
/// * **`suite_id`** = [`id`](Self::id) ([`AlgorithmId`]). Identifies the EXACT
///   parameterization (e.g. `ML-DSA-65` = `AlgorithmId(2)`, a specific FIPS-204
///   param set). A re-parameterization would be a genuinely different suite and
///   gets a NEW id — so an explicit separate `suite_version` field is subsumed
///   by the id and deliberately not added (adding a field would be a
///   state-format change for zero real gain; the id already versions the suite,
///   and each signature declares its suite ids via its `KeyComponent.scheme`s).
/// * **`activation_height`** = [`activation_epoch`](Self::activation_epoch).
///   The first round a scheme may be used. **Enforced per-signature** at apply
///   time (`Ledger::check_registry_status`, #201): a transaction whose payer
///   combo includes a scheme with `activation_epoch > current_round` is
///   rejected — a governance activation scheduled for the future does not take
///   effect early. `0` (every genesis scheme) = active since genesis.
/// * **`deprecation_height`** = the `retirement_epoch` inside
///   [`AlgorithmStatus::Deprecated`]. Enforced: a `Deprecated` scheme turns
///   away NEW accounts immediately and, once `current_round >= retirement_epoch`,
///   governance can `Retire` it (after which no signature under it verifies).
/// * **status lifecycle**: `Active` → `Deprecated{retirement_epoch}` → `Retired`,
///   all via `Registry`-tier governance with a timelock (see
///   `qchain-execution::governance`).
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

    #[test]
    fn combo_components_are_ordered_and_known_combos_round_trip() {
        assert_eq!(combo_components(COMBO_HYBRID_ED25519_ML_DSA_65), Some(&[ALGORITHM_ED25519, ALGORITHM_ML_DSA_65][..]));
        assert_eq!(
            combo_components(COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA),
            Some(&[ALGORITHM_ED25519, ALGORITHM_ML_DSA_65, ALGORITHM_SLH_DSA][..])
        );
        assert_eq!(combo_components(AlgorithmId(9999)), None);

        assert_eq!(combo_from_components(&[ALGORITHM_ED25519, ALGORITHM_ML_DSA_65]), Some(COMBO_HYBRID_ED25519_ML_DSA_65));
        assert_eq!(
            combo_from_components(&[ALGORITHM_ED25519, ALGORITHM_ML_DSA_65, ALGORITHM_SLH_DSA]),
            Some(COMBO_HYBRID_ED25519_ML_DSA_65_SLH_DSA)
        );
    }

    #[test]
    fn combo_from_components_rejects_missing_extra_or_reordered_schemes() {
        // Dropping the mandatory PQC half.
        assert_eq!(combo_from_components(&[ALGORITHM_ED25519]), None);
        // Reordered - not the same combo even though the set matches.
        assert_eq!(combo_from_components(&[ALGORITHM_ML_DSA_65, ALGORITHM_ED25519]), None);
        // An extra, unregistered scheme appended.
        assert_eq!(combo_from_components(&[ALGORITHM_ED25519, ALGORITHM_ML_DSA_65, AlgorithmId(777)]), None);
    }
}
