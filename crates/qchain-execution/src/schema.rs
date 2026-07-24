//! Explicit, uniform schema versions for every critical protocol singleton
//! (roadmap #19).
//!
//! **What this closes.** Before #19 a singleton's on-disk format was recovered
//! by *trial-Borsh*: each decoder (`EconomicParams::read_or_legacy`,
//! `FeeState::read_or_legacy`, `decode_registry`, …) tries the current layout
//! and, on EOF, falls back to an older one. That works, but the schema is
//! *implicit and scattered* — there is no single place that declares "singleton
//! X is schema version N", and only the validator registry (task #3) had a
//! first-class `RegistrySchema`/`detect_registry_schema`/`.version()` API. #19
//! generalizes that pattern to **every** critical singleton: one canonical table
//! (`Singleton`), explicit per-singleton version detection (`detect_version`),
//! and an on-chain `SchemaManifest` that records the expected versions so a node
//! can VERIFY them at startup instead of hoping a Borsh decode means the right
//! format.
//!
//! **What a schema version means here.** A version bumps on a *non-append layout
//! change* — a genuinely different byte layout (e.g. the validator registry's
//! role-separation, v1→v2; or the treasury's single-authority→multisig, v1→v2).
//! Appending optional trailing fields (what the `read_or_legacy` migrations do —
//! `EconomicParams`' emission field, the treasury tiers of #17, …) is
//! *backward-compatible within the same schema version*, since an old blob is a
//! byte-prefix of the new one. So most singletons are schema **v1** today; only
//! the two that had a real layout change are **v2**.
//!
//! **Byte-identical by default.** The `Singleton`/`detect_version` machinery is
//! pure detection over the bytes a singleton already stores — it changes NOTHING
//! on disk. The persisted `SchemaManifest` singleton is **opt-in** (config
//! `explicit_schema_versions`, folded into `chain_id` only when set): a network
//! that doesn't enable it is byte-identical and keeps its exact `chain_id`;
//! enabling it is a fresh-genesis decision (a new account = a new Merkle leaf =
//! a different state root). This is exactly the "coordinated cutover that
//! persists the version" that task #3 flagged as roadmap #19.

use crate::governance::EmergencyState;
use crate::ids;
use crate::params::{EconomicParams, FeeState};
use crate::staking::RewardPoolData;
use crate::staking_v7::GlobalStakingState;
use crate::treasury_v7::TreasuryState;
use crate::validator_v7::detect_registry_schema;
use borsh::BorshDeserialize;
use qchain_core::Account;
use qchain_crypto::{Pubkey, RegistryEntry};
use std::collections::HashMap;

/// A critical protocol singleton whose `account.data` carries versioned state.
///
/// Pure-balance pools (reserve, fee pool, escrows, emission reserve, admin
/// wallet) are intentionally excluded — they hold no encoded `data`, only a
/// `balance`, so there is no schema to version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Singleton {
    /// `PARAMS_ACCOUNT_ID` — economic parameters (`EconomicParams`).
    EconomicParams,
    /// `FEE_STATE_ACCOUNT_ID` — dynamic-fee accumulator (`FeeState`).
    FeeState,
    /// `REGISTRY_ACCOUNT_ID` — crypto algorithm registry (`Vec<RegistryEntry>`).
    CryptoRegistry,
    /// `VALIDATOR_REGISTRY_ACCOUNT_ID` — the v7 validator registry (v1/v2).
    ValidatorRegistry,
    /// `STAKING_GLOBAL_ID` — v7 global staking state (`GlobalStakingState`).
    GlobalStaking,
    /// `STAKING_STATS_ID` — total delegated stake (`u64`).
    StakingStats,
    /// `STAKING_REWARDS_POOL_ID` — v6 reward-per-share pool (`RewardPoolData`).
    RewardPool,
    /// `TREASURY_ACCOUNT_ID` — multisig treasury (v1 authority / v2 multisig).
    Treasury,
    /// `EMERGENCY_ACCOUNT_ID` — governance emergency multisig (`EmergencyState`).
    Emergency,
}

impl Singleton {
    /// Every critical versioned singleton, in canonical (tag) order.
    pub const ALL: [Singleton; 9] = [
        Singleton::EconomicParams,
        Singleton::FeeState,
        Singleton::CryptoRegistry,
        Singleton::ValidatorRegistry,
        Singleton::GlobalStaking,
        Singleton::StakingStats,
        Singleton::RewardPool,
        Singleton::Treasury,
        Singleton::Emergency,
    ];

    /// The account id this singleton lives at.
    pub fn id(&self) -> Pubkey {
        match self {
            Singleton::EconomicParams => ids::PARAMS_ACCOUNT_ID,
            Singleton::FeeState => ids::FEE_STATE_ACCOUNT_ID,
            Singleton::CryptoRegistry => ids::REGISTRY_ACCOUNT_ID,
            Singleton::ValidatorRegistry => ids::VALIDATOR_REGISTRY_ACCOUNT_ID,
            Singleton::GlobalStaking => ids::STAKING_GLOBAL_ID,
            Singleton::StakingStats => ids::STAKING_STATS_ID,
            Singleton::RewardPool => ids::STAKING_REWARDS_POOL_ID,
            Singleton::Treasury => ids::TREASURY_ACCOUNT_ID,
            Singleton::Emergency => ids::EMERGENCY_ACCOUNT_ID,
        }
    }

    /// A small stable numeric tag, the key used in the on-chain `SchemaManifest`.
    /// Stable across schema-version bumps (a version bump changes the *value*,
    /// never the tag).
    pub fn tag(&self) -> u8 {
        match self {
            Singleton::EconomicParams => 1,
            Singleton::FeeState => 2,
            Singleton::CryptoRegistry => 3,
            Singleton::ValidatorRegistry => 4,
            Singleton::GlobalStaking => 5,
            Singleton::StakingStats => 6,
            Singleton::RewardPool => 7,
            Singleton::Treasury => 8,
            Singleton::Emergency => 9,
        }
    }

    /// Resolve a singleton from its manifest tag.
    pub fn from_tag(tag: u8) -> Option<Singleton> {
        Singleton::ALL.into_iter().find(|s| s.tag() == tag)
    }

    /// Human-readable name (for `qchain-inspect-state` / diagnostics).
    pub fn name(&self) -> &'static str {
        match self {
            Singleton::EconomicParams => "economic_params",
            Singleton::FeeState => "fee_state",
            Singleton::CryptoRegistry => "crypto_registry",
            Singleton::ValidatorRegistry => "validator_registry",
            Singleton::GlobalStaking => "staking_global",
            Singleton::StakingStats => "staking_stats",
            Singleton::RewardPool => "staking_rewards_pool",
            Singleton::Treasury => "treasury",
            Singleton::Emergency => "emergency",
        }
    }

    /// The schema version this build writes/expects for a fresh genesis. A
    /// version bumps only on a real byte-layout change (not on an appended
    /// optional field, which `read_or_legacy` migrates within the same version).
    pub fn current_version(&self) -> u16 {
        match self {
            // Genuine layout changes: the validator registry is now V3 — the
            // role-separated V2 (task #3) plus the #20 advanced key-role fields
            // (rotation/revocation/expiration) appended; the treasury is V2
            // (single-authority → multisig, task #222).
            Singleton::ValidatorRegistry => 3,
            Singleton::Treasury => 2,
            _ => 1,
        }
    }

    /// The EXPLICIT schema version of a singleton's on-disk `data`, or `None` if
    /// the bytes match no known version (genuinely corrupt — the caller must
    /// fail-loud, never guess). Generalizes `detect_registry_schema` (task #3)
    /// to every singleton.
    pub fn detect_version(&self, data: &[u8]) -> Option<u16> {
        match self {
            Singleton::EconomicParams => EconomicParams::read_or_legacy(data).map(|_| 1),
            Singleton::FeeState => FeeState::read_or_legacy(data).map(|_| 1),
            Singleton::CryptoRegistry => Vec::<RegistryEntry>::try_from_slice(data).ok().map(|_| 1),
            // v1 (pre-role-separation) or v2 (current) — the one with a real
            // multi-version history; None on unrecognized bytes.
            Singleton::ValidatorRegistry => detect_registry_schema(data).map(|s| s.version()),
            Singleton::GlobalStaking => GlobalStakingState::try_from_slice(data).ok().map(|_| 1),
            Singleton::StakingStats => u64::try_from_slice(data).ok().map(|_| 1),
            Singleton::RewardPool => RewardPoolData::try_from_slice(data).ok().map(|_| 1),
            // v2 = the multisig layout (its #17 tier fields are appended within
            // v2, migrated by `read_or_legacy`); v1 = the legacy 32-byte
            // single-authority blob (`{authority}`); else corrupt.
            Singleton::Treasury => {
                if TreasuryState::read_or_legacy(data).is_some() {
                    Some(2)
                } else if data.len() == 32 && Pubkey::try_from_slice(data).is_ok() {
                    Some(1)
                } else {
                    None
                }
            }
            Singleton::Emergency => EmergencyState::try_from_slice(data).ok().map(|_| 1),
        }
    }
}

/// The on-chain SCHEMA MANIFEST (roadmap #19): the canonical, explicit
/// `{singleton tag -> schema version}` map this chain was launched with. Stored
/// (opt-in) at [`ids::SCHEMA_MANIFEST_ID`] so a node verifies each singleton's
/// ACTUAL format against the DECLARED version at startup instead of relying on
/// trial-Borsh alone. `versions` is kept sorted by tag so the encoding is
/// deterministic (a stable Merkle leaf).
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct SchemaManifest {
    /// `(singleton tag, schema version)` pairs, sorted ascending by tag.
    pub versions: Vec<(u8, u16)>,
}

impl SchemaManifest {
    /// The manifest for THIS build — every versioned singleton at its
    /// `current_version`. Deterministic (sorted by tag).
    pub fn canonical() -> Self {
        let mut versions: Vec<(u8, u16)> =
            Singleton::ALL.into_iter().map(|s| (s.tag(), s.current_version())).collect();
        versions.sort_by_key(|(tag, _)| *tag);
        SchemaManifest { versions }
    }

    /// The declared version for a singleton, if present in the manifest.
    pub fn version_of(&self, s: Singleton) -> Option<u16> {
        self.versions.iter().find(|(tag, _)| *tag == s.tag()).map(|(_, v)| *v)
    }

    /// Verify a set of singleton accounts against this manifest (roadmap #19,
    /// the fail-loud startup check). For every declared `(tag, version)`:
    ///   * if the singleton's account is **present**, its detected schema version
    ///     MUST equal the declared version — a mismatch (or genuinely corrupt
    ///     bytes) is an `Err` (the node must not run on an unexpected format);
    ///   * if the singleton's account is **absent**, it is skipped (that
    ///     singleton simply doesn't exist on this network — e.g. a v6 network has
    ///     no `STAKING_GLOBAL`, a treasury-less network has no `TREASURY`).
    ///
    /// Determinism: reads only committed account bytes, no clock/RNG. Returns
    /// the list of every singleton it actually verified (for diagnostics).
    pub fn verify(&self, accounts: &HashMap<Pubkey, Account>) -> Result<Vec<Singleton>, String> {
        let mut verified = Vec::new();
        for (tag, declared) in &self.versions {
            let Some(singleton) = Singleton::from_tag(*tag) else {
                return Err(format!("schema manifest declares an unknown singleton tag {tag}"));
            };
            let Some(acct) = accounts.get(&singleton.id()) else {
                continue; // absent → this singleton isn't on this network
            };
            match singleton.detect_version(&acct.data) {
                Some(actual) if actual == *declared => verified.push(singleton),
                Some(actual) => {
                    return Err(format!(
                        "singleton {} is schema v{actual} but the on-chain manifest declares v{declared} — a coordinated schema migration is required before this node can run",
                        singleton.name()
                    ));
                }
                None => {
                    return Err(format!(
                        "singleton {} is present but decodes as NO known schema version (corrupt) — the manifest declares v{declared}; refusing to run",
                        singleton.name()
                    ));
                }
            }
        }
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::EconomicParams;

    fn acct(data: Vec<u8>) -> Account {
        let mut a = Account::new_wallet(qchain_crypto::Pubkey::system_program_id());
        a.data = data;
        a
    }

    #[test]
    fn every_singleton_has_a_unique_tag_and_id_and_all_is_complete() {
        let mut tags = std::collections::HashSet::new();
        let mut idset = std::collections::HashSet::new();
        for s in Singleton::ALL {
            assert!(tags.insert(s.tag()), "duplicate tag for {}", s.name());
            assert!(idset.insert(s.id().0), "duplicate id for {}", s.name());
            assert_eq!(Singleton::from_tag(s.tag()), Some(s), "from_tag round-trips");
            assert!(s.current_version() >= 1);
        }
        assert_eq!(tags.len(), 9, "all nine singletons present");
    }

    #[test]
    fn canonical_manifest_matches_each_singletons_current_version_and_is_sorted() {
        let m = SchemaManifest::canonical();
        assert_eq!(m.versions.len(), 9);
        // Sorted by tag.
        let sorted: Vec<u8> = m.versions.iter().map(|(t, _)| *t).collect();
        let mut want = sorted.clone();
        want.sort();
        assert_eq!(sorted, want);
        // Each entry matches the singleton's current_version.
        for s in Singleton::ALL {
            assert_eq!(m.version_of(s), Some(s.current_version()), "{}", s.name());
        }
        // The two genuine layout-change singletons are v2, the rest v1.
        assert_eq!(m.version_of(Singleton::ValidatorRegistry), Some(3));
        assert_eq!(m.version_of(Singleton::Treasury), Some(2));
        assert_eq!(m.version_of(Singleton::EconomicParams), Some(1));
    }

    #[test]
    fn detect_version_reports_current_for_a_real_blob_and_none_for_garbage() {
        // A real EconomicParams blob detects as v1; garbage as None (corrupt).
        let params = borsh::to_vec(&EconomicParams::default()).unwrap();
        assert_eq!(Singleton::EconomicParams.detect_version(&params), Some(1));
        assert_eq!(Singleton::EconomicParams.detect_version(&[0xFFu8; 3]), None);
        // StakingStats is a bare u64.
        let stats = borsh::to_vec(&123u64).unwrap();
        assert_eq!(Singleton::StakingStats.detect_version(&stats), Some(1));
        // Treasury: a legacy 32-byte authority detects as v1.
        let legacy_treasury = vec![7u8; 32];
        assert_eq!(Singleton::Treasury.detect_version(&legacy_treasury), Some(1));
    }

    #[test]
    fn verify_passes_when_present_singletons_match_and_fails_on_a_version_mismatch() {
        let mut accounts: HashMap<Pubkey, Account> = HashMap::new();
        // Seed PARAMS (v1) + STAKING_STATS (v1).
        accounts.insert(
            Singleton::EconomicParams.id(),
            acct(borsh::to_vec(&EconomicParams::default()).unwrap()),
        );
        accounts.insert(Singleton::StakingStats.id(), acct(borsh::to_vec(&7u64).unwrap()));

        // A manifest that only declares those two (others absent → skipped).
        let manifest = SchemaManifest {
            versions: vec![(Singleton::EconomicParams.tag(), 1), (Singleton::StakingStats.tag(), 1)],
        };
        let verified = manifest.verify(&accounts).expect("matching versions verify");
        assert_eq!(verified.len(), 2);

        // Absent singletons are skipped, not an error.
        let full = SchemaManifest::canonical();
        assert!(full.verify(&accounts).is_ok(), "absent singletons are tolerated");

        // A manifest that declares PARAMS at v2 (wrong) fails loud.
        let wrong = SchemaManifest { versions: vec![(Singleton::EconomicParams.tag(), 2)] };
        assert!(wrong.verify(&accounts).is_err(), "a declared-vs-actual mismatch must fail");

        // A present-but-corrupt singleton fails loud too.
        accounts.insert(Singleton::EconomicParams.id(), acct(vec![0xAA; 2]));
        assert!(manifest.verify(&accounts).is_err(), "corrupt bytes must fail");
    }

    #[test]
    fn canonical_manifest_round_trips_through_borsh() {
        let m = SchemaManifest::canonical();
        let bytes = borsh::to_vec(&m).unwrap();
        let back: SchemaManifest = borsh::from_slice(&bytes).unwrap();
        assert_eq!(m, back);
    }
}
