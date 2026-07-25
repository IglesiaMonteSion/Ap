//! Genesis state seeding + the genesis manifest (roadmap #7).
//!
//! `seed_genesis` is the SINGLE source of truth for what a fresh network's
//! initial state is — extracted verbatim from `main`'s `if is_fresh` block so
//! the running node and the offline `qchain-verify-genesis` tool seed the
//! BYTE-IDENTICAL genesis state (same accounts, same balances, same Merkle
//! root). That shared code path is what makes the manifest trustworthy: it is
//! recomputed by exactly the code the node runs, not a parallel description
//! that could drift.
//!
//! The genesis manifest is the canonical, publishable record of a launch:
//! chain_id + network fingerprint + the genesis state root + total supply + the
//! full sorted account list (address / balance / owner / data hash) + the
//! folded genesis decisions. Anyone can run `qchain-verify-genesis --config
//! node.json` to recompute it from their own config and confirm — offline, with
//! no trust in the launcher — that they are about to seed the exact same
//! genesis everyone else agreed on (no hidden allocation, no chain_id mismatch,
//! the announced supply and treasury/guardian setup and nothing else).

use crate::config::NodeConfig;
use qchain_execution::{
    genesis_params_account_data, genesis_registry_account_data, Ledger, RewardPoolData,
    GOVERNANCE_PROGRAM_ID, PARAMS_ACCOUNT_ID, REGISTRY_ACCOUNT_ID, STAKING_PROGRAM_ID,
    STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, VALIDATOR_REGISTRY_ACCOUNT_ID,
};

/// Seed a fresh ledger with the genesis state for `config`. This is the exact
/// block the node runs on a fresh store (`main`'s `if is_fresh`), kept here so
/// the node and `qchain-verify-genesis` seed identically. Deterministic: same
/// config in → byte-identical accounts (hence the same genesis Merkle root) on
/// every machine. Must be called on a freshly-constructed `Ledger` (matching
/// `compressed_state_tree`/`economics_v7`), before any transaction.
pub fn seed_genesis(ledger: &mut Ledger, config: &NodeConfig) -> anyhow::Result<()> {
    for alloc in &config.genesis {
        ledger.credit(alloc.address, alloc.balance);
    }
    // Phase-2 governance prerequisites (§6/§5 - see `qchain-execution`'s
    // `staking`/`governance` module docs): the staking-stats counter starts
    // at zero, and the algorithm registry starts at its genesis contents
    // (Ed25519 + ML-DSA-65, both Active).
    // #187 — identidad de red on-chain. Los 32 bytes del `chain_id` que este
    // nodo derivo de su config, sembrados en un singleton para que un programa
    // nativo pueda ATAR una verificacion a ESTA red. Lo consume el handler de
    // `ReportEquivocation` (v6 y v7): el voto se firma como
    // `VERTEX_VOTE_V1 || chain_id || digest`, asi que sin el chain_id local no se
    // puede distinguir una equivocacion REAL de dos vertices legitimos firmados
    // por el mismo validador en dos REDES distintas (el robo de bono que #187
    // cierra). Sembrarlo NO cambia el `chain_id` (que se computa del CONFIG, no
    // del estado), solo el state root de genesis — como cualquier singleton nuevo.
    ledger.seed_account(
        qchain_execution::ids::CHAIN_ID_ACCOUNT_ID,
        qchain_core::Account {
            data: config.chain_id().to_vec(),
            ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
        },
    );
    ledger.seed_account(
        STAKING_STATS_ID,
        qchain_core::Account {
            data: borsh::to_vec(&0u64)?,
            ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
        },
    );
    ledger.seed_account(
        REGISTRY_ACCOUNT_ID,
        qchain_core::Account {
            data: genesis_registry_account_data(),
            ..qchain_core::Account::new_wallet(GOVERNANCE_PROGRAM_ID)
        },
    );
    // Economic parameters (base fee, dust threshold, gas price) start at
    // their compiled-in defaults and become governable (Low-tier
    // proposals, no time-lock) from here - see `qchain-execution`'s
    // `params`/`governance` module docs.
    ledger.seed_account(
        PARAMS_ACCOUNT_ID,
        qchain_core::Account {
            data: genesis_params_account_data(),
            ..qchain_core::Account::new_wallet(GOVERNANCE_PROGRAM_ID)
        },
    );
    // Emergency governance guardian multisig (task #213). Seeded with the
    // configured guardian set (empty by default = the pause feature is
    // inert). Folded into `chain_id` only when set (see `NodeConfig::
    // chain_id`), so a network without guardians is byte-identical.
    {
        let guardians = config.guardian_pubkeys()?;
        let threshold = config.governance_guardian_threshold;
        ledger.seed_account(
            qchain_execution::EMERGENCY_ACCOUNT_ID,
            qchain_core::Account {
                data: qchain_execution::genesis_emergency_account_data(guardians, threshold),
                ..qchain_core::Account::new_wallet(GOVERNANCE_PROGRAM_ID)
            },
        );
    }
    // Shared delegator staking-reward pool (`ARCHITECTURE.md` §5's
    // staking-rewards paragraph, `qchain-execution::staking`'s module
    // docs for the reward-per-share accrual mechanism): starts empty,
    // `balance` accrues from every transaction's fee split from here.
    ledger.seed_account(
        STAKING_REWARDS_POOL_ID,
        qchain_core::Account {
            data: borsh::to_vec(&RewardPoolData::default())?,
            ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
        },
    );
    // On-chain validator registry (phase 3 - `qchain-execution::
    // validator_registry`): starts empty and is populated live by
    // `RegisterValidator`. Inert this increment (nothing reads it for
    // consensus yet), but seeded at genesis the same way every other
    // program singleton is so the account exists for the first
    // registration to mutate.
    // With rotation ON, pre-seed the registry with the genesis validators
    // so the per-epoch committee derived from it starts out equal to the
    // genesis committee (nobody dropped; a newcomer is *added* by stake
    // rank). With rotation OFF, seed the EMPTY registry exactly as before,
    // so the genesis state root is byte-identical for existing networks
    // (`genesis_validator_registry_with` vs `..._account_data`).
    let validator_registry_data = if config.validator_rotation {
        qchain_execution::validator_registry::genesis_validator_registry_with(
            config
                .validators
                .iter()
                .map(|v| (v.pubkey_bundle.clone(), v.addr.to_string(), v.stake)),
        )
    } else {
        qchain_execution::validator_registry::genesis_validator_registry_account_data()
    };
    ledger.seed_account(
        VALIDATOR_REGISTRY_ACCOUNT_ID,
        qchain_core::Account {
            data: validator_registry_data,
            ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
        },
    );
    // v7 genesis (SPEC §15 + §12 strict pool separation): the six separate
    // economic pools start empty (or at their genesis state for the global
    // staking singleton), and the admin-fee wallet is a real system-owned
    // wallet ready to receive the 10% admin share once fee routing is wired.
    // The founder's 10M allocation is a normal `genesis` entry the operator
    // sets (handled by the credit loop above), not hardcoded here. Seeded only
    // for a v7 network, so a v6 genesis state root is byte-identical.
    if config.economics_v7 {
        use qchain_execution::ids::{
            ADMIN_FEE_WALLET, STAKING_GLOBAL_ID, STAKING_RESERVE_ID, STAKING_UNBONDING_POOL_ID,
            VALIDATOR_BOND_ESCROW_ID, VALIDATOR_FEE_POOL_ID, VALIDATOR_UNBONDING_POOL_ID,
        };
        // Global staking singleton: MUST seed with `genesis_with_rate` (index =
        // 1.0, carrying the per-quanto rate), never `Default` (index = 0) — the
        // per-quanto close reads this, and `stake()` reads `rate_fp` to price a
        // fresh deposit's shares at the NEXT quanto's index (epoch-aligned
        // activation: a deposit earns from the next quanto, not the partial one
        // it joined during).
        ledger.seed_account(
            STAKING_GLOBAL_ID,
            qchain_core::Account {
                data: borsh::to_vec(
                    &qchain_execution::staking_v7::GlobalStakingState::genesis_with_rate(
                        config.quanto_rate_fp(),
                    ),
                )?,
                ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
            },
        );
        // The fund pools start empty; each is program-owned so the dust
        // sweep never touches it and no source subsidizes another (§12). The
        // bond escrow is seeded below with the founder validators' bonds.
        for pool in [
            STAKING_RESERVE_ID,
            VALIDATOR_FEE_POOL_ID,
            STAKING_UNBONDING_POOL_ID,
            VALIDATOR_UNBONDING_POOL_ID,
        ] {
            ledger.seed_account(pool, qchain_core::Account::new_wallet(STAKING_PROGRAM_ID));
        }
        // HARD-CAP model (§5, #221): pre-mint the emission reserve. Staking
        // emission is DRAWN from here each quanto (a transfer to the staking
        // reserve), never minted — so total supply is fixed at the genesis
        // total and can never exceed the cap. Program-owned so the dust sweep
        // never touches it. Seeded only under `hard_cap_supply`, so an
        // inflationary v7 network's genesis root is unchanged.
        if config.hard_cap_supply {
            use qchain_execution::ids::EMISSION_RESERVE_ID;
            ledger.seed_account(
                EMISSION_RESERVE_ID,
                qchain_core::Account {
                    balance: config.emission_reserve_atoms(),
                    ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
                },
            );
        }
        // Admin-fee wallet: a REAL system-owned wallet (the operator spends it
        // with a normal signed transfer). Seeded empty; the 10% admin share
        // credits here once v7 fee routing is wired.
        ledger.seed_account(
            ADMIN_FEE_WALLET,
            qchain_core::Account::new_wallet(qchain_crypto::Pubkey::system_program_id()),
        );
        // The validator registry account ([9;32]) was seeded above in the
        // phase-3 (`validator_registry`) format; a v7 network instead uses the
        // `validator_v7::ValidatorV7Registry` format at the SAME id (SPEC §7).
        // Seed it with the FOUNDER validators (the genesis `validators` set) as
        // Active from quanto 0, so a fresh v7 network has an eligible committee
        // for the fee distribution from the first quanto (instead of pooling
        // fees with nobody to pay until someone `v7-bond-register`s). Each
        // founder's 500 QCH bond is MINTED into the escrow at genesis (operator
        // decision), so the §13 invariant holds: escrow balance == Σ bonds and
        // every bond == VALIDATOR_BOND_ATOMS. Deterministic (config order), so
        // every node of the network seeds the identical registry + escrow → same
        // genesis state root, no fork. Monikers: the config `name` if it's a
        // valid, unique moniker, else a deterministic `founder-<i>` fallback.
        use qchain_execution::economics_v7::{
            moniker_is_valid, normalize_moniker, VALIDATOR_BOND_ATOMS,
        };
        use qchain_execution::validator_v7::{
            ValidatorV7Entry, ValidatorV7Registry, ValidatorV7State,
        };
        let mut used_monikers = std::collections::HashSet::new();
        let mut founders = Vec::with_capacity(config.validators.len());
        for (i, v) in config.validators.iter().enumerate() {
            let named = v
                .name
                .as_deref()
                .map(normalize_moniker)
                .filter(|m| moniker_is_valid(m));
            let mut moniker = match named {
                Some(m) if !used_monikers.contains(&m) => m,
                _ => format!("founder-{i}"),
            };
            let mut k = 0u32;
            while used_monikers.contains(&moniker) {
                k += 1;
                moniker = format!("founder-{i}-{k}");
            }
            used_monikers.insert(moniker.clone());
            let consensus_addr = v.pubkey_bundle.to_address();
            founders.push(ValidatorV7Entry {
                address: consensus_addr,
                // At genesis a founder controls its own consensus key (no cold
                // operator was posted), so the operator defaults to the consensus
                // address; the WITHDRAWAL address routes bond + fee earnings to the
                // configured cold address (#193-B) when set, else the consensus key
                // (byte-identical to a network that doesn't separate the funds key).
                operator_address: consensus_addr,
                withdrawal_address: v.withdrawal_address.unwrap_or(consensus_addr),
                moniker,
                pubkey_bundle: v.pubkey_bundle.clone(),
                p2p_address: v.addr.to_string(),
                bond: VALIDATOR_BOND_ATOMS,
                state: ValidatorV7State::Active,
                registered_quanto: 0,
                activation_quanto: 0,
                exit_requested_quanto: 0,
                bond_release_quanto: 0,
                participation_credits: 0,
                participation_opportunities: 0,
                // #20 advanced key-role fields: a genesis founder starts with no
                // forced expiry, not revoked, and no retired keys (byte-identical
                // behavior to a network that never uses key rotation).
                consensus_key_expiry_quanto: 0,
                consensus_key_revoked: false,
                retired_consensus_keys: Vec::new(),
                frozen_until_quanto: 0,
            });
        }
        let escrow_total = VALIDATOR_BOND_ATOMS.saturating_mul(founders.len() as u64);
        ledger.seed_account(
            VALIDATOR_REGISTRY_ACCOUNT_ID,
            qchain_core::Account {
                data: borsh::to_vec(&ValidatorV7Registry {
                    validators: founders,
                })?,
                ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
            },
        );
        ledger.seed_account(
            VALIDATOR_BOND_ESCROW_ID,
            qchain_core::Account {
                balance: escrow_total,
                ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
            },
        );
        // Genesis treasury (optional): mint the initial circulating supply
        // LOCKED into the treasury account, releasable only by the configured
        // authority (SPEC: v7 treasury). Deterministic (same authority+amount on
        // every node → identical genesis root). Absent when no treasury is
        // configured, so a v7 network without one is unchanged.
        // MULTISIG treasury (task #222) takes precedence: if signers are
        // configured, seed the M-of-N multisig; otherwise fall back to a single
        // authority (1-of-1, backward-compatible). Both require an amount.
        if let (Some(state), Some(amount)) =
            (config.treasury_multisig_state()?, config.treasury_amount)
        {
            let n = state.signers.len();
            let m = state.threshold;
            ledger.seed_account(
                qchain_execution::ids::TREASURY_ACCOUNT_ID,
                qchain_execution::treasury_v7::genesis_treasury_account_multisig(state, amount),
            );
            tracing::info!(
                    "treasury: seeded {} QCH LOCKED under a {m}-of-{n} MULTISIG (timelock {} rounds, per-op {} QCH, per-window {} QCH/{} rounds) — no single key can release funds",
                    amount / 1_000_000_000,
                    config.treasury_timelock_rounds,
                    config.treasury_max_per_release_qch,
                    config.treasury_max_per_window_qch,
                    config.treasury_window_rounds,
                );
        } else if let (Some(auth_b58), Some(amount)) =
            (config.treasury_authority.as_deref(), config.treasury_amount)
        {
            let authority = auth_b58
                .parse::<qchain_crypto::Pubkey>()
                .map_err(|e| anyhow::anyhow!("treasury_authority is not a valid address: {e}"))?;
            ledger.seed_account(
                qchain_execution::ids::TREASURY_ACCOUNT_ID,
                qchain_execution::treasury_v7::genesis_treasury_account(authority, amount),
            );
            tracing::info!(
                    "treasury: seeded {} units ({} QCH) LOCKED, single authority {} (1-of-1) — consider a multisig (treasury_signers)",
                    amount,
                    amount / 1_000_000_000,
                    auth_b58
                );
        }
    }
    // Explicit schema manifest (roadmap #19): opt-in, seeded for ANY network
    // (independent of economics_v7). Records the canonical `{singleton ->
    // schema_version}` map on-chain so the node verifies each singleton's format
    // against the declared version at startup. Seeding it is what changes the
    // genesis state root (a new leaf), which is why `explicit_schema_versions`
    // folds into the chain_id — a network without it is byte-identical.
    if config.explicit_schema_versions {
        let manifest = qchain_execution::SchemaManifest::canonical();
        ledger.seed_account(
            qchain_execution::SCHEMA_MANIFEST_ID,
            qchain_core::Account {
                data: borsh::to_vec(&manifest)?,
                ..qchain_core::Account::new_wallet(STAKING_PROGRAM_ID)
            },
        );
        tracing::info!(
            "schema manifest: seeded {} explicit singleton schema versions (roadmap #19)",
            manifest.versions.len()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Genesis manifest (roadmap #7): the canonical, publishable, independently
// reproducible record of a network's genesis.
// ---------------------------------------------------------------------------

use borsh::BorshSerialize;
use qchain_storage::InMemoryStore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// One genesis-seeded account, in a stable, human-auditable form. `data` is
/// summarized by its length + SHA3-256 (the full bytes aren't reproduced — the
/// hash is enough to prove two manifests describe the identical account).
#[derive(Serialize, Deserialize, BorshSerialize, Clone, PartialEq, Eq, Debug)]
pub struct GenesisAccount {
    pub address: String,
    pub balance: u64,
    pub owner: String,
    pub nonce: u64,
    pub data_len: u64,
    pub data_sha3: String,
}

/// The genesis-level, network-wide decisions (all folded into `chain_id` except
/// where noted) — surfaced so a reader sees the economic/authority posture at a
/// glance rather than having to diff a raw config.
#[derive(Serialize, Deserialize, BorshSerialize, Clone, PartialEq, Eq, Debug)]
pub struct GenesisDecisions {
    pub economics_v7: bool,
    pub compressed_state_tree: bool,
    pub validator_rotation: bool,
    pub hard_cap_supply: bool,
    pub supply_cap_qch: Option<u64>,
    pub network_profile: Option<String>,
    pub treasury: Option<String>,
    pub guardians: u64,
    pub guardian_threshold: u8,
    pub admin_fee_wallet: Option<String>,
}

/// The canonical genesis manifest. Two operators who publish/compute this from
/// the same config get a byte-identical document (same `manifest_hash`); a
/// single differing allocation, flag, or seeded singleton changes the
/// `genesis_state_root` and the `manifest_hash`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GenesisManifest {
    pub chain_id: String,
    pub network_fingerprint: String,
    pub genesis_state_root: String,
    pub validator_count: u64,
    pub account_count: u64,
    pub total_supply_atoms: String,
    pub total_supply_qch: String,
    pub decisions: GenesisDecisions,
    pub accounts: Vec<GenesisAccount>,
    /// SHA3-256 over the canonical bytes of every field above — the single
    /// value to compare when checking two manifests agree.
    pub manifest_hash: String,
}

impl GenesisManifest {
    /// Recompute the manifest purely from a config: seed a fresh in-memory
    /// ledger via the SAME `seed_genesis` the node runs, read back the accounts
    /// and the genesis Merkle root, and summarize. Deterministic and offline.
    pub fn compute(config: &NodeConfig) -> anyhow::Result<Self> {
        // Match the node's genesis-relevant ledger construction (only the tree
        // mode + economics affect the seeded state / root).
        let mut ledger = Ledger::new_with_config(
            Box::new(InMemoryStore::new()),
            config.compressed_state_tree,
            config.economics_v7,
            config.quanto_rate_fp(),
            config.rounds_per_quanto(),
        )?;
        seed_genesis(&mut ledger, config)?;
        let genesis_state_root = hex::encode(ledger.merkle_root());

        let mut accounts: Vec<GenesisAccount> = ledger
            .store()
            .iter()
            .map(|(pk, acc)| {
                let data_sha3 = if acc.data.is_empty() {
                    String::new()
                } else {
                    let d: [u8; 32] = Sha3_256::digest(&acc.data).into();
                    hex::encode(d)
                };
                GenesisAccount {
                    address: pk.to_string(),
                    balance: acc.balance,
                    owner: acc.owner.to_string(),
                    nonce: acc.nonce,
                    data_len: acc.data.len() as u64,
                    data_sha3,
                }
            })
            .collect();
        // Deterministic order: by address string (base58), independent of store
        // iteration order.
        accounts.sort_by(|a, b| a.address.cmp(&b.address));

        let total_supply_atoms: u128 = accounts.iter().map(|a| a.balance as u128).sum();

        let treasury = if let Ok(Some(state)) = config.treasury_multisig_state() {
            config.treasury_amount.map(|amt| {
                format!(
                    "{}-of-{} multisig, {} QCH locked",
                    state.threshold,
                    state.signers.len(),
                    amt / 1_000_000_000
                )
            })
        } else if let (Some(auth), Some(amt)) =
            (config.treasury_authority.as_deref(), config.treasury_amount)
        {
            Some(format!(
                "single authority {auth}, {} QCH locked",
                amt / 1_000_000_000
            ))
        } else {
            None
        };

        let decisions = GenesisDecisions {
            economics_v7: config.economics_v7,
            compressed_state_tree: config.compressed_state_tree,
            validator_rotation: config.validator_rotation,
            hard_cap_supply: config.hard_cap_supply,
            supply_cap_qch: if config.hard_cap_supply {
                Some((config.supply_cap_atoms() / 1_000_000_000) as u64)
            } else {
                None
            },
            network_profile: config.network_profile.clone(),
            treasury,
            guardians: config.guardian_pubkeys()?.len() as u64,
            guardian_threshold: config.governance_guardian_threshold,
            admin_fee_wallet: config.admin_fee_wallet_pubkey()?.map(|p| p.to_string()),
        };

        let mut m = GenesisManifest {
            chain_id: hex::encode(config.chain_id()),
            network_fingerprint: hex::encode(config.network_fingerprint()),
            genesis_state_root,
            validator_count: config.validators.len() as u64,
            account_count: accounts.len() as u64,
            total_supply_atoms: total_supply_atoms.to_string(),
            total_supply_qch: (total_supply_atoms / 1_000_000_000).to_string(),
            decisions,
            accounts,
            manifest_hash: String::new(),
        };
        m.manifest_hash = hex::encode(m.canonical_hash());
        Ok(m)
    }

    /// SHA3-256 over the canonical bytes of every field EXCEPT `manifest_hash`.
    /// Deterministic and formatting-independent (does not hash the pretty JSON).
    fn canonical_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"qchain-genesis-manifest-v1");
        h.update(self.chain_id.as_bytes());
        h.update(self.network_fingerprint.as_bytes());
        h.update(self.genesis_state_root.as_bytes());
        h.update(self.validator_count.to_le_bytes());
        h.update(self.account_count.to_le_bytes());
        h.update(self.total_supply_atoms.as_bytes());
        h.update(borsh::to_vec(&self.decisions).expect("decisions serialize"));
        for a in &self.accounts {
            h.update(borsh::to_vec(a).expect("account serialize"));
        }
        h.finalize().into()
    }

    /// Verify this recomputed manifest against a published one. Returns the list
    /// of mismatched fields (empty = they agree). Compares the strong single
    /// value (`manifest_hash`) plus the headline fields for a readable diff.
    pub fn diff_against(&self, published: &GenesisManifest) -> Vec<String> {
        let mut diffs = Vec::new();
        let mut check = |name: &str, a: &str, b: &str| {
            if a != b {
                diffs.push(format!("{name}: recomputed {a} != published {b}"));
            }
        };
        check("chain_id", &self.chain_id, &published.chain_id);
        check(
            "genesis_state_root",
            &self.genesis_state_root,
            &published.genesis_state_root,
        );
        check(
            "total_supply_atoms",
            &self.total_supply_atoms,
            &published.total_supply_atoms,
        );
        check(
            "account_count",
            &self.account_count.to_string(),
            &published.account_count.to_string(),
        );
        check(
            "manifest_hash",
            &self.manifest_hash,
            &published.manifest_hash,
        );
        diffs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_crypto::Keypair;

    /// Build a minimal but valid `NodeConfig` with one real validator and one
    /// genesis allocation, optionally turning on the v7 economics.
    fn cfg(alloc_balance: u64, economics_v7: bool) -> NodeConfig {
        let v = Keypair::generate().unwrap();
        let bundle = serde_json::to_value(v.public_key_bundle()).unwrap();
        let alloc_addr = Keypair::generate().unwrap().pubkey().to_string();
        let json = serde_json::json!({
            "keypair_path": "keypair.json",
            "listen_addr": "127.0.0.1:9101",
            "rpc_addr": "127.0.0.1:8080",
            "validators": [{ "pubkey_bundle": bundle, "addr": "127.0.0.1:9101", "stake": 20_000_000u64 }],
            "genesis": [{ "address": alloc_addr, "balance": alloc_balance }],
            "economics_v7": economics_v7,
            "rounds_per_quanto": 100u64,
        });
        serde_json::from_value(json).unwrap()
    }

    /// Roadmap #19: with `explicit_schema_versions`, genesis seeds the on-chain
    /// SCHEMA_MANIFEST and `verify_schema_manifest` passes against the seeded
    /// state; without it, no manifest is seeded and verification is a no-op
    /// (byte-identical). Also: seeding the manifest changes the genesis root.
    #[test]
    fn schema_manifest_is_seeded_and_verifies_only_when_enabled() {
        fn seed(explicit: bool, economics_v7: bool) -> (Ledger, String) {
            let mut c = cfg(50_000_000_000, economics_v7);
            c.explicit_schema_versions = explicit;
            let mut ledger = Ledger::new_with_config(
                Box::new(InMemoryStore::new()),
                c.compressed_state_tree,
                c.economics_v7,
                c.quanto_rate_fp(),
                c.rounds_per_quanto(),
            )
            .unwrap();
            seed_genesis(&mut ledger, &c).unwrap();
            let root = hex::encode(ledger.merkle_root());
            (ledger, root)
        }

        // OFF: no manifest account, verify is a no-op (None).
        let (off_ledger, off_root) = seed(false, true);
        assert!(off_ledger.store().get(&qchain_execution::SCHEMA_MANIFEST_ID).is_none());
        assert_eq!(off_ledger.verify_schema_manifest().unwrap(), None);

        // ON: the manifest is seeded, verify passes and returns how many
        // singletons it checked (the ones actually present on this network).
        let (on_ledger, on_root) = seed(true, true);
        assert!(on_ledger.store().get(&qchain_execution::SCHEMA_MANIFEST_ID).is_some());
        let verified = on_ledger.verify_schema_manifest().unwrap();
        assert!(verified.is_some_and(|n| n >= 4), "verified the present singletons");

        // Seeding the manifest changed the genesis state root (a new leaf) — this
        // is why the flag folds into the chain_id.
        assert_ne!(off_root, on_root, "the manifest adds a leaf → different genesis root");
    }

    #[test]
    fn a_genesis_manifest_is_deterministic_and_matches_itself() {
        let c = cfg(50_000_000_000, false);
        let m1 = GenesisManifest::compute(&c).unwrap();
        let m2 = GenesisManifest::compute(&c).unwrap();
        assert_eq!(
            m1.manifest_hash, m2.manifest_hash,
            "same config → identical manifest hash"
        );
        assert_eq!(
            m1.genesis_state_root, m2.genesis_state_root,
            "same config → identical genesis root"
        );
        assert_eq!(
            m1.chain_id,
            hex::encode(c.chain_id()),
            "manifest carries the config chain_id"
        );
        assert!(
            m1.diff_against(&m2).is_empty(),
            "a manifest verifies against itself"
        );
        // The genesis supply equals the single allocation (a v6 network seeds no
        // balance-bearing singletons beyond the allocation).
        assert_eq!(m1.total_supply_atoms, "50000000000");
        assert!(
            m1.account_count >= 1,
            "at least the allocation + program singletons are present"
        );
    }

    #[test]
    fn changing_a_single_allocation_changes_the_root_and_the_manifest_hash() {
        // Two configs identical except for one allocation's balance must produce
        // a different genesis state root AND a different manifest hash — a hidden
        // or altered allocation cannot hide behind a matching manifest.
        let a = GenesisManifest::compute(&cfg(50_000_000_000, false)).unwrap();
        let b = GenesisManifest::compute(&cfg(50_000_000_001, false)).unwrap();
        // (Different random validator/alloc keys per cfg() too, but the balance
        // change alone guarantees the supply differs.)
        assert_ne!(a.total_supply_atoms, b.total_supply_atoms);
        assert_ne!(
            a.genesis_state_root, b.genesis_state_root,
            "a changed allocation changes the genesis root"
        );
        assert_ne!(
            a.manifest_hash, b.manifest_hash,
            "a changed allocation changes the manifest hash"
        );
        assert!(!a.diff_against(&b).is_empty(), "diff surfaces the mismatch");
    }

    #[test]
    fn a_v7_genesis_seeds_more_singletons_than_a_v6_genesis() {
        // Turning on v7 economics seeds the extra economic singletons (global
        // staking, the pools, the admin wallet, the founder registry) — the
        // manifest reflects that richer genesis and the decision flags.
        let v6 = GenesisManifest::compute(&cfg(10_000_000_000, false)).unwrap();
        let v7 = GenesisManifest::compute(&cfg(10_000_000_000, true)).unwrap();
        assert!(!v6.decisions.economics_v7);
        assert!(v7.decisions.economics_v7);
        assert!(
            v7.account_count > v6.account_count,
            "v7 seeds more genesis singletons ({} > {})",
            v7.account_count,
            v6.account_count
        );
    }
}
