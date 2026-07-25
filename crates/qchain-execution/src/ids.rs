//! Well-known, unkeyed protocol program/account addresses - sentinel
//! pubkeys the same way `Pubkey::system_program_id()` ([0u8;32]) already
//! is. Nobody holds a private key for any of these; only the matching
//! native program is ever allowed to mutate the accounts it owns.

use qchain_crypto::Pubkey;

pub const STAKING_PROGRAM_ID: Pubkey = Pubkey::new([1u8; 32]);
/// Singleton account (owned by `STAKING_PROGRAM_ID`) whose `data` is a
/// borsh-encoded `u64` running total of currently-delegated stake -
/// updated on every `Delegate`/`Undelegate` so governance quorum checks
/// never need to scan every stake account in existence.
pub const STAKING_STATS_ID: Pubkey = Pubkey::new([2u8; 32]);

pub const GOVERNANCE_PROGRAM_ID: Pubkey = Pubkey::new([3u8; 32]);
/// Singleton account (owned by `GOVERNANCE_PROGRAM_ID`) whose `data` is a
/// borsh-encoded `Vec<qchain_crypto::RegistryEntry>` - the on-chain
/// algorithm registry a passed `Registry`-tier proposal mutates.
pub const REGISTRY_ACCOUNT_ID: Pubkey = Pubkey::new([4u8; 32]);
/// Singleton account (owned by `GOVERNANCE_PROGRAM_ID`) whose `data` is a
/// borsh-encoded `crate::params::EconomicParams` - the on-chain economic
/// parameters a passed `Low`-tier proposal mutates, and what `Ledger`
/// reads fee/dust/gas pricing from at execution time.
pub const PARAMS_ACCOUNT_ID: Pubkey = Pubkey::new([5u8; 32]);
/// Singleton account (owned by `STAKING_PROGRAM_ID`) whose `data` is a
/// borsh-encoded `crate::staking::RewardPoolData` and whose `balance` is
/// the real QCH held for delegators to claim - see `staking.rs`'s module
/// docs for the reward-per-share accrual mechanism this backs.
pub const STAKING_REWARDS_POOL_ID: Pubkey = Pubkey::new([6u8; 32]);

/// Owner of every account created by `SystemInstruction::DeployProgram`
/// (see `native.rs`) - a deployed contract's bytecode lives in that
/// account's `data` (borsh-encoded `native::WasmProgramData`), the same
/// way any other program-owned account works, so it persists through
/// `SledStore` like everything else instead of living only in the
/// in-memory `Ledger::programs` registry the three built-in native
/// programs use. `Ledger::apply_transaction`'s instruction dispatch falls
/// back to reading this owner + deserializing this data whenever
/// `ix.program_id` isn't one of the fixed native ids.
pub const LOADER_PROGRAM_ID: Pubkey = Pubkey::new([7u8; 32]);

/// Well-known singleton holding the dynamic-fee bookkeeping (`FeeState`: the
/// current fee epoch/round and the bytes committed in it so far). Kept in its
/// OWN account rather than folded into `EconomicParams` so existing persisted
/// `PARAMS` accounts (from a network deployed before dynamic fees) still
/// deserialize unchanged - this account is simply absent there and created,
/// deterministically, on the first transaction after the upgrade. The dynamic
/// `base_fee_per_byte` itself stays in `EconomicParams`; only the accumulator
/// lives here. See `Ledger::advance_dynamic_fee`.
pub const FEE_STATE_ACCOUNT_ID: Pubkey = Pubkey::new([8u8; 32]);

/// Well-known singleton holding the on-chain validator registry - the directory
/// of validators that have registered themselves by locking self-stake
/// (`StakingInstruction::RegisterValidator`): their consensus key bundle, their
/// P2P network address (for peer discovery), and the self-stake backing them.
/// This is the foundation of dynamic, permissionless validator membership
/// (phase 3): a newcomer stakes and registers here instead of a coordinator
/// hand-editing a genesis file. Inert on its own - nothing reads it for
/// consensus yet; the active-set-by-stake selection and epoch rotation that
/// wire it into `qchain-consensus` are the following increments.
pub const VALIDATOR_REGISTRY_ACCOUNT_ID: Pubkey = Pubkey::new([9u8; 32]);

// ---------------------------------------------------------------------------
// v7 economic pools (SPEC: docs/ECONOMIC-REDESIGN.md §12 — strict separation of
// economic sources). Additive sentinel addresses; INERT until the v7 execution
// phases wire them. Kept separate so no source ever subsidizes another (bonds
// never pay rewards, fees never pay staking, emission never pays validators),
// which is what the mandatory supply/pool invariants (§13) check.
// ---------------------------------------------------------------------------

/// Escrow holding every validator's 500 QCH bond (collateral; earns nothing).
/// `Σ bonds in the registry == this account's balance` is an invariant.
pub const VALIDATOR_BOND_ESCROW_ID: Pubkey = Pubkey::new([10u8; 32]);
/// Reserve backing staker rewards. Emission is minted here each quanto; a
/// withdrawal pays out from here. Distinct from the v6 `STAKING_REWARDS_POOL_ID`
/// (the old reward-per-share pool) because v7 uses the shares/index model.
pub const STAKING_RESERVE_ID: Pubkey = Pubkey::new([11u8; 32]);
/// Pool accumulating the non-burned half of fees during a quanto, split 1/N
/// among eligible validators at the close (remainder kept for the next quanto).
pub const VALIDATOR_FEE_POOL_ID: Pubkey = Pubkey::new([12u8; 32]);
/// Holds common-staking principal that is in its unbonding window (no longer
/// earning) until it becomes withdrawable.
pub const STAKING_UNBONDING_POOL_ID: Pubkey = Pubkey::new([13u8; 32]);
/// Holds a validator bond that is unbonding after a valid exit (still slashable
/// until the evidence window closes) until it can be withdrawn.
pub const VALIDATOR_UNBONDING_POOL_ID: Pubkey = Pubkey::new([14u8; 32]);
/// Global staking state singleton: the `staking_index`, `total_staking_shares`,
/// `current_quanto`, `last_settled_quanto` — everything the O(1) per-quanto
/// close needs (see `economics_v7`). No funds; bookkeeping only.
pub const STAKING_GLOBAL_ID: Pubkey = Pubkey::new([15u8; 32]);

/// v7 validator program: processes `ValidatorV7Instruction` (BondAndRegister /
/// BeginExit / WithdrawBond / ReportEquivocation). A DISTINCT id from
/// `STAKING_PROGRAM_ID` (which in a v7 network runs `StakingV7Program`): both v7
/// instruction enums start at discriminant 0, so a single-id dispatcher could not
/// disambiguate them — the node registers each program under its own id. Only
/// registered when `economics_v7` is on.
pub const VALIDATOR_V7_PROGRAM_ID: Pubkey = Pubkey::new([16u8; 32]);

/// Administrative-expenses wallet: receives 10% of every fee under the v7 split
/// (45% validators / 45% burn / 10% admin — SPEC §11). Unlike the sentinel pool
/// IDs above this is a REAL operator-controlled wallet (base58
/// `AhcJAnfV3g7w9BpPVTbPzMMoEpGgBQBSb9vPm8B5Te2y`), so its share is liquid and
/// spendable with a normal signed transfer — no claim, no pool. Provided by the
/// operator; change these bytes to re-point administrative revenue.
pub const ADMIN_FEE_WALLET: Pubkey = Pubkey::new([
    144, 32, 82, 243, 147, 55, 160, 242, 118, 129, 105, 137, 140, 206, 47, 83, 87, 91, 106, 239,
    138, 12, 249, 6, 33, 130, 72, 75, 174, 92, 140, 246,
]);

/// v7 treasury program: processes `TreasuryV7Instruction` (Release / SetAuthority).
/// Owns `TREASURY_ACCOUNT_ID`, so the locked genesis supply there can only be moved
/// by a `Release` signed by the treasury authority — never by a plain transfer.
/// Only registered when `economics_v7` is on. A distinct id from the staking/
/// validator programs (whose instruction enums also start at discriminant 0).
pub const TREASURY_V7_PROGRAM_ID: Pubkey = Pubkey::new([17u8; 32]);
/// The genesis-locked treasury account (owned by `TREASURY_V7_PROGRAM_ID`). Its
/// `balance` is the locked circulating supply the operator seeds at genesis; its
/// `data` is a borsh-encoded `treasury_v7::TreasuryState` naming the release
/// authority. Absent on a v6 network or a v7 network with no treasury configured.
pub const TREASURY_ACCOUNT_ID: Pubkey = Pubkey::new([18u8; 32]);

/// Emergency governance multisig singleton (owned by `GOVERNANCE_PROGRAM_ID`).
/// Its `data` is a borsh-encoded `governance::EmergencyState` naming a set of
/// guardian pubkeys, an approval threshold, and a `paused` flag (task #213).
/// When `paused`, governance `Execute` is blocked for ALL proposals — the
/// guardians' emergency brake on any pending/rushed change. The pause flips a
/// flag and gates execution only; it can NEVER touch a balance, so it is
/// structurally incapable of confiscating funds. Seeded at genesis (empty
/// guardian set = the feature is inert). Absent on a network whose genesis
/// predates this feature (a legacy already-seeded chain), which `Execute`
/// tolerates as "not paused".
pub const EMERGENCY_ACCOUNT_ID: Pubkey = Pubkey::new([19u8; 32]);

/// Pre-minted **emission reserve** for the HARD-CAP supply model (SPEC §5, task
/// #221). Under `hard_cap_supply`, each quanto's staking emission is DRAWN from
/// this account (debited here, credited to `STAKING_RESERVE_ID`) instead of
/// minted — so total supply can NEVER grow past what genesis minted. Seeded at
/// genesis with the operator's chosen reserve (part of the ≤100M split); fee
/// income routed here refills it. When it empties, staking yield falls to
/// whatever real income provides ("fees only"). Owned by `STAKING_PROGRAM_ID`
/// so the dust sweep never touches it. Absent on an inflationary v7 network
/// (`hard_cap_supply` off) or any v6 network, so their genesis roots are
/// unchanged — this is a fresh-genesis, chain_id-folded decision.
pub const EMISSION_RESERVE_ID: Pubkey = Pubkey::new([20u8; 32]);

/// Unspendable BURN sink — the all-`0xFF` address. Nobody can derive its private
/// key, so value credited here is permanently out of circulation (the same
/// deflationary burn address the wallet already uses when deleting a funded
/// account, v4.0.2). Used by governance `CloseProposal` (roadmap #16) to forfeit
/// a spam proposal's anti-spam deposit: routing it to a real (if unspendable)
/// balance keeps supply conservation trivially intact (`Σ balances` is
/// unchanged, the value just moves to an address no one controls), unlike
/// zeroing an account, which would silently destroy supply. System-owned, so if
/// the forfeited amount happens to be below `dust_threshold` the ordinary dust
/// sweep also removes it — either way it leaves circulation.
pub const BURN_ADDRESS: Pubkey = Pubkey::new([0xFFu8; 32]);

/// On-chain SCHEMA MANIFEST singleton (roadmap #19). Holds the canonical,
/// EXPLICIT `{singleton -> schema_version}` map for this chain, so a node no
/// longer relies on trial-Borsh alone to know a singleton's format — the
/// expected version is declared on-chain and verified at startup (fail-loud on
/// a mismatch). **Absent** on a network that doesn't opt in
/// (`explicit_schema_versions` off — the default), so existing genesis roots and
/// chain_ids are unchanged; seeding it is a fresh-genesis, chain_id-folded
/// decision (a new leaf changes the state root). System-owned; carries no funds.
pub const SCHEMA_MANIFEST_ID: Pubkey = Pubkey::new([21u8; 32]);

/// Singleton account (owned by `STAKING_PROGRAM_ID`) whose `data` is the v7
/// **recovery registry** (programa de gestión de claves, KM#4). Maps each
/// validator's consensus address to its OFFLINE recovery committee (M-de-N
/// recovery pubkeys + threshold + monotonic nonce). Held in its OWN account
/// (not on each validator entry) so it is purely ADDITIVE: an existing v7
/// network with no such account sees an empty recovery registry until a
/// validator opts in via `SetRecoveryCommittee` — no registry-format migration,
/// no chain_id change, brick-safe on a live network. Lazily created on the first
/// `SetRecoveryCommittee`. If any validator's keys are lost/compromised, its
/// recovery committee can REVOKE it (M-de-N offline signatures) WITHOUT any of
/// the compromised keys. Carries no funds.
pub const VALIDATOR_RECOVERY_REGISTRY_ID: Pubkey = Pubkey::new([22u8; 32]);

/// Singleton account (owned by `STAKING_PROGRAM_ID`) whose `data` is the v7 **key
/// timelock registry** (programa de gestión de claves, KM#5). Holds the PENDING
/// cold-key changes of validators — an operator rotation (~24h), a withdrawal
/// rotation (~72h), or a recovery-committee change (~7d) is PROPOSED here and only
/// takes effect after its mandatory window, so a compromised operator key cannot
/// instantly rotate the withdrawal to itself (drain the bond/fees) or lock out the
/// real owner: the window gives time to react (e.g. a recovery-committee REVOKE,
/// KM#4). Held in its OWN account (not on each validator entry) so it is purely
/// ADDITIVE: an existing v7 network with no such account has no pending changes
/// until a validator first proposes one — no registry-format migration, no
/// chain_id change, brick-safe on a live network. Lazily created. Carries no funds.
pub const VALIDATOR_KEY_TIMELOCK_REGISTRY_ID: Pubkey = Pubkey::new([23u8; 32]);

/// Singleton account (owned by `STAKING_PROGRAM_ID`) whose `data` is the v7
/// **consensus-key rotation registry** (programa de gestión de claves, KM#6). Holds
/// the PENDING two-phase consensus-key rotations of validators: the cold operator
/// PROPOSES a new consensus key (phase 1), and the NEW key ACCEPTS by proving
/// possession (phase 2, domain `KEY_ROTATION_ACCEPT_V1`) before the rotation takes
/// effect — so a rotation to an unpossessed key is impossible, the acceptance can
/// be signed on a machine separate (air-gapped) from the operator, and the rotation
/// is a two-party agreement. Held in its OWN account (not on each validator entry)
/// so it is purely ADDITIVE: an existing v7 network has no pending rotations until a
/// validator first proposes one — no registry-format migration, no chain_id change,
/// brick-safe. Lazily created. Carries no funds.
pub const VALIDATOR_CONSENSUS_ROTATION_REGISTRY_ID: Pubkey = Pubkey::new([24u8; 32]);

/// **audit trail encadenado por hash de gestión de claves** (programa de gestión
/// de claves, KM#9). Guarda un log ON-CHAIN, encadenado por hash, de cada evento
/// sensible del ciclo de vida de claves de un validador: freeze/unfreeze de
/// emergencia (por el comité de recuperación), expiración/rotación obligatoria, y
/// revoke por recuperación. Cada entrada compromete la anterior con SHA3 (dominio
/// `KM_AUDIT_V1`) y el `head_hash` del log compromete TODA la historia →
/// tamper-evident aunque el log se exporte fuera de banda, verificable por un
/// auditor externo. Vive en su PROPIO account (no en cada entrada de validador) →
/// puramente ADITIVO: un v7 existente no tiene log hasta el primer evento — cero
/// migración del formato del registro, sin cambio de `chain_id`, brick-safe.
/// Creado perezosamente. No lleva fondos.
pub const VALIDATOR_KM_AUDIT_LOG_ID: Pubkey = Pubkey::new([25u8; 32]);


/// **Identidad de red on-chain (`chain_id`) — sembrada en génesis, inmutable
/// (tarea #187).** Guarda los 32 bytes del `chain_id` que el nodo deriva de su
/// config (`validators` + `genesis`), para que un programa nativo pueda ATAR una
/// verificación a ESTA red sin que haya que enroscar el chain_id por la firma de
/// `NativeProgram::process`.
///
/// **Por qué existe.** La evidencia de equivocación (`ReportEquivocation`, v6 y
/// v7) sólo exige (misma ronda, mismo autor, digests distintos, ambas firmas
/// verifican). Como el voto pasó a firmar `VERTEX_VOTE_V1 ‖ chain_id ‖ digest`,
/// el handler necesita saber CUÁL es el chain_id de esta red para verificar bajo
/// él — si no, un atacante nombraría el de otra cadena y las dos firmas (hechas
/// en redes distintas por un validador HONESTO) verificarían igual, quemándole el
/// bono. El valor vive en un singleton porque es exactamente el patrón que este
/// código ya usa para `PARAMS`/`STAKING_STATS`/`STAKING_GLOBAL`: un dato de
/// consenso que el handler lee de una cuenta PINNEADA en `ix.accounts`.
///
/// No lleva fondos y ninguna instrucción lo escribe: se siembra una vez en
/// génesis y queda fijo. Sembrarlo NO cambia el `chain_id` (que se computa del
/// CONFIG, no del estado) — sólo el state root de génesis, igual que cualquier
/// otro singleton nuevo.
pub const CHAIN_ID_ACCOUNT_ID: Pubkey = Pubkey::new([26u8; 32]);

/// Lee el `chain_id` de esta red desde [`CHAIN_ID_ACCOUNT_ID`], que el llamador
/// DEBE haber pinneado en `ix.accounts` (la lección de KM#6: sin el pin, la
/// cuenta no está en el working set y la lectura fallaría en silencio).
///
/// **Fail-closed a propósito:** si la cuenta falta o no tiene exactamente 32
/// bytes, esto es un ERROR, nunca un default. Un default (p. ej. ceros) haría que
/// las firmas se verificaran bajo un chain_id que ninguna red usa —o peor, bajo
/// uno común a todas—, reabriendo justo el agujero que el binding cierra (la
/// clase EC-18: la protección coincide con el default y desaparece en silencio).
pub fn read_chain_id(
    accounts: &std::collections::HashMap<Pubkey, qchain_core::Account>,
) -> Result<[u8; 32], crate::ExecError> {
    let acct = accounts
        .get(&CHAIN_ID_ACCOUNT_ID)
        .ok_or_else(|| crate::ExecError::ProgramError("the chain-id singleton is not in this instruction's accounts (#187)".into()))?;
    let bytes: [u8; 32] = acct
        .data
        .as_slice()
        .try_into()
        .map_err(|_| crate::ExecError::ProgramError("the chain-id singleton must hold exactly 32 bytes".into()))?;
    Ok(bytes)
}

#[cfg(test)]
mod wasm_id_contract_tests {
    use super::*;

    /// `qchain-wasm` (the browser self-custody signer, excluded from this
    /// workspace and built separately for wasm32) hand-copies the singleton
    /// account ids it needs to build v7 staking/governance instructions, since
    /// it can't depend on this crate. Those literals MUST stay byte-identical to
    /// the ids here — a drift wouldn't move funds without the payer's signature
    /// (the node validates the account set, so a wrong id yields a rejected tx,
    /// not a loss), but it is a silent footgun that breaks the wallet's v7
    /// flows. This test mirrors `qchain-wasm/src/lib.rs`'s hardcoded values so
    /// any change to an id here fails loudly, flagging that the wasm copy (and
    /// its regenerated assets) must be updated in the same change.
    #[test]
    fn wasm_hardcoded_singleton_ids_match_this_crate() {
        assert_eq!(STAKING_PROGRAM_ID, Pubkey::new([1u8; 32]), "wasm STAKING_PROGRAM_ID");
        assert_eq!(STAKING_STATS_ID, Pubkey::new([2u8; 32]), "wasm STAKING_STATS_ID");
        assert_eq!(GOVERNANCE_PROGRAM_ID, Pubkey::new([3u8; 32]), "wasm GOVERNANCE_PROGRAM_ID");
        assert_eq!(REGISTRY_ACCOUNT_ID, Pubkey::new([4u8; 32]), "wasm REGISTRY_ACCOUNT_ID");
        assert_eq!(PARAMS_ACCOUNT_ID, Pubkey::new([5u8; 32]), "wasm PARAMS_ACCOUNT_ID");
        assert_eq!(STAKING_REWARDS_POOL_ID, Pubkey::new([6u8; 32]), "wasm STAKING_REWARDS_POOL_ID");
        assert_eq!(EMERGENCY_ACCOUNT_ID, Pubkey::new([19u8; 32]), "wasm EMERGENCY_ACCOUNT_ID");
        assert_eq!(STAKING_RESERVE_ID, Pubkey::new([11u8; 32]), "wasm STAKING_RESERVE_ID");
        assert_eq!(STAKING_UNBONDING_POOL_ID, Pubkey::new([13u8; 32]), "wasm STAKING_UNBONDING_POOL_ID");
        assert_eq!(STAKING_GLOBAL_ID, Pubkey::new([15u8; 32]), "wasm STAKING_GLOBAL_ID");
    }
}
