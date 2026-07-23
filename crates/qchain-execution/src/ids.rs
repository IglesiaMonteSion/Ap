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
