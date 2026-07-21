//! Browser/WASM self-custody signing for qchain.
//!
//! Phase 2 of the wallet: the private key is generated and used **in the
//! user's browser**, never on any server. This crate compiles the *same*
//! `qchain-core` + `qchain-crypto` code the node uses (with the pure-Rust
//! `pure` crypto backend, since liboqs/C doesn't target wasm) to WebAssembly,
//! so a transaction signed here is byte-identical to one from `qchain-cli` and
//! is accepted by the live node (byte-compatibility proven in
//! `qchain-crypto/tests/wasm_feasibility.rs`).
//!
//! The browser supplies 32 bytes of real entropy (`crypto.getRandomValues`) as
//! the master seed; the whole hybrid keypair is derived from it deterministically
//! (`Keypair::generate_from_seed`). The seed is the only secret, and it never
//! leaves the device.
//!
//! Two layers here:
//!   - backend-agnostic core functions (`address_from_seed`, `sign_transfer_json`)
//!     — plain Rust, testable natively;
//!   - `#[wasm_bindgen]` wrappers (wasm target only) exposing them to JavaScript.

use qchain_core::{Instruction, Transaction};
use qchain_crypto::{Keypair, Pubkey};

/// SystemInstruction::Transfer { amount } is variant 1 in
/// `qchain-execution::native`; its Borsh encoding is `[1u8]` followed by the
/// amount as 8 little-endian bytes. Replicated here (rather than depending on
/// qchain-execution, which pulls wasmtime and won't target wasm) and guarded by
/// `transfer_instruction_encoding_is_stable` in qchain-execution so a future
/// enum change is caught immediately.
fn transfer_instruction_data(amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(9);
    data.push(1u8);
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

/// `SystemInstruction::DeployProgram { module_bytes, entry_point }` Borsh
/// encoding (variant order in `qchain-execution::native`: CreateAccount=0,
/// Transfer=1, DeployProgram=2), guarded by
/// `deploy_program_instruction_encoding_is_stable` in qchain-execution.
/// `[2]` ++ Vec<u8>(u32 LE len ++ bytes) ++ String(u32 LE len ++ utf8).
fn deploy_program_instruction_data(module_bytes: &[u8], entry_point: &str) -> Vec<u8> {
    let mut data = Vec::with_capacity(1 + 4 + module_bytes.len() + 4 + entry_point.len());
    data.push(2u8);
    data.extend_from_slice(&(module_bytes.len() as u32).to_le_bytes());
    data.extend_from_slice(module_bytes);
    data.extend_from_slice(&(entry_point.len() as u32).to_le_bytes());
    data.extend_from_slice(entry_point.as_bytes());
    data
}

// Well-known staking addresses (qchain-execution::ids), replicated here for the
// same reason as the instruction encodings above.
const STAKING_PROGRAM_ID: [u8; 32] = [1u8; 32];
const STAKING_STATS_ID: [u8; 32] = [2u8; 32];
const GOVERNANCE_PROGRAM_ID: [u8; 32] = [3u8; 32];
const REGISTRY_ACCOUNT_ID: [u8; 32] = [4u8; 32];
const PARAMS_ACCOUNT_ID: [u8; 32] = [5u8; 32];
const STAKING_REWARDS_POOL_ID: [u8; 32] = [6u8; 32];
// v7 staking singletons (economics_v7 networks). On a v7 network STAKING_PROGRAM_ID
// dispatches to StakingV7Program, whose instructions (Stake/IncreaseStake/
// BeginUnstake/WithdrawUnbonded) use the shares+index reserve model - a different
// account set from the v6 Delegate/Undelegate above.
const STAKING_RESERVE_ID: [u8; 32] = [11u8; 32];
const STAKING_UNBONDING_POOL_ID: [u8; 32] = [13u8; 32];
const STAKING_GLOBAL_ID: [u8; 32] = [15u8; 32];

/// `StakingInstruction` Borsh encodings (variant order in
/// `qchain-execution::staking`: Delegate=0, Undelegate=1, ClaimReward=2),
/// guarded by `stake_instruction_encoding_is_stable` in qchain-execution.
/// Delegate = `[0]` ++ validator (32 bytes) ++ amount (8 LE bytes).
fn delegate_instruction_data(validator: &[u8; 32], amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(41);
    data.push(0u8);
    data.extend_from_slice(validator);
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

/// Derive the wallet address (base58) from a 32-byte master seed.
pub fn address_from_seed(seed: &[u8; 32]) -> anyhow::Result<String> {
    Ok(Keypair::generate_from_seed(seed)?.pubkey().to_string())
}

/// Base58 address of an arbitrary 32-byte value. Used by the browser to turn
/// the fresh random bytes it picked for a new stake account into an address it
/// can save and later undelegate/claim against (nobody ever signs *as* this
/// address, so it needs no key - see the CLI's `StakeDelegate`).
pub fn address_from_bytes(bytes: &[u8; 32]) -> String {
    Pubkey::new(*bytes).to_string()
}

/// Deterministically derive the address of the `index`-th stake account for a
/// given master seed.
///
/// A stake account is program-owned - nobody ever signs *as* it (see the CLI's
/// `StakeDelegate`), and only its stored `owner` (the delegator's wallet) can
/// undelegate or claim against it - so its address only needs to be unique and
/// reproducible, not a real keypair. Deriving it from the seed (instead of
/// fresh randomness the browser saves only in `localStorage`) is what makes a
/// staked position RECOVERABLE from the seed alone: after a restore, re-derive
/// index 0, 1, 2, ... and query each against the chain to rebuild the list.
///
/// Domain-separated (`"qchain-stake-account-v1"`) so it can never collide with
/// the wallet address itself (a completely different derivation), and
/// preimage-resistant (SHA3-256) so publishing the derived address never leaks
/// the seed. Nobody can pre-create or grief the account either: computing the
/// address at all requires the seed.
pub fn stake_address_from_seed(seed: &[u8; 32], index: u32) -> String {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"qchain-stake-account-v1");
    hasher.update(seed);
    hasher.update(index.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    Pubkey::new(digest).to_string()
}

/// Derive the `index`-th ACCOUNT seed from a single master seed - the HD-style
/// "create a new address" feature (like MetaMask/Phantom's multiple accounts).
/// One master seed (the only thing the user backs up) yields an unlimited number
/// of independent accounts, each a real, distinct signing keypair, ALL
/// recoverable from that one seed alone.
///
/// **Account 0 returns the master seed unchanged**, so an existing wallet's
/// first (and until now, only) address is byte-identical to before this feature
/// existed - nobody's address moves. Accounts `1, 2, 3, ...` are
/// domain-separated (`"qchain-account-v1"`) SHA3-256 derivations, so they can
/// never collide with account 0, with each other, or with the stake-account
/// derivation (`"qchain-stake-account-v1"`). Preimage-resistant, so publishing a
/// derived account address never leaks the master seed.
pub fn derive_account_seed(master_seed: &[u8; 32], index: u32) -> [u8; 32] {
    if index == 0 {
        return *master_seed;
    }
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"qchain-account-v1");
    hasher.update(master_seed);
    hasher.update(index.to_le_bytes());
    hasher.finalize().into()
}

/// Sign a `Delegate` (stake `amount` to `validator`). `stake_account` is the
/// fresh address the browser generated for this position. accounts order matches
/// the CLI: [payer, stake_account, stats, reward_pool].
pub fn sign_delegate_json(
    seed: &[u8; 32],
    validator: &str,
    amount: u64,
    stake_account: &str,
    nonce: u64,
    chain_id: &[u8; 32],
    fee_limit: u64,
) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let validator_pk: Pubkey = validator.trim().parse().map_err(|e| anyhow::anyhow!("validator address invalid: {e}"))?;
    let stake_pk: Pubkey = stake_account.trim().parse().map_err(|e| anyhow::anyhow!("stake account address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::new(STAKING_PROGRAM_ID),
        accounts: vec![payer.pubkey(), stake_pk, Pubkey::new(STAKING_STATS_ID), Pubkey::new(STAKING_REWARDS_POOL_ID)],
        data: delegate_instruction_data(&validator_pk.to_bytes(), amount),
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// Sign an `Undelegate` (`[1]`) against a stake account. accounts:
/// [stake_account, stats, reward_pool].
pub fn sign_undelegate_json(
    seed: &[u8; 32],
    stake_account: &str,
    nonce: u64,
    chain_id: &[u8; 32],
    fee_limit: u64,
) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let stake_pk: Pubkey = stake_account.trim().parse().map_err(|e| anyhow::anyhow!("stake account address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::new(STAKING_PROGRAM_ID),
        accounts: vec![stake_pk, Pubkey::new(STAKING_STATS_ID), Pubkey::new(STAKING_REWARDS_POOL_ID)],
        data: vec![1u8],
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// Sign a `ClaimReward` (`[2]`) against a stake account. accounts:
/// [stake_account, reward_pool].
pub fn sign_claim_reward_json(
    seed: &[u8; 32],
    stake_account: &str,
    nonce: u64,
    chain_id: &[u8; 32],
    fee_limit: u64,
) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let stake_pk: Pubkey = stake_account.trim().parse().map_err(|e| anyhow::anyhow!("stake account address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::new(STAKING_PROGRAM_ID),
        accounts: vec![stake_pk, Pubkey::new(STAKING_REWARDS_POOL_ID)],
        data: vec![2u8],
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// v7 staking instruction Borsh encodings (`StakingV7Instruction` variant order
/// in qchain-execution::staking_v7: Stake=0, IncreaseStake=1, BeginUnstake=2,
/// WithdrawUnbonded=3), guarded by `staking_v7_instruction_encoding_is_stable`
/// in qchain-execution. Stake/IncreaseStake/BeginUnstake = `[disc]` ++ amount
/// (8 LE bytes); WithdrawUnbonded = `[3]`.
fn v7_amount_instruction_data(disc: u8, amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(9);
    data.push(disc);
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

/// v7 `Stake` (`[0]`): open a NEW position holding `amount` atoms. Unlike v6
/// `Delegate` there is NO validator target - principal moves into the global
/// staking reserve and the position accrues via the index. `position` is the
/// fresh, seed-derived address the browser picked for this position. accounts =
/// [payer, position, STAKING_GLOBAL, STAKING_RESERVE].
pub fn sign_v7_stake_json(seed: &[u8; 32], position: &str, amount: u64, nonce: u64, chain_id: &[u8; 32], fee_limit: u64) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let pos_pk: Pubkey = position.trim().parse().map_err(|e| anyhow::anyhow!("position address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::new(STAKING_PROGRAM_ID),
        accounts: vec![payer.pubkey(), pos_pk, Pubkey::new(STAKING_GLOBAL_ID), Pubkey::new(STAKING_RESERVE_ID)],
        data: v7_amount_instruction_data(0, amount),
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// v7 `IncreaseStake` (`[1]`): add `amount` to an EXISTING position you own.
/// accounts = [payer, position, STAKING_GLOBAL, STAKING_RESERVE].
pub fn sign_v7_increase_json(seed: &[u8; 32], position: &str, amount: u64, nonce: u64, chain_id: &[u8; 32], fee_limit: u64) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let pos_pk: Pubkey = position.trim().parse().map_err(|e| anyhow::anyhow!("position address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::new(STAKING_PROGRAM_ID),
        accounts: vec![payer.pubkey(), pos_pk, Pubkey::new(STAKING_GLOBAL_ID), Pubkey::new(STAKING_RESERVE_ID)],
        data: v7_amount_instruction_data(1, amount),
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// v7 `BeginUnstake` (`[2]`): move `amount` atoms of value into unbonding
/// (withdrawing rewards = a partial unstake of the accrued value). accounts =
/// [payer, position, STAKING_GLOBAL, STAKING_RESERVE, STAKING_UNBONDING_POOL].
pub fn sign_v7_begin_unstake_json(seed: &[u8; 32], position: &str, amount: u64, nonce: u64, chain_id: &[u8; 32], fee_limit: u64) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let pos_pk: Pubkey = position.trim().parse().map_err(|e| anyhow::anyhow!("position address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::new(STAKING_PROGRAM_ID),
        accounts: vec![payer.pubkey(), pos_pk, Pubkey::new(STAKING_GLOBAL_ID), Pubkey::new(STAKING_RESERVE_ID), Pubkey::new(STAKING_UNBONDING_POOL_ID)],
        data: v7_amount_instruction_data(2, amount),
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// v7 `WithdrawUnbonded` (`[3]`): pay out the matured unbonding chunk. accounts =
/// [payer, position, STAKING_UNBONDING_POOL, STAKING_GLOBAL]. The global account
/// is required so the maturity check reads the real current quanto (audit fix).
pub fn sign_v7_withdraw_unbonded_json(seed: &[u8; 32], position: &str, nonce: u64, chain_id: &[u8; 32], fee_limit: u64) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let pos_pk: Pubkey = position.trim().parse().map_err(|e| anyhow::anyhow!("position address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::new(STAKING_PROGRAM_ID),
        accounts: vec![payer.pubkey(), pos_pk, Pubkey::new(STAKING_UNBONDING_POOL_ID), Pubkey::new(STAKING_GLOBAL_ID)],
        data: vec![3u8],
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// Governance `Vote` (`GovernanceInstruction` discriminant `1`), weighted by a
/// stake account you own. accounts match the CLI: [proposal, stake_account];
/// `choice` is 0=Yes, 1=No, 2=Abstain (`VoteChoice` Borsh order, guarded by
/// `governance_instruction_encoding_is_stable` in qchain-execution). The stake
/// account's stored `owner` must equal this payer, so only positions you
/// control can vote.
pub fn sign_vote_json(
    seed: &[u8; 32],
    proposal: &str,
    stake_account: &str,
    choice: u8,
    nonce: u64,
    chain_id: &[u8; 32],
    fee_limit: u64,
) -> anyhow::Result<String> {
    if choice > 2 {
        anyhow::bail!("vote choice must be 0=Yes, 1=No, or 2=Abstain");
    }
    let payer = Keypair::generate_from_seed(seed)?;
    let proposal_pk: Pubkey = proposal.trim().parse().map_err(|e| anyhow::anyhow!("proposal address invalid: {e}"))?;
    let stake_pk: Pubkey = stake_account.trim().parse().map_err(|e| anyhow::anyhow!("stake account address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::new(GOVERNANCE_PROGRAM_ID),
        accounts: vec![proposal_pk, stake_pk],
        data: vec![1u8, choice],
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// Governance `Finalize` (`GovernanceInstruction` discriminant `2`, data `[2]`),
/// permissionless once voting ends. accounts match the CLI: [proposal,
/// staking-stats singleton].
pub fn sign_finalize_json(
    seed: &[u8; 32],
    proposal: &str,
    nonce: u64,
    chain_id: &[u8; 32],
    fee_limit: u64,
) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let proposal_pk: Pubkey = proposal.trim().parse().map_err(|e| anyhow::anyhow!("proposal address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::new(GOVERNANCE_PROGRAM_ID),
        accounts: vec![proposal_pk, Pubkey::new(STAKING_STATS_ID)],
        data: vec![2u8],
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// Governance `Execute` (`GovernanceInstruction` discriminant `3`, data `[3]`),
/// permissionless once a passed proposal's timelock has elapsed. accounts match
/// the CLI: [proposal, target-singleton]. The target is the economic-params
/// account for a Low-tier action or the registry account for a Registry-tier
/// action - the caller passes `registry=true` for the latter. The node
/// enforces the correct singleton per the proposal's real tier, so a wrong
/// choice is rejected, never mis-applied.
pub fn sign_execute_json(
    seed: &[u8; 32],
    proposal: &str,
    registry: bool,
    nonce: u64,
    chain_id: &[u8; 32],
    fee_limit: u64,
) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let proposal_pk: Pubkey = proposal.trim().parse().map_err(|e| anyhow::anyhow!("proposal address invalid: {e}"))?;
    let target = if registry { REGISTRY_ACCOUNT_ID } else { PARAMS_ACCOUNT_ID };
    let ix = Instruction {
        program_id: Pubkey::new(GOVERNANCE_PROGRAM_ID),
        accounts: vec![proposal_pk, Pubkey::new(target)],
        data: vec![3u8],
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// Build and sign a Transfer, returning the signed `Transaction` as JSON, ready
/// to POST to the node's `/tx`. Byte-identical to what `qchain-cli transfer`
/// produces, and signed entirely in-browser.
pub fn sign_transfer_json(
    seed: &[u8; 32],
    to: &str,
    amount: u64,
    nonce: u64,
    chain_id: &[u8; 32],
    fee_limit: u64,
) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let to_pk: Pubkey = to.trim().parse().map_err(|e| anyhow::anyhow!("destination address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::system_program_id(),
        accounts: vec![payer.pubkey(), to_pk],
        data: transfer_instruction_data(amount),
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// Derive a fresh, recoverable **program (contract) address** from the master
/// seed + an index. Domain-separated (`"qchain-program-account-v1"`) so it can
/// never collide with the wallet address or a stake account. A program account
/// is program-owned (nobody signs *as* it), so its address just needs to be
/// unique and reproducible — deriving it from the seed means a restored wallet
/// can re-find the contracts it deployed. Deploy-once: pick the next unused
/// index (the node's `/programs` / `/account` says which exist).
pub fn program_address_from_seed(seed: &[u8; 32], index: u32) -> String {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(b"qchain-program-account-v1");
    hasher.update(seed);
    hasher.update(index.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    Pubkey::new(digest).to_string()
}

/// SDK v0.3 — deriva la dirección de una cuenta de estado PROPIA DEL PROGRAMA
/// (PDA) a partir del `program_id` (base58) y una `seed` de bytes. MISMA fórmula
/// que el nodo (`qchain_execution::wasm::derive_pda`): `SHA3-256("qchain-program-
/// pda-v1" ‖ program_id(32) ‖ seed)`. El cliente la usa para incluir la
/// dirección correcta en `accounts` al llamar a un contrato que usa `use_pda`.
pub fn program_pda(program_id: &str, seed: &[u8]) -> anyhow::Result<String> {
    use sha3::{Digest, Sha3_256};
    let pid: Pubkey = program_id.trim().parse().map_err(|e| anyhow::anyhow!("program id invalid: {e}"))?;
    let mut hasher = Sha3_256::new();
    hasher.update(b"qchain-program-pda-v1");
    hasher.update(pid.to_bytes());
    hasher.update(seed);
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(Pubkey::new(digest).to_string())
}

/// Sign a `DeployProgram` transaction: publish `module_bytes` (raw `.wasm`) as a
/// contract at `program_address` (a fresh address, e.g. `programAddressFromSeed`),
/// callable via `entry_point`. accounts = [program_address], program_id =
/// System Program (the loader runs on deploy). The payer (seed) signs and pays
/// the byte fee (bigger `.wasm` = proportionally bigger fee).
pub fn sign_deploy_program_json(
    seed: &[u8; 32],
    program_address: &str,
    module_bytes: &[u8],
    entry_point: &str,
    nonce: u64,
    chain_id: &[u8; 32],
    fee_limit: u64,
) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let program_pk: Pubkey = program_address.trim().parse().map_err(|e| anyhow::anyhow!("program address invalid: {e}"))?;
    let ix = Instruction {
        program_id: Pubkey::system_program_id(),
        accounts: vec![program_pk],
        data: deploy_program_instruction_data(module_bytes, entry_point),
    };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

/// Sign a contract-call transaction: invoke the contract at `program_id` with
/// `accounts` (comma-separated base58 addresses the instruction touches) and
/// `args` (comma-separated `i64` values — the on-chain calling convention packs
/// each as little-endian `i64` in `ix.data`). program_id = the contract's
/// address (the ledger dispatches loader-owned accounts to WASM). The payer
/// (seed) signs; `host_is_signer` sees the payer as the authenticated signer.
pub fn sign_call_program_json(
    seed: &[u8; 32],
    program_id: &str,
    accounts_csv: &str,
    args_csv: &str,
    nonce: u64,
    chain_id: &[u8; 32],
    fee_limit: u64,
) -> anyhow::Result<String> {
    let payer = Keypair::generate_from_seed(seed)?;
    let program_pk: Pubkey = program_id.trim().parse().map_err(|e| anyhow::anyhow!("program address invalid: {e}"))?;
    let mut accounts = Vec::new();
    for a in accounts_csv.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        accounts.push(a.parse::<Pubkey>().map_err(|e| anyhow::anyhow!("account address '{a}' invalid: {e}"))?);
    }
    let mut data = Vec::new();
    for arg in args_csv.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        data.extend_from_slice(&arg.parse::<i64>().map_err(|e| anyhow::anyhow!("arg '{arg}' is not an i64: {e}"))?.to_le_bytes());
    }
    let ix = Instruction { program_id: program_pk, accounts, data };
    let tx = Transaction::new_signed(&payer, nonce, *chain_id, fee_limit, vec![ix])?;
    Ok(serde_json::to_string(&tx)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_zero_is_the_master_and_higher_accounts_are_distinct_and_recoverable() {
        let master = [7u8; 32];
        // Account 0 MUST equal the master seed unchanged - existing wallets
        // keep their exact address.
        assert_eq!(derive_account_seed(&master, 0), master);
        // Higher accounts are distinct from account 0 and from each other.
        assert_ne!(derive_account_seed(&master, 1), master);
        assert_ne!(derive_account_seed(&master, 1), derive_account_seed(&master, 2));
        // Deterministic - the property recovery depends on (re-derive index N,
        // get the same account back).
        assert_eq!(derive_account_seed(&master, 5), derive_account_seed(&master, 5));
        // A different master gives different accounts.
        assert_ne!(derive_account_seed(&master, 1), derive_account_seed(&[8u8; 32], 1));
        // Each account is a real, distinct wallet address.
        let a0 = address_from_seed(&derive_account_seed(&master, 0)).unwrap();
        let a1 = address_from_seed(&derive_account_seed(&master, 1)).unwrap();
        assert_ne!(a0, a1);
        // An account seed must not collide with the stake-account derivation
        // (different domain separators).
        assert_ne!(derive_account_seed(&master, 1).to_vec(), stake_address_from_seed(&master, 1).into_bytes());
    }

    #[test]
    fn stake_address_is_deterministic_and_index_separated() {
        let seed = [7u8; 32];
        // Same (seed, index) always yields the same address - the property a
        // restore depends on.
        assert_eq!(stake_address_from_seed(&seed, 0), stake_address_from_seed(&seed, 0));
        // Different indices give different accounts (so a second delegation
        // never lands on the first account, which Delegate would reject).
        assert_ne!(stake_address_from_seed(&seed, 0), stake_address_from_seed(&seed, 1));
        // A different seed gives different addresses (positions are per-wallet).
        assert_ne!(stake_address_from_seed(&seed, 0), stake_address_from_seed(&[8u8; 32], 0));
        // And it must never equal the wallet address itself (distinct domains).
        assert_ne!(stake_address_from_seed(&seed, 0), address_from_seed(&seed).unwrap());
    }

    #[test]
    fn program_address_is_deterministic_index_separated_and_distinct_from_wallet_and_stake() {
        let seed = [7u8; 32];
        // Recoverable: same (seed, index) → same address.
        assert_eq!(program_address_from_seed(&seed, 0), program_address_from_seed(&seed, 0));
        // Distinct per index (deploy-once needs a fresh address each time).
        assert_ne!(program_address_from_seed(&seed, 0), program_address_from_seed(&seed, 1));
        // Per-wallet.
        assert_ne!(program_address_from_seed(&seed, 0), program_address_from_seed(&[8u8; 32], 0));
        // Distinct domain from the wallet address and the stake-account address.
        assert_ne!(program_address_from_seed(&seed, 0), address_from_seed(&seed).unwrap());
        assert_ne!(program_address_from_seed(&seed, 0), stake_address_from_seed(&seed, 0));
    }

    #[test]
    fn program_pda_is_deterministic_and_separated_by_program_and_seed() {
        let prog_a = program_address_from_seed(&[7u8; 32], 0);
        let prog_b = program_address_from_seed(&[8u8; 32], 0);
        // Determinista: mismo (program_id, seed) → misma PDA.
        assert_eq!(program_pda(&prog_a, b"global").unwrap(), program_pda(&prog_a, b"global").unwrap());
        // Separada por seed.
        assert_ne!(program_pda(&prog_a, b"global").unwrap(), program_pda(&prog_a, b"other").unwrap());
        // Separada por programa (sin front-running: A y B derivan PDAs distintas).
        assert_ne!(program_pda(&prog_a, b"global").unwrap(), program_pda(&prog_b, b"global").unwrap());
        // Distinta de la dirección de deploy del propio programa.
        assert_ne!(program_pda(&prog_a, b"global").unwrap(), prog_a);
        // Rechaza un program_id inválido.
        assert!(program_pda("not-base58!!", b"x").is_err());
    }

    #[test]
    fn deploy_and_call_signers_produce_valid_signed_txs() {
        let seed = [7u8; 32];
        let chain = [9u8; 32];
        let prog = program_address_from_seed(&seed, 0);
        let module = vec![0x00u8, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        // Deploy signs and round-trips as JSON.
        let dep = sign_deploy_program_json(&seed, &prog, &module, "run", 0, &chain, 10_000_000).unwrap();
        assert!(dep.contains("signature"), "deploy tx must be a signed tx json");
        // Call signs with i64 args + accounts.
        let call = sign_call_program_json(&seed, &prog, &format!("{prog}"), "1,2,3", 1, &chain, 10_000_000).unwrap();
        assert!(call.contains("signature"), "call tx must be a signed tx json");
        // A bad program address is rejected, not silently mis-encoded.
        assert!(sign_call_program_json(&seed, "not-an-address", "", "", 0, &chain, 1).is_err());
        // A non-i64 arg is rejected.
        assert!(sign_call_program_json(&seed, &prog, "", "abc", 0, &chain, 1).is_err());
    }
}

// -------------------------------------------------------------------------
// JavaScript bindings (wasm target only)
// -------------------------------------------------------------------------
#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    fn as32(bytes: &[u8], what: &str) -> Result<[u8; 32], JsValue> {
        bytes
            .try_into()
            .map_err(|_| JsValue::from_str(&format!("{what} must be exactly 32 bytes")))
    }

    /// `address_from_seed(seed: Uint8Array) -> string`
    #[wasm_bindgen(js_name = addressFromSeed)]
    pub fn address_from_seed(seed: &[u8]) -> Result<String, JsValue> {
        super::address_from_seed(&as32(seed, "seed")?).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signTransfer(seed, to, amount, nonce, chainId, feeLimit) -> string`
    /// Returns the signed transaction as a JSON string to POST to the node.
    #[wasm_bindgen(js_name = signTransfer)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_transfer(
        seed: &[u8],
        to: &str,
        amount: u64,
        nonce: u64,
        chain_id: &[u8],
        fee_limit: u64,
    ) -> Result<String, JsValue> {
        super::sign_transfer_json(&as32(seed, "seed")?, to, amount, nonce, &as32(chain_id, "chain_id")?, fee_limit)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `addressFromBytes(bytes: Uint8Array) -> string` - base58 of 32 raw bytes
    /// (browser turns fresh random bytes into a stake-account address to save).
    #[wasm_bindgen(js_name = addressFromBytes)]
    pub fn address_from_bytes(bytes: &[u8]) -> Result<String, JsValue> {
        Ok(super::address_from_bytes(&as32(bytes, "bytes")?))
    }

    /// `deriveAccountSeed(masterSeed: Uint8Array, index: number) -> Uint8Array`
    /// The 32-byte seed for HD account `index` (0 returns the master unchanged).
    /// The browser keeps the master seed and derives each account's seed on the
    /// fly; every existing sign/address function then works unchanged on the
    /// per-account seed.
    #[wasm_bindgen(js_name = deriveAccountSeed)]
    pub fn derive_account_seed(master_seed: &[u8], index: u32) -> Result<Vec<u8>, JsValue> {
        Ok(super::derive_account_seed(&as32(master_seed, "master_seed")?, index).to_vec())
    }

    /// `stakeAddressFromSeed(seed: Uint8Array, index: number) -> string`
    /// Deterministic, seed-derived stake-account address for `index` - lets a
    /// restored wallet re-derive and recover its staking positions without any
    /// browser-local state.
    #[wasm_bindgen(js_name = stakeAddressFromSeed)]
    pub fn stake_address_from_seed(seed: &[u8], index: u32) -> Result<String, JsValue> {
        Ok(super::stake_address_from_seed(&as32(seed, "seed")?, index))
    }

    /// `signDelegate(seed, validator, amount, stakeAccount, nonce, chainId, feeLimit) -> string`
    #[wasm_bindgen(js_name = signDelegate)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_delegate(
        seed: &[u8],
        validator: &str,
        amount: u64,
        stake_account: &str,
        nonce: u64,
        chain_id: &[u8],
        fee_limit: u64,
    ) -> Result<String, JsValue> {
        super::sign_delegate_json(&as32(seed, "seed")?, validator, amount, stake_account, nonce, &as32(chain_id, "chain_id")?, fee_limit)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signUndelegate(seed, stakeAccount, nonce, chainId, feeLimit) -> string`
    #[wasm_bindgen(js_name = signUndelegate)]
    pub fn sign_undelegate(
        seed: &[u8],
        stake_account: &str,
        nonce: u64,
        chain_id: &[u8],
        fee_limit: u64,
    ) -> Result<String, JsValue> {
        super::sign_undelegate_json(&as32(seed, "seed")?, stake_account, nonce, &as32(chain_id, "chain_id")?, fee_limit)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signClaimReward(seed, stakeAccount, nonce, chainId, feeLimit) -> string`
    #[wasm_bindgen(js_name = signClaimReward)]
    pub fn sign_claim_reward(
        seed: &[u8],
        stake_account: &str,
        nonce: u64,
        chain_id: &[u8],
        fee_limit: u64,
    ) -> Result<String, JsValue> {
        super::sign_claim_reward_json(&as32(seed, "seed")?, stake_account, nonce, &as32(chain_id, "chain_id")?, fee_limit)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signV7Stake(seed, position, amount, nonce, chainId, feeLimit) -> string`
    /// v7 networks only: open a new staking position (no validator target).
    #[wasm_bindgen(js_name = signV7Stake)]
    pub fn sign_v7_stake(seed: &[u8], position: &str, amount: u64, nonce: u64, chain_id: &[u8], fee_limit: u64) -> Result<String, JsValue> {
        super::sign_v7_stake_json(&as32(seed, "seed")?, position, amount, nonce, &as32(chain_id, "chain_id")?, fee_limit).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signV7IncreaseStake(seed, position, amount, nonce, chainId, feeLimit) -> string`
    #[wasm_bindgen(js_name = signV7IncreaseStake)]
    pub fn sign_v7_increase(seed: &[u8], position: &str, amount: u64, nonce: u64, chain_id: &[u8], fee_limit: u64) -> Result<String, JsValue> {
        super::sign_v7_increase_json(&as32(seed, "seed")?, position, amount, nonce, &as32(chain_id, "chain_id")?, fee_limit).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signV7BeginUnstake(seed, position, amount, nonce, chainId, feeLimit) -> string`
    #[wasm_bindgen(js_name = signV7BeginUnstake)]
    pub fn sign_v7_begin_unstake(seed: &[u8], position: &str, amount: u64, nonce: u64, chain_id: &[u8], fee_limit: u64) -> Result<String, JsValue> {
        super::sign_v7_begin_unstake_json(&as32(seed, "seed")?, position, amount, nonce, &as32(chain_id, "chain_id")?, fee_limit).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signV7WithdrawUnbonded(seed, position, nonce, chainId, feeLimit) -> string`
    #[wasm_bindgen(js_name = signV7WithdrawUnbonded)]
    pub fn sign_v7_withdraw_unbonded(seed: &[u8], position: &str, nonce: u64, chain_id: &[u8], fee_limit: u64) -> Result<String, JsValue> {
        super::sign_v7_withdraw_unbonded_json(&as32(seed, "seed")?, position, nonce, &as32(chain_id, "chain_id")?, fee_limit).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signVote(seed, proposal, stakeAccount, choice, nonce, chainId, feeLimit) -> string`
    /// choice: 0=Yes, 1=No, 2=Abstain.
    #[wasm_bindgen(js_name = signVote)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_vote(
        seed: &[u8],
        proposal: &str,
        stake_account: &str,
        choice: u8,
        nonce: u64,
        chain_id: &[u8],
        fee_limit: u64,
    ) -> Result<String, JsValue> {
        super::sign_vote_json(&as32(seed, "seed")?, proposal, stake_account, choice, nonce, &as32(chain_id, "chain_id")?, fee_limit)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signFinalize(seed, proposal, nonce, chainId, feeLimit) -> string`
    #[wasm_bindgen(js_name = signFinalize)]
    pub fn sign_finalize(
        seed: &[u8],
        proposal: &str,
        nonce: u64,
        chain_id: &[u8],
        fee_limit: u64,
    ) -> Result<String, JsValue> {
        super::sign_finalize_json(&as32(seed, "seed")?, proposal, nonce, &as32(chain_id, "chain_id")?, fee_limit)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signExecute(seed, proposal, registry, nonce, chainId, feeLimit) -> string`
    /// `registry`=true targets the algorithm-registry singleton (Registry tier);
    /// false targets the economic-params singleton (Low tier).
    #[wasm_bindgen(js_name = signExecute)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_execute(
        seed: &[u8],
        proposal: &str,
        registry: bool,
        nonce: u64,
        chain_id: &[u8],
        fee_limit: u64,
    ) -> Result<String, JsValue> {
        super::sign_execute_json(&as32(seed, "seed")?, proposal, registry, nonce, &as32(chain_id, "chain_id")?, fee_limit)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `programAddressFromSeed(seed, index) -> string` — a fresh, recoverable
    /// contract address to deploy at.
    #[wasm_bindgen(js_name = programAddressFromSeed)]
    pub fn program_address_from_seed(seed: &[u8], index: u32) -> Result<String, JsValue> {
        Ok(super::program_address_from_seed(&as32(seed, "seed")?, index))
    }

    /// `signDeployProgram(seed, programAddress, moduleBytes, entryPoint, nonce, chainId, feeLimit) -> string`
    #[wasm_bindgen(js_name = signDeployProgram)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_deploy_program(
        seed: &[u8],
        program_address: &str,
        module_bytes: &[u8],
        entry_point: &str,
        nonce: u64,
        chain_id: &[u8],
        fee_limit: u64,
    ) -> Result<String, JsValue> {
        super::sign_deploy_program_json(&as32(seed, "seed")?, program_address, module_bytes, entry_point, nonce, &as32(chain_id, "chain_id")?, fee_limit)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// `signCallProgram(seed, programId, accountsCsv, argsCsv, nonce, chainId, feeLimit) -> string`
    #[wasm_bindgen(js_name = signCallProgram)]
    #[allow(clippy::too_many_arguments)]
    pub fn sign_call_program(
        seed: &[u8],
        program_id: &str,
        accounts_csv: &str,
        args_csv: &str,
        nonce: u64,
        chain_id: &[u8],
        fee_limit: u64,
    ) -> Result<String, JsValue> {
        super::sign_call_program_json(&as32(seed, "seed")?, program_id, accounts_csv, args_csv, nonce, &as32(chain_id, "chain_id")?, fee_limit)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
