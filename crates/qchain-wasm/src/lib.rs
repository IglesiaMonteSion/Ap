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

// Well-known staking addresses (qchain-execution::ids), replicated here for the
// same reason as the instruction encodings above.
const STAKING_PROGRAM_ID: [u8; 32] = [1u8; 32];
const STAKING_STATS_ID: [u8; 32] = [2u8; 32];
const STAKING_REWARDS_POOL_ID: [u8; 32] = [6u8; 32];

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
}
