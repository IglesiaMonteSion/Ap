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
}
