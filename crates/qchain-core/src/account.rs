use borsh::{BorshDeserialize, BorshSerialize};
use qchain_crypto::{AlgorithmId, Pubkey, COMBO_HYBRID_ED25519_ML_DSA_65};
use serde::{Deserialize, Serialize};

/// Base unit of the native token. Ticker and name are placeholders
/// ("QCH") - not a branding decision, just needs a symbol to write code
/// against; trivial to rename project-wide later.
pub const UNITS_PER_QCH: u64 = 1_000_000_000;

/// Economic constants calibrated against a real, explicit target - see
/// `ARCHITECTURE.md` §5 for the full derivation and the reference-price
/// caveat - not the arbitrary placeholders these used to be (2 / 10_000).
///
/// **Anchor:** a simple `SystemProgram::Transfer` should cost ~$0.001 USD.
/// The token has no real market price yet (no exchange/listing), so this
/// uses an explicit, documented, easily-rescaled reference of $1/QCH - if
/// a real price ever exists, every value below scales by one multiplier
/// (`assumed_price / real_price`), nothing else about the derivation
/// changes.
///
/// **`BASE_FEE_PER_BYTE_UNITS`:** a real signed `Transfer` transaction
/// (default hybrid Ed25519+ML-DSA-65 combo, the exact shape `qchain-cli
/// transfer` builds - not an estimate) measures `tx.byte_size() == 5,571`
/// bytes, dominated by the ~1.9KB ML-DSA-65 pubkey + ~3.3KB signature (see
/// `ARCHITECTURE.md` §2's bandwidth analysis). `fee = base_fee_per_byte *
/// byte_size` for a native (non-WASM) instruction like `Transfer` - no gas
/// component, `run_wasm_instruction` is never invoked. Target fee in
/// units: `$0.001 / $1 * UNITS_PER_QCH = 1,000,000`. `1,000,000 / 5,571 ≈
/// 179.5`, rounded to `180` - the resulting real fee for this exact
/// transaction shape is `180 * 5,571 = 1,002,780` units (`$0.0010028` at
/// the assumed price, 0.28% over target).
pub const BASE_FEE_PER_BYTE_UNITS: u64 = 180;
/// **`DUST_THRESHOLD_UNITS`:** set equal to the target simple-transfer fee
/// above (`1,000,000` units) - the defensible anchor for "dust" is exactly
/// "can no longer afford to make another transfer," not an arbitrary small
/// number. An account below this is functionally dead regardless of its
/// nominal balance, so sweeping it (see `Ledger::apply_transaction`'s dust
/// sweep) doesn't destroy anything the holder could have spent anyway.
pub const DUST_THRESHOLD_UNITS: u64 = 1_000_000;
/// Not part of this calibration pass - no target was set for WASM
/// contract gas pricing (`gas_price_per_fuel`), only for a simple native
/// transfer's byte fee. Left at its prior placeholder value.
pub const PRIORITY_FEE_MIN_UNITS: u64 = 0;

/// Account leaf, matching the state tree schema in `ARCHITECTURE.md` §3.
/// `storage_root` is deferred (see module docs in `qchain-storage`) -
/// contract storage is a flat byte blob in phase 1, not a nested Merkle
/// tree per account yet.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
    /// Which registered signing policy controls this account - see
    /// `qchain_crypto::registry` for the distinction between individual
    /// scheme ids and combo ids. Every phase-1 account is
    /// `COMBO_HYBRID_ED25519_ML_DSA_65`.
    pub algorithm_id: AlgorithmId,
    /// The program allowed to mutate this account's `data`. Plain wallets
    /// are owned by the System Program.
    pub owner: Pubkey,
    /// 0 for plain wallets; the WASM module hash for a contract account.
    pub code_hash: [u8; 32],
    pub data: Vec<u8>,
}

impl Account {
    pub fn new_wallet(owner: Pubkey) -> Self {
        Account {
            balance: 0,
            nonce: 0,
            algorithm_id: COMBO_HYBRID_ED25519_ML_DSA_65,
            owner,
            code_hash: [0u8; 32],
            data: Vec::new(),
        }
    }
}
