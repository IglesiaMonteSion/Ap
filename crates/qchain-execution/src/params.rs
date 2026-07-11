//! On-chain economic parameters (design: `ARCHITECTURE.md` §5/§6 - "bajo
//! riesgo: constantes de la curva de fee, tabla de precios de gas").
//! Governable via a `Low`-tier `qchain_governance::ProposalAction`
//! (simple majority, no time-lock - see `governance.rs`'s `Execute`
//! handling). `Ledger` reads the current values from this account at
//! every `apply_transaction` call, falling back to these same defaults
//! if the account hasn't been seeded yet (e.g. in tests that construct a
//! bare `Ledger` directly) - see `ledger.rs::current_params`.

use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{BASE_FEE_PER_BYTE_UNITS, DUST_THRESHOLD_UNITS};

/// Placeholder gas price - see `ARCHITECTURE.md` §5's tokenomics
/// disclaimer: a starting point, not a modeled figure. Was a bare
/// `ledger.rs` constant before this account existed; kept here as the
/// genesis default.
pub const DEFAULT_GAS_PRICE_UNITS_PER_FUEL: u64 = 1;

/// Default validator commission on the staking-reward share of `base_fee`
/// (see `staking.rs`'s module docs and `ledger.rs`'s fee-split) - 10%, a
/// common real-world validator commission rate, explicitly a starting
/// point like every other constant in this module, adjustable via the
/// same `Low`-tier governance path as `base_fee_per_byte` etc.
pub const DEFAULT_STAKING_COMMISSION_BPS: u16 = 1_000;

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct EconomicParams {
    pub base_fee_per_byte: u64,
    pub dust_threshold: u64,
    pub gas_price_per_fuel: u64,
    /// Basis points (out of 10,000) of the staking-reward share of
    /// `base_fee` that goes directly to the proposing validator as
    /// commission - the rest funds the shared delegator reward pool
    /// (`STAKING_REWARDS_POOL_ID`). Only applies once real stake is
    /// delegated (`STAKING_STATS_ID` > 0) - see `ledger.rs`.
    pub staking_commission_bps: u16,
}

impl Default for EconomicParams {
    fn default() -> Self {
        EconomicParams {
            base_fee_per_byte: BASE_FEE_PER_BYTE_UNITS,
            dust_threshold: DUST_THRESHOLD_UNITS,
            gas_price_per_fuel: DEFAULT_GAS_PRICE_UNITS_PER_FUEL,
            staking_commission_bps: DEFAULT_STAKING_COMMISSION_BPS,
        }
    }
}
