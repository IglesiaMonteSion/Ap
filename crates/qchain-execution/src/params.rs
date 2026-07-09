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

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct EconomicParams {
    pub base_fee_per_byte: u64,
    pub dust_threshold: u64,
    pub gas_price_per_fuel: u64,
}

impl Default for EconomicParams {
    fn default() -> Self {
        EconomicParams {
            base_fee_per_byte: BASE_FEE_PER_BYTE_UNITS,
            dust_threshold: DUST_THRESHOLD_UNITS,
            gas_price_per_fuel: DEFAULT_GAS_PRICE_UNITS_PER_FUEL,
        }
    }
}
