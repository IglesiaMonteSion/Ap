pub(crate) mod arith;
pub mod economics_v7;
pub mod error;
pub mod fees_v7;
pub mod governance;
pub mod ids;
pub mod invariants;
pub mod invariants_v7;
pub mod ledger;
pub mod native;
pub mod params;
pub mod receipt;
pub mod staking;
pub mod staking_v7;
pub mod treasury_v7;
pub mod validator_registry;
pub mod validator_v7;
pub mod wasm;

pub use error::ExecError;
pub use governance::{genesis_emergency_account_data, genesis_params_account_data, genesis_registry_account_data, EmergencyState, GovernanceInstruction, GovernanceProgram};
pub use ids::{EMERGENCY_ACCOUNT_ID, GOVERNANCE_PROGRAM_ID, PARAMS_ACCOUNT_ID, REGISTRY_ACCOUNT_ID, STAKING_PROGRAM_ID, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, VALIDATOR_REGISTRY_ACCOUNT_ID};
pub use ledger::{register_standard_programs, Ledger, Program, SimAccountChange, SimOutcome, SimSnapshot, SimStatus, DEFAULT_FUEL_LIMIT};
pub use native::{NativeProgram, SystemInstruction, SystemProgram};
pub use params::EconomicParams;
pub use ledger::EconomicSnapshot;
pub use receipt::{CompressedProofSet, StakingEvent, StakingEventKind, TransferReceipt};
pub use staking::{RewardPoolData, StakeAccountData, StakingInstruction, StakingProgram};
pub use wasm::{WasmCallResult, WasmExecutor};

#[cfg(test)]
mod fuzz_proptests {
    //! Property tests de TODOS los decodificadores de estado on-chain y del borde
    //! WASM (roadmap #14, superficies "gobernanza" + "WASM"). Cada uno toma la
    //! `data` de una cuenta o el `data` de una instrucción — bytes que provienen de
    //! una tx de un usuario o de un account posiblemente corrupto/manipulado.
    //! Deserializar bytes ARBITRARIOS nunca debe panicar/colgar; los decodificadores
    //! tolerantes (`read_or_legacy`, `decode_registry`) deben devolver Ok/Some/None
    //! o Err, jamás romper. Complementa el fuzzing coverage-guided de `fuzz/`.
    use borsh::BorshDeserialize;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic_onchain_decoders(bytes in proptest::collection::vec(any::<u8>(), 0..8192)) {
            // Decodificadores tolerantes (versión-migrantes / con fallback legacy).
            let _ = crate::params::EconomicParams::read_or_legacy(&bytes);
            let _ = crate::params::FeeState::read_or_legacy(&bytes);
            let _ = crate::staking::StakeAccountData::read_or_legacy(&bytes);
            let _ = crate::validator_v7::decode_registry(&bytes);
            let _ = crate::validator_v7::detect_registry_schema(&bytes);
            // Instrucciones (Borsh) — el `data` de una instrucción de una tx.
            let _ = crate::staking::StakingInstruction::try_from_slice(&bytes);
            let _ = crate::governance::GovernanceInstruction::try_from_slice(&bytes);
            let _ = crate::validator_v7::ValidatorV7Instruction::try_from_slice(&bytes);
            let _ = crate::treasury_v7::TreasuryV7Instruction::try_from_slice(&bytes);
            // Cuentas de estado (Borsh) — la `data` de un account.
            let _ = crate::native::WasmProgramData::try_from_slice(&bytes);
            let _ = crate::treasury_v7::TreasuryState::try_from_slice(&bytes);
            let _ = crate::staking_v7::GlobalStakingState::try_from_slice(&bytes);
            let _ = crate::staking_v7::StakePositionV7::try_from_slice(&bytes);
            let _ = crate::validator_v7::ValidatorV7Registry::try_from_slice(&bytes);
        }
    }
}
