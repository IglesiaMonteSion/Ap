#![no_main]
//! Fuzz de TODOS los decodificadores de estado on-chain y del borde WASM (roadmap
//! #14, superficies "WASM" + "gobernanza"). Cada decodificador toma la `data` de
//! una cuenta o el `data` de una instrucción — bytes que provienen de una tx de un
//! usuario o de un account posiblemente corrupto/manipulado. Deserializar bytes
//! ARBITRARIOS nunca debe panicar/OOM; los decodificadores tolerantes
//! (`read_or_legacy`, `decode_registry`) devuelven Ok/Some/None o Err, jamás rompen.
//! Espejo coverage-guided del property test
//! `arbitrary_bytes_never_panic_onchain_decoders`.
use borsh::BorshDeserialize;
use libfuzzer_sys::fuzz_target;
use qchain_execution::{
    governance::GovernanceInstruction,
    native::WasmProgramData,
    params::{EconomicParams, FeeState},
    staking::{StakeAccountData, StakingInstruction},
    staking_v7::{GlobalStakingState, StakePositionV7},
    treasury_v7::{TreasuryState, TreasuryV7Instruction},
    validator_v7::{decode_registry, detect_registry_schema, ValidatorV7Instruction, ValidatorV7Registry},
};

fuzz_target!(|data: &[u8]| {
    // Decodificadores tolerantes (versión-migrantes / con fallback legacy).
    let _ = EconomicParams::read_or_legacy(data);
    let _ = FeeState::read_or_legacy(data);
    let _ = StakeAccountData::read_or_legacy(data);
    let _ = decode_registry(data);
    let _ = detect_registry_schema(data);
    // Instrucciones (Borsh) — el `data` de una instrucción de una tx.
    let _ = StakingInstruction::try_from_slice(data);
    let _ = GovernanceInstruction::try_from_slice(data);
    let _ = ValidatorV7Instruction::try_from_slice(data);
    let _ = TreasuryV7Instruction::try_from_slice(data);
    // Cuentas de estado (Borsh) — la `data` de un account.
    let _ = WasmProgramData::try_from_slice(data);
    let _ = TreasuryState::try_from_slice(data);
    let _ = GlobalStakingState::try_from_slice(data);
    let _ = StakePositionV7::try_from_slice(data);
    let _ = ValidatorV7Registry::try_from_slice(data);
});
