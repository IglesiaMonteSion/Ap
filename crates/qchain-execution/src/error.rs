use qchain_crypto::Pubkey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("account not found: {0}")]
    AccountNotFound(Pubkey),
    #[error("insufficient funds")]
    InsufficientFunds,
    #[error("unknown program: {0}")]
    UnknownProgram(Pubkey),
    #[error("program error: {0}")]
    ProgramError(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    /// `fuel_consumed` is real fuel spent before the trap, not zero - see
    /// `qchain_execution::wasm::WasmCallResult::trap`'s doc comment and
    /// `Ledger::apply_transaction`'s handling of this variant for the real,
    /// live-confirmed gas-metering-bypass this closes: a contract that
    /// burns fuel and then traps must still be billed for it.
    #[error("wasm execution error: {message}")]
    Wasm { message: String, fuel_consumed: u64 },
    #[error("out of gas")]
    OutOfGas,
    #[error("algorithm not acceptable: {0}")]
    AlgorithmNotAcceptable(String),
    #[error("fee {actual} exceeds the transaction's declared fee_limit {limit}")]
    FeeExceedsLimit { actual: u64, limit: u64 },
}
