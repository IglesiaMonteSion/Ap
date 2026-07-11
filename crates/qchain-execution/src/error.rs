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
    #[error("wasm execution error: {0}")]
    Wasm(String),
    #[error("out of gas")]
    OutOfGas,
    #[error("algorithm not acceptable: {0}")]
    AlgorithmNotAcceptable(String),
    #[error("fee {actual} exceeds the transaction's declared fee_limit {limit}")]
    FeeExceedsLimit { actual: u64, limit: u64 },
}
