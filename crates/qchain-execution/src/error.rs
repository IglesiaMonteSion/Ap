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
    /// The transaction's nonce is HIGHER than the account's current nonce - its
    /// predecessors have not executed yet. Distinct from a nonce-too-low replay
    /// (a genuinely already-executed tx, reported as `ProgramError`): a
    /// too-high nonce is TRANSIENT and recoverable, because once its
    /// predecessors execute (they commit in an earlier round) the account nonce
    /// catches up and this tx applies. This is what makes nonce pipelining safe:
    /// a validator can propose a payer's later nonces while its earlier batch is
    /// still in flight; in the rare case the two execute out of order (a skipped
    /// round), the later one just re-queues instead of being dropped.
    #[error("nonce too high: account is at {account}, transaction has {tx} (predecessors pending)")]
    NonceTooHigh { account: u64, tx: u64 },
}
