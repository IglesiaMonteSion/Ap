//! Checked money arithmetic (#218). Balances, pools and value aggregates use
//! these instead of `saturating_*`: on overflow/underflow they return
//! `ExecError::ArithmeticOverflow`, so the caller can `?`-propagate it and the
//! WHOLE state transition is rejected — never silently saturated to a wrong
//! value (which would create or destroy funds). `saturating_*` stays only for
//! NON-monetary metrics (report counters, round/quanto numbers, byte counters,
//! fuel/compute bounds, participation).
//!
//! Deterministic: a pure function of the committed inputs, so every validator
//! rejects an overflowing transition identically — no fork. Unreachable in
//! normal operation (total supply is far below `u64::MAX`); it fires only on an
//! attack or corrupt state.

use crate::error::ExecError;

#[inline]
pub fn add_u64(a: u64, b: u64) -> Result<u64, ExecError> {
    a.checked_add(b).ok_or(ExecError::ArithmeticOverflow)
}

#[inline]
pub fn sub_u64(a: u64, b: u64) -> Result<u64, ExecError> {
    a.checked_sub(b).ok_or(ExecError::ArithmeticOverflow)
}

#[inline]
#[allow(dead_code)]
pub fn mul_u64(a: u64, b: u64) -> Result<u64, ExecError> {
    a.checked_mul(b).ok_or(ExecError::ArithmeticOverflow)
}

#[inline]
pub fn add_u128(a: u128, b: u128) -> Result<u128, ExecError> {
    a.checked_add(b).ok_or(ExecError::ArithmeticOverflow)
}

#[inline]
#[allow(dead_code)]
pub fn sub_u128(a: u128, b: u128) -> Result<u128, ExecError> {
    a.checked_sub(b).ok_or(ExecError::ArithmeticOverflow)
}

#[inline]
pub fn mul_u128(a: u128, b: u128) -> Result<u128, ExecError> {
    a.checked_mul(b).ok_or(ExecError::ArithmeticOverflow)
}
