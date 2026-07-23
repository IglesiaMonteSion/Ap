//! v7 treasury — a genesis-locked reserve of QCH released only by a designated
//! AUTHORITY key. **v7 only** (a v6 network never seeds or dispatches this, so it
//! is byte-identical). Execution-layer native program, same pattern as
//! `StakingV7Program`/`ValidatorV7Program` — it does NOT touch consensus.
//!
//! ## Why it exists
//! A clean v7 genesis has zero spendable supply (the only minted QCH is each
//! founder's 500 QCH bond, which is locked collateral). The operator mints the
//! initial circulating supply into a TREASURY account at genesis, LOCKED: the
//! account is owned by `TREASURY_V7_PROGRAM_ID`, so no ordinary signed transfer
//! can move it — only a `Release` instruction, and only when signed by the
//! `authority` pubkey baked into the treasury state at genesis, moves funds out.
//! This gives a transparent, on-chain-verifiable treasury (anyone can read the
//! locked balance) whose release is gated by a single operator-controlled key —
//! the model for "unlock a slice as liquidity comes in" without a fixed vesting
//! schedule.
//!
//! Emission is orthogonal: the network can still mint staking rewards per quanto
//! (there is no hard supply cap). The treasury is a genesis allocation that
//! conserves supply on release (it MOVES QCH, never mints).
//!
//! ## Instructions
//! - `Release { amount }` — accounts=[authority, treasury, destination]. Moves
//!   `amount` from the treasury to `destination`. Requires the payer to be the
//!   authority stored in the treasury state.
//! - `SetAuthority` — accounts=[authority, treasury, new_authority]. Rotates the
//!   controlling key (e.g. to a fresh key, or a multisig-controlled address).
//!   Requires the current authority to sign. Never moves funds.
//!
//! Both are inert on a v6 network (the program is only registered, and the
//! treasury account only seeded, when `economics_v7` is on).

use crate::error::ExecError;
use crate::ids::TREASURY_ACCOUNT_ID;
use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{Account, Instruction};
use qchain_crypto::Pubkey;
use std::collections::HashMap;

/// The treasury singleton's `data` (`TREASURY_ACCOUNT_ID.data`). The locked QCH
/// lives in that account's `balance`; only the `authority` may release it.
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub struct TreasuryState {
    /// The only key allowed to sign `Release`/`SetAuthority`.
    pub authority: Pubkey,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq, Eq)]
pub enum TreasuryV7Instruction {
    /// Unlock+send `amount` from the treasury to accounts[2]. Authority-gated.
    Release { amount: u64 },
    /// Rotate the controlling key to accounts[2]. Authority-gated; moves no funds.
    SetAuthority,
}

pub struct TreasuryV7Program;

fn read_state(accounts: &HashMap<Pubkey, Account>) -> Option<TreasuryState> {
    // FAIL-LOUD (#217): absent = no treasury on this network (None). But PRESENT
    // and undecodable is corruption of the account that guards the locked supply
    // → refuse to run rather than returning None (which a caller reads as "no
    // treasury / not authorized", silently changing who controls locked funds).
    accounts.get(&TREASURY_ACCOUNT_ID).map(|a| {
        TreasuryState::try_from_slice(&a.data).unwrap_or_else(|e| {
            panic!("TREASURY_ACCOUNT is present but does not decode as TreasuryState ({e}); refusing to run on corrupt treasury state")
        })
    })
}

impl TreasuryV7Program {
    /// Apply a treasury instruction to the working set. Pure over `accounts`.
    pub fn execute(
        accounts: &mut HashMap<Pubkey, Account>,
        instruction: &Instruction,
        payer: &Pubkey,
    ) -> Result<(), ExecError> {
        let instr = TreasuryV7Instruction::try_from_slice(&instruction.data)
            .map_err(|e| ExecError::ProgramError(format!("bad treasury instruction: {e}")))?;
        match instr {
            TreasuryV7Instruction::Release { amount } => Self::release(accounts, instruction, payer, amount),
            TreasuryV7Instruction::SetAuthority => Self::set_authority(accounts, instruction, payer),
        }
    }

    /// Shared authority check: accounts[0] is the authority (must be the payer),
    /// accounts[1] must be the canonical treasury account, and the payer must
    /// equal the authority recorded in the treasury state.
    fn authorize(
        accounts: &HashMap<Pubkey, Account>,
        ix: &Instruction,
        payer: &Pubkey,
    ) -> Result<(), ExecError> {
        let authority_pk = *ix
            .accounts
            .first()
            .ok_or_else(|| ExecError::ProgramError("treasury ix requires accounts[0] (authority)".into()))?;
        let treasury_pk = *ix
            .accounts
            .get(1)
            .ok_or_else(|| ExecError::ProgramError("treasury ix requires accounts[1] (treasury)".into()))?;
        if treasury_pk != TREASURY_ACCOUNT_ID {
            return Err(ExecError::Unauthorized("treasury ix must name the canonical treasury account".into()));
        }
        // The payer is the only authenticated signer in this single-signer model,
        // so requiring authority == payer ties the action to a real signature.
        if authority_pk != *payer {
            return Err(ExecError::Unauthorized("the treasury authority account must be the transaction payer".into()));
        }
        let state = read_state(accounts)
            .ok_or_else(|| ExecError::ProgramError("treasury account is not initialized".into()))?;
        if state.authority != *payer {
            return Err(ExecError::Unauthorized("only the treasury authority may release or rotate".into()));
        }
        Ok(())
    }

    fn release(
        accounts: &mut HashMap<Pubkey, Account>,
        ix: &Instruction,
        payer: &Pubkey,
        amount: u64,
    ) -> Result<(), ExecError> {
        Self::authorize(accounts, ix, payer)?;
        let dest_pk = *ix
            .accounts
            .get(2)
            .ok_or_else(|| ExecError::ProgramError("Release requires accounts[2] (destination)".into()))?;
        if amount == 0 {
            return Err(ExecError::ProgramError("cannot release zero".into()));
        }
        if dest_pk == TREASURY_ACCOUNT_ID {
            return Err(ExecError::ProgramError("cannot release the treasury to itself".into()));
        }
        let treasury_balance = accounts
            .get(&TREASURY_ACCOUNT_ID)
            .ok_or(ExecError::AccountNotFound(TREASURY_ACCOUNT_ID))?
            .balance;
        if treasury_balance < amount {
            return Err(ExecError::InsufficientFunds);
        }
        // Move (never mint): debit the treasury, credit the destination. Supply is
        // conserved. The destination is created as a normal system-owned wallet if
        // it does not exist yet, so released funds are immediately spendable.
        // #218: checked money — debit/credit reject the release on over/underflow.
        {
            let t = accounts.get_mut(&TREASURY_ACCOUNT_ID).unwrap();
            t.balance = crate::arith::sub_u64(t.balance, amount)?;
        }
        let dest = accounts
            .entry(dest_pk)
            .or_insert_with(|| Account::new_wallet(Pubkey::system_program_id()));
        dest.balance = crate::arith::add_u64(dest.balance, amount)?;
        Ok(())
    }

    fn set_authority(
        accounts: &mut HashMap<Pubkey, Account>,
        ix: &Instruction,
        payer: &Pubkey,
    ) -> Result<(), ExecError> {
        Self::authorize(accounts, ix, payer)?;
        let new_authority = *ix
            .accounts
            .get(2)
            .ok_or_else(|| ExecError::ProgramError("SetAuthority requires accounts[2] (new authority)".into()))?;
        let acct = accounts
            .get_mut(&TREASURY_ACCOUNT_ID)
            .ok_or(ExecError::AccountNotFound(TREASURY_ACCOUNT_ID))?;
        let state = TreasuryState { authority: new_authority };
        acct.data = borsh::to_vec(&state).map_err(|e| ExecError::ProgramError(e.to_string()))?;
        Ok(())
    }
}

impl crate::native::NativeProgram for TreasuryV7Program {
    fn process(
        &self,
        accounts: &mut HashMap<Pubkey, Account>,
        instruction: &Instruction,
        payer: &Pubkey,
        _current_round: qchain_core::Round,
    ) -> Result<(), ExecError> {
        TreasuryV7Program::execute(accounts, instruction, payer)
    }
}

/// Build the genesis treasury account: `balance` QCH-units locked, owned by the
/// treasury program, releasable only by `authority`. Seeded at genesis by the
/// node when `economics_v7` is on and a treasury is configured. Kept here so the
/// seeding and the release logic share one definition of the account layout.
pub fn genesis_treasury_account(authority: Pubkey, balance: u64) -> Account {
    let mut acct = Account::new_wallet(crate::ids::TREASURY_V7_PROGRAM_ID);
    acct.balance = balance;
    acct.data = borsh::to_vec(&TreasuryState { authority }).expect("TreasuryState serializes");
    acct
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::TREASURY_V7_PROGRAM_ID;

    fn pk(n: u8) -> Pubkey {
        Pubkey::new([n; 32])
    }

    fn ix(instr: &TreasuryV7Instruction, accounts: Vec<Pubkey>) -> Instruction {
        Instruction {
            program_id: TREASURY_V7_PROGRAM_ID,
            accounts,
            data: borsh::to_vec(instr).unwrap(),
        }
    }

    fn world(authority: Pubkey, locked: u64) -> HashMap<Pubkey, Account> {
        let mut a = HashMap::new();
        a.insert(TREASURY_ACCOUNT_ID, genesis_treasury_account(authority, locked));
        a
    }

    #[test]
    fn the_authority_can_release_and_supply_is_conserved() {
        let authority = pk(1);
        let dest = pk(9);
        let mut accounts = world(authority, 100_000);
        TreasuryV7Program::execute(
            &mut accounts,
            &ix(&TreasuryV7Instruction::Release { amount: 30_000 }, vec![authority, TREASURY_ACCOUNT_ID, dest]),
            &authority,
        )
        .unwrap();
        assert_eq!(accounts[&TREASURY_ACCOUNT_ID].balance, 70_000);
        assert_eq!(accounts[&dest].balance, 30_000);
        // conserved: locked before == treasury after + released
        assert_eq!(70_000 + 30_000, 100_000);
        // destination is a normal spendable system wallet
        assert_eq!(accounts[&dest].owner, Pubkey::system_program_id());
    }

    #[test]
    fn a_non_authority_cannot_release() {
        let authority = pk(1);
        let attacker = pk(2);
        let dest = pk(9);
        let mut accounts = world(authority, 100_000);
        // attacker signs (payer=attacker) but names themselves as authority acct
        let e = TreasuryV7Program::execute(
            &mut accounts,
            &ix(&TreasuryV7Instruction::Release { amount: 100_000 }, vec![attacker, TREASURY_ACCOUNT_ID, dest]),
            &attacker,
        );
        assert!(matches!(e, Err(ExecError::Unauthorized(_))));
        // treasury untouched
        assert_eq!(accounts[&TREASURY_ACCOUNT_ID].balance, 100_000);
        assert!(!accounts.contains_key(&dest));
    }

    #[test]
    fn cannot_release_more_than_locked_or_zero_or_wrong_treasury() {
        let authority = pk(1);
        let dest = pk(9);
        let mut accounts = world(authority, 1_000);
        // over-balance
        assert!(matches!(
            TreasuryV7Program::execute(
                &mut accounts,
                &ix(&TreasuryV7Instruction::Release { amount: 1_001 }, vec![authority, TREASURY_ACCOUNT_ID, dest]),
                &authority,
            ),
            Err(ExecError::InsufficientFunds)
        ));
        // zero
        assert!(matches!(
            TreasuryV7Program::execute(
                &mut accounts,
                &ix(&TreasuryV7Instruction::Release { amount: 0 }, vec![authority, TREASURY_ACCOUNT_ID, dest]),
                &authority,
            ),
            Err(ExecError::ProgramError(_))
        ));
        // a fake treasury account (accounts[1] != TREASURY_ACCOUNT_ID) is rejected
        assert!(matches!(
            TreasuryV7Program::execute(
                &mut accounts,
                &ix(&TreasuryV7Instruction::Release { amount: 1 }, vec![authority, pk(77), dest]),
                &authority,
            ),
            Err(ExecError::Unauthorized(_))
        ));
        assert_eq!(accounts[&TREASURY_ACCOUNT_ID].balance, 1_000);
    }

    #[test]
    fn authority_rotation_transfers_control() {
        let authority = pk(1);
        let new_authority = pk(3);
        let dest = pk(9);
        let mut accounts = world(authority, 100_000);
        // rotate to new_authority
        TreasuryV7Program::execute(
            &mut accounts,
            &ix(&TreasuryV7Instruction::SetAuthority, vec![authority, TREASURY_ACCOUNT_ID, new_authority]),
            &authority,
        )
        .unwrap();
        // old authority can no longer release
        assert!(matches!(
            TreasuryV7Program::execute(
                &mut accounts,
                &ix(&TreasuryV7Instruction::Release { amount: 1 }, vec![authority, TREASURY_ACCOUNT_ID, dest]),
                &authority,
            ),
            Err(ExecError::Unauthorized(_))
        ));
        // the new authority can
        TreasuryV7Program::execute(
            &mut accounts,
            &ix(&TreasuryV7Instruction::Release { amount: 5_000 }, vec![new_authority, TREASURY_ACCOUNT_ID, dest]),
            &new_authority,
        )
        .unwrap();
        assert_eq!(accounts[&dest].balance, 5_000);
    }

    #[test]
    fn genesis_account_is_program_owned_and_locked() {
        let authority = pk(1);
        let acct = genesis_treasury_account(authority, 100_000_000_000_000_000);
        // owned by the treasury program → no plain System transfer can move it
        assert_eq!(acct.owner, TREASURY_V7_PROGRAM_ID);
        assert_eq!(acct.balance, 100_000_000_000_000_000);
        assert_eq!(read_state(&HashMap::from([(TREASURY_ACCOUNT_ID, acct)])).unwrap().authority, authority);
    }

    #[test]
    fn treasury_instruction_encoding_is_stable() {
        // Guards the on-chain wire encoding (the wallet/CLI hand-encode this).
        assert_eq!(borsh::to_vec(&TreasuryV7Instruction::Release { amount: 1 }).unwrap(), vec![0, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(borsh::to_vec(&TreasuryV7Instruction::SetAuthority).unwrap(), vec![1]);
    }
}
