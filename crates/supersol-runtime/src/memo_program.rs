use supersol_core::{Account, Instruction, ProgramProcessor, TxError};
use supersol_crypto::Pubkey;
use std::collections::HashMap;

pub const MEMO_PROGRAM_ID: Pubkey = Pubkey::new([1u8; 32]);

/// A minimal example custom program: it stores whatever bytes are passed as
/// instruction data into the target account's `data` field. It exists to
/// demonstrate how little boilerplate a new SuperSol program needs -
/// implement one trait method - compared to writing, compiling and
/// deploying BPF bytecode for a Solana program.
pub struct MemoProgram;

impl ProgramProcessor for MemoProgram {
    fn process(
        &self,
        accounts: &mut HashMap<Pubkey, Account>,
        instruction: &Instruction,
        _payer: &Pubkey,
    ) -> Result<(), TxError> {
        let target = instruction
            .accounts
            .first()
            .ok_or_else(|| TxError::ProgramError("Memo requires accounts[0]".into()))?;
        let account = accounts.get_mut(target).ok_or(TxError::AccountNotFound(*target))?;
        if account.owner != MEMO_PROGRAM_ID {
            return Err(TxError::ProgramError("account not owned by memo program".into()));
        }
        account.data = instruction.data.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_memo_data_into_owned_account() {
        let target = supersol_crypto::Keypair::generate().pubkey();
        let mut accounts = HashMap::new();
        accounts.insert(target, Account::new_wallet(MEMO_PROGRAM_ID));
        let ix = Instruction {
            program_id: MEMO_PROGRAM_ID,
            accounts: vec![target],
            data: b"hello".to_vec(),
        };
        MemoProgram.process(&mut accounts, &ix, &target).unwrap();
        assert_eq!(accounts.get(&target).unwrap().data, b"hello");
    }

    #[test]
    fn rejects_writing_to_unowned_account() {
        let target = supersol_crypto::Keypair::generate().pubkey();
        let mut accounts = HashMap::new();
        accounts.insert(target, Account::new_wallet(Pubkey::system_program_id()));
        let ix = Instruction {
            program_id: MEMO_PROGRAM_ID,
            accounts: vec![target],
            data: b"hello".to_vec(),
        };
        assert!(MemoProgram.process(&mut accounts, &ix, &target).is_err());
    }
}
