use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use supersol_crypto::{HybridSignature, Keypair, PublicKeyBundle, Pubkey};

/// A single instruction routed to a program. `accounts` lists the pubkeys the
/// instruction touches, in an order the target program defines and
/// interprets - the same convention Solana programs use.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data: Vec<u8>,
}

/// The signable payload of a transaction. Kept separate from the signature so
/// we have an unambiguous byte string to sign and to verify against.
///
/// `payer_keys` carries the payer's full hybrid public key bundle (ed25519 +
/// ML-DSA-65). `payer` is the compact address derived from it
/// (`sha256(ed25519 || mldsa)`) - carrying both lets a validator check that
/// the bundle really corresponds to the claimed address before trusting the
/// signatures made with it.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Message {
    pub payer: Pubkey,
    pub payer_keys: PublicKeyBundle,
    /// Hash of a recent block, binding this transaction to a point in time
    /// and preventing indefinite replay.
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Transaction {
    pub message: Message,
    pub signature: HybridSignature,
}

impl Transaction {
    pub fn new_signed(payer: &Keypair, recent_blockhash: [u8; 32], instructions: Vec<Instruction>) -> Self {
        let payer_keys = payer.public_key_bundle();
        let message = Message {
            payer: payer_keys.to_address(),
            payer_keys,
            recent_blockhash,
            instructions,
        };
        let bytes = borsh::to_vec(&message).expect("message always serializes");
        let signature = payer.sign(&bytes);
        Transaction { message, signature }
    }

    /// Checks that the attached key bundle really hashes to the claimed
    /// payer address, then verifies both the ed25519 and ML-DSA-65 halves of
    /// the signature over the message. Both checks must pass.
    pub fn verify_signature(&self) -> bool {
        if self.message.payer_keys.to_address() != self.message.payer {
            return false;
        }
        match borsh::to_vec(&self.message) {
            Ok(bytes) => supersol_crypto::verify(&self.message.payer_keys, &bytes, &self.signature),
            Err(_) => false,
        }
    }

    /// Content-addressed id for this transaction, used as its "signature"
    /// handle in RPC responses and as the data mixed into Proof of History.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        if let Ok(bytes) = borsh::to_vec(&self.message) {
            hasher.update(bytes);
        }
        hasher.update(self.signature.ed25519.to_bytes());
        hasher.update(&self.signature.mldsa);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_transaction_verifies() {
        let payer = Keypair::generate();
        let to = Keypair::generate().pubkey();
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![payer.pubkey(), to],
            data: vec![1, 2, 3],
        };
        let tx = Transaction::new_signed(&payer, [0u8; 32], vec![ix]);
        assert!(tx.verify_signature());
    }

    #[test]
    fn tampered_transaction_fails_verification() {
        let payer = Keypair::generate();
        let to = Keypair::generate().pubkey();
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![payer.pubkey(), to],
            data: vec![1, 2, 3],
        };
        let mut tx = Transaction::new_signed(&payer, [0u8; 32], vec![ix]);
        tx.message.instructions[0].data = vec![9, 9, 9];
        assert!(!tx.verify_signature());
    }

    #[test]
    fn forged_key_bundle_fails_verification() {
        let payer = Keypair::generate();
        let attacker = Keypair::generate();
        let to = Keypair::generate().pubkey();
        let ix = Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![payer.pubkey(), to],
            data: vec![1, 2, 3],
        };
        let mut tx = Transaction::new_signed(&payer, [0u8; 32], vec![ix]);
        // Swap in an attacker-controlled bundle while keeping the original
        // (now mismatched) payer address - must not verify.
        tx.message.payer_keys = attacker.public_key_bundle();
        assert!(!tx.verify_signature());
    }
}
