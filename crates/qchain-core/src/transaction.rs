use borsh::{BorshDeserialize, BorshSerialize};
use qchain_crypto::{Keypair, MultiSignature, PublicKeyBundle, Pubkey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// A single instruction routed to a program. `accounts` lists the pubkeys
/// the instruction touches, in an order the target program defines and
/// interprets - the Solana-style convention this project's execution model
/// is built on (see `ARCHITECTURE.md` §4 and the `blockchain-core-rust`
/// skill for why: declared account lists are what make conflict detection,
/// and therefore parallel execution, possible).
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data: Vec<u8>,
}

/// The signable payload of a transaction. Format per `ARCHITECTURE.md` §2.
///
/// `nonce` (not just a recency anchor) matters more here than in a
/// single-leader chain: DAG-ordered transactions don't have one linear
/// "block height" the way a sequential chain does until Bullshark commits
/// an order, so explicit per-account nonces are the primary replay defense,
/// with `recent_cert_ref` as a secondary recency bound.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Message {
    pub version: u8,
    pub payer: Pubkey,
    pub payer_keys: PublicKeyBundle,
    pub nonce: u64,
    /// Digest of a recently-seen DAG certificate, binding this transaction
    /// to a point in time it was constructed at.
    pub recent_cert_ref: [u8; 32],
    /// Maximum total fee (base + priority + gas) the payer authorizes.
    pub fee_limit: u64,
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Transaction {
    pub message: Message,
    pub signature: MultiSignature,
}

impl Transaction {
    pub fn new_signed(
        payer: &Keypair,
        nonce: u64,
        recent_cert_ref: [u8; 32],
        fee_limit: u64,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Self> {
        let payer_keys = payer.public_key_bundle();
        let message = Message {
            version: 1,
            payer: payer_keys.to_address(),
            payer_keys,
            nonce,
            recent_cert_ref,
            fee_limit,
            instructions,
        };
        let bytes = borsh::to_vec(&message).expect("message always serializes");
        let signature = payer.sign(&bytes)?;
        Ok(Transaction { message, signature })
    }

    /// Checks the attached key bundle hashes to the claimed payer address,
    /// then verifies every signature component of the combo the bundle
    /// resolves to. See `ARCHITECTURE.md` §2's hybrid signature policy and
    /// `qchain_crypto::verify`'s docs for exactly how an incomplete or
    /// substituted combo gets rejected, not silently accepted.
    pub fn verify_signature(&self) -> bool {
        if self.message.payer_keys.to_address() != self.message.payer {
            return false;
        }
        match borsh::to_vec(&self.message) {
            Ok(bytes) => qchain_crypto::verify(&self.message.payer_keys, &bytes, &self.signature),
            Err(_) => false,
        }
    }

    /// Which combo the payer's key bundle resolves to (`None` if it doesn't
    /// resolve to any known combo at all). Callers that need this - e.g.
    /// `Ledger::apply_transaction` checking the live on-chain registry's
    /// status for each of the combo's component schemes - should still call
    /// `verify_signature()` first; this alone does not check that the
    /// attached signature actually verifies.
    pub fn resolved_combo(&self) -> Option<qchain_crypto::AlgorithmId> {
        let schemes: Vec<qchain_crypto::AlgorithmId> = self.message.payer_keys.components.iter().map(|c| c.scheme).collect();
        qchain_crypto::combo_from_components(&schemes)
    }

    /// Content-addressed id, used as the transaction's handle in RPC
    /// responses and as the digest included in a Narwhal batch.
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        if let Ok(bytes) = borsh::to_vec(&self.message) {
            hasher.update(bytes);
        }
        for component in &self.signature.components {
            hasher.update(component.scheme.0.to_le_bytes());
            hasher.update(&component.bytes);
        }
        hasher.finalize().into()
    }

    /// Serialized byte size - what the fee's byte-scaled component prices
    /// (`ARCHITECTURE.md` §5). Dominated by the PQC signature component(s)
    /// and (on first use of an address) the public key bundle - scales up
    /// automatically for a triple-hybrid (SLH-DSA opt-in) combo, since it
    /// sums every signature component's real length rather than assuming a
    /// fixed two-component shape.
    pub fn byte_size(&self) -> usize {
        borsh::to_vec(&self.message).map(|b| b.len()).unwrap_or(0)
            + self.signature.components.iter().map(|c| c.bytes.len()).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ix(payer: Pubkey, to: Pubkey) -> Instruction {
        Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![payer, to],
            data: vec![1, 2, 3],
        }
    }

    #[test]
    fn signed_transaction_verifies() {
        let payer = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        assert!(tx.verify_signature());
    }

    #[test]
    fn tampered_transaction_fails_verification() {
        let payer = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let mut tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        tx.message.nonce = 999;
        assert!(!tx.verify_signature());
    }

    #[test]
    fn forged_key_bundle_fails_verification() {
        let payer = Keypair::generate().unwrap();
        let attacker = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let mut tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        tx.message.payer_keys = attacker.public_key_bundle();
        assert!(!tx.verify_signature());
    }

    #[test]
    fn byte_size_reflects_pqc_signature_weight() {
        let payer = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        // Dominated by the ~1.9KB ML-DSA-65 pubkey + ~3.3KB signature, not
        // the handful of bytes of instruction data - the exact number this
        // project's fee model has to account for (ARCHITECTURE.md §2).
        assert!(tx.byte_size() > 5_000, "byte_size = {}", tx.byte_size());
    }
}
