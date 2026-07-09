use crate::poh::PohEntry;
use crate::transaction::Transaction;
use supersol_crypto::Pubkey;
use serde::{Deserialize, Serialize};

/// A confirmed slice of history: the PoH ticks produced during a slot, the
/// transactions that were applied to the ledger during it, and any faucet
/// airdrops (devnet only). Unlike Solana's BPF-executed, gossiped blocks,
/// state here is applied immediately on receipt (see `Ledger`) and a Block is
/// just the durable, auditable record of what happened - a deliberate MVP
/// simplification, tracked as a roadmap item toward true leader-ordered
/// blocks.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Block {
    pub slot: u64,
    pub leader: Pubkey,
    #[serde(with = "crate::hex32")]
    pub previous_blockhash: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub blockhash: [u8; 32],
    pub poh_entries: Vec<PohEntry>,
    pub transactions: Vec<Transaction>,
    pub airdrops: Vec<(Pubkey, u64)>,
}
