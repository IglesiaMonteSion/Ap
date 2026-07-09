pub mod memo_program;
pub mod system_program;

pub use memo_program::{MemoProgram, MEMO_PROGRAM_ID};
pub use system_program::{SystemInstruction, SystemProgram};

use supersol_core::ProgramRegistry;
use supersol_crypto::Pubkey;

/// The set of native programs every SuperSol node ships with.
pub fn default_program_registry() -> ProgramRegistry {
    let mut registry: ProgramRegistry = ProgramRegistry::new();
    registry.insert(Pubkey::system_program_id(), Box::new(SystemProgram));
    registry.insert(MEMO_PROGRAM_ID, Box::new(MemoProgram));
    registry
}
