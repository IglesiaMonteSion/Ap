#![no_main]
//! Fuzz del borde de wire de una Transaction (task #200). Deserializar bytes
//! ARBITRARIOS como Transaction nunca debe panicar/OOM; si deserializa, verificar
//! la firma y computar txid/byte_size tampoco. Es la misma invariante que el
//! property test `arbitrary_bytes_deserialize_without_panic` de qchain-core,
//! aquí bajo fuzzing coverage-guided (encuentra caminos que un generador aleatorio
//! no).
use libfuzzer_sys::fuzz_target;
use qchain_core::Transaction;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = borsh::from_slice::<Transaction>(data) {
        let _ = tx.verify_signature();
        let _ = tx.txid();
        let _ = tx.hash();
        let _ = tx.byte_size();
        // Re-serializar tampoco debe panicar.
        let _ = borsh::to_vec(&tx);
    }
});
