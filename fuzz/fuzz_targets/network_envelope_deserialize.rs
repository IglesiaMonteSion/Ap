#![no_main]
//! Fuzz del borde de wire P2P (roadmap #14, superficie "P2P"). Un peer envía
//! `[u32 LE len][Borsh(Envelope)]`; el receptor decodifica el `Envelope` (y su
//! `NetMessage` interno, que envuelve Transaction/Batch/Vertex/Certificate/…)
//! DIRECTO de bytes que controla un atacante. Deserializar bytes ARBITRARIOS nunca
//! debe panicar/OOM ni al re-serializar. Es la misma invariante que el property
//! test `arbitrary_bytes_never_panic_p2p_wire` de qchain-network, aquí bajo fuzzing
//! coverage-guided (encuentra caminos que un generador aleatorio no).
use libfuzzer_sys::fuzz_target;
use qchain_network::message::{Envelope, NetMessage};

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = borsh::from_slice::<Envelope>(data) {
        let _ = borsh::to_vec(&env);
    }
    if let Ok(m) = borsh::from_slice::<NetMessage>(data) {
        let _ = borsh::to_vec(&m);
    }
});
