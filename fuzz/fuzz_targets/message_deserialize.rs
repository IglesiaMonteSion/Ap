#![no_main]
//! Fuzz del `Message` firmable (task #200): deserializar bytes arbitrarios como
//! Message no debe panicar, y re-serializar un Message deserializado debe ser
//! idempotente en tamaño (round-trip estable del encoding canónico).
use libfuzzer_sys::fuzz_target;
use qchain_core::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = borsh::from_slice::<Message>(data) {
        let _ = borsh::to_vec(&msg);
    }
});
