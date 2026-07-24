#![no_main]
//! Fuzz del borde de decodificación de gobernanza (roadmap #14, superficie
//! "gobernanza"). Una `Proposal` y su `ProposalAction` se decodifican de la `data`
//! de una cuenta on-chain (Borsh) — bytes que en última instancia provienen de una
//! tx de un usuario. Deserializar bytes ARBITRARIOS nunca debe panicar/OOM ni al
//! re-serializar. Espejo coverage-guided del property test
//! `arbitrary_bytes_never_panic_governance`.
use libfuzzer_sys::fuzz_target;
use qchain_governance::{Proposal, ProposalAction};

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = borsh::from_slice::<Proposal>(data) {
        let _ = borsh::to_vec(&p);
    }
    let _ = borsh::from_slice::<ProposalAction>(data);
});
