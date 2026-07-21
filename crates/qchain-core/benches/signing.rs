//! Benchmarks del camino caliente de firma (task #200, criterion). Mide el verify
//! híbrido PQC (Ed25519+ML-DSA-65) y el txid canónico — el costo dominante por
//! transacción, medido con intervalos de confianza y reproducible en cualquier
//! máquina (corré `cargo bench -p qchain-core`).
use criterion::{criterion_group, criterion_main, Criterion};
use qchain_core::{Instruction, Transaction};
use qchain_crypto::{Keypair, Pubkey};
use std::hint::black_box;

fn a_signed_tx() -> Transaction {
    let payer = Keypair::generate().unwrap();
    let to = Keypair::generate().unwrap().pubkey();
    let ix = Instruction {
        program_id: Pubkey::system_program_id(),
        accounts: vec![payer.pubkey(), to],
        data: 5u64.to_le_bytes().to_vec(),
    };
    Transaction::new_signed(&payer, 0, [0u8; 32], 1_000_000, vec![ix]).unwrap()
}

fn bench(c: &mut Criterion) {
    let tx = a_signed_tx();
    c.bench_function("verify_signature (hybrid PQC)", |b| b.iter(|| black_box(tx.verify_signature())));
    c.bench_function("txid (canonical)", |b| b.iter(|| black_box(tx.txid())));
    c.bench_function("byte_size", |b| b.iter(|| black_box(tx.byte_size())));
}

criterion_group!(benches, bench);
criterion_main!(benches);
