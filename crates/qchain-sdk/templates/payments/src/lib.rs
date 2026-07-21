//! Contrato de ejemplo: "Tesorería / Pagos" — escrito con `qchain-sdk` en Rust.
//!
//! Es el equivalente en Rust del contrato WAT de ejemplo, pero legible y seguro.
//! Despacha por un SELECTOR (el 1er arg). Convención de cuentas:
//!   accounts[0] = ORIGEN (tiene que ser el firmante)
//!   accounts[1] = destino 1
//!   accounts[2] = destino 2 (para sel=2 y sel=3)
//!   accounts[3] = destino 3 (para sel=3)
//!
//! Llamada: SIEMPRE 4 args i64 → `sel, x, y, z` (rellená con 0 lo que no uses).
#![no_std]

use qchain_sdk::{abort, balance, entrypoint, log, require, transfer};

// El handler puede llamarse como quieras MENOS `run` (ese nombre lo exporta el
// macro `entrypoint!` como punto de entrada del contrato).
fn dispatch([sel, x, y, z]: [i64; 4]) {
    match sel {
        // sel=1  transfer(x): x de acct0 -> acct1
        1 => {
            log("transfer");
            transfer(0, 1, x);
        }
        // sel=2  split2(x,y): x -> acct1, y -> acct2
        2 => {
            log("split2");
            transfer(0, 1, x);
            transfer(0, 2, y);
        }
        // sel=3  split3(x,y,z): x -> acct1, y -> acct2, z -> acct3
        3 => {
            log("split3");
            transfer(0, 1, x);
            transfer(0, 2, y);
            transfer(0, 3, z);
        }
        // sel=4  sweep(): TODO el saldo de acct0 -> acct1
        4 => {
            log("sweep");
            transfer(0, 1, balance(0));
        }
        // sel=5  pct(x = puntos básicos 0..10000): mueve x/10000 del saldo -> acct1
        5 => {
            log("pct");
            require!(x >= 0 && x <= 10_000);
            let amount = (balance(0) / 10_000) * x; // /10000 primero evita overflow
            transfer(0, 1, amount);
        }
        // sel=6  tip(x = pago, y = propina): x -> acct1 (comercio), y -> acct2 (tesorería)
        6 => {
            log("tip");
            transfer(0, 1, x);
            transfer(0, 2, y);
        }
        _ => abort(),
    }
}

entrypoint!(dispatch);
