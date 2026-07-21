//! Contrato de ejemplo (SDK v0.2): "Contador con estado estructurado".
//!
//! Demuestra ESTADO ESTRUCTURADO on-chain: guarda un struct en la `data` de la
//! cuenta del USUARIO (accounts[0], el firmante). Layout fijo de 16 bytes:
//!
//!   offset 0  : count   (i64 LE)  — el valor del contador
//!   offset 8  : updates (u64 LE)  — cuántas veces se modificó
//!
//! El usuario guarda SU propio estado (accounts[0] = firmante ⇒ el ledger
//! autoriza la escritura). Se lee de vuelta por RPC: `GET /account/<dir>` →
//! el campo `data` trae esos 16 bytes.
//!
//! Selectores (SIEMPRE 4 args i64: sel, x, _, _):
//!   1 init(x) : count = x, updates = 0
//!   2 add(x)  : count += x, updates += 1   (saturating)
//!   3 sub(x)  : count -= x, updates += 1   (saturating)
#![no_std]

use qchain_sdk::{abort, entrypoint, get_data, is_signer, log, read_i64, read_u64, require, set_data, write_i64, write_u64};

const STATE_LEN: usize = 16;

fn dispatch([sel, x, _y, _z]: [i64; 4]) {
    // El estado vive en la cuenta del firmante: solo su dueño lo toca.
    require!(is_signer(0));

    let mut buf = [0u8; STATE_LEN];
    let n = get_data(0, &mut buf);
    let mut count = if n >= 8 { read_i64(&buf, 0) } else { 0 };
    let mut updates = if n >= 16 { read_u64(&buf, 8) } else { 0 };

    match sel {
        1 => {
            count = x;
            updates = 0;
            log("init");
        }
        2 => {
            count = count.saturating_add(x);
            updates = updates.saturating_add(1);
            log("add");
        }
        3 => {
            count = count.saturating_sub(x);
            updates = updates.saturating_add(1);
            log("sub");
        }
        _ => abort(),
    }

    write_i64(&mut buf, 0, count);
    write_u64(&mut buf, 8, updates);
    set_data(0, &buf);
}

entrypoint!(dispatch);
