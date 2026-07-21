//! Contrato de ejemplo (SDK v0.3): "Contador GLOBAL compartido".
//!
//! Demuestra estado COMPARTIDO en una cuenta PROPIA DEL PROGRAMA (PDA) — no la
//! de ningún usuario. CUALQUIER usuario puede incrementar el mismo contador
//! global; el estado vive en la PDA `pda(program_id, "global")`, que ningún
//! usuario firma. Layout en la PDA (16 bytes):
//!
//!   offset 0 : total (u64 LE) — la suma acumulada de todos los usuarios
//!   offset 8 : hits  (u64 LE) — cuántas veces se llamó
//!
//! Convención de cuentas:
//!   accounts[0] = el usuario que llama (firma; paga el fee)
//!   accounts[1] = la PDA "global" = pda(program_id, b"global")  (la deriva el cliente)
//!
//! Selectores (SIEMPRE 4 args i64: sel, x, _, _):
//!   1 add(x) : total += x, hits += 1
//!
//! Se lee por RPC: `GET /account/<pda>` → campo `data` (16 bytes).
#![no_std]

use qchain_sdk::{abort, entrypoint, get_data, log, read_u64, require, set_data, use_pda, write_u64};

const STATE_LEN: usize = 16;

fn dispatch([sel, x, _y, _z]: [i64; 4]) {
    // accounts[1] tiene que ser NUESTRA PDA "global" (la reclama la 1ª vez).
    require!(use_pda(1, b"global"));

    let mut buf = [0u8; STATE_LEN];
    let n = get_data(1, &mut buf);
    let mut total = if n >= 8 { read_u64(&buf, 0) } else { 0 };
    let mut hits = if n >= 16 { read_u64(&buf, 8) } else { 0 };

    match sel {
        1 => {
            require!(x >= 0);
            total = total.saturating_add(x as u64);
            hits = hits.saturating_add(1);
            log("add");
        }
        _ => abort(),
    }

    write_u64(&mut buf, 0, total);
    write_u64(&mut buf, 8, hits);
    set_data(1, &buf);
}

entrypoint!(dispatch);
