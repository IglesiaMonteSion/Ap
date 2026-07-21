//! Contrato de ejemplo (SDK v0.4): "Tesorería / bóveda con DUEÑO".
//!
//! Demuestra una TESORERÍA DE PROGRAMA: fondos guardados en una PDA propia del
//! programa (que ningún usuario firma), con control de acceso por DUEÑO —
//! CUALQUIERA puede depositar, pero SÓLO el admin puede retirar. Cierra el
//! límite honesto de v0.3 (mover fondos DESDE una cuenta del programa) usando
//! `pda_transfer` (paga desde la PDA sin firma sobre el origen — el ledger lo
//! autoriza porque el programa la posee) y `pubkey` (compara el firmante contra
//! el admin guardado).
//!
//! Estado en la PDA `pda(program_id, "vault")` (layout, 40 bytes):
//!   offset 0  : admin (32 bytes) — la dirección que puede retirar
//!   offset 32 : total_deposited (u64 LE) — contabilidad acumulada de depósitos
//!
//! Convención de cuentas:
//!   accounts[0] = el usuario que llama (firma; paga el fee)
//!   accounts[1] = la PDA "vault" = pda(program_id, b"vault")  (la deriva el cliente)
//!   accounts[2] = destino del retiro (a quién le paga la bóveda)  [sólo withdraw]
//!
//! Selectores (SIEMPRE 4 args i64: sel, x, _, _):
//!   1 init()        : reclama la bóveda y fija al DEPLOYER (accounts[0]) como admin. SÓLO el deployer, una vez (require_deployer).
//!   2 deposit(x)    : CUALQUIERA mueve x de su cuenta (accounts[0]) a la bóveda.
//!   3 withdraw(x)   : SÓLO el admin mueve x de la bóveda a accounts[2].
//!
//! Se lee por RPC: `GET /account/<pda>` → `balance` (los fondos) + `data` (admin+total).
#![no_std]

use qchain_sdk::{
    abort, deposit, entrypoint, get_data, log, pda_transfer, pubkey, read_u64, require, require_deployer,
    require_signer, set_data, use_pda, write_u64,
};

const VAULT_SEED: &[u8] = b"vault";
const STATE_LEN: usize = 40; // 32 (admin) + 8 (total_deposited)

fn dispatch([sel, x, _y, _z]: [i64; 4]) {
    // accounts[1] tiene que ser NUESTRA PDA de bóveda (la reclama la 1ª vez).
    require!(use_pda(1, VAULT_SEED), "accounts[1] no es la PDA de la bóveda");

    let mut buf = [0u8; STATE_LEN];
    let n = get_data(1, &mut buf);
    let initialized = n >= STATE_LEN;

    match sel {
        // init: fija al DEPLOYER como admin. Sólo una vez, y SÓLO el deployer.
        // ANTI INIT-TAKEOVER (re-auditoría): sin `require_deployer()`, cualquier
        // tercero podía llamar `init` primero tras el despliegue y quedar como
        // admin de la bóveda (y luego drenar todos los depósitos). `require_deployer`
        // exige que accounts[0] sea el firmante Y la dirección que desplegó el
        // contrato (ligada a la dirección del programa por construcción), cerrando
        // el front-run. Reemplaza al viejo `require_signer(0)` (que sólo probaba
        // que alguien firmó, no QUIÉN).
        1 => {
            require!(!initialized, "la bóveda ya está inicializada");
            require_deployer();
            let admin = pubkey(0);
            buf[0..32].copy_from_slice(&admin);
            write_u64(&mut buf, 32, 0); // total_deposited = 0
            set_data(1, &buf);
            log("init");
        }
        // deposit: cualquiera aporta fondos a la bóveda. El firmante autoriza
        // debitar lo suyo; acreditar la PDA es un crédito simple.
        2 => {
            require!(initialized, "la bóveda no está inicializada");
            require!(x >= 0);
            deposit(0, 1, x); // acct0 (firma) -> bóveda
            let total = read_u64(&buf, 32).saturating_add(x as u64);
            write_u64(&mut buf, 32, total);
            set_data(1, &buf);
            log("deposit");
        }
        // withdraw: SÓLO el admin guardado. Paga desde la bóveda (PDA) a accounts[2].
        3 => {
            require!(initialized, "la bóveda no está inicializada");
            require!(x >= 0);
            require_signer(0);
            let mut admin = [0u8; 32];
            admin.copy_from_slice(&buf[0..32]);
            // El firmante (accounts[0]) DEBE ser el admin guardado.
            require!(pubkey(0) == admin, "sólo el admin puede retirar");
            pda_transfer(1, 2, x); // bóveda (PDA, sin firma) -> accounts[2]
            log("withdraw");
            // (dejamos total_deposited como contabilidad histórica de aportes)
        }
        _ => abort(),
    }
}

entrypoint!(dispatch);
