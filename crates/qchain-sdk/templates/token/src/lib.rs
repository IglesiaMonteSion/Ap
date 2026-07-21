//! Contrato de ejemplo (SDK v0.5): "Token fungible ENDURECIDO".
//!
//! Un token propio (distinto del QCH nativo) cuyo libro de saldos vive en cuentas
//! del programa (PDAs por-titular). Es el contrato donde MÁS importan las lecciones
//! de la auditoría, y este ejemplo las aplica TODAS de forma verificable:
//!
//!   • OVERFLOW-SAFETY: supply y saldos con `add_u64`/`sub_u64` (abortan, no
//!     envuelven) → imposible acuñar por wraparound. (lección `overflow-checks`)
//!   • MINT AUTORIZADO: sólo la mint-authority guardada puede acuñar
//!     (`require_owner`). (lección del borde de autorización WASM)
//!   • SUPPLY CAP + CONSERVACIÓN: `supply <= cap` y `supply == Σ saldos` — mint
//!     sube supply, transfer lo conserva, burn lo baja.
//!   • "DEBITAR SÓLO LO TUYO" POR CONSTRUCCIÓN: la PDA de saldo de un titular se
//!     deriva de SU dirección (`holder_seed`), así el origen de un transfer se
//!     deriva de `pubkey(0)` (el firmante) → NADIE puede drenar el saldo de otro.
//!     (la clase exacta del fix del borde WASM de v2.0.4, ahora en el contrato)
//!
//! La garantía DURA la sigue reforzando el LEDGER para TODO bytecode (no acuñar,
//! débito autorizado sólo si firmante o program-owned); esto lo hace además
//! seguro-por-diseño a nivel contrato.
//!
//! ## Estado
//!   Mint PDA = pda(program_id, "mint")   → [authority:32][supply:u64@32][cap:u64@40]  (48B)
//!   Saldo de H = pda(program_id, 0x01‖H)  → [balance:u64@0]                            (8B)
//!   (deriva la PDA de saldo off-chain con `qchain-wasm-signer token-balance-pda <prog> <H>`)
//!
//! ## Selectores (SIEMPRE 4 args i64: sel, a, _, _)
//!   1 init(cap)      : accounts=[authority(firma), mint_pda]. Fija authority=firmante, supply=0, cap.
//!   2 mint(amount)   : accounts=[authority(firma), mint_pda, bal_pda(dest), dest_addr]. Sólo la authority; supply+=amount<=cap.
//!   3 transfer(amount): accounts=[remitente(firma), bal_pda(remitente), bal_pda(dest), dest_addr]. Debita al FIRMANTE, acredita al dest.
//!   4 burn(amount)   : accounts=[titular(firma), bal_pda(titular), mint_pda]. Quema del propio saldo; supply-=amount.
#![no_std]

use qchain_sdk::{
    abort, add_u64, entrypoint, get_data, holder_seed, log, pubkey, read_u64, require, require_owner, require_signer,
    set_data, sub_u64, use_pda, write_pubkey, write_u64,
};

const TAG_BAL: u8 = 0x01; // espacio de PDA de saldos
const MINT_LEN: usize = 48; // [authority:32][supply@32][cap@40]
const BAL_LEN: usize = 8; // [balance@0]

/// Carga los 8 bytes de saldo de una PDA de saldo ya validada con `use_pda`.
fn load_balance(idx: u32) -> u64 {
    let mut b = [0u8; BAL_LEN];
    let n = get_data(idx, &mut b);
    if n >= BAL_LEN {
        read_u64(&b, 0)
    } else {
        0
    }
}
fn store_balance(idx: u32, v: u64) {
    let mut b = [0u8; BAL_LEN];
    write_u64(&mut b, 0, v);
    set_data(idx, &b);
}

fn dispatch([sel, a, _b, _c]: [i64; 4]) {
    require!(a >= 0, "monto negativo");
    let amount = a as u64;

    match sel {
        // init(cap): reclama la mint PDA y fija al firmante como authority.
        1 => {
            require!(use_pda(1, b"mint"), "accounts[1] no es la mint PDA");
            require_signer(0);
            let mut m = [0u8; MINT_LEN];
            let n = get_data(1, &mut m);
            require!(n < MINT_LEN, "el token ya está inicializado");
            let authority = pubkey(0);
            write_pubkey(&mut m, 0, &authority); // authority
            write_u64(&mut m, 32, 0); // supply
            write_u64(&mut m, 40, amount); // cap
            set_data(1, &m);
            log("token:init");
        }
        // mint(amount): sólo la authority; sube supply (<= cap) y acredita al dest.
        2 => {
            require!(use_pda(1, b"mint"), "accounts[1] no es la mint PDA");
            require_signer(0);
            let mut m = [0u8; MINT_LEN];
            let n = get_data(1, &mut m);
            require!(n >= MINT_LEN, "token no inicializado");
            require_owner(&m, 0); // firmante == mint authority

            // accounts[2] = PDA de saldo del dest; accounts[3] = dirección del dest.
            let dest = pubkey(3);
            require!(use_pda(2, &holder_seed(TAG_BAL, &dest)), "accounts[2] no es la PDA de saldo del dest");

            let supply = read_u64(&m, 32);
            let cap = read_u64(&m, 40);
            let new_supply = add_u64(supply, amount); // aborta en overflow
            require!(new_supply <= cap, "supera el cap del token");
            let bal = add_u64(load_balance(2), amount);
            store_balance(2, bal);
            write_u64(&mut m, 32, new_supply);
            set_data(1, &m);
            log("token:mint");
        }
        // transfer(amount): el origen es el FIRMANTE por construcción.
        3 => {
            require_signer(0);
            let from = pubkey(0);
            // accounts[1] = PDA de saldo del FIRMANTE (derivada de SU dirección):
            // un atacante no puede nombrar la PDA de otro — este use_pda fallaría.
            require!(use_pda(1, &holder_seed(TAG_BAL, &from)), "accounts[1] no es TU PDA de saldo");
            let dest = pubkey(3);
            require!(use_pda(2, &holder_seed(TAG_BAL, &dest)), "accounts[2] no es la PDA de saldo del dest");

            let from_bal = sub_u64(load_balance(1), amount); // aborta si no alcanza
            let to_bal = add_u64(load_balance(2), amount);
            store_balance(1, from_bal);
            store_balance(2, to_bal);
            log("token:transfer");
        }
        // burn(amount): quema del propio saldo del firmante; baja el supply.
        4 => {
            require_signer(0);
            let holder = pubkey(0);
            require!(use_pda(1, &holder_seed(TAG_BAL, &holder)), "accounts[1] no es TU PDA de saldo");
            require!(use_pda(2, b"mint"), "accounts[2] no es la mint PDA");
            let new_bal = sub_u64(load_balance(1), amount);
            store_balance(1, new_bal);
            let mut m = [0u8; MINT_LEN];
            require!(get_data(2, &mut m) >= MINT_LEN, "token no inicializado");
            let supply = sub_u64(read_u64(&m, 32), amount);
            write_u64(&mut m, 32, supply);
            set_data(2, &m);
            log("token:burn");
        }
        _ => abort(),
    }
}

entrypoint!(dispatch);
