//! Contrato de ejemplo (SDK v0.6): "Compra a PRECIO LÍMITE" — una plantilla
//! FINANCIERA que demuestra las GUARDAS del §7 de `docs/CONTRACT-SECURITY.md`
//! (el patrón `amountInMax` / `deadline` de un DEX, adaptado a un precio fijo).
//!
//! Un VENDEDOR publica un precio por unidad; un COMPRADOR compra N unidades, pero
//! firma el MÁXIMO TOTAL que acepta pagar. Si el vendedor sube el precio entre que
//! el comprador cotiza y que su tx ejecuta (o hace front-running), la compra ABORTA
//! en vez de sobre-pagar — la protección real del comprador. El `deadline` (una
//! orden vieja atascada en el mempool no debe ejecutarse a un precio de hace horas)
//! lo da la propia transacción con `valid_until_round` (la wallet lo pone
//! obligatorio y corto, el nodo lo enforza — #191); no hay reloj in-contract.
//!
//! Demuestra: `require_deployer` (anti init-takeover), `use_pda` (estado propio del
//! programa), `mul_u64` (precio total sin overflow), `require_at_most` (la guarda
//! de precio máximo firmada por el comprador), y `pubkey_eq` (el pago va SÍ o SÍ al
//! vendedor registrado, no a una cuenta que elija el comprador).
//!
//! Estado en la PDA `pda(program_id, "escrow")` (40 bytes):
//!   offset 0  : seller (32 bytes) — quién cobra
//!   offset 32 : unit_price (u64 LE) — precio por unidad (en unidades, 1 QCH = 1e9)
//!
//! Convención de cuentas:
//!   accounts[0] = quien llama (firma; paga el fee)
//!   accounts[1] = la PDA "escrow" = pda(program_id, b"escrow")  (la deriva el cliente)
//!   accounts[2] = la cuenta del VENDEDOR (destino del pago)      [sólo buy]
//!
//! Selectores (SIEMPRE 4 args i64: sel, a, b, _):
//!   1 list(unit_price)        : el DEPLOYER reclama el escrow y se fija como vendedor + precio. Una vez.
//!   2 set_price(unit_price)   : SÓLO el vendedor actualiza el precio.
//!   3 buy(units, max_total)   : el comprador paga `units*unit_price` al vendedor,
//!                               abortando si supera `max_total` (su guarda firmada).
//!
//! Se lee por RPC: `GET /account/<pda>` → `data` (seller + unit_price).
#![no_std]

use qchain_sdk::{
    abort, deposit, entrypoint, get_data, log, mul_u64, pubkey, pubkey_eq, read_pubkey, read_u64,
    require, require_at_most, require_deployer, set_data, use_pda, write_u64,
};

const ESCROW_SEED: &[u8] = b"escrow";
const STATE_LEN: usize = 40; // 32 (seller) + 8 (unit_price)

fn dispatch([sel, a, b, _c]: [i64; 4]) {
    // accounts[1] tiene que ser NUESTRA PDA de escrow (la reclama la 1ª vez).
    require!(use_pda(1, ESCROW_SEED), "accounts[1] no es la PDA del escrow");

    let mut buf = [0u8; STATE_LEN];
    let n = get_data(1, &mut buf);
    let initialized = n >= STATE_LEN;

    match sel {
        // list: el DEPLOYER (vendedor) fija precio por unidad. Una vez, y SÓLO el
        // deployer — `require_deployer` cierra el front-run del `init` (sin él, un
        // tercero podría publicar primero y quedar como vendedor cobrando los pagos).
        1 => {
            require!(!initialized, "el escrow ya fue publicado");
            require!(a >= 0, "precio negativo");
            require_deployer();
            let seller = pubkey(0);
            buf[0..32].copy_from_slice(&seller);
            write_u64(&mut buf, 32, a as u64);
            set_data(1, &buf);
            log("list");
        }
        // set_price: SÓLO el vendedor guardado puede reprecificar.
        2 => {
            require!(initialized, "el escrow no fue publicado");
            require!(a >= 0, "precio negativo");
            let seller = read_pubkey(&buf, 0);
            require!(pubkey(0) == seller, "sólo el vendedor puede cambiar el precio");
            write_u64(&mut buf, 32, a as u64);
            set_data(1, &buf);
            log("set_price");
        }
        // buy: el comprador paga `units * unit_price` al vendedor. GUARDA: aborta si
        // el total supera `max_total` (el máximo que el comprador firmó) — su
        // protección contra que el precio suba entre cotizar y ejecutar.
        3 => {
            require!(initialized, "el escrow no fue publicado");
            require!(a >= 0, "units negativo");
            require!(b >= 0, "max_total negativo");
            let units = a as u64;
            let max_total = b as u64;
            let unit_price = read_u64(&buf, 32);
            // Precio total con multiplicación overflow-safe (un `*` que envuelve
            // daría un total disparatado y quizás barato).
            let total = mul_u64(units, unit_price);
            // GUARDA FINANCIERA firmada por el comprador: nunca pagar de más.
            require_at_most(total, max_total);
            // El pago va SÍ o SÍ al VENDEDOR registrado, no a una cuenta que elija
            // quien llama (accounts[2] debe ser el seller guardado).
            let seller = read_pubkey(&buf, 0);
            require!(pubkey_eq(2, &seller), "accounts[2] no es el vendedor registrado");
            // El comprador (firma, autoriza debitar lo suyo) paga al vendedor.
            deposit(0, 2, total as i64);
            log("buy");
        }
        _ => abort(),
    }
}

entrypoint!(dispatch);
