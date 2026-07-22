# Seguridad de contratos en Qchain (checklist para autores)

Los contratos de Qchain corren en WASM detrás de un **borde de autorización del
ledger** que refuerza garantías duras para TODO bytecode (no sólo el que se porta
bien). Este documento traduce los **hallazgos y lecciones de la auditoría del
proyecto** a una checklist accionable para quien escribe un contrato, y separa
explícitamente **lo que el LEDGER ya te garantiza** de **lo que TENÉS que hacer vos**.

El SDK (`qchain-sdk`, v0.5+) trae helpers que hacen difícil equivocarse. Usalos.

---

## Lo que el LEDGER refuerza por vos (no lo podés romper desde el contrato)

Estas garantías viven en `run_wasm_instruction` (fixes reales v2.0.4 / v5.5.3) y
aplican a CUALQUIER `.wasm`, aunque sea malicioso:

1. **No se puede acuñar.** El total de saldo sobre las cuentas declaradas NUNCA
   puede crecer en una instrucción. Un contrato que intente `set_balance(self, MAX)`
   es rechazado y la tx se descarta.
2. **Débito autorizado.** Una cuenta sólo se DEBITA si el llamador está autorizado:
   es el **firmante** de la tx, o **el programa la posee** (`owner == program_id`,
   una PDA reclamada con `use_pda`). Nombrar la cuenta de una víctima y debitarla
   sin su firma → rechazado.
3. **Sin aliasing.** Nombrar la misma cuenta dos veces en `ix.accounts` para
   "conservar la suma posicional" pero duplicar un saldo al commitear → rechazado.
4. **`owner`/`data` protegidos.** Un contrato no puede cambiar el `owner` de una
   cuenta (salvo reclamar una PDA fresca de sí mismo), y sólo escribe la `data` de
   una cuenta que firmó o que posee.
5. **Fuel + memoria acotados.** Trap-billing del gas, tope de memoria (16MiB),
   tope de `data` por cuenta (16KB). Un bucle infinito o un `memory.grow` gigante
   trapea y paga su fuel — no tumba el nodo.
6. **Determinismo.** NaN canónico, sin SIMD relajado, sin reloj/RNG en el host →
   el mismo contrato produce el mismo estado en toda arquitectura (sin fork).

---

## Lo que TENÉS que hacer vos (el LEDGER no lo puede saber por vos)

El ledger sabe "¿este débito está autorizado?" pero NO sabe la lógica de tu
contrato (quién es tu admin, cuál es el cap de tu token, qué saldo le corresponde
a quién). Eso es responsabilidad del contrato. Checklist:

### 1. Overflow / underflow — la fuente #1 de bugs de dinero
- Usá **`add_u64` / `sub_u64`** del SDK (abortan, no envuelven) para supply,
  saldos, contadores. Un `+`/`-` crudo que envuelve puede acuñar o destruir valor.
- El perfil de release del workspace tiene `overflow-checks=true`, pero tu
  aritmética de estado la manejás vos: no confíes, chequeá.

### 2. Autorización por dueño (admin / mint authority / roles)
- Guardá la dirección del dueño en la `data` de una PDA al inicializar
  (`write_pubkey`), y al hacer una acción privilegiada exigí que el firmante
  coincida: **`require_owner(&data, offset)`**. Nunca asumas "el que llama es el
  admin" sin comparar contra el dueño guardado.
- Inicialización **una sola vez**: chequeá que el estado no exista ya
  (`require!(n < LEN, ...)`) o alguien re-inicializa y se roba el rol.
- **Anti init-takeover (el front-run del deploy):** "una sola vez" no alcanza si
  *cualquiera* puede ser ese único que inicializa — un tercero puede llamar tu
  `init` ANTES que vos y quedarse como admin/authority. Cerralo con
  **`require_deployer()`** en la `init`: exige que el firmante sea la dirección
  que DESPLEGÓ el contrato (registrada on-chain por `DeployProgram` y ligada a la
  dirección del programa por construcción). Sólo el deployer inicializa.

### 3. "Debitar sólo lo tuyo" — POR CONSTRUCCIÓN, no por un chequeo olvidable
- Para un libro de saldos (token), guardá el saldo de cada titular en una **PDA
  derivada de SU dirección**: `use_pda(idx, &holder_seed(TAG, &holder))`.
- Derivá el ORIGEN de un `transfer` de **`pubkey(0)`** (el firmante). Así la PDA
  de saldo del origen SÓLO puede ser la del firmante: un atacante que nombre la
  PDA de una víctima falla el `use_pda` (esa PDA no deriva de su dirección) y la
  tx se descarta. La autorización queda en la ESTRUCTURA, imposible de olvidar.

### 4. Conservación e invariantes de tu propio estado
- Si manejás un supply: `supply == Σ saldos` siempre. Mint sube supply y un saldo
  por el MISMO monto; transfer conserva; burn baja ambos. Nunca toques uno sin el
  otro.
- Aplicá caps (`require!(new_supply <= cap, ...)`) ANTES de escribir.

### 5. Validá las entradas
- Rechazá montos negativos (`require!(a >= 0)`), longitudes fuera de rango, y
  cuentas que no son las que esperás (el `use_pda`/`require!` ya lo hace si
  derivás la PDA vos: una cuenta que no es la PDA esperada falla).

### 6. Fallá fuerte y temprano
- `require!(cond, "motivo")` / `abort()` → trap → la tx entera se descarta, pero
  el pagador igual paga el fee de su intento (no es un reintento gratis para un
  atacante). No "sigas de largo" ante una condición inesperada.

### 7. Guardas de contratos FINANCIEROS (slippage / precio máx / deadline / estado esperado)
Si tu contrato mueve valor a un precio que puede cambiar entre que el usuario
FIRMA y que la tx EJECUTA (un swap, una subasta, un préstamo, comprar un NFT), el
usuario necesita protegerse de recibir algo peor de lo que aceptó — el patrón
`amountOutMin` + `deadline` de Uniswap. **El LEDGER no puede hacerlo por vos: no
sabe qué significa "precio" o "monto de salida" para tu contrato** — es lógica de
negocio tuya. Pero es fácil, y estos límites deben viajar como ARGS de la
instrucción (i64), fijados por el usuario al firmar, y chequearse con `require!`
ANTES de comprometer la operación:

- **`min_amount_out` (anti-slippage):** el usuario dice "acepto AL MENOS N de
  salida". `require!(amount_out >= min_out, ...)`.
- **precio máximo:** "no pagues más de P por unidad".
  `require!(precio_efectivo <= max_price, ...)`.
- **estado esperado:** "ejecuta sólo si el pool/oráculo está como lo vi". Leé el
  estado actual con `read_u64(get_data(idx, ...))` y `require!(actual == esperado, ...)`.
- **deadline:** hoy se hace a **nivel de TRANSACCIÓN** con `valid_until_round` (la
  wallet lo pone OBLIGATORIO y corto, y el nodo lo enforza en admisión + ejecución,
  #191) — una orden vieja atascada en el mempool NO se ejecuta a un precio de hace
  horas. No hay un reloj in-contract todavía (un `host_get_round` sería un syscall
  futuro si algún contrato necesita un deadline interno distinto del de la tx).

Ejemplo — un swap que respeta slippage + precio máximo (los `require!` abortan la
tx si el resultado real es peor que lo aceptado; el pagador sólo pierde el fee):

```rust
use qchain_sdk::{entrypoint, require, abort, add_u64, sub_u64};

fn handle(args: [i64; 4]) {
    // El usuario firma: [selector, amount_in, min_out, max_price]. min_out y
    // max_price son los LÍMITES que aceptó — fijos en el momento de firmar.
    let [sel, amount_in, min_out, max_price] = args;
    match sel {
        1 => {
            let amount_in  = amount_in as u64;
            let min_out    = min_out   as u64;
            let max_price  = max_price as u64;

            // Cotización AL MOMENTO DE EJECUTAR (pudo moverse desde que firmó):
            let amount_out = quote(amount_in);
            // Anti-slippage: nunca menos de lo que el usuario aceptó.
            require!(amount_out >= min_out, "slippage: recibirias menos de lo aceptado");
            // Precio máximo (in por cada out); evita dividir por cero.
            let precio = amount_in / amount_out.max(1);
            require!(precio <= max_price, "precio por encima del maximo aceptado");

            // ... ejecutar el intercambio con add_u64/sub_u64 (overflow-safe) ...
        }
        _ => abort(),
    }
}
entrypoint!(handle);
```

Regla mental: **cualquier valor que el usuario querría fijar "yo acepto como
máximo/mínimo X" debe ser un ARG firmado, no algo que el contrato calcule solo** —
si el contrato decide el límite por su cuenta, no hay protección real para el
usuario. El `deadline` corto ya lo garantiza la wallet vía `valid_until_round`.

---

## Ejemplo de referencia auditado

`crates/qchain-sdk/templates/token/` — un **token fungible endurecido** que aplica
las 6 reglas. Verificado EN VIVO contra un nodo real, incluyendo ataques:
mint no-autorizado → rechazado; mint sobre el cap → rechazado; **drenar el saldo de
otro → rechazado por construcción**; gastar más de lo que se tiene → rechazado;
`supply == Σ saldos` mantenido. Copialo como punto de partida.

## Y una capa más: el auditor IA de PRs

`.github/workflows/ai-security-review.yml` (#183 Fase A) audita cada PR contra los
10 invariantes de seguridad del proyecto con la API de Claude. Está **INERTE** hasta
que el operador agregue el secret `ANTHROPIC_API_KEY` — actívalo para auditar
automáticamente cada cambio de contrato/código.
