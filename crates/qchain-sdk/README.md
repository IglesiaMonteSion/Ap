# qchain-sdk

SDK de alto nivel para escribir **contratos inteligentes de Qchain en Rust** (en
vez de WebAssembly a mano). Compila a `wasm32-unknown-unknown` y produce un
`.wasm` listo para `qchain deploy-program` o el panel **Contratos** de QScan.

- `no_std`, sin dependencias (solo `core` + los syscalls del host).
- Wrappers seguros: `balance`, `set_balance`, `is_signer`, `require_signer`,
  `credit`, `debit`, `transfer`, `log`, `abort`, `require!`.
- **Estado estructurado on-chain (v0.2):** `get_data`/`set_data`/`data_len` +
  helpers LE (`read_u64`/`write_i64`/…) para guardar structs en `account.data`.
- **Estado compartido / PDAs (v0.3):** `use_pda` — cuentas de estado propias del
  programa (estilo PDA de Solana) que ningún usuario firma.
- **Tesorerías de programa + control de acceso por dueño (v0.4):** `pda_transfer`
  (paga fondos DESDE una PDA), `deposit`, `pubkey`/`pubkey_eq` (lee la dirección
  de una cuenta para exigir "el firmante es el admin guardado").
- **Capa de seguridad (v0.5):** `add_u64`/`sub_u64` (aritmética checkeada),
  `require_owner`, `holder_seed` ("debitar sólo lo tuyo" por construcción),
  `read_pubkey`/`write_pubkey`. Ver [`docs/CONTRACT-SECURITY.md`](../../docs/CONTRACT-SECURITY.md).
- **Anti init-takeover (v0.6):** `deployer()` / `require_deployer()` — la `init`
  de un contrato exige que el firmante sea la dirección que lo DESPLEGÓ, cerrando
  el front-run donde un tercero llama `init` primero y se registra como admin.
- Macro `entrypoint!` que exporta el punto de entrada `run` (4 args `i64`).

**Ejemplos listos para compilar:**
- `templates/payments/` — tesorería/pagos con 6 funciones (saldos).
- `templates/counter/` — contador con **estado estructurado** en la cuenta del
  usuario (v0.2).
- `templates/shared_counter/` — contador **GLOBAL compartido** en una PDA del
  programa que cualquiera incrementa (v0.3).
- `templates/vault/` — **tesorería con dueño**: cualquiera deposita, sólo el admin
  retira (fondos en una PDA + control de acceso por `pubkey`, v0.4).
- `templates/token/` — **token fungible ENDURECIDO**: mint autorizado + cap,
  saldos en PDAs por-titular, transfer que debita al firmante por construcción
  (v0.5, verificado en vivo contra ataques).

Compilalos con:

```bash
deploy/build-contract.sh crates/qchain-sdk/templates/payments
deploy/build-contract.sh crates/qchain-sdk/templates/counter
```

Guía completa (modelo de ejecución, convención de llamada, seguridad, API):
[`docs/SMART-CONTRACTS.md`](../../docs/SMART-CONTRACTS.md).

> Se compila **aparte** del workspace principal (targetea wasm32 / `no_std`),
> igual que `qchain-wasm`. Está en el `exclude` del workspace raíz.
