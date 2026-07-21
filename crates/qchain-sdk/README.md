# qchain-sdk

SDK de alto nivel para escribir **contratos inteligentes de Qchain en Rust** (en
vez de WebAssembly a mano). Compila a `wasm32-unknown-unknown` y produce un
`.wasm` listo para `qchain deploy-program` o el panel **Contratos** de QScan.

- `no_std`, sin dependencias (solo `core` + los syscalls del host).
- Wrappers seguros: `balance`, `set_balance`, `is_signer`, `require_signer`,
  `credit`, `debit`, `transfer`, `log`, `abort`, `require!`.
- **Estado estructurado on-chain (v0.2):** `get_data`/`set_data`/`data_len` +
  helpers LE (`read_u64`/`write_i64`/…) para guardar structs en `account.data`.
- Macro `entrypoint!` que exporta el punto de entrada `run` (4 args `i64`).

**Ejemplos listos para compilar:**
- `templates/payments/` — tesorería/pagos con 6 funciones (saldos).
- `templates/counter/` — contador con **estado estructurado** en la cuenta del
  usuario (v0.2).

Compilalos con:

```bash
deploy/build-contract.sh crates/qchain-sdk/templates/payments
deploy/build-contract.sh crates/qchain-sdk/templates/counter
```

Guía completa (modelo de ejecución, convención de llamada, seguridad, API):
[`docs/SMART-CONTRACTS.md`](../../docs/SMART-CONTRACTS.md).

> Se compila **aparte** del workspace principal (targetea wasm32 / `no_std`),
> igual que `qchain-wasm`. Está en el `exclude` del workspace raíz.
