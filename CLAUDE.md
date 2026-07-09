# qchain — memoria del proyecto

Blockchain L1 propia con **agilidad cuántica** (post-cuántica desde el diseño, no parcheada después). Diseño completo en `ARCHITECTURE.md` (8 secciones: consenso, cripto, estado/storage, ejecución, tokenomics, gobernanza, seguridad, interoperabilidad). Lecciones técnicas acumuladas en `/mnt/skills/user/project-lessons-learned/SKILL.md` — revisar antes de rehacer una decisión ya tomada.

## Estado actual: Fase 1 completa + Fase 2 con gobernanza real (dos niveles de riesgo)

Workspace Rust de 9 crates en `crates/`, 66 tests unitarios pasan, testnet local de 3 validadores probado en vivo tres veces: (1) transferencia firmada propagada por consenso a estado idéntico en los tres nodos (fase 1); (2) ciclo completo de gobernanza tier `Registry` — delegar stake, proponer, votar, finalizar, ejecutar — con el registro de algoritmos actualizándose idéntico en los tres nodos sin paso manual; (3) gobernanza tier `Low` — cambiar el fee base y confirmar que una transferencia real subsecuente cobra exactamente la nueva tarifa, convergiendo en los tres nodos.

| Crate | Qué hace |
|---|---|
| `qchain-crypto` | Firmas híbridas Ed25519 + ML-DSA-65 (liboqs real vía crate `oqs`), registro on-chain de algoritmos para poder migrar sin hard fork |
| `qchain-core` | Tipos: cuenta, transacción, instrucción, vértice/certificado del DAG |
| `qchain-storage` | Árbol Merkle disperso (hash-based, sin Verkle/KZG) con pruebas de inclusión/exclusión |
| `qchain-execution` | VM de contratos (Wasmtime), System Program, `StakingProgram`, `GovernanceProgram`, **`EconomicParams`** on-chain (`params.rs`) leído en vivo por `Ledger` en cada transacción |
| `qchain-governance` | Lógica pura de gobernanza: `RiskTier::Registry` y `RiskTier::Low`, quórum, tally — sin I/O, testeada aislada |
| `qchain-consensus` | Narwhal (DAG) + Bullshark (elección de líder y orden causal), quórum ponderado por stake |
| `qchain-network` | Transporte TCP real (framing JSON con prefijo de longitud) |
| `qchain-node` | Binario validador: junta storage+ejecución+consenso+red, expone JSON-RPC, siembra cuentas génesis (registro, stats de staking, parámetros económicos) |
| `qchain-cli` | Wallet CLI: transferencias, staking, y gobernanza completa (ver comandos abajo) |

Decisiones cerradas (ver `ARCHITECTURE.md` § "Decisiones cerradas"): 10-20 validadores geodistribuidos en testnet, split de fee 50/50 quema/validadores, auto-quema de polvo, sin puente EVM/Solana en fase 1, estructura legal/distribución de tokens pendiente a propósito.

**Gobernanza — dos niveles de riesgo (`ARCHITECTURE.md` §6):**
- **`Registry`** (alta/baja de algoritmos criptográficos): quórum de participación 20%, supermayoría 2/3, 200 rondas de votación + 100 rondas de time-lock obligatorio antes de ejecutar.
- **`Low`** (parámetros económicos — `base_fee_per_byte`, `dust_threshold`, precio del gas): mayoría simple estricta (50%+1, un empate no pasa), piso de participación 10%, 100 rondas de votación, **sin time-lock** (ejecuta el mismo round que se finaliza).
- Todos placeholders explícitos, ajustables por gobernanza. `Finalize` y `Execute` son permissionless. Direcciones bien conocidas en `qchain-execution::ids`: `STAKING_PROGRAM_ID=[1;32]`, `STAKING_STATS_ID=[2;32]`, `GOVERNANCE_PROGRAM_ID=[3;32]`, `REGISTRY_ACCOUNT_ID=[4;32]`, `PARAMS_ACCOUNT_ID=[5;32]`.

Hallazgos reales corregidos durante fase 2 (detalle en `project-lessons-learned`): (1) `SystemProgram::Transfer` de fase 1 no verificaba que la cuenta origen fuera el `payer` — cualquiera podía firmar una tx propia y vaciar cuentas ajenas; arreglado. (2) "Delegated staking" estaba decidido como parte de fase 1 pero nunca se construyó — se implementó como prerequisito real de gobernanza. (3) Las constantes económicas (`BASE_FEE_PER_BYTE_UNITS` etc.) pasaron de ser `const` de compilación a estado on-chain mutable (`EconomicParams`), con las constantes originales como valor por defecto de respaldo si la cuenta no fue sembrada.

Simplificaciones explícitas de fase 1 (documentadas en el código, no ocultas): sin capa de "workers" separada en Narwhal, sin reintento si un certificado llega antes que su batch, regla de commit de Bullshark solo "directa" (sin fallback indirecto), sin inyección de fallos bizantinos, sin persistencia en disco (todo en memoria). De fase 2 quedan pendientes: compresión STARK (Winterfell), testing de simulación determinista, expansión del conjunto de validadores, investigación de agregación lattice-based.

## Cómo levantar el testnet local

1. `cargo build --workspace`
2. Generar keypairs: `qchain keygen --out v1.json` (repetir para cada validador + wallets)
3. Sacar el bundle de cada validador: `qchain bundle --keypair v1.json` → pegar en `validators` del config JSON de cada nodo
4. Escribir un `nodeN.json` por validador (ver `crates/qchain-node/src/config.rs` para el formato exacto)
5. Levantar cada nodo: `qchain-node --config nodeN.json`
6. Transferir: `qchain transfer --rpc http://127.0.0.1:<rpc_port> --keypair alice.json --to <dirección> --amount <u64>`
7. Delegar stake: `qchain stake-delegate --rpc <url> --keypair alice.json --validator <dirección> --amount <u64>` (imprime la dirección de la cuenta de stake — guardarla)
8. Proponer — tier `Registry`: `qchain propose-activate/propose-deprecate/propose-retire ...`; tier `Low`: `qchain propose-set-base-fee/propose-set-dust-threshold/propose-set-gas-price --value <u64> ...` (imprime la dirección de la propuesta)
9. Votar: `qchain vote --rpc <url> --keypair alice.json --proposal <dirección> --stake-account <dirección> --choice yes|no|abstain`
10. Esperar a que pase `voting_ends_round`, luego `qchain finalize`; si es tier `Registry` esperar el time-lock, si es `Low` ya se puede ejecutar en el momento; luego `qchain execute-proposal` (detecta solo la cuenta destino correcta)
11. Verificar convergencia: `qchain balance` / `qchain registry` / `qchain params` / `qchain proposal-status` contra el puerto RPC de cada nodo debería dar el mismo resultado en los tres

## Próximos pasos pendientes (no empezados)

Persistencia real (RocksDB en vez de `InMemoryStore`), tolerancia a fallos bizantinos con inyección de adversarios, regla de commit indirecta de Bullshark, capa de workers de Narwhal, compresión STARK (Winterfell), testing de simulación determinista, expansión del conjunto de validadores, investigación de agregación lattice-based, puente EVM/Solana (si hay demanda), calibración económica real de fees/dust/gobernanza (los valores actuales son placeholders explícitos, no cifras modeladas).
