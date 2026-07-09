# qchain — memoria del proyecto

Blockchain L1 propia con **agilidad cuántica** (post-cuántica desde el diseño, no parcheada después). Diseño completo en `ARCHITECTURE.md` (8 secciones: consenso, cripto, estado/storage, ejecución, tokenomics, gobernanza, seguridad, interoperabilidad). Lecciones técnicas acumuladas en `/mnt/skills/user/project-lessons-learned/SKILL.md` — revisar antes de rehacer una decisión ya tomada.

## Estado actual: Fase 1 completa + Fase 2 casi completa (falta solo compresión STARK)

Workspace Rust de 10 crates en `crates/`, 77 tests unitarios pasan, testnet local probado en vivo varias veces, incluyendo una corrida real de **10 validadores** (no simulada) sin errores durante varios minutos: (1) transferencia firmada propagada por consenso a estado idéntico en los tres nodos (fase 1); (2) ciclo completo de gobernanza tier `Registry` — delegar stake, proponer, votar, finalizar, ejecutar — con el registro de algoritmos actualizándose idéntico en los tres nodos sin paso manual; (3) gobernanza tier `Low` — cambiar el fee base y confirmar que una transferencia real subsecuente cobra exactamente la nueva tarifa; (4) benchmark real de throughput (`qchain-cli load-test`): ~186-203 tx/s de convergencia real de punta a punta (envío→gossip→consenso→ejecución) en un lote limpio de 300 transacciones; (5) medición real de tamaño de certificado por número de validadores (n=3→~14KB, n=10→~47KB, n=20→~94KB, n=50→~227KB, escalando linealmente como se esperaba).

De los 6 puntos de fase 2 (`ARCHITECTURE.md` §roadmap), quedan **5 completos**: registro de algoritmos con gobernanza real, ejecución automatizada, gobernanza de parámetros de bajo riesgo, testing de simulación determinista, y expansión/medición del conjunto de validadores + investigación de agregación lattice (conclusión: ningún esquema disponible hoy es adoptable, revisar más adelante). Queda **1 pendiente, deliberadamente diferido**: compresión STARK (Winterfell) — se decidió tratarlo como su propio proyecto con una sesión de diseño dedicada al AIR (arithmetization), no improvisarlo al final de esta sesión ya larga.

| Crate | Qué hace |
|---|---|
| `qchain-crypto` | Firmas híbridas Ed25519 + ML-DSA-65 (liboqs real vía crate `oqs`), registro on-chain de algoritmos para poder migrar sin hard fork |
| `qchain-core` | Tipos: cuenta, transacción, instrucción, vértice/certificado del DAG |
| `qchain-storage` | Árbol Merkle disperso (hash-based, sin Verkle/KZG) con pruebas de inclusión/exclusión |
| `qchain-execution` | VM de contratos (Wasmtime), System Program, `StakingProgram`, `GovernanceProgram`, **`EconomicParams`** on-chain (`params.rs`) leído en vivo por `Ledger` en cada transacción |
| `qchain-governance` | Lógica pura de gobernanza: `RiskTier::Registry` y `RiskTier::Low`, quórum, tally — sin I/O, testeada aislada |
| `qchain-consensus` | Narwhal (DAG) + Bullshark (elección de líder y orden causal), quórum ponderado por stake |
| `qchain-simulation` | **Testing de simulación determinista**: event-loop síncrono con PRNG semillado, inyección de fallos (drop/delay/partición), reutiliza `qchain-consensus` real sin modificar |
| `qchain-network` | Transporte TCP real (framing JSON con prefijo de longitud) |
| `qchain-node` | Binario validador: junta storage+ejecución+consenso+red, expone JSON-RPC, siembra cuentas génesis (registro, stats de staking, parámetros económicos) |
| `qchain-cli` | Wallet CLI: transferencias, staking, gobernanza completa, y `load-test` (benchmark real de red) |

Decisiones cerradas (ver `ARCHITECTURE.md` § "Decisiones cerradas"): 10-20 validadores geodistribuidos en testnet, split de fee 50/50 quema/validadores, auto-quema de polvo, sin puente EVM/Solana en fase 1, estructura legal/distribución de tokens pendiente a propósito.

**Gobernanza — dos niveles de riesgo (`ARCHITECTURE.md` §6):**
- **`Registry`** (alta/baja de algoritmos criptográficos): quórum de participación 20%, supermayoría 2/3, 200 rondas de votación + 100 rondas de time-lock obligatorio antes de ejecutar.
- **`Low`** (parámetros económicos — `base_fee_per_byte`, `dust_threshold`, precio del gas): mayoría simple estricta (50%+1, un empate no pasa), piso de participación 10%, 100 rondas de votación, **sin time-lock** (ejecuta el mismo round que se finaliza).
- Todos placeholders explícitos, ajustables por gobernanza. `Finalize` y `Execute` son permissionless. Direcciones bien conocidas en `qchain-execution::ids`: `STAKING_PROGRAM_ID=[1;32]`, `STAKING_STATS_ID=[2;32]`, `GOVERNANCE_PROGRAM_ID=[3;32]`, `REGISTRY_ACCOUNT_ID=[4;32]`, `PARAMS_ACCOUNT_ID=[5;32]`.

Hallazgos reales corregidos durante fase 2 (detalle en `project-lessons-learned`): (1) `SystemProgram::Transfer` de fase 1 no verificaba que la cuenta origen fuera el `payer` — cualquiera podía firmar una tx propia y vaciar cuentas ajenas; arreglado. (2) "Delegated staking" estaba decidido como parte de fase 1 pero nunca se construyó — se implementó como prerequisito real de gobernanza. (3) Las constantes económicas (`BASE_FEE_PER_BYTE_UNITS` etc.) pasaron de ser `const` de compilación a estado on-chain mutable (`EconomicParams`), con las constantes originales como valor por defecto de respaldo si la cuenta no fue sembrada. (4) Una carga concurrente desde una sola cuenta puede perder transacciones para siempre (mempool sin orden de nonce, sin reintento) — documentado, no arreglado todavía. (5) Un validador honesto firmaba voto para cualquier vértice propuesto sin chequear si ya había votado por uno distinto en la misma (ronda, autor) — vulnerabilidad de equivocación real; arreglado con un candado de voto por (ronda, autor). (6) Una partición de red que sana nunca recuperaba el progreso, porque cada validador transmitía su propuesta de vértice una sola vez; arreglado con reenvío periódico mientras esté pendiente de certificar.

Simplificaciones explícitas de fase 1 (documentadas en el código, no ocultas): sin capa de "workers" separada en Narwhal, sin reintento si un certificado llega antes que su batch, regla de commit de Bullshark solo "directa" (sin fallback indirecto), sin inyección de fallos bizantinos, sin persistencia en disco (todo en memoria). De fase 2 queda pendiente: compresión STARK (Winterfell).

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

Compresión STARK (Winterfell) — el pendiente grande de fase 2, requiere su propia sesión de diseño del AIR. Además: persistencia real (RocksDB en vez de `InMemoryStore`), regla de commit indirecta de Bullshark, capa de workers de Narwhal, puente EVM/Solana (si hay demanda), calibración económica real de fees/dust/gobernanza (los valores actuales son placeholders explícitos, no cifras modeladas), arreglo real del mempool (orden de nonce/reintento de transacciones perdidas), retransmisión de votos individuales y re-sincronización de certificados perdidos (solo se arregló el reenvío de la propuesta de vértice), y expansión del conjunto de validadores más allá de n=50 (validado empíricamente solo hasta ahí).
