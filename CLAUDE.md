# qchain — memoria del proyecto

Blockchain L1 propia con **agilidad cuántica** (post-cuántica desde el diseño, no parcheada después). Diseño completo en `ARCHITECTURE.md` (8 secciones: consenso, cripto, estado/storage, ejecución, tokenomics, gobernanza, seguridad, interoperabilidad). Lecciones técnicas acumuladas en `/mnt/skills/user/project-lessons-learned/SKILL.md` — revisar antes de rehacer una decisión ya tomada.

## Estado actual: Fase 1 completa + primer incremento de Fase 2 (gobernanza real)

Workspace Rust de 9 crates en `crates/`, 58 tests unitarios pasan, testnet local de 3 validadores probado en vivo dos veces: (1) transferencia firmada propagada por consenso a estado idéntico en los tres nodos (fase 1), y (2) ciclo completo de gobernanza — delegar stake, proponer, votar, finalizar, ejecutar — con el registro de algoritmos actualizándose de forma idéntica en los tres nodos sin ningún paso manual (fase 2).

| Crate | Qué hace |
|---|---|
| `qchain-crypto` | Firmas híbridas Ed25519 + ML-DSA-65 (liboqs real vía crate `oqs`), registro on-chain de algoritmos para poder migrar sin hard fork |
| `qchain-core` | Tipos: cuenta, transacción, instrucción, vértice/certificado del DAG |
| `qchain-storage` | Árbol Merkle disperso (hash-based, sin Verkle/KZG) con pruebas de inclusión/exclusión |
| `qchain-execution` | VM de contratos (Wasmtime), System Program, **StakingProgram** (delegar/undelegar), **GovernanceProgram** (proponer/votar/finalizar/ejecutar), fees (50% quema/validadores) y auto-quema de "polvo" |
| `qchain-governance` | Lógica pura de gobernanza: umbrales por nivel de riesgo, quórum, tally — sin I/O, testeada aislada |
| `qchain-consensus` | Narwhal (DAG) + Bullshark (elección de líder y orden causal), quórum ponderado por stake |
| `qchain-network` | Transporte TCP real (framing JSON con prefijo de longitud) |
| `qchain-node` | Binario validador: junta storage+ejecución+consenso+red, expone JSON-RPC, siembra cuentas génesis (registro, stats de staking) |
| `qchain-cli` | Wallet CLI: `keygen`, `bundle`, `address`, `balance`, `transfer`, `stake-delegate`, `stake-undelegate`, `propose-activate/deprecate/retire`, `vote`, `finalize`, `execute-proposal`, `registry`, `proposal-status` |

Decisiones cerradas (ver `ARCHITECTURE.md` § "Decisiones cerradas"): 10-20 validadores geodistribuidos en testnet, split de fee 50/50 quema/validadores, auto-quema de polvo, sin puente EVM/Solana en fase 1, estructura legal/distribución de tokens pendiente a propósito.

**Gobernanza (nuevo, fase 2):** votación ponderada por stake real (no la lista fija de validadores de consenso). Nivel de riesgo `Registry` (alta/baja de algoritmos): quórum de participación 20%, supermayoría 2/3, 200 rondas de votación + 100 rondas de time-lock obligatorio antes de poder ejecutar — todos placeholders explícitos, ajustables por gobernanza. `Finalize` y `Execute` son permissionless (cualquiera puede llamarlos una vez se cumplen las condiciones de ronda). Direcciones bien conocidas en `qchain-execution::ids` (`STAKING_PROGRAM_ID=[1;32]`, `STAKING_STATS_ID=[2;32]`, `GOVERNANCE_PROGRAM_ID=[3;32]`, `REGISTRY_ACCOUNT_ID=[4;32]`).

Dos hallazgos reales corregidos durante fase 2 (detalle en `project-lessons-learned`): (1) `SystemProgram::Transfer` de fase 1 no verificaba que la cuenta origen fuera el `payer` — cualquiera podía firmar una tx propia y vaciar cuentas ajenas; arreglado. (2) "Delegated staking" estaba decidido como parte de fase 1 pero nunca se construyó — se implementó ahora como prerequisito real de gobernanza, no como scope nuevo de fase 2 disfrazado.

Simplificaciones explícitas de fase 1 (documentadas en el código, no ocultas): sin capa de "workers" separada en Narwhal, sin reintento si un certificado llega antes que su batch, regla de commit de Bullshark solo "directa" (sin fallback indirecto), sin inyección de fallos bizantinos, sin persistencia en disco (todo en memoria). De fase 2 quedan pendientes: compresión STARK (Winterfell), testing de simulación determinista, expansión del conjunto de validadores, investigación de agregación lattice-based, y gobernanza de parámetros de bajo riesgo (fee curve — requiere primero convertir esas constantes en estado on-chain).

## Cómo levantar el testnet local

1. `cargo build --workspace`
2. Generar keypairs: `qchain keygen --out v1.json` (repetir para cada validador + wallets)
3. Sacar el bundle de cada validador: `qchain bundle --keypair v1.json` → pegar en `validators` del config JSON de cada nodo
4. Escribir un `nodeN.json` por validador (ver `crates/qchain-node/src/config.rs` para el formato exacto: `keypair_path`, `listen_addr`, `rpc_addr`, `validators[]`, `genesis[]`, `round_interval_ms`)
5. Levantar cada nodo: `qchain-node --config nodeN.json`
6. Transferir: `qchain transfer --rpc http://127.0.0.1:<rpc_port> --keypair alice.json --to <dirección> --amount <u64>`
7. Delegar stake: `qchain stake-delegate --rpc <url> --keypair alice.json --validator <dirección> --amount <u64>` (imprime la dirección de la cuenta de stake — guardarla)
8. Proponer: `qchain propose-activate/propose-deprecate/propose-retire --rpc <url> --keypair alice.json ...` (imprime la dirección de la propuesta)
9. Votar: `qchain vote --rpc <url> --keypair alice.json --proposal <dirección> --stake-account <dirección> --choice yes|no|abstain`
10. Esperar a que pase `voting_ends_round`, luego `qchain finalize`; esperar el time-lock, luego `qchain execute-proposal`
11. Verificar convergencia: `qchain balance` / `qchain registry` / `qchain proposal-status` contra el puerto RPC de cada nodo debería dar el mismo resultado en los tres

## Próximos pasos pendientes (no empezados)

Persistencia real (RocksDB en vez de `InMemoryStore`), tolerancia a fallos bizantinos con inyección de adversarios, regla de commit indirecta de Bullshark, capa de workers de Narwhal, compresión STARK (Winterfell), testing de simulación determinista, expansión del conjunto de validadores, gobernanza de parámetros de bajo riesgo, puente EVM/Solana (si hay demanda), calibración económica real de fees/dust/gobernanza (los valores actuales son placeholders explícitos, no cifras modeladas).
