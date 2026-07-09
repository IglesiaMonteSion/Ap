# qchain — memoria del proyecto

Blockchain L1 propia con **agilidad cuántica** (post-cuántica desde el diseño, no parcheada después). Diseño completo en `ARCHITECTURE.md` (8 secciones: consenso, cripto, estado/storage, ejecución, tokenomics, gobernanza, seguridad, interoperabilidad). Lecciones técnicas acumuladas en `/mnt/skills/user/project-lessons-learned/SKILL.md` — revisar antes de rehacer una decisión ya tomada.

## Estado actual: Fase 1 completa (testnet local funcionando de verdad)

Workspace Rust de 8 crates en `crates/`, los 40 tests unitarios pasan, y se probó en vivo un testnet local de 3 validadores (procesos reales, TCP real, firmas PQC reales) donde una transferencia firmada se propagó por consenso y llegó a estado idéntico en los tres nodos.

| Crate | Qué hace |
|---|---|
| `qchain-crypto` | Firmas híbridas Ed25519 + ML-DSA-65 (liboqs real vía crate `oqs`), registro on-chain de algoritmos para poder migrar sin hard fork |
| `qchain-core` | Tipos: cuenta, transacción, instrucción, vértice/certificado del DAG |
| `qchain-storage` | Árbol Merkle disperso (hash-based, sin Verkle/KZG) con pruebas de inclusión/exclusión |
| `qchain-execution` | VM de contratos con Wasmtime (gas por "fuel"), System Program nativo, lógica de fees (50% quema / 50% validadores) y auto-quema de "polvo" (dust) |
| `qchain-consensus` | Narwhal (DAG) + Bullshark (elección de líder y orden causal), quórum ponderado por stake |
| `qchain-network` | Transporte TCP real (framing JSON con prefijo de longitud) |
| `qchain-node` | Binario validador: junta storage+ejecución+consenso+red, expone JSON-RPC |
| `qchain-cli` | Wallet de línea de comandos: `keygen`, `bundle`, `address`, `balance`, `transfer` |

Decisiones cerradas (ver `ARCHITECTURE.md` § "Decisiones cerradas"): 10-20 validadores geodistribuidos en testnet, split de fee 50/50 quema/validadores, auto-quema de polvo, sin puente EVM/Solana en fase 1, estructura legal/distribución de tokens pendiente a propósito.

Simplificaciones explícitas de fase 1 (documentadas en el código, no ocultas): sin capa de "workers" separada en Narwhal, sin reintento si un certificado llega antes que su batch, regla de commit de Bullshark solo "directa" (sin fallback indirecto), sin inyección de fallos bizantinos, sin persistencia en disco (todo en memoria).

## Cómo levantar el testnet local

1. `cargo build --workspace`
2. Generar keypairs: `qchain keygen --out v1.json` (repetir para cada validador + wallets)
3. Sacar el bundle de cada validador: `qchain bundle --keypair v1.json` → pegar en `validators` del config JSON de cada nodo
4. Escribir un `nodeN.json` por validador (ver `crates/qchain-node/src/config.rs` para el formato exacto: `keypair_path`, `listen_addr`, `rpc_addr`, `validators[]`, `genesis[]`, `round_interval_ms`)
5. Levantar cada nodo: `qchain-node --config nodeN.json`
6. Transferir: `qchain transfer --rpc http://127.0.0.1:<rpc_port> --keypair alice.json --to <dirección> --amount <u64>`
7. Verificar convergencia: `qchain balance --rpc http://127.0.0.1:<rpc_port_de_cada_nodo> <dirección>` debería dar el mismo resultado en los tres nodos

## Próximos pasos pendientes (no empezados)

Persistencia real (RocksDB en vez de `InMemoryStore`), tolerancia a fallos bizantinos con inyección de adversarios, regla de commit indirecta de Bullshark, capa de workers de Narwhal, gobernanza on-chain ejecutable, puente EVM/Solana (si hay demanda), calibración económica real de fees/dust (los valores actuales son placeholders explícitos, no cifras modeladas).
