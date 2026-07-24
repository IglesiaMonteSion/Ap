# Fuzzing + property testing de qchain — cobertura del borde de deserialización

**Objetivo (roadmap #14):** ningún byte ARBITRARIO que un atacante controla —
del wire P2P, de un certificado/vértice, de un snapshot de state-sync, de una
propuesta de gobernanza, de bytecode/instrucciones WASM, o del cuerpo de una
petición RPC — debe **panicar, colgar (loop/OOM), ni corromper** el nodo al
deserializarse. Un deserializador robusto devuelve `Err`/`None` sobre basura,
nunca rompe.

Dos herramientas complementarias, cada una con su rol:

| Herramienta | Corre en | Qué aporta |
|---|---|---|
| **proptest** ("arbitrary bytes never panic") | **cada CI** (stable, `cargo test`) | cobertura amplia por-commit sobre inputs generados, en el crate dueño de cada tipo — la red de seguridad continua |
| **cargo-fuzz** (libFuzzer, coverage-guided) | nightly / `workflow_dispatch` (nightly + `cargo-fuzz`) | profundidad coverage-guided sobre los mismos tipos — encuentra caminos que un generador aleatorio no |

Las dos usan **exactamente las mismas llamadas de decodificación** (`borsh::from_slice`,
`serde_json::from_slice`, `read_or_legacy`, `decode_registry`, `try_from_slice`),
así que un property test verde es prueba de que el target de fuzz correspondiente
compila y decodifica el mismo tipo.

## Las 6 superficies cubiertas

| # | Superficie | Tipo(s) / decodificador | Property test (crate) | cargo-fuzz target |
|---|---|---|---|---|
| 1 | **P2P** | `Envelope`, `NetMessage` (Borsh); frames de handshake `HandshakeInit/Resp/Final` (Borsh, pre-auth) | `qchain-network::message::fuzz_proptests`, `::handshake::fuzz_proptests` | `network_envelope_deserialize` |
| 2 | **certs / DAG** | `Batch`, `Vertex`, `Certificate` (Borsh) + `verify_certificate` | `qchain-core::dag::fuzz_proptests`, `qchain-consensus::fuzz_proptests` | (vía `transaction_deserialize` + property) |
| 3 | **snapshots** | `SnapshotMeta`, `SnapshotPage`, `SnapshotAccount`, `StateSnapshot` (JSON) | `qchain-node::engine::fuzz_proptests` | (property; JSON no es libFuzzer-friendly) |
| 4 | **gobernanza** | `Proposal`, `ProposalAction`, `VoteChoice`, `RiskTier` (Borsh); `GovernanceInstruction` | `qchain-governance::fuzz_proptests`, `qchain-execution::fuzz_proptests` | `governance_proposal_deserialize` |
| 5 | **WASM + decodificadores on-chain** | `WasmProgramData`, `decode_registry`, `EconomicParams/FeeState/StakeAccountData::read_or_legacy`, `Staking/Validator/Treasury*Instruction`, `TreasuryState`, `GlobalStakingState`, `StakePositionV7`, `ValidatorV7Registry` | `qchain-execution::fuzz_proptests` | `execution_decoders` |
| 6 | **RPC** | `Transaction` (JSON, cuerpo de `/tx` y `/simulate`) | `qchain-node::engine::fuzz_proptests` + `qchain-core` | `transaction_deserialize` |

## Cómo correrlo

**Property tests (parte de la suite normal, en cada CI):**
```
cargo test --workspace          # incluye todos los `fuzz_proptests`
cargo test -p qchain-execution fuzz_proptests   # sólo una superficie
```

**cargo-fuzz (coverage-guided, nightly/manual):**
```
cargo install cargo-fuzz                       # una vez
cd fuzz
cargo +nightly fuzz run network_envelope_deserialize -- -max_total_time=120
cargo +nightly fuzz run governance_proposal_deserialize -- -max_total_time=120
cargo +nightly fuzz run execution_decoders -- -max_total_time=120
cargo +nightly fuzz run transaction_deserialize -- -max_total_time=120
cargo +nightly fuzz run message_deserialize -- -max_total_time=120
```
El crate `fuzz/` está EXCLUIDO del workspace y necesita **nightly + libFuzzer**.
El job `fuzz` de `.github/workflows/ci.yml` corre los 5 targets 120s cada uno de
noche o a demanda (coverage-guided es caro para cada push). Un crash deja un
artefacto reproducible que tumba el job.

## Sanitizers (ASan / UBSan)

El job `sanitizers` corre los tests bajo AddressSanitizer + UndefinedBehaviorSanitizer
sobre los crates de deserialización **PUROS-Rust** (`qchain-core`, `qchain-storage`,
`qchain-stark`). **Límite honesto:** un sanitizer sobre el workspace COMPLETO
tropieza con el **liboqs en C** (las firmas PQC) — todos los demás crates
(`qchain-network/consensus/governance/execution/node`) linkean qchain-crypto →
liboqs en su path de test, cuyo análisis de canal lateral / memory-safety del C
es un proceso externo aparte (#185). Por eso los **property tests de proptest**
(que NO necesitan sanitizer y corren en cada CI) son la cobertura cross-crate de
esas 5 superficies, y ASan queda acotado a los 3 crates sin liboqs.

## Límites honestos

- No hay nightly ni `cargo-fuzz` en el sandbox de desarrollo → los targets de
  cargo-fuzz se corren en CI; su corrección se verifica en sesión por los property
  tests (mismas llamadas de decodificación, verdes en stable).
- Los snapshots y el RPC usan JSON (serde), no un target libFuzzer dedicado (JSON
  arbitrario es menos útil para libFuzzer que Borsh) — su cobertura es el property
  test, que sí ejercita `serde_json::from_slice` sobre bytes arbitrarios.
- El fuzzing prueba **robustez** (no panic/OOM/corrupción del deserializador), NO
  correctitud semántica — esa la cubren los tests unitarios/DST/invariantes.
