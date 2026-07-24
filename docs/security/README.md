# Seguridad de QChain — índice y mapa de cumplimiento QSEP-1

El protocolo obligatorio es [`QSEP-1.md`](./QSEP-1.md). El instructivo para
agentes de IA es [`/AGENTS.md`](../../AGENTS.md). Este archivo mapea cada
requisito de QSEP-1 a lo que YA existe en el repo, honestamente marcado
**hecho / parcial / gap**, para no fingir cumplimiento.

## Documentos de seguridad existentes

| Tema | Documento |
|---|---|
| Invariantes (ejecutables) | [`../INVARIANTS.md`](../INVARIANTS.md) + `crates/qchain-execution/src/invariants_v7.rs`, `invariants.rs` |
| Límites de recursos | [`../RESOURCE-LIMITS.md`](../RESOURCE-LIMITS.md) |
| Esquema/versionado de singletons | [`../SCHEMA-VERSIONS.md`](../SCHEMA-VERSIONS.md) |
| Roles de clave del validador | [`../KEY-ROLES.md`](../KEY-ROLES.md) |
| Tesorería multisig | [`../TREASURY-MULTISIG.md`](../TREASURY-MULTISIG.md) |
| Endurecimiento de la wallet | [`../WALLET-HARDENING.md`](../WALLET-HARDENING.md) |
| Seguridad de contratos | [`../CONTRACT-SECURITY.md`](../CONTRACT-SECURITY.md) |
| Fuzzing | [`../FUZZING.md`](../FUZZING.md) |
| Recuperación / runbook | [`../RECOVERY-PLAN.md`](../RECOVERY-PLAN.md) |
| Verificación de release | [`../RELEASE-VERIFY.md`](../RELEASE-VERIFY.md) |
| Builds reproducibles | [`../REPRODUCIBLE-BUILDS.md`](../REPRODUCIBLE-BUILDS.md) |
| Manifiesto de génesis | [`../GENESIS-MANIFEST.md`](../GENESIS-MANIFEST.md) |
| Política de bug bounty | [`/SECURITY.md`](../../SECURITY.md) |
| Revisión IA en PRs / runtime | [`../AI-SECURITY-REVIEW.md`](../AI-SECURITY-REVIEW.md), [`../AI-RUNTIME-WATCHDOG.md`](../AI-RUNTIME-WATCHDOG.md) |
| Programa de gestión de claves (KM #1–#10, **COMPLETO**) | [`key-management-program.md`](./key-management-program.md) + harness adversarial `deploy/km-lifecycle-test.sh` |
| Memoria de clases de error (EC-01…EC-17) | [`LESSONS-LEDGER.md`](./LESSONS-LEDGER.md) + `deploy/qsep-sweep.sh` |
| Modelo de amenazas | [`threat-model.md`](./threat-model.md) |
| Supuestos de seguridad | [`security-assumptions.md`](./security-assumptions.md) |
| Respuesta a incidentes | [`incident-response.md`](./incident-response.md) |

## Mapa de cumplimiento (honesto)

| QSEP-1 | Estado | Evidencia / gap |
|---|---|---|
| §4.1 No programar primero (investigación) | **hecho (informal)** | Práctica documentada en `CLAUDE.md` (tmkms, EIP-1559, Cosmos state-sync, verificar API real de winterfell/oqs). Formalizado ahora por QSEP-1. |
| §4.2 No confiar en el camino feliz | **hecho** | Tests de ataque reales + auditorías multi-agente por incremento. |
| §4.3 No inventar criptografía | **hecho** | Ed25519+ML-DSA-65 (liboqs), SLH-DSA, ML-KEM, SHA3 — todas primitivas estándar; sin cripto propia salvo la separación de dominios (documentada, con vectores). |
| §4.4 Seguridad no depende de la interfaz | **hecho** | El nodo revalida (p.ej. #117 borde WASM, admisión RPC, gate de gobernanza). |
| §4.5 Todo dato externo es hostil | **hecho** | Fuzzing 6 superficies (#14), `read_or_legacy`, verify PQC fail-closed. |
| §4.6 Fallar seguro | **hecho** | Fail-loud singletons (#217), rechazo de versión desconocida (`decode_registry`→halt), atomicidad (#207). |
| §Puerta 3 Invariantes | **hecho** | `docs/INVARIANTS.md` + módulos `invariants*`. |
| §Puerta 4 Modelo de amenazas | **parcial** | Auditorías repetidas, pero faltaba doc formal → creado `threat-model.md`. |
| §Puerta 5 Migración versionada | **hecho** | `read_or_legacy`, `decode_registry` V3→V2→V1, schema manifest #19, `qchain-migrate-registry`. |
| §Puerta 6 Plan de pruebas (negativas/fuzz/diferencial/reinicio) | **hecho** | Extenso; `docs/FUZZING.md`, DST diferencial, tests de reinicio. |
| §7.2 Aritmética comprobada | **hecho** | Módulo `arith` (#218), `overflow-checks=true`. |
| §7.3 Límites de recursos | **hecho** | #18, `RESOURCE-LIMITS.md`. |
| §7.5 Determinismo | **hecho** | DST (`qchain-simulation`), plegado en `chain_id`, `nan_canonicalization` (#195). |
| §7.6 Serialización versionada/canónica | **hecho** | borsh canónico + fuzz + `SCHEMA-VERSIONS.md`. |
| §7.7 Dominio de firmas | **hecho** | #187 (`TX_SIG_V1`/`VERTEX_VOTE_V1`/`VALIDATOR_POP_V1`). |
| §13 Causa raíz + barrido de la clase | **hecho** | Lección recurrente documentada. |
| §10 CI: clippy `-D`, test, audit, SBOM, fuzz, reproducible | **hecho** | `.github/workflows/ci.yml`. |
| §10 CI: `cargo fmt --all --check` | **GAP** | El repo nunca enforzó rustfmt (documentado en `PERFORMANCE-BASELINE.md`); habilitarlo requiere un `cargo fmt` de ~68 archivos como cambio propio con OK del operador. |
| §10 CI: `cargo deny check` | **parcial** | Existe `cargo audit`. Se agregó [`/deny.toml`](../../deny.toml); habilitar el job de CI requiere una primera corrida de triage (licencias). |
| §10 `cargo miri` / `llvm-cov` | **GAP acotado** | miri/sanitizers no corren sobre el C de liboqs → acotados a crates puros (core/storage/stark), igual que los sanitizers de #219. |
| §9 Dos revisores / uno de seguridad / autor ≠ único aprobador | **GAP humano** | Estructural en un repo de mantenedor único + IA. Responsabilidad del operador (branch protection: `RELEASE-VERIFY.md`). |
| §12 RC congelada + testnet + activación gradual + auditoría externa | **parcial/humano** | Deploy + reversión documentados por incremento; RC congelada, auditoría externa y bug bounty público son gates del operador (`SECURITY.md`, `PRE-LAUNCH.md`). |

## Qué falta habilitar (acción del operador)

1. **`cargo fmt`** una vez + agregar `cargo fmt --all -- --check` al CI (diff grande, cambio propio).
2. **`cargo deny check`** al CI tras triage inicial de licencias con `deny.toml`.
3. **Branch protection** + revisión obligatoria + required status checks (ver `RELEASE-VERIFY.md`).
4. **Auditoría externa + bug bounty público** antes de valor real (`SECURITY.md`, `PRE-LAUNCH.md`).
