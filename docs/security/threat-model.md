# Modelo de amenazas de QChain (QSEP-1 §Puerta 4)

Documento vivo. Cada RFC R2/R3 debe extenderlo con las amenazas específicas de su
cambio. Aquí van las transversales.

## Activos protegidos
QCH (emisión/quema/balances) · reservas y suministro bloqueado · claves privadas
(consenso/operador/retiro/tesorería) · estado de consenso (no-fork) ·
disponibilidad de la red · identidad de validadores · propuestas de gobernanza ·
fondos de tesorería · recompensas de staking · integridad de las actualizaciones.

## Límites de confianza
wallet ↔ nodo · RPC ↔ internet · nodo ↔ P2P · runtime ↔ WASM · nodo ↔ firmante
remoto · software ↔ SO · CI ↔ artefactos publicados · versión nueva ↔ estado
antiguo.

## Capacidades de atacante consideradas
Sin claves · con una wallet válida · que controla un nodo · que controla un
validador · con una clave de tesorería · con acceso parcial a CI · dependencia
comprometida · respaldo de wallet malicioso · contrato WASM malicioso · estado
histórico manipulado en disco.

## Amenazas transversales y sus mitigaciones (evidencia)

| Amenaza | Mitigación en el repo |
|---|---|
| Falsificar identidad / sustituir cuenta | Validación de dirección canónica + propietario + firmante (gate WASM #117, gate de gobernanza, pin de singletons). |
| Acuñar/robar valor vía contrato (aliasing) | Borde del ledger: conservación + débito autorizado + rechazo de cuentas duplicadas (#117, v2.0.4). |
| Overflow monetario | Módulo `arith` (`checked_*`) + `overflow-checks=true` (#218). |
| Replay entre redes | `chain_id` en el `Message` firmado. |
| Reuso de firma en otro contexto | Dominios etiquetados `TX_SIG_V1`/`VERTEX_VOTE_V1`/`VALIDATOR_POP_V1` (#187, #20). |
| Doble ejecución (tesorería/gobernanza) | Umbral + nonce + timelock + estado; op vinculada criptográficamente. |
| Fork por no-determinismo | DST (`qchain-simulation`), sin reloj/RNG/orden-de-mapa/float no controlado; `nan_canonicalization` (#195). |
| Estado corrupto / versión desconocida | Fail-loud (#217), `decode_registry`→halt, migración tolerante `read_or_legacy`. |
| Migración que destruye estado | Estructuras históricas preservadas + `read_or_legacy` + `qchain-migrate-registry` con backup/rollback (#3/#20). |
| Estado parcial ante error | Commit atómico (#207). |
| Agotamiento de recursos (DoS) | Límites formales (#18), rate-limit RPC/P2P (#196/#208/#210), fuzzing (#14). |
| Fuga de clave de consenso | Separación de roles + rotación/revocación/expiración (#193/#20); firmante remoto con allowlist (#193-A). |
| Withholding de data-availability | Voto exige disponibilidad del batch (#175). |
| Dependencia comprometida | `Cargo.lock` + `--locked` + liboqs vendorizado + `cargo audit` + SBOM (#198/#219). |
| Respaldo de wallet malicioso | Confirmación re-decodificada, semillas débiles rechazadas, cifrado Argon2id (#12/#13/#197). |

## Riesgos residuales / gates humanos
Auditoría externa + bug bounty público + revisión humana independiente + branch
protection son gates del operador (ver `README.md` de esta carpeta, `SECURITY.md`,
`PRE-LAUNCH.md`). La verificación multi-nodo EN VIVO de la rotación de claves (#20)
es el gate recomendado antes de usarla en una red de varios validadores.
