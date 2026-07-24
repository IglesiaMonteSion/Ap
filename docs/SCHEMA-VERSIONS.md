# Versiones de esquema explícitas de los singletons (tarea #19)

> **Qué cierra.** Antes de #19 el formato on-disk de cada singleton crítico se
> recuperaba por *trial-Borsh*: cada decodificador (`EconomicParams::read_or_legacy`,
> `FeeState::read_or_legacy`, `decode_registry`, …) probaba el layout actual y, ante
> EOF, caía a uno más viejo. Funciona, pero el esquema quedaba **implícito y disperso**
> — no había un lugar único que declarara "el singleton X es esquema versión N", y sólo
> el registro de validadores (tarea #3) tenía una API de primera clase
> (`RegistrySchema`/`detect_registry_schema`/`.version()`). #19 **generaliza ese patrón
> a TODOS los singletons**: una tabla canónica (`Singleton`), detección explícita por
> singleton (`detect_version`), y un **manifiesto de esquema on-chain** (`SchemaManifest`)
> que un nodo verifica al arrancar en vez de confiar en que un decode de Borsh signifique
> el formato correcto. Es el "paso coordinado que persiste el byte de versión" que la
> tarea #3 dejó marcado como roadmap #19.

## Qué significa una "versión de esquema" acá

Una versión sube ante un **cambio de layout NO-append** — un layout de bytes
genuinamente distinto. Agregar campos opcionales al final (lo que hacen las
migraciones `read_or_legacy` — el campo de emisión de `EconomicParams`, los tiers de
tesorería de #17, …) es **compatible hacia atrás DENTRO de la misma versión de esquema**,
porque un blob viejo es un byte-prefijo del nuevo. Por eso hoy casi todos los singletons
son esquema **v1**; sólo los dos que tuvieron un cambio de layout real son **v2**.

## Tabla canónica

Fuente única de verdad: `qchain_execution::schema::Singleton`. `tag` es la clave estable
en el manifiesto on-chain (nunca cambia; una subida de versión cambia el *valor*, no el tag).

| tag | singleton | id | struct | versión actual | decodificador |
|---|---|---|---|---|---|
| 1 | `economic_params` | `PARAMS_ACCOUNT_ID` `[5]` | `EconomicParams` | **1** | `read_or_legacy` (append-tolerante) |
| 2 | `fee_state` | `FEE_STATE_ACCOUNT_ID` `[8]` | `FeeState` | **1** | `read_or_legacy` |
| 3 | `crypto_registry` | `REGISTRY_ACCOUNT_ID` `[4]` | `Vec<RegistryEntry>` | **1** | `try_from_slice` |
| 4 | `validator_registry` | `VALIDATOR_REGISTRY_ACCOUNT_ID` `[9]` | `ValidatorV7Registry` | **2** | `detect_registry_schema` (v1 legacy / v2 actual) |
| 5 | `staking_global` | `STAKING_GLOBAL_ID` `[15]` | `GlobalStakingState` | **1** | `try_from_slice` |
| 6 | `staking_stats` | `STAKING_STATS_ID` `[2]` | `u64` | **1** | `try_from_slice` |
| 7 | `staking_rewards_pool` | `STAKING_REWARDS_POOL_ID` `[6]` | `RewardPoolData` | **1** | `try_from_slice` |
| 8 | `treasury` | `TREASURY_ACCOUNT_ID` `[18]` | `TreasuryState` | **2** | `read_or_legacy` (v2 multisig) / 32-byte authority (v1 legacy) |
| 9 | `emergency` | `EMERGENCY_ACCOUNT_ID` `[19]` | `EmergencyState` | **1** | `try_from_slice` |

Los **dos v2** son los únicos con un cambio de layout genuino:
- **`validator_registry`**: separación de roles de clave (v6.19.0, tarea #3) — v1 legacy
  migra a v2 en lectura.
- **`treasury`**: autoridad única (32 bytes) → multisig M-de-N (v8.4.0, tarea #222) — el
  blob legacy de 32 bytes se levanta como 1-de-1.

Las **pools de sólo-balance** (reserve, fee pool, escrows, emission reserve, admin wallet)
se excluyen a propósito: no guardan `data` codificada, sólo un `balance`, así que no hay
esquema que versionar.

## `detect_version` — detección explícita

`Singleton::detect_version(&data) -> Option<u16>` reporta la versión EXPLÍCITA de los bytes,
o `None` si no matchean ninguna versión conocida (genuinamente corrupto → el llamador
debe fallar-fuerte, nunca adivinar). Generaliza `detect_registry_schema` (#3) a cada
singleton. Es **detección pura** sobre los bytes que el singleton ya guarda — no cambia
NADA en disco.

## El manifiesto on-chain (opt-in) — "persiste el byte de versión"

`SchemaManifest { versions: Vec<(tag, version)> }` (ordenado por tag → encoding
determinista, hoja Merkle estable). Se guarda en `SCHEMA_MANIFEST_ID` `[21]`.

- **Config**: `explicit_schema_versions: bool` (default `false`). Con `true`, génesis
  siembra el manifiesto con `SchemaManifest::canonical()` (cada singleton en su
  `current_version`).
- **Arranque**: `Ledger::verify_schema_manifest()` (corre tras `validate_critical_singletons`
  en `main.rs`). Si el manifiesto está presente: decodifica (falla-fuerte si el manifiesto
  mismo está corrupto) y, por cada `(tag, versión declarada)`, si el singleton está
  **presente**, su `detect_version` DEBE igualar lo declarado — un mismatch (o bytes
  corruptos) hace **halt fail-loud** ("se requiere una migración de esquema coordinada
  antes de arrancar"); si está **ausente**, se saltea (ese singleton no existe en esta red).
- **Gating / `chain_id`**: sembrar el manifiesto agrega una cuenta = una hoja Merkle nueva
  = un state root de génesis distinto, así que `explicit_schema_versions` se **pliega en el
  `chain_id`** — pero **sólo cuando está en `true`**. Una red que no opta es **byte-idéntica**
  y conserva su `chain_id` exacto; optar es una decisión de **génesis fresco**.

### Por qué un MANIFIESTO en vez de un byte de versión ANTEPUESTO a cada singleton

Antepuso un byte de versión DENTRO de cada account cambiaría los bytes de TODO singleton ya
existente → su hoja Merkle → el state root, un rewrite de formato de altísima superficie y
con riesgo real de fork en cada decodificador. El manifiesto entrega la MISMA garantía
(versión explícita, persistida on-chain, verificada fail-loud al arrancar) con **superficie
acotada** (una cuenta nueva + siembra + verificación de arranque; CERO cambio a los bytes de
ningún singleton existente). Es la elección segura por la regla del proyecto ("sin
optimización segura, nada").

## Herramientas

`qchain-inspect-state` reporta ahora la versión de esquema EXPLÍCITA de **cada** singleton
(no sólo del registro), y la presencia/contenido del manifiesto — la vista pre-actualización
del operador. `qchain-genesis-build --explicit-schema-versions` siembra el manifiesto en una
red nueva.

## Migración futura (el flujo coordinado)

Cuando un singleton tenga un cambio de layout real (una v→v+1):
1. Bump `current_version()` de ese singleton en `schema.rs` y agrega su rama de detección de
   la versión nueva (como `detect_registry_schema` distingue v1/v2).
2. Provee la migración (un decodificador tolerante como `read_or_legacy`/`decode_registry`, y
   —si hay que persistir el cambio— una herramienta offline coordinada como
   `qchain-migrate-registry` de la tarea #3).
3. En el cutover coordinado, migra el singleton Y actualiza su entrada del manifiesto
   juntos. El gate de arranque garantiza que ningún nodo corra con un singleton en una
   versión que su manifiesto no espera.

## Despliegue

Node-local + gated: la red del usuario (sin `explicit_schema_versions`) es **byte-idéntica**,
sin cambio de wire/consenso/estado/`chain_id` → `git pull && sudo ./deploy/update-node.sh`.
Para exigir el manifiesto explícito se decide al **crear** la red (génesis nuevo) con
`--explicit-schema-versions`.
