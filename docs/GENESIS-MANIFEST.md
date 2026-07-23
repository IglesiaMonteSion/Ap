# Manifiesto de génesis + `qchain-verify-genesis` (roadmap #7)

Un **manifiesto de génesis** es el registro canónico y publicable de un lanzamiento:
todo lo que define, byte a byte, el estado inicial de una red. Cualquiera puede
**recomputarlo offline desde su propia config** y confirmar — sin confiar en el
lanzador — que va a arrancar EXACTAMENTE la misma red que todos acordaron.

## Por qué

El `chain_id` (hash de `validators`+`genesis`) ya ata la red a su config, pero
**no prueba qué ESTADO siembra esa config**: las asignaciones de balance, los
singletons de protocolo (params económicos, registro cripto, tesorería, pools
v7, guardianes…), el suministro total, y la raíz de Merkle del estado de génesis.
Dos operadores con configs que *parecen* iguales podrían sembrar estados distintos
(una asignación de más, un flag económico distinto) y forkear en el bloque 1.

El manifiesto cierra eso: es la **foto determinista y verificable** del estado de
génesis completo, recomputable por cualquiera con **el MISMO código que corre el
nodo** (`qchain_node::genesis::seed_genesis`), así que **nunca puede driftear** de
lo que un nodo realmente siembra.

## Qué contiene

- `chain_id` — el identificador de red (hash de validators+genesis).
- `network_fingerprint` — SHA3 de chain_id + auth/cifrado/rotación/perfil (compara config de red entre nodos).
- `genesis_state_root` — la **raíz de Merkle del estado sembrado** (la prueba dura: cualquier diferencia de estado la cambia).
- `validator_count`, `account_count`.
- `total_supply_atoms` / `total_supply_qch` — el suministro sembrado (suma de todos los balances).
- `decisions` — las decisiones de génesis plegadas: `economics_v7`, `compressed_state_tree`, `validator_rotation`, `hard_cap_supply`, `supply_cap_qch`, `network_profile`, `treasury`, `guardians`, `admin_fee_wallet`.
- `accounts` — la lista COMPLETA de cuentas sembradas, **ordenada por dirección** (address, balance, owner, nonce, data_len, data_sha3 — el hash del `data`, no el `data` crudo, para mantener el manifiesto chico y no filtrar nada).
- `manifest_hash` — SHA3-256 domain-tagged (`qchain-genesis-manifest-v1`) sobre todo lo anterior. Un solo bit distinto en cualquier campo lo cambia.

## Uso

```bash
# 1. El lanzador PUBLICA el manifiesto (junto a la config compartida)
qchain-verify-genesis --config node.json --emit genesis-manifest.json

# 2. Cada operador RECOMPUTA desde su propia config y verifica contra el publicado
qchain-verify-genesis --config mi-node.json --manifest genesis-manifest.json
#   == MATCH — this config reproduces the published genesis exactly. ==   (exit 0)
#   == MISMATCH ... Do NOT join/launch ...                                (exit 2)

# 3. Sólo imprimir el manifiesto (para inspección)
qchain-verify-genesis --config node.json
```

El modo `--manifest` es el **chequeo de confianza**: un operador a punto de unirse o
lanzar una red recomputa el manifiesto desde SU config y confirma que coincide —
mismo `chain_id`, misma `genesis_state_root`, mismo suministro, mismas cuentas —
**sin confiar en el lanzador**. Un MISMATCH imprime exactamente qué campo difiere
(p.ej. `total_supply_atoms: recomputed X != published Y`) y sale con código 2.

## Determinismo — por qué es sólido

- El manifiesto se computa sembrando un `Ledger` en memoria fresco con
  `qchain_node::genesis::seed_genesis` — **la MISMA función que el nodo llama en
  su arranque de génesis** (extraída a `src/genesis.rs`, un solo source-of-truth).
  Verificado en vivo: el `genesis state root` que loguea un nodo real coincide
  con la `genesis_state_root` que computa `qchain-verify-genesis` offline, tanto
  en una red v6 como en una v7+hard-cap+tesorería.
- El orden de cuentas es determinista (ordenado por dirección), así que el
  `manifest_hash` es una función pura de la config.
- No hay reloj, RNG ni orden de HashMap en el camino (misma disciplina que el resto
  del proyecto).

## Alcance honesto

- El manifiesto captura el **estado de GÉNESIS** (lo que se siembra en el bloque 0),
  no el estado en vivo — es exactamente lo que se necesita verificar antes de arrancar.
- `data_sha3` es el hash del `data` de cada cuenta, no el `data` crudo: mantiene el
  manifiesto chico y no expone nada, mientras sigue detectando cualquier cambio (un
  singleton con contenido distinto tiene un `data_sha3` distinto Y una
  `genesis_state_root` distinta).
- No reemplaza al `chain_id` ni al `network_fingerprint` (que cubren la config de red
  y consenso) — los **complementa** con la prueba del estado sembrado.
