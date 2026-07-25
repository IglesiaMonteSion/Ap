# Auditoría #187 — binding de red en la firma de consenso (interna)

- **Fecha / versión:** v8.6.38
- **Alcance:** el ítem que #187 dejó diferido en v6.15.0 — *"`chain_id` en los
  votos"* — y, alrededor de él, todas las superficies que verifican la **misma**
  firma de voto: consenso (`verify_certificate`), el engine del nodo, el firmante
  remoto, y **el camino de slashing** (`ReportEquivocation`, v6 y v7). Al cerrar
  eso, el barrido mecánico de la clase se extendió a **los 11 dominios de firma**
  del sistema (tabla más abajo), que destapó un segundo ALTO en el camino de
  RECUPERACIÓN.
- **Método:** barrido de preimágenes firmadas/hasheadas sin dominio o sin binding
  de instancia → test del exploit escrito **antes** del fix (debe demostrar el
  robo) → fix → el mismo test como regresión.
- **Motivo:** al retomar #187 la duda era si el diferimiento seguía siendo
  razonable. No lo era: el razonamiento cubría una superficie y se aplicó a todas.

## Hallazgos

| # | Severidad | Hallazgo | Estado |
|---|---|---|---|
| 1 | **ALTO (alcanzable)** | La firma de un voto no ataba la red. Dos vértices firmados por el MISMO validador en DOS cadenas distintas forman evidencia de equivocación válida → le queman el bono/self-stake completo a un validador que se portó bien. | **CERRADO** |
| 2 | **ALTO (alcanzable)** | La aprobación de RECUPERACIÓN (`RECOVERY_AUTH_V1`) tampoco ataba la red, y el relayer es **permissionless**: las firmas juntadas legítimamente en la cadena A revocaban/congelaban en la B a un validador honesto (bono al pool de unbonding, fuera del comité). Encontrado por el barrido MECÁNICO de la clase, no por lectura dirigida. | **CERRADO** |
| 3 | Medio | La política de binding de `chain_id` del firmante remoto (KM#7) **no cubría los votos** — los únicos pedidos que no nombraban su red. Un nodo comprometido/mal-cableado podía usar un firmante configurado para la red A y producir votos válidos en la B. | **CERRADO** |
| 4 | Doc/test | El repo tenía un test (`chain_id_binding_rejects_a_wrong_network_request`) cuya aserción decía literalmente *"votes unaffected by chain binding"*, y la doc del firmante afirmaba que "los votos están atados a la red por su estructura". **Un test que codificaba el hueco** — por eso ninguna corrida lo delataba. | **CERRADO** (dado vuelta) |

### Hallazgo 1 (ALTO) — detalle

El voto firmaba `VERTEX_VOTE_V1 ‖ digest`, y

```
vertex.digest() = ronda ‖ autor ‖ batch_digests ‖ parents
```

**nada de eso identifica la red.** `ReportEquivocation` sólo exige: misma ronda,
mismo autor, digests distintos, ambas firmas verifican bajo el bundle del acusado.

El escenario **no es exótico para este proyecto**: relanzar con génesis fresco
manteniendo las mismas claves de validador está documentado como procedimiento
normal (§15, [`RELAUNCH-V7.md`](../../RELAUNCH-V7.md); el hard cap de #221 lo
**exige**). Un validador honesto firma un vértice por ronda en cada incarnación;
cualquiera que archivó la cadena vieja puede parear uno de allá con uno de acá.

**Por qué el diferimiento de v6.15.0 no alcanzaba.** Decía: *"un vértice de otra
red se rechaza igual — sus `parents` son digests de certificados de SU red, acá
son desconocidos"*. Cierto **para el consenso**, donde el vértice se inserta en un
DAG. El camino de slashing **no inserta nada**: verifica dos firmas y quema.

**Cierre.** El voto pasa a firmar `VERTEX_VOTE_V1 ‖ chain_id ‖ digest` (32+32,
largo fijo, sin ambigüedad de framing), cableado en las cinco superficies. Para
que el handler de evidencia sepa cuál es el `chain_id` local sin enroscar el dato
por la firma de `NativeProgram::process`, se agrega el singleton
`CHAIN_ID_ACCOUNT_ID` sembrado en génesis, exigido por presencia en `ix.accounts`
y leído **fail-closed** (`read_chain_id`): sin él, o con `data` que no sean
exactamente 32 bytes, la instrucción se rechaza. Tolerar su ausencia sería
reabrir el agujero.

### Hallazgo 2 (ALTO) — detalle

Salió del barrido de la clase: al agregar la sección **EC-19** a
`deploy/qsep-sweep.sh` (enumera los 11 dominios de firma y **todos** los sitios que
construyen/verifican una preimagen con dominio), `RECOVERY_AUTH_V1` quedó a la
vista con su preimagen `validador ‖ op ‖ param ‖ nonce`. Su propio doc decía
*"anti-replay dentro de la red, consistente con `pop_message`, que tampoco ata
chain_id"* — la MISMA extrapolación del hallazgo 1, escrita en el código.

Por qué es alcanzable: la aprobación es un artefacto **OFFLINE independiente** y
**`RecoverOp` es permissionless** (el `--keypair` del relayer sólo paga el fee).
Basta con que ambas redes tengan registrado al mismo validador con el mismo comité
de recuperación y el nonce en el mismo valor — exactamente lo que deja un
relanzamiento con génesis fresco y las mismas claves (§15), donde el nonce arranca
en 0 en las dos. Un `Revoke` legítimo en A (p. ej. clave perdida) valía tal cual
en B: estado `Revoked`, bono movido al pool de unbonding, fuera del comité.

**Cierre.** `recovery_message` pasa a ser `chain_id ‖ validador ‖ tag ‖ param ‖
nonce`; `RecoverOp` exige el singleton `CHAIN_ID_ACCOUNT_ID` en `ix.accounts` y lo
lee fail-closed. `qchain v7-recovery-sign` gana `--chain-id` (el firmante frío está
offline y no puede consultarlo; se obtiene de `GET /chain_id` de cualquier nodo de
la red objetivo).

### Barrido completo de los 11 dominios (la respuesta con evidencia a la pregunta recurrente de EC-19)

| Dominio | ¿nombra la instancia? | Veredicto |
|---|---|---|
| `TX_SIG_V1` | sí — el `Message` firmado lleva `chain_id` | OK |
| `STATE_CHECKPOINT_V1` | sí — `state_checkpoint_message(chain_id, …)` | OK |
| `NETWORK_KEY_CERT_V1` | sí — `network_key_cert_message(chain_id, …)` | OK |
| `VERTEX_VOTE_V1` | **ahora sí** (hallazgo 1) | CERRADO |
| `RECOVERY_AUTH_V1` | **ahora sí** (hallazgo 2) | CERRADO |
| `VALIDATOR_POP_V1` | no | **no alcanzable**: `BondAndRegister`/`RotateConsensusKey` exigen que el PAYER sea la clave fría de operador, y la firma de ESA transacción sí está atada al `chain_id`. Replayar el PoP sólo habilita al mismo operador a hacer lo que ya podía. |
| `KEY_ROTATION_ACCEPT_V1` | no | **no alcanzable**, idéntico razonamiento (la rotación la firma el operador). |
| `TXID_V1` | n/a | no es una autorización, es un identificador. |
| `KEYSTORE_HKDF_V2` | n/a | derivación de clave local, no autoriza nada cross-instancia. |
| `KM_AUDIT_V1` | n/a | encadenado por hash de un log local, no es una firma de autorización. |
| `P2P_AUTH_V1` | sí — el transcript firmado incluye el `chain_id` (v6.4.0) | OK |

Los dos "no alcanzable" quedan **documentados a propósito**: no se les agrega
binding porque el cambio no compra seguridad y sí rompería PoPs ya publicados
on-chain (regla del proyecto: *si no hay una optimización segura, mejor no se hace
nada*). Si en el futuro alguna instrucción dejara de exigir la firma del operador,
la conclusión se cae — por eso queda escrita, no asumida.

## Evidencia

- **Exploit escrito ANTES del fix, y confirmado:**
  `evidence_built_from_two_different_chains_must_not_slash_an_honest_validator`
  — sin el binding, `StakingProgram::process` devolvía `Ok` y el self-stake
  quedaba en 0. Hoy es test de regresión (rechaza).
- **Cross-verify negativo en cripto:** una firma de voto hecha para una red **no**
  verifica bajo otra (`domain_tagged_signatures_do_not_cross_verify`).
- **Consenso:** un certificado con firmas perfectamente válidas de otra red
  verifica a `false` (`verify_certificate` toma el `chain_id`).
- **Firmante remoto:** un `SignOwnVote`/`SignPeerVote` que nombra otra red se
  **rechaza** bajo la política de KM#7 (la aserción que antes decía lo contrario).
- **Recuperación (hallazgo 2), test con dientes:**
  `recovery_approvals_from_another_chain_must_not_revoke_a_validator_here` — con el
  binding revertido a propósito, FALLA (las aprobaciones de otra cadena revocan);
  con el fix, la op se rechaza y el validador queda intacto (estado, bono y nonce
  sin mover) mientras el camino legítimo de la MISMA red sigue funcionando. Más
  `recover_op_without_the_chain_id_singleton_is_rejected` (fail-closed).
- **Multinodo EN VIVO (el gate real de un cambio de consenso):** testnet de 3
  validadores con el voto atado a la red — los 3 avanzan en lockstep (ronda ~51,
  154 certificados) y una transferencia converge con **root IDÉNTICO en los 3**
  (`9d98a66f08d20b37…`, destino 7.777.777 en los tres) → **sin fork**. El singleton
  de `chain_id` quedó sembrado en los 3 con exactamente el valor que reporta
  `GET /chain_id` (`c4b8d517…`), owned por el programa de staking.

## Clase de error registrada

**EC-19** — *una firma sin binding de INSTANCIA vale como evidencia en otra
instancia, y la superficie de ACUSACIÓN se olvida* →
[`../LESSONS-LEDGER.md`](../LESSONS-LEDGER.md).

**Pregunta recurrente que deja instalada:** *para cada firma del sistema — ¿su
preimagen nombra la red/época? ¿En qué superficies se verifica además de aquella
donde el objeto se consume, y esas superficies re-ejecutan las validaciones de las
que depende el argumento de "está cerrado estructuralmente"?*

## Estado de #187

| Ítem original | Estado |
|---|---|
| dominio + object_type en tx/voto/vértice | **HECHO** (v6.15.0) |
| `chain_id` en votos | **HECHO** (esta pasada) |
| prefijos Merkle versionados | **DIFERIDO** — el árbol ya separa dominios (hoja `0x03` / interno `0x04` / vacío `0x05`, mutuamente no colisionables); versionarlos cambiaría **cada state root** (hard fork masivo de estado) por beneficio ~nulo. Decisión mantenida, con la razón escrita. |

## Despliegue

Cambia la **preimagen firmada** de consenso — no el `vertex.digest()` (el
content-address del DAG) ni el layout wire de ningún struct. Por eso:

- El DAG y los batches persistidos en disco siguen siendo válidos (sus digests no
  cambian).
- Pero una firma vieja **no verifica** contra un binario nuevo ni al revés →
  **cutover COORDINADO**: todos los validadores actualizan juntos.
- El singleton nuevo cambia el **state root de génesis**, no el `chain_id` (que se
  computa del CONFIG, no del estado) → una red nueva lo siembra; una red viva que
  quiera el fix hace el cutover con el resto.
- **Aprobaciones de recuperación ya juntadas offline** (si alguien tenía firmas
  guardadas para una op futura) dejan de valer: hay que re-firmarlas con
  `--chain-id`. Es el precio correcto — esas firmas eran precisamente las que
  valían en cualquier red.

## Límite honesto

Esta pasada cierra el binding de red del **voto**. El barrido dejó anotado, sin
cerrar, que `Vertex::digest()`/`Batch::digest()` no llevan etiqueta de dominio
(sí llevan delimitadores de largo desde #110): una colisión entre ambos requiere
una preimagen de SHA3 elegida por el atacante sobre campos que no controla, así
que es disciplina, no un vector — y cambiarlos rompería los digests persistidos,
que es una operación bastante más cara que este cutover.
