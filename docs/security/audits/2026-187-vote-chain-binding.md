# Auditoría #187 — binding de red en la firma de consenso (interna)

- **Fecha / versión:** v8.6.38
- **Alcance:** el ítem que #187 dejó diferido en v6.15.0 — *"`chain_id` en los
  votos"* — y, alrededor de él, todas las superficies que verifican la **misma**
  firma de voto: consenso (`verify_certificate`), el engine del nodo, el firmante
  remoto, y **el camino de slashing** (`ReportEquivocation`, v6 y v7).
- **Método:** barrido de preimágenes firmadas/hasheadas sin dominio o sin binding
  de instancia → test del exploit escrito **antes** del fix (debe demostrar el
  robo) → fix → el mismo test como regresión.
- **Motivo:** al retomar #187 la duda era si el diferimiento seguía siendo
  razonable. No lo era: el razonamiento cubría una superficie y se aplicó a todas.

## Hallazgos

| # | Severidad | Hallazgo | Estado |
|---|---|---|---|
| 1 | **ALTO (alcanzable)** | La firma de un voto no ataba la red. Dos vértices firmados por el MISMO validador en DOS cadenas distintas forman evidencia de equivocación válida → le queman el bono/self-stake completo a un validador que se portó bien. | **CERRADO** |
| 2 | Medio | La política de binding de `chain_id` del firmante remoto (KM#7) **no cubría los votos** — los únicos pedidos que no nombraban su red. Un nodo comprometido/mal-cableado podía usar un firmante configurado para la red A y producir votos válidos en la B. | **CERRADO** |
| 3 | Doc/test | El repo tenía un test (`chain_id_binding_rejects_a_wrong_network_request`) cuya aserción decía literalmente *"votes unaffected by chain binding"*, y la doc del firmante afirmaba que "los votos están atados a la red por su estructura". **Un test que codificaba el hueco** — por eso ninguna corrida lo delataba. | **CERRADO** (dado vuelta) |

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

## Límite honesto

Esta pasada cierra el binding de red del **voto**. El barrido dejó anotado, sin
cerrar, que `Vertex::digest()`/`Batch::digest()` no llevan etiqueta de dominio
(sí llevan delimitadores de largo desde #110): una colisión entre ambos requiere
una preimagen de SHA3 elegida por el atacante sobre campos que no controla, así
que es disciplina, no un vector — y cambiarlos rompería los digests persistidos,
que es una operación bastante más cara que este cutover.
