# qchain-byzantine-injector

Un adversario BIZANTINO de primera clase para una red qchain viva. A diferencia
del `deploy/chaos-test.sh` mecánico (crash / partición / corrupción de disco),
este ejerce las defensas de **consenso** con mensajes genuinamente firmados por
una clave de validador del comité — el atacante piensa, no sólo rompe.

## Modelo de amenaza

Un validador bizantino es un **miembro del comité**: su clave está en el génesis
y pesa en el quórum. El inyector impersona a esa identidad — su clave existe en
el set, pero su nodo honesto NO se corre; en su lugar el inyector le habla el
protocolo P2P real. Es exactamente el peor caso que la BFT promete tolerar
mientras los honestos mantengan el quórum.

## Ataques (cada uno mapea 1:1 a una defensa del proyecto)

| Subcomando | Qué envía | Defensa que ejerce |
|---|---|---|
| `equivocate --round R` | Dos `VertexProposal` firmados y VÁLIDOS para la MISMA (ronda, autor) con padres distintos | Slashing por equivocación (#88) + candado `voted_for`. Un nodo honesto captura la evidencia (`/equivocation_evidence`) → slasheable. |
| `withhold --round R [--count N]` | Un vértice que referencia un `Batch` que el inyector **nunca envía** | Gate de disponibilidad en el voto (HIGH #175): un honesto no vota un vértice cuyos batches no tiene → nunca certifica → no puede trabar la ejecución. |
| `oversized --round R [--parents K]` | Un vértice auténtico con miles de `parents` fabricados | Cotas estructurales pre-proceso (#208): `parents.len() <= n`. El mensaje se descarta antes de tocar el estado. |
| `flood [--count N]` | N `TransactionGossip`, cada uno una tx REAL firmada por un pagador sin fondos | Cuota de admisión + tope de verify concurrente (#210/#90). El trabajo queda acotado; la red no se satura. |

Los mensajes se construyen con los tipos REALES de `qchain-core` /
`qchain-crypto` / `qchain-network`, así que son byte-fieles a lo que un nodo
malicioso emitiría — no un encoding a mano que podría divergir del wire.

## Uso

```
qchain-byzantine-injector \
  --keypair v4.json --chain-id <hex> \
  --targets 127.0.0.1:9501,127.0.0.1:9502,127.0.0.1:9503 \
  equivocate --round 42
```

Con el transporte autenticado hay que nombrar la identidad de cada objetivo
(`--target-ids <b58>,...` en el mismo orden que `--targets`) porque el handshake
del cliente rechaza un objetivo sin identidad esperada. `--authenticated`
(+`--encrypted`) selan los frames como lo haría un peer real.

## El oráculo: la red honesta, por RPC

El inyector **no verifica nada por sí mismo**. El harness `deploy/byzantine-injector.sh`
levanta 3 nodos honestos + esta identidad bizantina y, tras cada ataque, exige
por RPC: (a) SIN FORK — roots idénticos al mismo nº de tx ejecutadas —, y (b)
VIVACIDAD — una transferencia nueva finaliza en todos los nodos vivos. Es el
mismo oráculo que las verificaciones en vivo del resto del proyecto.

```
deploy/byzantine-injector.sh   # → VEREDICTO: PASS (PASS=6 FAIL=0)
```

## Alcance honesto

Ejercita las defensas de consenso/red/admisión desde el borde del protocolo. NO
reemplaza al DST (`qchain-simulation`), que prueba safety+liveness de forma
determinista bajo pérdida de certificados y equivocación — esa es la garantía
más fuerte, sin depender de timing. Este inyector es su complemento EN VIVO: un
adversario real sobre el wire real, contra un nodo real.
