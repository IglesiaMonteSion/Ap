# Vigilante de runtime con IA (tarea #183, Fase B)

`deploy/qchain-watchdog.py` es un servicio de **monitoreo read-only** que corre
FUERA del validador y vigila un nodo qchain **vivo** en producción. Es la
contraparte de runtime del auditor de dev-time (`ai_security_review.py`, Fase A):
aquél revisa **código** en cada PR; éste vigila un **nodo en marcha**.

## Arquitectura de dos capas (el LLM NUNCA en el hot path)

- **Capa 1 — heurísticas baratas, deterministas, SIN IA, siempre corriendo.**
  Sondea cada `--interval` segundos los endpoints que el nodo YA expone
  (`/status`, `/economics`, `/resources`, y opcional cross-check de `/root`
  entre nodos) y dispara **señales** con umbrales fijos:
  `rpc_down`, `consensus_stalled`, `fee_spike`, `mempool_backlog`, `ram_high`,
  `ram_growth`, `disk_high`, `fork` (roots divergen a la misma ronda),
  `emission_out_of_range`, `update_available`. Esta capa ya da valor **sin IA**.

- **Capa 2 — Claude como ANALISTA** (sólo si hay `ANTHROPIC_API_KEY` y una señal
  disparó o pasó el tick mínimo). Se le manda un **resumen compacto** de las
  últimas muestras + las señales disparadas; su valor es **correlacionar**
  señales débiles en un veredicto que un umbral fijo no puede
  ("fee subiendo + mempool creciendo + pocos pagadores distintos = posible
  intento de deadlock del fee-market"). Devuelve severidad + causa probable +
  **acción HUMANA recomendada**. Es advisory: **nunca actúa**.

## Modelo de seguridad del propio agente

Un agente de seguridad mal puesto **ES** el ataque, así que:

- **READ-ONLY sobre HTTP** — nunca toca claves, consenso ni producción.
- **SIN llaves de la cadena** — jamás ve `keypair.json` ni la clave de tesorería.
- **SIN poder de acción destructiva** — sólo EMPUJA un aviso (ntfy/Discord/Slack/
  webhook). Peor caso si se compromete = "mandó una alerta falsa".
- **La API key vive en una env var** (`ANTHROPIC_API_KEY`), NUNCA en el repo, y
  sólo la usa la Capa 2 (una llamada saliente HTTPS a la API de Claude).
- **INERTE por defecto** para la Capa 2: sin la key, la Capa 1 corre igual
  (heurísticas + alertas, CERO IA). El servicio vive sin efecto de IA hasta que
  el operador la activa.
- Corré el watchdog en una **caja aparte** del validador (no comparte proceso ni
  claves). La unidad systemd usa `NoNewPrivileges`/`ProtectSystem`/`ProtectHome`.

## Límites honestos

Latencia de segundos-minutos → el agente **AVISA, NO frena** un exploit en vivo.
Las defensas reales siguen siendo las on-chain ya construidas (overflow-checks,
conservación de valor, slashing, cotas de recursos, el fork-check del consenso).
Es una capa **ENCIMA** de la revisión humana + las defensas del nodo, no un
reemplazo. La Capa 2 puede tener falsos positivos/alucinar; por eso es advisory.

## Uso

```sh
# un chequeo ahora (imprime el estado; alerta si hay canal):
./deploy/qchain-watchdog.py --check --rpc http://<ip-del-nodo>:8080 \
  --ntfy https://ntfy.sh/mi-canal-secreto

# instalar como servicio systemd (Restart=on-failure), como root:
sudo ./deploy/qchain-watchdog.py --install --rpc http://<ip>:8080 \
  --ntfy https://ntfy.sh/mi-canal --cross-check http://<ip-otro-nodo>:8080

# aviso de prueba / autotest offline (sin red):
./deploy/qchain-watchdog.py --test --ntfy https://ntfy.sh/mi-canal
./deploy/qchain-watchdog.py --selftest
```

### Activar la Capa 2 (Claude)

Poné la API key en el entorno del servicio, **nunca en el repo**:

```sh
sudo sh -c 'echo "ANTHROPIC_API_KEY=sk-ant-..." > /etc/qchain-watchdog.env'
sudo chmod 600 /etc/qchain-watchdog.env
sudo systemctl restart qchain-watchdog
```

La unidad ya referencia `EnvironmentFile=-/etc/qchain-watchdog.env` (el `-` la
hace opcional: sin ese archivo, la Capa 2 queda inerte y la Capa 1 corre igual).
Modelo configurable con `--claude-model` (default `claude-haiku-4-5-20251001`,
barato para chequeos frecuentes); el costo se acota con `--claude-min-interval`
(default 900s = a lo sumo una llamada cada 15 min).

## Canales de aviso

Mismos que `monitor-node.sh`: `--ntfy` (lo más simple para el teléfono),
`--discord`, `--slack`, `--webhook` (POST genérico `{"text":"..."}`). Configurá
uno o varios. Anti-spam: una señal sólo re-alerta si desaparece y vuelve, o si
escala de severidad.

## Umbrales (todos ajustables por flag)

`--stall-secs` (180), `--fee-spike-mult` (10× el piso 180), `--mempool-max`
(5000), `--ram-max-mb` (3000), `--disk-max-mb` (20000), `--trend-samples` (3),
`--ram-growth-frac` (0.2). Subilos/bajalos según el tamaño real de tu VPS y tu
tráfico esperado.

## Relación con `monitor-node.sh`

`monitor-node.sh` (bash, Fase 0) es el chequeo mínimo de "vivo/congelado" que
corre **en** la máquina del nodo. `qchain-watchdog.py` es el escalón siguiente:
más heurísticas de Capa 1 + la correlación de Capa 2 con Claude, corriendo desde
**afuera**. Podés usar los dos (el monitor local como red de seguridad barata, el
watchdog remoto como análisis profundo) o sólo el watchdog.

## Verificación

`--selftest` corre 11 grupos de aserciones OFFLINE (sin red) sobre la lógica pura
de Capa 1 (cada señal), el anti-spam y la inercia de la Capa 2 sin key. El path
HTTP real (sondeo de los 4 endpoints, cross-check de fork) y la construcción del
request a la API de Claude se verificaron con servidores mock en la sesión de
desarrollo.
