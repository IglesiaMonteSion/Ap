#!/usr/bin/env python3
"""qchain-watchdog — vigilante de RUNTIME de dos capas (tarea #183, Fase B).

Servicio de monitoreo READ-ONLY que corre FUERA del validador (idealmente en
otra máquina) y sondea los endpoints que el nodo YA expone. Es la contraparte de
runtime del auditor de dev-time (`ai_security_review.py`, Fase A): aquel revisa
CÓDIGO en cada PR; éste vigila un nodo VIVO en producción.

Arquitectura de DOS CAPAS (crítica — el LLM NUNCA en el hot path):

  CAPA 1 (heurísticas baratas, deterministas, SIN IA, siempre corriendo):
    sondea /status, /economics, /resources (y opcional cross-check de /root
    entre nodos) cada `--interval` segundos y dispara SEÑALES con umbrales fijos:
    RPC caído, consenso congelado, fee disparado, mempool creciendo sin cota,
    RAM/disco altos o creciendo, FORK (roots divergen a la misma ronda),
    emisión/comisión fuera de rango, actualización disponible.

  CAPA 2 (Claude como ANALISTA, sólo si hay ANTHROPIC_API_KEY y una señal disparó
    o en un tick periódico): se le manda un RESUMEN compacto de las últimas
    muestras + las señales disparadas; su valor es CORRELACIONAR señales débiles
    en un veredicto ("flood dirigido de 3 wallets = intento de deadlock del
    fee-market") que un umbral fijo solo no puede. Devuelve severidad + causa
    probable + acción HUMANA recomendada. Advisory: NUNCA actúa.

MODELO DE SEGURIDAD DEL PROPIO AGENTE (un agente mal puesto ES el ataque):
  * READ-ONLY sobre HTTP — nunca toca claves, consenso, ni producción.
  * SIN llaves de la cadena — jamás ve keypair.json ni la clave de tesorería.
  * SIN poder de acción destructiva — sólo EMPUJA un aviso (ntfy/Discord/Slack/
    webhook); peor caso si se compromete = "mandó una alerta falsa".
  * La API key de Claude vive en una env var (ANTHROPIC_API_KEY), NUNCA en el
    repo, y sólo la usa la Capa 2 (una llamada saliente HTTPS a la API).
  * INERTE por defecto para la Capa 2: sin la key, la Capa 1 corre igual
    (heurísticas + alertas, CERO IA — valor inmediato, como monitor-node.sh).

Stdlib only (urllib/json/http) — la caja de monitoreo no necesita `pip`.

Uso (en una caja de monitoreo, apuntando al RPC del nodo):
  # un chequeo ahora (imprime el estado; alerta si hay canal configurado):
  ./qchain-watchdog.py --check --rpc http://<ip-del-nodo>:8080 --ntfy https://ntfy.sh/mi-canal
  # correr en loop (lo normal para un servicio):
  ./qchain-watchdog.py --daemon --rpc http://<ip>:8080 --ntfy https://ntfy.sh/mi-canal
  # instalar como servicio systemd (Restart=on-failure), como root:
  sudo ./qchain-watchdog.py --install --rpc http://<ip>:8080 --ntfy https://ntfy.sh/mi-canal
  sudo ./qchain-watchdog.py --uninstall
  # aviso de prueba / autotest offline (sin red):
  ./qchain-watchdog.py --test --ntfy https://ntfy.sh/mi-canal
  ./qchain-watchdog.py --selftest

Para activar la Capa 2 (correlación con Claude): exportá ANTHROPIC_API_KEY en el
entorno del servicio (nunca en el repo). Ver docs/AI-RUNTIME-WATCHDOG.md.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

# --- Capa 2 (Claude) --------------------------------------------------------
ANTHROPIC_VERSION = "2023-06-01"
# Haiku para chequeos frecuentes/baratos; se puede subir a un modelo mayor para
# juicio más profundo vía --claude-model.
DEFAULT_MODEL = "claude-haiku-4-5-20251001"
CLAUDE_MAX_TOKENS = 1024

# El nodo nunca deja el base fee por debajo de este piso (FEE_MIN_BASE_FEE_PER_BYTE).
FEE_FLOOR = 180
# El registro on-chain rechaza un APR de emisión por encima de esto (bps).
MAX_EMISSION_APR_BPS = 5000

SYSTEM_PROMPT = """\
Sos el analista de seguridad de RUNTIME de `qchain`, una blockchain L1 \
post-cuántica. Recibís un RESUMEN JSON de telemetría read-only de un nodo vivo \
(varias muestras recientes de /status, /economics, /resources) más las SEÑALES \
que unas heurísticas baratas ya dispararon. Tu trabajo es CORRELACIONAR señales \
débiles en un veredicto que un umbral fijo no puede: p.ej. un fee que sube + \
mempool creciendo + pocos pagadores distintos = posible intento de deadlock del \
fee-market; roots divergentes entre nodos a la misma ronda = FORK; una caída de \
distribución de holders + quema masiva = posible drenaje/exploit. \

Sos ADVISORY y READ-ONLY: NUNCA proponés una acción automática destructiva ni \
que mueva fondos/toque consenso — como mucho una acción HUMANA reversible y \
acotada (revisar logs, subir el fee mínimo por gobernanza, pausar el faucet). \
No inventes: si los datos no alcanzan para un veredicto, decilo. Sé breve. \

Contexto de invariantes de qchain (para juzgar anomalías): el base fee flota por \
congestión (EIP-1559) y NUNCA baja del piso 180; la emisión y la quema son \
deterministas; TODOS los nodos honestos convergen al mismo Merkle root por \
ronda (roots distintos a la misma ronda = fork real); el APR de emisión on-chain \
está acotado a 5000 bps; el consenso avanza de ronda continuamente (rondas \
congeladas = consenso trabado). \

Respondé SOLO un objeto JSON: {"severity":"none|low|medium|high|critical",\
"summary":"...","likely_cause":"...","recommended_human_action":"..."}."""


# ---------------------------------------------------------------------------
# HTTP helpers (read-only GET + alert POST). Stdlib urllib, con timeouts.
# ---------------------------------------------------------------------------
def http_get_json(url, timeout=8):
    """GET una URL y devolver el JSON parseado, o None ante cualquier fallo."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "qchain-watchdog"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            ValueError, OSError):
        return None


def http_get_text(url, timeout=8):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "qchain-watchdog"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace").strip()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


def sample_node(rpc, timeout=8):
    """Una muestra read-only del nodo: status + economics + resources + root.

    Devuelve un dict con lo que se pudo leer; `up=False` si /status no responde
    (el nodo está caído o el RPC no es alcanzable).
    """
    now = int(time.time())
    status = http_get_json(rpc.rstrip("/") + "/status", timeout)
    if status is None:
        return {"t": now, "up": False}
    econ = http_get_json(rpc.rstrip("/") + "/economics", timeout) or {}
    res = http_get_json(rpc.rstrip("/") + "/resources", timeout) or {}
    root = http_get_text(rpc.rstrip("/") + "/root", timeout)
    return {"t": now, "up": True, "status": status, "economics": econ,
            "resources": res, "root": root}


# ---------------------------------------------------------------------------
# CAPA 1 — heurísticas deterministas. Función PURA sobre una ventana de muestras
# (para poder testearla sin red). Devuelve una lista de señales:
#   {"name","severity","detail"}  (severity: low|medium|high|critical)
# ---------------------------------------------------------------------------
def evaluate_signals(window, cross_roots, cfg):
    """Evaluar señales sobre `window` (lista de muestras, más nueva al final).

    `cross_roots` = lista de (round, root) reportados por OTROS nodos (cross-check
    de fork). `cfg` = umbrales (dict). No hace I/O.
    """
    signals = []
    if not window:
        return signals
    cur = window[-1]

    # RPC caído: la muestra más nueva no respondió.
    if not cur.get("up"):
        signals.append({"name": "rpc_down", "severity": "critical",
                        "detail": "el /status del nodo no respondió"})
        return signals  # sin datos vivos no se pueden evaluar las demás

    st = cur.get("status", {})
    econ = cur.get("economics", {})
    res = cur.get("resources", {})

    # Consenso congelado: next_round no avanzó en >= stall_secs.
    ups = [s for s in window if s.get("up")]
    if len(ups) >= 2:
        first = ups[0]
        last = ups[-1]
        r0 = first.get("status", {}).get("next_round")
        r1 = last.get("status", {}).get("next_round")
        span = last["t"] - first["t"]
        if (r0 is not None and r1 is not None and r1 <= r0
                and span >= cfg["stall_secs"]):
            signals.append({"name": "consensus_stalled", "severity": "critical",
                            "detail": f"next_round fijo en {r1} hace {span}s "
                                      f">= {cfg['stall_secs']}s"})

    # Fee disparado: base_fee muy por encima del piso.
    base_fee = st.get("base_fee_per_byte")
    if isinstance(base_fee, int) and base_fee > FEE_FLOOR * cfg["fee_spike_mult"]:
        signals.append({"name": "fee_spike", "severity": "high",
                        "detail": f"base_fee_per_byte={base_fee} "
                                  f"(> {cfg['fee_spike_mult']}x el piso {FEE_FLOOR})"})

    # Mempool creciendo sin cota: por encima del umbral Y en aumento sostenido.
    mp = st.get("mempool_transactions")
    if isinstance(mp, int) and mp >= cfg["mempool_max"]:
        rising = _monotonic_rising([s.get("status", {}).get("mempool_transactions")
                                    for s in ups], cfg["trend_samples"])
        sev = "high" if rising else "medium"
        signals.append({"name": "mempool_backlog", "severity": sev,
                        "detail": f"mempool_transactions={mp} "
                                  f"(>= {cfg['mempool_max']}{', y creciendo' if rising else ''})"})

    # RAM alta o creciendo de forma sostenida (posible fuga / flood).
    rss = res.get("rss_bytes")
    if isinstance(rss, int):
        rss_mb = rss // (1024 * 1024)
        if rss_mb >= cfg["ram_max_mb"]:
            signals.append({"name": "ram_high", "severity": "high",
                            "detail": f"RSS={rss_mb}MB (>= {cfg['ram_max_mb']}MB)"})
        elif _monotonic_rising([s.get("resources", {}).get("rss_bytes") for s in ups],
                               cfg["trend_samples"], min_frac=cfg["ram_growth_frac"]):
            signals.append({"name": "ram_growth", "severity": "medium",
                            "detail": f"RSS creciendo de forma sostenida (ahora {rss_mb}MB)"})

    # Disco alto.
    disk = res.get("disk_bytes")
    if isinstance(disk, int) and disk // (1024 * 1024) >= cfg["disk_max_mb"]:
        signals.append({"name": "disk_high", "severity": "medium",
                        "detail": f"data_dir={disk // (1024*1024)}MB "
                                  f"(>= {cfg['disk_max_mb']}MB)"})

    # FORK: otro nodo reporta un root DISTINTO a la MISMA ronda.
    my_round = st.get("next_round")
    my_root = cur.get("root")
    if my_root:
        for (pr, proot) in cross_roots:
            if pr == my_round and proot and proot != my_root:
                signals.append({"name": "fork", "severity": "critical",
                                "detail": f"root divergente en la ronda {pr}: "
                                          f"local {my_root[:16]}… vs par {proot[:16]}…"})
                break

    # Emisión/comisión fuera de rango (sanity del registro económico).
    apr = econ.get("emission_apr_bps")
    if isinstance(apr, int) and apr > MAX_EMISSION_APR_BPS:
        signals.append({"name": "emission_out_of_range", "severity": "high",
                        "detail": f"emission_apr_bps={apr} (> cap {MAX_EMISSION_APR_BPS})"})

    # Actualización disponible (informativo).
    upd = st.get("update_available")
    if upd:
        signals.append({"name": "update_available", "severity": "low",
                        "detail": f"hay una versión más nueva anunciada: {upd}"})

    return signals


def _monotonic_rising(values, k, min_frac=0.0):
    """¿Los últimos k valores (ints) son estrictamente crecientes?

    Con `min_frac`>0 exige además que el total haya crecido esa fracción (para
    'crecimiento sostenido', evitando alarmar por ruido chico).
    """
    vs = [v for v in values if isinstance(v, int)]
    if len(vs) < k:
        return False
    tail = vs[-k:]
    if not all(tail[i] < tail[i + 1] for i in range(len(tail) - 1)):
        return False
    if min_frac > 0 and tail[0] > 0:
        return (tail[-1] - tail[0]) / tail[0] >= min_frac
    return True


# ---------------------------------------------------------------------------
# CAPA 2 — Claude como analista. Sólo si hay API key. Devuelve el texto crudo
# del veredicto (idealmente un JSON), o None ante error (advisory — nunca frena).
# ---------------------------------------------------------------------------
def build_claude_context(window, signals, cfg):
    """Resumen compacto para mandarle a Claude (sólo datos, sin PII/claves)."""
    def trim(s):
        st = s.get("status", {}) if s.get("up") else {}
        econ = s.get("economics", {}) if s.get("up") else {}
        res = s.get("resources", {}) if s.get("up") else {}
        return {
            "t": s.get("t"), "up": s.get("up", False),
            "round": st.get("next_round"),
            "mempool": st.get("mempool_transactions"),
            "base_fee": st.get("base_fee_per_byte"),
            "executed": st.get("executed_transactions"),
            "peers": econ.get("peer_count"),
            "burned": econ.get("total_burned"),
            "emitted": econ.get("total_emitted"),
            "emission_apr_bps": econ.get("emission_apr_bps"),
            "rss_mb": (res.get("rss_bytes") or 0) // (1024 * 1024),
            "root": (s.get("root") or "")[:16],
        }
    return {
        "recent_samples": [trim(s) for s in window[-cfg["trend_samples"]:]],
        "fired_signals": signals,
    }


def call_claude(api_key, model, context):
    body = {
        "model": model,
        "max_tokens": CLAUDE_MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [{
            "role": "user",
            "content": "Telemetría y señales de un nodo qchain vivo. Correlacioná "
                       "y devolvé el veredicto JSON.\n\n"
                       + json.dumps(context, ensure_ascii=False),
        }],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode(),
        headers={"x-api-key": api_key, "anthropic-version": ANTHROPIC_VERSION,
                 "content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
    return "".join(parts).strip()


# ---------------------------------------------------------------------------
# Alertas — mismos canales que monitor-node.sh (ntfy/discord/slack/webhook).
# ---------------------------------------------------------------------------
def _post(url, data, headers, timeout=10):
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        sys.stderr.write(f"aviso falló ({url.split('/')[2] if '//' in url else url}): {e}\n")
        return False


def notify(channels, name, title, body, priority="default"):
    msg = f"[{name}] {title} — {body}"
    if channels.get("ntfy"):
        _post(channels["ntfy"], msg.encode(),
              {"Title": f"qchain: {title}", "Priority": priority})
    for key, field in (("discord", "content"), ("slack", "text"), ("webhook", "text")):
        if channels.get(key):
            _post(channels[key], json.dumps({field: msg}).encode(),
                  {"Content-Type": "application/json"})


# ---------------------------------------------------------------------------
# Motor: mantiene la ventana de muestras + el anti-spam + orquesta las 2 capas.
# ---------------------------------------------------------------------------
class Watchdog:
    def __init__(self, cfg, channels, api_key, model):
        self.cfg = cfg
        self.channels = channels
        self.api_key = api_key
        self.model = model
        self.window = []            # muestras recientes
        self.active_signals = {}    # name -> última severidad alertada (anti-spam)
        self.last_claude = 0        # timestamp de la última llamada a Claude

    def cycle(self, sample, cross_roots):
        """Una iteración: agregar la muestra, evaluar señales, alertar lo NUEVO."""
        self.window.append(sample)
        # Ventana acotada por tiempo (stall + margen) para no crecer sin fin.
        horizon = self.cfg["stall_secs"] * 3 + self.cfg["interval"] * 4
        cutoff = sample["t"] - horizon
        self.window = [s for s in self.window if s["t"] >= cutoff][-256:]

        signals = evaluate_signals(self.window, cross_roots, self.cfg)
        by_name = {s["name"]: s for s in signals}

        # Anti-spam: alertar sólo señales NUEVAS o que ESCALARON de severidad.
        sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        fresh = []
        for name, sig in by_name.items():
            prev = self.active_signals.get(name)
            if prev is None or sev_rank[sig["severity"]] > sev_rank.get(prev, 0):
                fresh.append(sig)
            self.active_signals[name] = sig["severity"]
        # Limpiar las que se resolvieron (para poder re-alertar si vuelven).
        for name in list(self.active_signals):
            if name not in by_name:
                del self.active_signals[name]

        if fresh:
            self._alert(fresh)
        return signals, fresh

    def _alert(self, fresh):
        worst = max(fresh, key=lambda s: {"low": 1, "medium": 2, "high": 3,
                                          "critical": 4}[s["severity"]])
        prio = {"low": "default", "medium": "default", "high": "high",
                "critical": "urgent"}[worst["severity"]]
        title = f"{worst['severity'].upper()}: {worst['name']}"
        lines = [f"- {s['name']} [{s['severity']}]: {s['detail']}" for s in fresh]
        body = "; ".join(s["detail"] for s in fresh)

        # CAPA 2: correlación con Claude, rate-limited y sólo si hay key.
        verdict = self._maybe_correlate(fresh)
        if verdict:
            body += f" || análisis IA: {verdict}"

        print(f"[ALERTA] {title}")
        for ln in lines:
            print("  " + ln)
        if verdict:
            print("  IA: " + verdict)
        if any(self.channels.values()):
            notify(self.channels, self.cfg["name"], title, body, prio)

    def _maybe_correlate(self, fresh):
        if not self.api_key:
            return None
        now = int(time.time())
        # Sólo llamar a Claude si pasó el intervalo mínimo (control de costo).
        if now - self.last_claude < self.cfg["claude_min_interval"]:
            return None
        self.last_claude = now
        ctx = build_claude_context(self.window, fresh, self.cfg)
        try:
            raw = call_claude(self.api_key, self.model, ctx)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                ValueError, OSError) as e:
            sys.stderr.write(f"correlación IA saltada (error de API): {e}\n")
            return None
        # Preferimos el resumen del JSON; si no parsea, devolvemos el texto crudo.
        try:
            obj = json.loads(raw)
            sev = obj.get("severity", "?")
            summ = obj.get("summary", "")
            act = obj.get("recommended_human_action", "")
            return f"[{sev}] {summ} → {act}".strip()
        except (ValueError, AttributeError):
            return raw[:400]


# ---------------------------------------------------------------------------
# CLI / systemd / selftest
# ---------------------------------------------------------------------------
def build_cfg(args):
    return {
        "name": args.name, "interval": args.interval, "stall_secs": args.stall_secs,
        "fee_spike_mult": args.fee_spike_mult, "mempool_max": args.mempool_max,
        "ram_max_mb": args.ram_max_mb, "disk_max_mb": args.disk_max_mb,
        "trend_samples": args.trend_samples, "ram_growth_frac": args.ram_growth_frac,
        "claude_min_interval": args.claude_min_interval,
    }


def fetch_cross_roots(peers, timeout=8):
    out = []
    for p in peers:
        st = http_get_json(p.rstrip("/") + "/status", timeout)
        root = http_get_text(p.rstrip("/") + "/root", timeout)
        if st and root:
            out.append((st.get("next_round"), root))
    return out


def run_one_cycle(wd, args):
    sample = sample_node(args.rpc)
    cross = fetch_cross_roots(args.cross_check) if args.cross_check else []
    signals, _ = wd.cycle(sample, cross)
    if not sample.get("up"):
        print("estado: CAÍDO (el /status del nodo no respondió)")
    elif not signals:
        st = sample.get("status", {})
        print(f"estado: OK (ronda {st.get('next_round')}, "
              f"mempool {st.get('mempool_transactions')}, "
              f"fee {st.get('base_fee_per_byte')})")


def systemd_install(args):
    if os.geteuid() != 0:
        sys.exit("instalá con sudo (necesita escribir la unidad systemd).")
    self_path = os.path.realpath(sys.argv[0])
    ch = []
    for flag in ("ntfy", "discord", "slack", "webhook"):
        v = getattr(args, flag)
        if v:
            ch += [f"--{flag}", v]
    if not ch:
        sys.exit("configurá al menos un canal (--ntfy/--discord/--slack/--webhook) antes de instalar.")
    cross = []
    for c in args.cross_check:
        cross += ["--cross-check", c]
    execstart = ([sys.executable, self_path, "--daemon", "--rpc", args.rpc,
                  "--interval", str(args.interval), "--stall-secs", str(args.stall_secs),
                  "--name", args.name] + ch + cross)
    unit = "/etc/systemd/system/qchain-watchdog.service"
    # La API key (si se usa la Capa 2) se pasa por el entorno del servicio, NO en
    # la línea de comando ni en el repo: EnvironmentFile opcional.
    envline = "EnvironmentFile=-/etc/qchain-watchdog.env\n"
    content = (
        "[Unit]\nDescription=qchain runtime security watchdog (read-only, advisory)\n"
        "After=network-online.target\nWants=network-online.target\n\n"
        "[Service]\nType=simple\n" + envline
        + "ExecStart=" + " ".join(_shq(x) for x in execstart) + "\n"
        "Restart=on-failure\nRestartSec=15\n"
        "NoNewPrivileges=true\nProtectSystem=strict\nProtectHome=true\n"
        "PrivateTmp=true\n\n[Install]\nWantedBy=multi-user.target\n")
    with open(unit, "w") as f:
        f.write(content)
    os.system("systemctl daemon-reload && systemctl enable --now qchain-watchdog.service")
    print(f"instalado: {unit}")
    print("Para la Capa 2 (Claude), creá /etc/qchain-watchdog.env con:")
    print("  ANTHROPIC_API_KEY=sk-ant-...   (chmod 600)")
    print("y reiniciá:  systemctl restart qchain-watchdog")
    print("Ver:  journalctl -u qchain-watchdog -f")


def systemd_uninstall():
    if os.geteuid() != 0:
        sys.exit("desinstalá con sudo.")
    os.system("systemctl disable --now qchain-watchdog.service 2>/dev/null")
    try:
        os.remove("/etc/systemd/system/qchain-watchdog.service")
    except OSError:
        pass
    os.system("systemctl daemon-reload")
    print("watchdog desinstalado (no toca /etc/qchain-watchdog.env).")


def _shq(s):
    return "'" + s.replace("'", "'\\''") + "'" if any(c.isspace() for c in s) else s


def selftest():
    """Autotest OFFLINE de la lógica pura (sin red). Verifica cada señal."""
    cfg = {"name": "t", "interval": 15, "stall_secs": 60, "fee_spike_mult": 10,
           "mempool_max": 5000, "ram_max_mb": 3000, "disk_max_mb": 20000,
           "trend_samples": 3, "ram_growth_frac": 0.2, "claude_min_interval": 900}

    def mk(t, up=True, rnd=100, mp=0, fee=180, rss_mb=100, disk_mb=100, root="aa", apr=1200, upd=None):
        if not up:
            return {"t": t, "up": False}
        return {"t": t, "up": True,
                "status": {"next_round": rnd, "mempool_transactions": mp,
                           "base_fee_per_byte": fee, "executed_transactions": 1,
                           "update_available": upd},
                "economics": {"emission_apr_bps": apr, "peer_count": 3,
                              "total_burned": 0, "total_emitted": 0},
                "resources": {"rss_bytes": rss_mb * 1024 * 1024, "disk_bytes": disk_mb * 1024 * 1024},
                "root": root}

    def names(sigs):
        return {s["name"] for s in sigs}

    # 1) OK limpio → sin señales.
    assert evaluate_signals([mk(0), mk(15), mk(30, rnd=101)], [], cfg) == [], "OK debe estar limpio"

    # 2) RPC caído → sólo rpc_down (crítico).
    s = evaluate_signals([mk(0), mk(15, up=False)], [], cfg)
    assert names(s) == {"rpc_down"}, s

    # 3) Consenso congelado: ronda fija >= stall_secs.
    s = evaluate_signals([mk(0, rnd=100), mk(70, rnd=100)], [], cfg)
    assert "consensus_stalled" in names(s), s
    # pero si avanzó, NO.
    s = evaluate_signals([mk(0, rnd=100), mk(70, rnd=101)], [], cfg)
    assert "consensus_stalled" not in names(s), s

    # 4) Fee disparado: > 10x el piso.
    s = evaluate_signals([mk(0, fee=180), mk(15, fee=2000)], [], cfg)
    assert "fee_spike" in names(s), s

    # 5) Mempool backlog creciendo.
    s = evaluate_signals([mk(0, mp=6000), mk(15, mp=7000), mk(30, mp=8000)], [], cfg)
    sig = [x for x in s if x["name"] == "mempool_backlog"]
    assert sig and sig[0]["severity"] == "high", s

    # 6) RAM alta.
    s = evaluate_signals([mk(0, rss_mb=3100)], [], cfg)
    assert "ram_high" in names(s), s
    # RAM creciendo sostenido (por debajo del cap).
    s = evaluate_signals([mk(0, rss_mb=100), mk(15, rss_mb=200), mk(30, rss_mb=400)], [], cfg)
    assert "ram_growth" in names(s), s

    # 7) FORK: par con root distinto a la misma ronda.
    s = evaluate_signals([mk(0, rnd=100, root="aa")], [(100, "bb")], cfg)
    assert "fork" in names(s), s
    # mismo root a la misma ronda → sin fork.
    s = evaluate_signals([mk(0, rnd=100, root="aa")], [(100, "aa")], cfg)
    assert "fork" not in names(s), s
    # ronda distinta → no comparable, sin fork.
    s = evaluate_signals([mk(0, rnd=100, root="aa")], [(99, "bb")], cfg)
    assert "fork" not in names(s), s

    # 8) Emisión fuera de rango + update disponible.
    s = evaluate_signals([mk(0, apr=6000, upd="9.9.9")], [], cfg)
    assert "emission_out_of_range" in names(s) and "update_available" in names(s), s

    # 9) Capa 2 INERTE sin API key: el motor no llama a Claude.
    wd = Watchdog(cfg, {}, api_key="", model=DEFAULT_MODEL)
    assert wd._maybe_correlate([{"name": "fee_spike", "severity": "high", "detail": "x"}]) is None

    # 10) Anti-spam: la misma señal no re-alerta; una nueva sí.
    wd2 = Watchdog(cfg, {}, api_key="", model=DEFAULT_MODEL)
    _, fresh1 = wd2.cycle(mk(0, fee=2000), [])
    assert any(f["name"] == "fee_spike" for f in fresh1)
    _, fresh2 = wd2.cycle(mk(15, fee=2100), [])
    assert not any(f["name"] == "fee_spike" for f in fresh2), "no debe re-alertar la misma señal"

    # 11) build_claude_context es JSON-serializable y compacto.
    ctx = build_claude_context([mk(0, mp=6000)], [{"name": "x", "severity": "high", "detail": "y"}], cfg)
    json.dumps(ctx)
    assert ctx["fired_signals"][0]["name"] == "x"

    print("selftest OK — 11 grupos de aserciones pasaron (lógica de Capa 1 + anti-spam + Capa 2 inerte).")
    return 0


def main():
    ap = argparse.ArgumentParser(description="qchain runtime watchdog (read-only, advisory)")
    ap.add_argument("--rpc", default="http://127.0.0.1:8080", help="RPC del nodo a vigilar")
    ap.add_argument("--cross-check", action="append", default=[],
                    help="RPC de otro nodo para cross-check de fork (repetible)")
    ap.add_argument("--interval", type=int, default=15, help="segundos entre muestras (daemon)")
    ap.add_argument("--stall-secs", type=int, default=180, help="ronda fija >= esto = consenso congelado")
    ap.add_argument("--fee-spike-mult", type=int, default=10, help="base_fee > mult*piso(180) = alerta")
    ap.add_argument("--mempool-max", type=int, default=5000, help="mempool >= esto = backlog")
    ap.add_argument("--ram-max-mb", type=int, default=3000, help="RSS >= MB = alerta")
    ap.add_argument("--disk-max-mb", type=int, default=20000, help="data_dir >= MB = alerta")
    ap.add_argument("--trend-samples", type=int, default=3, help="muestras para tendencia (crecimiento)")
    ap.add_argument("--ram-growth-frac", type=float, default=0.2, help="fracción de crecimiento sostenido de RAM")
    ap.add_argument("--claude-min-interval", type=int, default=900, help="segundos mínimos entre llamadas a Claude")
    ap.add_argument("--claude-model", default=DEFAULT_MODEL, help="modelo de la Capa 2")
    ap.add_argument("--name", default=(os.uname().nodename if hasattr(os, "uname") else "nodo"),
                    help="nombre del nodo en los avisos")
    ap.add_argument("--ntfy", default=""); ap.add_argument("--discord", default="")
    ap.add_argument("--slack", default=""); ap.add_argument("--webhook", default="")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="un chequeo ahora y salir")
    mode.add_argument("--daemon", action="store_true", help="correr en loop")
    mode.add_argument("--test", action="store_true", help="mandar un aviso de prueba")
    mode.add_argument("--install", action="store_true", help="instalar servicio systemd")
    mode.add_argument("--uninstall", action="store_true", help="quitar el servicio systemd")
    mode.add_argument("--selftest", action="store_true", help="autotest offline (sin red)")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.uninstall:
        return systemd_uninstall() or 0
    if args.install:
        return systemd_install(args) or 0

    channels = {"ntfy": args.ntfy, "discord": args.discord,
                "slack": args.slack, "webhook": args.webhook}
    if args.test:
        if not any(channels.values()):
            sys.exit("configurá al menos un canal (--ntfy/--discord/--slack/--webhook).")
        notify(channels, args.name, "prueba", "si ves esto, los avisos funcionan.")
        print("aviso de prueba enviado.")
        return 0

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    cfg = build_cfg(args)
    wd = Watchdog(cfg, channels, api_key, args.claude_model)
    if api_key:
        print(f"Capa 2 (Claude) ACTIVA — modelo {args.claude_model}, "
              f"máx 1 llamada / {cfg['claude_min_interval']}s.")
    else:
        print("Capa 2 (Claude) INERTE — sin ANTHROPIC_API_KEY. La Capa 1 "
              "(heurísticas + alertas) corre igual.")
    if not any(channels.values()):
        print("AVISO: sin canal configurado — sólo imprimo el estado (no puedo notificar).")

    if args.check:
        run_one_cycle(wd, args)
        return 0

    if args.daemon:
        print(f"watchdog en marcha: {args.rpc} cada {args.interval}s "
              f"(cross-check: {len(args.cross_check)} pares).")
        while True:
            try:
                run_one_cycle(wd, args)
            except Exception as e:  # el loop NUNCA muere por un error transitorio
                sys.stderr.write(f"ciclo falló (se reintenta): {e}\n")
            time.sleep(args.interval)

    # sin modo → un chequeo (comportamiento útil por defecto)
    run_one_cycle(wd, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
