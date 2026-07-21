# Revisión de seguridad con IA en cada PR (tarea #183, Fase A)

Un **GitHub Action que audita el diff de cada Pull Request** con la API de Claude
y postea los hallazgos como un comentario en el PR. Es la **Fase A** del agente de
seguridad IA descrito en `CLAUDE.md` (el auditor de *dev-time*); la Fase B (el
vigilante de *runtime* en producción) es un incremento futuro aparte.

## Qué hace y qué NO hace

- **Es de AVISO (advisory).** Postea un comentario con hallazgos; **NUNCA bloquea
  el PR** ni lo marca como fallido. Un humano decide.
- **Read-only sobre el código.** Sólo lee el diff del PR y postea un comentario.
  No toca el consenso, ni las claves, ni producción.
- **No guarda ninguna clave en el repo.** La API key vive como un *secret* del
  repositorio (variable de entorno en el runner), nunca en el código.
- **Modelo de seguridad del CI (QCH-CI-001 corregido):** el workflow corre bajo
  `pull_request_target`, así que TANTO su definición COMO el script del auditor se
  toman de la rama BASE de confianza, nunca del HEAD del PR; el job que tiene la
  `ANTHROPIC_API_KEY` **nunca ejecuta el código del PR** (sólo lee el diff como
  DATO con `git diff`). Un PR malicioso no puede modificar lo que corre ni
  exfiltrar el secret. Como agente es read-only sobre el diff y advisory: nunca
  bloquea el PR ni mueve fondos ni toca el consenso.
- **Actualiza su propio comentario en el lugar** (marcador oculto) en vez de
  spammear uno nuevo por cada push.

## Está INERTE hasta que lo actives

El workflow (`.github/workflows/ai-security-review.yml`) ya vive en el repo, pero
**no hace nada hasta que agregues el secret**. Sin la API key el job corre y sale
limpio habiendo impreso un aviso.

### Activarlo (una vez)

1. Conseguí una API key de Anthropic en <https://console.anthropic.com>.
2. En el repo: **Settings → Secrets and variables → Actions → New repository
   secret**.
3. Nombre: `ANTHROPIC_API_KEY`. Valor: tu key. Guardar.

A partir de ahí, cada PR (abierto / actualizado / reabierto) recibe la revisión.

### Costo y modelo

Corre una llamada a la API por PR (y por push al PR). El diff se acota a ~200 KB
para acotar el costo por revisión. El modelo por defecto es un balance razonable
para un auditor frecuente; se puede cambiar editando `CLAUDE_MODEL` en el
workflow. Para juicio más profundo se puede subir a un modelo más capaz (más
caro); para chequeos muy frecuentes, a uno más barato — el patrón "Haiku para lo
frecuente, escalar a Opus para lo profundo" que documenta `CLAUDE.md`.

### Desactivarlo

Borrá el secret `ANTHROPIC_API_KEY` (vuelve a quedar inerte) o borrá el archivo
`.github/workflows/ai-security-review.yml`.

## Qué revisa

El *system prompt* (en `.github/scripts/ai_security_review.py`) codifica los
invariantes de seguridad del proyecto: conservación de valor, determinismo/no-fork
(nada que alimente el consenso puede depender de reloj/RNG/f64-no-canónico/orden
de iteración de HashMap ni de valores locales por-nodo), overflow-safety
(release corre `overflow-checks=true` → un `+` que desborda es un halt
determinista), crecimiento acotado (la clase de OOM recurrente), firmas
domain-tagged y verify PQC fail-closed, IDs de singleton pinneados, borde de
autorización WASM (débito sólo si firmante o program-owned; sin acuñar; sin
aliasing de cuentas), admisión que acota trabajo antes del verify PQC, y el
folding en `chain_id`. Pide reportar **sólo hallazgos reales de seguridad**
introducidos por el diff, con severidad + `archivo:línea`, o `No security
findings.` si está limpio.

## Límite honesto

Es un auditor de *dev-time* con latencia de la CI — **avisa, no frena** un
problema en vivo (las defensas reales siguen siendo las on-chain ya construidas:
overflow-checks, conservación, slashing, cotas). Como todo LLM puede tener falsos
positivos; es una capa **ENCIMA** de la revisión humana + el CI de Rust
(clippy/tests), no un reemplazo. La Fase B (vigilante de runtime de dos capas —
heurísticas baratas + correlador Claude — leyendo los endpoints que el nodo ya
expone) queda como incremento futuro, a arrancar cuando la wallet esté en
producción con usuarios reales.
