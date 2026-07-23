# QChain — Plan de recuperación ante incidentes (runbook)

Procedimiento documentado y **probado** para restaurar un validador o la red ante
fallos. Todo esto debe ensayarse en una testnet ANTES del lanzamiento de mainnet
(punto #9 del checklist pre-mainnet, y escenarios del `PRE-LAUNCH-TESTPLAN.md`).

> **Principio rector — fail-loud, nunca degradado.** El nodo se **niega a
> arrancar** sobre estado corrupto (params, registro cripto, staking global,
> pools, tesorería, y el registro de validadores) en vez de correr sobre valores
> por defecto silenciosos. Un halt es recuperable; un fork silencioso con dinero
> real no. Recuperar = restaurar un estado bueno, no forzar el arranque.

Lo que es **irreemplazable** vs **re-sincronizable**:

| Dato | ¿Recuperable de la red? | Cómo protegerlo |
|---|---|---|
| `keypair.json` (clave del validador) | **NO** — si se pierde, ese validador deja de existir | backup cifrado (`backup-node.sh`), clave fría/HSM (`remote_signer`) |
| clave de firmante de tesorería | **NO** | clave fría, multisig M-de-N (una pérdida no es fatal → rotar con `SetSigners`) |
| `config.json` | reconstruible | backup + está en el repo del operador |
| `data/` (estado, DAG, recibos) | **SÍ** — state-sync + DAG re-sync desde pares | backup opcional; en última instancia se borra y re-sincroniza |

Herramientas ya existentes que este runbook usa: `deploy/backup-node.sh`
(backup cifrado AES-256 de lo irreemplazable), `deploy/update-node.sh` (update
con health-check + rollback), state-sync verificado por quórum/ancla (§ config
`state_sync_*`), persistencia atómica redb (estado+ronda+economía en un commit),
flush en SIGTERM, y el `soak-canary.py` / `chaos-test.sh` para validar la
recuperación bajo caos.

---

## 0. Antes de cualquier incidente (preparación)

1. **Backups automáticos** de las claves + config:
   `sudo ./deploy/backup-node.sh --install --remote user@host:/ruta` (timer
   diario, cifrado, copia remota — durabilidad real si la VPS muere).
2. **Clave de consenso fuera del proceso** (opcional pero recomendado en
   mainnet): `remote_signer` → la clave vive en `qchain-remote-signer`, no en el
   nodo expuesto.
3. **Tesorería multisig** (v8.4.0): ninguna clave sola controla los fondos; una
   clave perdida/comprometida se **rota** con `treasury-propose-set-signers`.
4. **Monitoreo con aviso**: `sudo ./deploy/monitor-node.sh --install` (avisa por
   ntfy/Discord/Slack si el nodo cae o el consenso se estanca).
5. **Anotar**: `chain_id`, `network_fingerprint` (se loguea al arrancar), la
   ruta del `data_dir`, y el trust-anchor de state-sync (`state_sync_trusted_root`
   / `_round`) — necesarios para verificar una restauración.

---

## 1. Corrupción de la base de datos (`data/`)

**Síntoma**: el nodo arranca y hace `FATAL: … present but does not decode —
refusing to start on corrupt state`, o `VALIDATOR_REGISTRY … corrupt`, o
`SledStore/redb open failed`.

**Recuperación** (el estado es re-sincronizable — NO toques las claves):

```bash
sudo systemctl stop qchain-validator
# 1) Conservar las claves/config; descartar SÓLO el estado corrupto:
sudo mv /opt/qchain/data /opt/qchain/data.corrupt.$(date +%s)
# 2) Arrancar con state-sync configurado (state_sync_peers + trust anchor):
sudo systemctl start qchain-validator
```

El nodo descarga un snapshot **verificado** (raíz reconstruida == raíz reclamada,
+ quórum/ancla), fija `next_round`/checkpoint a la ronda del snapshot, y retoma
consenso. Verifica con `curl 127.0.0.1:8080/root` que la raíz coincide con la de
un par sano a la misma ronda ejecutada.

> Si NO hay pares (red de un solo validador) y no hay backup del `data/`: el
> estado no es recuperable de la nada → restaurar de un backup del `data/`, o —
> si es aceptable — relanzar con génesis (última opción, sólo pre-valor).

---

## 2. Pérdida de un nodo (VPS muerta / disco perdido)

El validador es su **clave**, no su máquina.

```bash
# En una VPS nueva:
git clone <repo> && cd <repo>
sudo ./deploy/install-node.sh --modo unirse --red-config <config-publico> \
     --sync-peer http://<par-vivo>:8080
# Restaurar la MISMA keypair.json del backup cifrado (NO generar una nueva):
sudo ./deploy/backup-node.sh --restore <backup.tar.gz.enc> --into /opt/qchain
sudo systemctl restart qchain-validator
```

Con la misma clave, es el MISMO validador (misma identidad de consenso). El
estado se re-sincroniza por state-sync. **Nunca** generes una clave nueva para
"recuperar" — sería un validador distinto.

---

## 3. Pérdida / compromiso de una clave de validador

- **Clave de consenso comprometida** (no puede mover fondos gracias a #193-B —
  el bono y las comisiones van a la `withdrawal_address` fría): `v7-begin-exit`
  con la clave FRÍA de operador, esperar el unbonding, `v7-withdraw-bond`; luego
  re-registrar con una clave de consenso nueva. Una fuga de la clave de consenso
  puede firmar/equivocar (slasheable) pero **no drena el bono**.
- **Clave de operador (fría) perdida**: el bono queda inmovilizable por esa vía;
  es la razón de mantenerla en frío/HSM y respaldada.

---

## 4. Pérdida / compromiso de una clave de TESORERÍA (multisig)

La tesorería es M-de-N (v8.4.0), así que **una** clave perdida/comprometida NO
es fatal:

```bash
# Un firmante propone rotar el set (reemplaza la clave perdida por una nueva):
qchain treasury-propose-set-signers --keypair firmante-vivo.json \
    --signer <nuevo> --signer <b> --signer <c> --signer <d> --signer <e> --threshold 3
# Otros firmantes aprueban hasta el umbral; tras el timelock, cualquiera ejecuta.
```

`SetSigners` reemplaza el set completo y **descarta las operaciones pendientes**
(una propuesta aprobada bajo el set viejo no ejecuta bajo el nuevo). El timelock
da a la comunidad tiempo de ver el cambio; los límites por-op/por-ventana acotan
el daño de un compromiso mientras se rota.

---

## 5. Restauración desde snapshot / backup (ensayo)

- **Desde state-sync** (sin backup): §1.
- **Desde backup de `data/`** (si se respaldó): `systemctl stop`, restaurar el
  `data/` del backup, `systemctl start`, verificar `/root` y que una transferencia
  nueva ejecuta y converge.
- **Verificación obligatoria** tras cualquier restauración: el `chain_id`
  coincide, la raíz a una ronda ejecutada coincide con un par sano, y una
  transferencia de prueba ejecuta y converge en todos los nodos vivos.

---

## 6. Recuperación tras un ataque

1. **Contener**: si el RPC público está bajo flood, bajarlo del borde
   (`--uninstall` del túnel/dashboard) y dejar el validador en loopback/privado;
   los rate-limits (`/tx`, `/simulate`) y las cuotas de admisión ya acotan el
   trabajo. Un flood NO puede robar fondos (aritmética chequeada + autorización
   en el borde WASM + firmas), sólo intentar DoS.
2. **Equivocación de un validador**: cualquiera reporta la evidencia
   (`report-equivocation`) → se quema su bono (slashing determinista).
3. **Gobernanza apurada**: los guardianes pausan `Execute` con el multisig de
   emergencia (`emergency-pause`) — freno sin confiscación, estructuralmente
   incapaz de mover fondos.
4. **Post-mortem**: comparar roots cross-nodo (`soak-canary.py`) para confirmar
   que no hubo fork; si un nodo divergió, tratarlo como corrupción (§1) y
   re-sincronizar desde los honestos.

---

## 7. Qué ENSAYAR antes de mainnet (checklist)

Correr en una testnet con varios validadores, con `chaos-test.sh` + observando
`soak-canary.py`:

- [ ] Matar y reiniciar un validador (SIGTERM y kill-9) → converge sin fork/pérdida.
- [ ] Borrar el `data/` de un nodo y re-sincronizar por state-sync → raíz verificada.
- [ ] Reinicio en el BORDE de una época → converge.
- [ ] Corromper el `data/` → el nodo se NIEGA a arrancar (fail-loud), y §1 lo recupera.
- [ ] Un registro de validadores en formato viejo → MIGRA y arranca (no brickea).
- [ ] Restaurar un validador en una VPS nueva desde el backup cifrado → misma identidad.
- [ ] Rotar una clave de tesorería con `SetSigners` → el firmante viejo ya no puede.
- [ ] Reportar una equivocación → el bono se quema.
- [ ] Pausar/despausar gobernanza con los guardianes → los fondos nunca se tocan.

**Criterio de aprobación**: varias semanas sin raíces divergentes, sin supply
inconsistente, sin pérdida de tx finalizadas, sin crecimiento no acotado de
RAM/disco, y sin congelamiento tras reinicios.
