# Checklist operativa PRE-LANZAMIENTO (antes de valor real)

Runbook para endurecer una VPS validador antes de que la red maneje **valor
real**. Todo se corre **en la VPS por SSH** — este proyecto no controla tu
máquina desde afuera. Empezá con la auditoría automática y después andá cerrando
cada ítem.

> **El código ya está endurecido** (auditorías, slashing, conservación de valor,
> overflow-safety, cifrado post-cuántico opcional). Esta checklist es la capa
> **operativa/despliegue**: cómo dejás la VPS y las llaves.

## 0. Auditoría automática (read-only, no cambia nada)

```bash
cd ~/qchain && git pull
sudo ./deploy/prelaunch-check.sh            # --home /opt/qchain --rpc-port 8080
```

Imprime ✓ / ⚠ / ✗ por ítem. Cerrá los **✗** antes de valor real; los **⚠** suelen
ser "todavía no aplica hasta el cutover / valor real". Re-corré después de cada
paso para ver el progreso.

---

## 1. RPC privado (que no sea accesible desde internet)

El JSON-RPC **no tiene autenticación** (como cualquier nodo Eth/Solana):
exponerlo deja a cualquiera mandar tx y saturar el nodo. Debe estar bindeado a
`127.0.0.1` (sólo local o por túnel SSH).

- Verificá `rpc_addr` en `/opt/qchain/config.json` → debe ser `127.0.0.1:8080`.
- El instalador (`install-node.sh`) ya lo hace privado por defecto desde v6.3.3.
- Si alguna vez lo abriste, cerralo en el firewall: `sudo ufw delete allow 8080/tcp`.

## 2. Bajar el dashboard público

Si expusiste el dashboard del operador por túnel (Cloudflare/Caddy) para verlo
desde afuera, **bajalo** antes de valor real:

```bash
sudo ./deploy/install-dashboard.sh --uninstall
```

Lo que SÍ podés dejar expuesto sin riesgo: **QScan** (indexer, solo-lectura) y la
**wallet** (por túnel HTTPS). El RPC y el dashboard del operador, no.

## 3. Clave de la AUTORIDAD de tesorería en FRÍO

La clave que libera la tesorería de 100M (`treasury-authority.json`) **no debe
vivir en el server** que da a internet. Modelo:

1. Copiala a un medio **offline** (pendrive cifrado / gestor de secretos / papel).
2. **Sacala del server** (`/root/qchain-treasury/`). El validador **no la necesita
   para operar** — sólo se usa cuando querés liberar fondos.
3. Cuando liberes: montás la clave temporalmente (o firmás desde una máquina
   aparte) y corrés:
   ```bash
   docker run --rm --network host -v /ruta/temporal:/keys qchain:latest \
     qchain treasury-release --rpc http://127.0.0.1:8080 \
     --keypair /keys/treasury-authority.json --to <dir> --amount <units>
   ```
4. Desmontás/sacás la clave de nuevo.

La **wallet de prueba** de génesis (`/opt/qchain/wallet.json`, 1000 QCH) también
tiene su clave en el server — movela a frío o vaciala antes de valor real.

## 4. Endurecer SSH (sólo clave, sin root, sin password)

```bash
# Copiá tu clave pública PRIMERO (desde tu Mac) si no lo hiciste:
#   ssh-copy-id -i <tu_clave>.pub ubuntu@<ip>
sudo ./deploy/harden-ssh.sh                 # + --fail2ban  + --port <n>
```

El script **no te deja quedarte afuera**: aborta si el usuario no tiene ya una
clave autorizada, valida con `sshd -t` antes de recargar, y hace `reload` (no
`restart`) así tu sesión actual sobrevive. **Dejá esta sesión abierta y probá
una nueva antes de cerrarla.** Revertir: `sudo ./deploy/harden-ssh.sh --revert`.

## 5. Respaldos automáticos + monitoreo externo

```bash
# Respaldo CIFRADO diario de lo irreemplazable (keypair, config, wallets):
sudo ./deploy/backup-node.sh --install --remote user@host:/ruta   # scp opcional

# Aviso hacia afuera si el nodo se cae o el consenso se estanca:
sudo ./deploy/monitor-node.sh --install --url https://ntfy.sh/tu-canal
```

El backup guarda la **clave que firma bloques** (si se pierde, el validador deja
de existir), no el estado (re-sincronizable). El monitor empuja a
ntfy/Discord/Slack.

## 6. Más validadores + transporte P2P autenticado y CIFRADO

Con un solo validador, auth/cifrado están OFF (está bien). Al **sumar nodos**,
encendé el transporte autenticado (anti-spoofing) + cifrado (confidencialidad +
anti-relay), **post-cuántico** (ML-DSA + ML-KEM-768 + ChaCha20-Poly1305):

- Sumar un nodo secundario: `sudo ./deploy/install-node.sh --modo unirse ...`
  (ver `DEPLOY.md`, "Sumar un nodo SECUNDARIO").
- Encender auth+cifrado = **cutover COORDINADO**: `authenticated_transport: true`
  + `encrypted_transport: true` en el config de **TODOS** los nodos, reinicio
  simultáneo. Es wire-breaking pero **NO cambia el génesis/chain_id/estado**.
  Un mismatch (un nodo on, otro off) simplemente no se conectan.
- Para crear una red nueva ya con auth+cifrado: `install-node.sh --modo solo
  --cifrado` (implica `--autenticado`).

## 7. Gate de mainnet: el arsenal COMPLETO sobre el commit que vas a lanzar

Antes de taguear el commit del lanzamiento, corré el gate sobre **ese commit
exacto** — no sobre "más o menos lo mismo":

```bash
deploy/mainnet-gate.sh --out mainnet-gate-report.json   # exit 0 = PASS
```

Corre todo (build/clippy/tests/DST/SDK-wasm32/audit/SBOM/reproducible
cross-builder/fuzzing/sanitizers/barrido QSEP-1) **más los harness adversariales
en vivo** (`chaos-test.sh` y `byzantine-injector.sh`), y emite un reporte
determinista con un `report_hash`.

Reglas duras:

- **`INCOMPLETE` NO es aprobado.** Si un chequeo obligatorio se saltea (falta
  `cargo-audit`, falta `nightly`, usaste un `--skip-*`), el script sale con
  código 2. No lances con eso.
- **Verificación independiente:** que un segundo operador corra el mismo script
  sobre el mismo commit y compare el `report_hash`. Si coinciden, dos partes
  verificaron los mismos bytes con el mismo arsenal.
- En GitHub: el workflow `mainnet-gate.yml` (manual o al pushear la tag) corre lo
  mismo **sin caché** y sube el reporte como artefacto.

## 8. Auditoría externa + bug bounty (proceso humano)

Antes de valor real serio: contratar una **auditoría externa** independiente y
abrir un **bug bounty** público. Esto es un proceso de semanas con terceros,
fuera del alcance de una sesión de código — pero es el paso que ninguna
herramienta reemplaza.

---

## Orden recomendado

1. `prelaunch-check.sh` (ver el estado).
2. RPC privado (1) + bajar dashboard (2) — cierra la superficie de internet.
3. SSH (4) — con tu clave ya copiada, sin quedarte afuera.
4. Backups + monitoreo (5).
5. Tesorería + wallet de prueba en frío (3).
6. Sumar validadores + auth/cifrado (6) cuando estés listo para descentralizar.
7. **Gate de mainnet (7) sobre el commit final** → `PASS`, y que un segundo
   operador reproduzca el mismo `report_hash`.
8. Auditoría externa (8) antes de valor real serio.
9. Re-corré `prelaunch-check.sh` → todo ✓.
