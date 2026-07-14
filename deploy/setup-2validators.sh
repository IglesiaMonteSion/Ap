#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# setup-2validators.sh — arma una red NUEVA de 2 validadores en un solo paso,
# corriendo este script SOLO en la VPS PRINCIPAL (la que lleva la mayoría del
# stake). Reutiliza `install-node.sh` para la instalación real (Docker, imagen,
# firewall, systemd) y `qchain-genesis-build` para coordinar el génesis.
#
# Reduce todo a:
#   1) En la VPS secundaria (Oracle): sacar su "bundle" (un comando).
#   2) En la VPS principal (nueva):  correr ESTE script pasándole ese bundle.
#      → instala el principal y te imprime UN comando listo para pegar en la
#        secundaria.
#   3) En la secundaria: pegar ese comando.
#   4) Abrir el puerto P2P (9000) en el firewall de la nube de AMBAS VPS.
#
# Uso típico (en la VPS principal, dentro del repo):
#   sudo ./deploy/setup-2validators.sh \
#       --ip-principal   <IP_PUBLICA_DE_ESTA_VPS> \
#       --ip-secundario  <IP_PUBLICA_DE_LA_ORACLE> \
#       --bundle-secundario bundle-secundario.json
#
# El bundle de la secundaria se saca en la Oracle con:
#   sudo docker run --rm -v /opt/qchain:/qchain -w /qchain qchain:latest \
#       qchain bundle --keypair keypair.json
# (pegá su salida en un archivo `bundle-secundario.json`, o pasásela por stdin.)
# ---------------------------------------------------------------------------
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Valores por defecto
IP_PRINCIPAL=""
IP_SECUNDARIO=""
BUNDLE_SECUNDARIO_SRC=""
STAKE_PRINCIPAL=3000000        # 75% de 4.000.000 → >2/3: el principal avanza solo
STAKE_SECUNDARIO=1000000       # 25%
NOMBRE_PRINCIPAL="principal"
NOMBRE_SECUNDARIO="secundario"
P2P_PORT=9000
RPC_PORT=8080
QCHAIN_HOME="/opt/qchain"
HOME_SECUNDARIO="/opt/qchain"  # dónde vive la instalación en la Oracle
WALLET_BALANCE=100000000000    # 100 QCH de prueba en el génesis (1 QCH = 1e9)
IMAGE="qchain:latest"
ASUMIR_SI=0
DRY_RUN=0

log() { printf '%s\n' "$*"; }
error() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
trap 'error "algo falló en la línea $LINENO. No se pisó ninguna clave/config existente; podés volver a correr el script."' ERR

usage() {
  cat <<EOF
setup-2validators.sh — red nueva de 2 validadores (correr en la VPS principal)

Requeridos:
  --ip-principal <IP>        IP pública de ESTA VPS (la principal / mayoría de stake)
  --ip-secundario <IP>       IP pública de la VPS secundaria (Oracle)
  --bundle-secundario <src>  Archivo con el bundle de la secundaria, o '-' para leerlo
                             de stdin. (Se obtiene en la Oracle con 'qchain bundle'.)

Opcionales:
  --stake-principal <n>      Stake del principal (def $STAKE_PRINCIPAL)
  --stake-secundario <n>     Stake del secundario (def $STAKE_SECUNDARIO)
  --nombre-principal <t>     Nombre visible del principal (def "$NOMBRE_PRINCIPAL")
  --nombre-secundario <t>    Nombre visible del secundario (def "$NOMBRE_SECUNDARIO")
  --p2p-port <p>             Puerto P2P (def $P2P_PORT)
  --rpc-port <p>             Puerto RPC (def $RPC_PORT)
  --home <ruta>              Carpeta de instalación del principal (def $QCHAIN_HOME)
  --home-secundario <ruta>   Carpeta de instalación en la Oracle (def $HOME_SECUNDARIO)
  --wallet-balance <n>       Fondo (en unidades) de la wallet de prueba (def $WALLET_BALANCE)
  --image <nombre>           Imagen Docker (def $IMAGE)
  --dry-run                  Solo generar los configs e imprimir, sin instalar nada
  --yes, -y                  No preguntar nada
  -h, --help                 Esta ayuda
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --ip-principal) IP_PRINCIPAL="${2:-}"; shift 2 ;;
    --ip-secundario) IP_SECUNDARIO="${2:-}"; shift 2 ;;
    --bundle-secundario) BUNDLE_SECUNDARIO_SRC="${2:-}"; shift 2 ;;
    --stake-principal) STAKE_PRINCIPAL="${2:-}"; shift 2 ;;
    --stake-secundario) STAKE_SECUNDARIO="${2:-}"; shift 2 ;;
    --nombre-principal) NOMBRE_PRINCIPAL="${2:-}"; shift 2 ;;
    --nombre-secundario) NOMBRE_SECUNDARIO="${2:-}"; shift 2 ;;
    --p2p-port) P2P_PORT="${2:-}"; shift 2 ;;
    --rpc-port) RPC_PORT="${2:-}"; shift 2 ;;
    --home) QCHAIN_HOME="${2:-}"; shift 2 ;;
    --home-secundario) HOME_SECUNDARIO="${2:-}"; shift 2 ;;
    --wallet-balance) WALLET_BALANCE="${2:-}"; shift 2 ;;
    --image) IMAGE="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    --yes|-y) ASUMIR_SI=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) error "opción desconocida: $1 (usá --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || error "corré esto como root (o con sudo)."
[ -n "$IP_PRINCIPAL" ] || error "falta --ip-principal (la IP pública de esta VPS)."
[ -n "$IP_SECUNDARIO" ] || error "falta --ip-secundario (la IP pública de la Oracle)."
[ -n "$BUNDLE_SECUNDARIO_SRC" ] || error "falta --bundle-secundario (archivo o '-' para stdin)."

# ---------------------------------------------------------------------------
# 1. Docker + imagen
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || error "Docker no está instalado. Corré primero 'sudo ./deploy/install-node.sh --modo unirse' una vez (instala Docker y construye la imagen), o instalá Docker a mano."
docker info >/dev/null 2>&1 || error "el demonio de Docker no está corriendo (probá 'systemctl start docker')."
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "==> La imagen $IMAGE no está; construyéndola desde el código (tarda unos minutos la primera vez)..."
  DOCKER_BUILDKIT=1 docker build -t "$IMAGE" "$REPO_ROOT" >/dev/null || error "no se pudo construir la imagen."
fi
# Sanity: los binarios están en la imagen
for bin in qchain qchain-genesis-build; do
  docker run --rm "$IMAGE" "$bin" --help >/dev/null 2>&1 || error "la imagen $IMAGE no trae '$bin' — ¿es la imagen correcta?"
done

mkdir -p "$QCHAIN_HOME"
qrun() { docker run --rm -v "$QCHAIN_HOME":/qchain -w /qchain "$IMAGE" "$@"; }

# ---------------------------------------------------------------------------
# 2. Clave del principal (se reutiliza si ya existe) + su bundle
# ---------------------------------------------------------------------------
if [ ! -f "$QCHAIN_HOME/keypair.json" ]; then
  log "==> Generando la clave del validador principal..."
  qrun qchain keygen --out keypair.json >/dev/null
else
  log "==> Ya existe $QCHAIN_HOME/keypair.json, se reutiliza (no se regenera)."
fi
BUNDLE_PRINCIPAL="$(qrun qchain bundle --keypair keypair.json)"

# ---------------------------------------------------------------------------
# 3. Bundle de la secundaria (archivo o stdin)
# ---------------------------------------------------------------------------
if [ "$BUNDLE_SECUNDARIO_SRC" = "-" ]; then
  log "==> Pegá el bundle de la secundaria y terminá con Ctrl-D:"
  BUNDLE_SECUNDARIO="$(cat)"
else
  [ -f "$BUNDLE_SECUNDARIO_SRC" ] || error "no encontré el archivo de bundle: $BUNDLE_SECUNDARIO_SRC"
  BUNDLE_SECUNDARIO="$(cat "$BUNDLE_SECUNDARIO_SRC")"
fi
# Validación mínima de que es JSON de un bundle
printf '%s' "$BUNDLE_SECUNDARIO" | grep -q '"components"' \
  || error "el bundle de la secundaria no parece válido (no tiene 'components'). Sacálo en la Oracle con: docker run --rm -v /opt/qchain:/qchain -w /qchain qchain:latest qchain bundle --keypair keypair.json"

# ---------------------------------------------------------------------------
# 4. Wallet de prueba fondeada en el génesis (se reutiliza si ya existe)
# ---------------------------------------------------------------------------
if [ ! -f "$QCHAIN_HOME/wallet.json" ]; then
  qrun qchain keygen --out wallet.json >/dev/null
fi
WALLET_DIR="$(qrun qchain address --keypair wallet.json)"

# ---------------------------------------------------------------------------
# 5. Armar manifiestos + génesis + construir los dos configs
#    (01-... => node1 = principal ; 02-... => node2 = secundario, por orden de nombre)
# ---------------------------------------------------------------------------
esc_json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
NP="$(esc_json "$NOMBRE_PRINCIPAL")"
NS="$(esc_json "$NOMBRE_SECUNDARIO")"

rm -rf "$QCHAIN_HOME/manifests" "$QCHAIN_HOME/out" "$QCHAIN_HOME/genesis.json"
mkdir -p "$QCHAIN_HOME/manifests" "$QCHAIN_HOME/out"
cat > "$QCHAIN_HOME/manifests/01-principal.json" <<EOF
{"pubkey_bundle": $BUNDLE_PRINCIPAL, "listen_addr": "$IP_PRINCIPAL:$P2P_PORT", "rpc_addr": "$IP_PRINCIPAL:$RPC_PORT", "stake": $STAKE_PRINCIPAL, "name": "$NP"}
EOF
cat > "$QCHAIN_HOME/manifests/02-secundario.json" <<EOF
{"pubkey_bundle": $BUNDLE_SECUNDARIO, "listen_addr": "$IP_SECUNDARIO:$P2P_PORT", "rpc_addr": "$IP_SECUNDARIO:$RPC_PORT", "stake": $STAKE_SECUNDARIO, "name": "$NS"}
EOF
cat > "$QCHAIN_HOME/genesis.json" <<EOF
[{"address": "$WALLET_DIR", "balance": $WALLET_BALANCE}]
EOF

log "==> Construyendo la configuración de la red (génesis compartido)..."
qrun qchain-genesis-build --manifests-dir manifests --genesis genesis.json --out-dir out --round-interval-ms 1000 >/dev/null
[ -f "$QCHAIN_HOME/out/node1.json" ] && [ -f "$QCHAIN_HOME/out/node2.json" ] \
  || error "genesis-build no generó los configs esperados."

# Aviso de tolerancia a fallos según el reparto de stake
TOTAL=$((STAKE_PRINCIPAL + STAKE_SECUNDARIO))
if [ $((STAKE_PRINCIPAL * 3)) -le $((TOTAL * 2)) ]; then
  log ""
  log "NOTA: el principal NO tiene >2/3 del stake ($STAKE_PRINCIPAL de $TOTAL)."
  log "      Con este reparto, si CUALQUIERA de las dos VPS se cae, la red se frena."
  log "      Para que el principal avance solo cuando la secundaria esté caída,"
  log "      dale >2/3 del total (ej. --stake-principal 3000000 --stake-secundario 1000000)."
fi

if [ "$DRY_RUN" -eq 1 ]; then
  log ""
  log "== DRY RUN: configs generados en $QCHAIN_HOME/out/ (node1.json principal, node2.json secundario). No se instaló nada. =="
  exit 0
fi

# ---------------------------------------------------------------------------
# 6. Instalar/actualizar el PRINCIPAL
#    - Si NO había nodo: install-node.sh hace todo (firewall + systemd + reusa clave).
#    - Si YA había un nodo (p.ej. modo solo): pasar a la red de 2 validadores es
#      OTRA red (chain_id nuevo), así que install-node.sh no pisaría el config por
#      seguridad. Acá lo hacemos a mano: reemplazar config, borrar el estado viejo
#      (es otra cadena) y reiniciar el servicio ya instalado.
# ---------------------------------------------------------------------------
NODE1="$QCHAIN_HOME/out/node1.json"
if [ -f /etc/systemd/system/qchain-validator.service ]; then
  log "==> Ya había un nodo instalado; migrándolo a la red de 2 validadores (chain_id nuevo, estado desde cero)..."
  cp "$NODE1" "$QCHAIN_HOME/config.json"
  chmod 600 "$QCHAIN_HOME/config.json" 2>/dev/null || true
  rm -rf "$QCHAIN_HOME/data"
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${P2P_PORT}/tcp" >/dev/null 2>&1 || true
    ufw allow "${RPC_PORT}/tcp" >/dev/null 2>&1 || true
  fi
  systemctl restart qchain-validator || error "no pude reiniciar qchain-validator; revisá 'journalctl -u qchain-validator -e'."
  log "==> Principal migrado y reiniciado en la red nueva. La wallet/túnel siguen igual (apuntan al mismo RPC)."
else
  log "==> Instalando el validador principal (servicio systemd)..."
  "$SCRIPT_DIR/install-node.sh" --modo unirse --config "$NODE1" \
    --home "$QCHAIN_HOME" --image "$IMAGE" --yes
fi

# ---------------------------------------------------------------------------
# 7. Imprimir el comando LISTO para pegar en la secundaria (Oracle)
# ---------------------------------------------------------------------------
NODE2_B64="$(base64 -w0 "$QCHAIN_HOME/out/node2.json")"

cat <<EOF

==================================================================
 PRINCIPAL LISTO. La red nueva está definida y este nodo corriendo.
==================================================================

Wallet de prueba fondeada en el génesis:
  dirección: $WALLET_DIR
  clave:     $QCHAIN_HOME/wallet.json   (NO la compartas)

FALTAN 2 COSAS:

1) En la VPS SECUNDARIA (Oracle) — que ya generó su clave al sacar el bundle,
   y con el repo clonado (git clone ... qchain) — pegá estos DOS comandos.
   Instala el validador secundario SIN wallet ni túnel y reusa su clave:

   echo '$NODE2_B64' | base64 -d | sudo tee /tmp/node2.json >/dev/null
   cd ~/qchain && sudo ./deploy/install-node.sh --modo unirse --config /tmp/node2.json --yes

2) Abrí el puerto P2P $P2P_PORT en el FIREWALL DE LA NUBE de AMBAS VPS
   (Security List / NSG en Oracle Cloud; grupo de seguridad en la otra).
   El 'ufw' del sistema ya se abrió solo, pero el firewall de la nube va aparte.

Verificar (deberían mostrar el MISMO next_round subiendo):
  curl http://$IP_PRINCIPAL:$RPC_PORT/status
  curl http://$IP_SECUNDARIO:$RPC_PORT/status

Guardá el config de la secundaria por las dudas: $QCHAIN_HOME/out/node2.json
==================================================================
EOF
