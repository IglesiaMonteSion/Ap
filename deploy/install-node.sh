#!/usr/bin/env bash
# Instalador simplificado de un nodo qchain - pensado para alguien SIN
# conocimientos tecnicos: un solo comando (`sudo ./install-node.sh`) que
# hace todo lo que docs/DEPLOY.md documenta a mano (generar clave, armar
# config.json, abrir puertos, instalar el servicio systemd) con preguntas
# minimas y valores por defecto sensatos. No reemplaza el flujo manual de
# docs/DEPLOY.md (sigue existiendo para despliegues multi-region reales
# con mas control) - es la puerta de entrada rapida para la primera vez.
#
# Uso (como root o con sudo):
#   sudo ./install-node.sh [imagen-docker]
#
# La imagen por defecto es qchain:latest. Si todavia no la tenes en esta
# maquina, este script te va a avisar como conseguirla (docker load /
# docker pull / compilarla) antes de continuar.
set -euo pipefail

IMAGE="${1:-qchain:latest}"
QCHAIN_HOME="${QCHAIN_HOME:-/opt/qchain}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

decir()  { printf '\n==> %s\n' "$1"; }
error()  { printf '\nERROR: %s\n' "$1" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  error "corre este script como root (sudo ./install-node.sh)"
fi

# ---------------------------------------------------------------------------
# Paso 0: Docker
# ---------------------------------------------------------------------------
decir "Verificando Docker"
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker no esta instalado. Instalando..."
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io
else
  echo "Docker ya esta instalado."
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "La imagen '$IMAGE' no esta disponible en esta maquina todavia."
  echo "Intentando 'docker pull $IMAGE'..."
  if ! docker pull "$IMAGE" >/dev/null 2>&1; then
    error "no se pudo obtener la imagen '$IMAGE'. Copiala vos mismo primero, por ejemplo:
  docker load -i qchain-image.tar
  docker tag <lo-que-cargaste> qchain:latest
...y despues volve a correr este script."
  fi
fi
if [ "$IMAGE" != "qchain:latest" ]; then
  docker tag "$IMAGE" qchain:latest
fi
qrun() { docker run --rm -v "$QCHAIN_HOME":/qchain -w /qchain qchain:latest "$@"; }

mkdir -p "$QCHAIN_HOME"

# ---------------------------------------------------------------------------
# Reinstalacion: si ya hay una instalacion, no la pisamos por accidente
# ---------------------------------------------------------------------------
if [ -f "$QCHAIN_HOME/config.json" ] && [ -f "$QCHAIN_HOME/keypair.json" ]; then
  decir "Ya existe una instalacion en $QCHAIN_HOME"
  echo "Esto reinstalaria el SERVICIO (systemd) pero no toca tu clave, tu"
  echo "config.json, ni la carpeta data/ (tu dinero y el estado de la red"
  echo "no se pierden)."
  read -rp "¿Continuar y (re)instalar el servicio con lo que ya hay? [s/N] " resp
  case "$resp" in
    s|S|si|Si|SI) ;;
    *) echo "Cancelado. No se cambio nada."; exit 0 ;;
  esac
  SALTAR_CONFIGURACION=1
else
  SALTAR_CONFIGURACION=0
fi

if [ "$SALTAR_CONFIGURACION" -eq 0 ]; then
  decir "¿Que querés hacer?"
  echo "  1) Crear mi propia red de prueba (recomendado si es tu primera vez)"
  echo "     -> Un solo nodo, vos sos el unico validador, con una wallet"
  echo "        de prueba ya cargada de fondos para que puedas probar"
  echo "        transferencias de inmediato."
  echo "  2) Unirme a una red que ya existe (alguien te va a dar un"
  echo "     archivo config.json, o vos ya lo tenes)"
  read -rp "Elegi 1 o 2: " modo

  case "$modo" in
    1)
      decir "Generando tu clave de validador"
      qrun qchain keygen --out keypair.json
      MI_DIRECCION="$(qrun qchain address --keypair keypair.json)"
      echo "Tu direccion de validador: $MI_DIRECCION"

      decir "Generando una wallet de prueba con fondos"
      qrun qchain keygen --out wallet.json
      WALLET_DIRECCION="$(qrun qchain address --keypair wallet.json)"
      echo "Wallet de prueba: $WALLET_DIRECCION (guarda wallet.json, es tu billetera de prueba)"

      LISTEN_ADDR="0.0.0.0:9000"
      RPC_ADDR="0.0.0.0:8080"
      STAKE="1000000000"
      BUNDLE_JSON="$(qrun qchain bundle --keypair keypair.json)"

      mkdir -p "$QCHAIN_HOME/manifests" "$QCHAIN_HOME/out"
      cat > "$QCHAIN_HOME/manifests/validador1.json" <<EOF
{"pubkey_bundle": $BUNDLE_JSON, "listen_addr": "$LISTEN_ADDR", "rpc_addr": "$RPC_ADDR", "stake": $STAKE}
EOF
      cat > "$QCHAIN_HOME/genesis.json" <<EOF
[{"address": "$WALLET_DIRECCION", "balance": 1000000000000}]
EOF

      decir "Armando la configuracion de la red (config.json)"
      qrun qchain-genesis-build --manifests-dir manifests --genesis genesis.json --out-dir out --round-interval-ms 500
      cp "$QCHAIN_HOME/out/node1.json" "$QCHAIN_HOME/config.json"
      rm -rf "$QCHAIN_HOME/manifests" "$QCHAIN_HOME/out" "$QCHAIN_HOME/genesis.json"
      mkdir -p "$QCHAIN_HOME/data"
      ;;
    2)
      if [ ! -f "$QCHAIN_HOME/keypair.json" ]; then
        decir "Generando tu clave de validador"
        qrun qchain keygen --out keypair.json
      else
        echo "Ya existe una clave en $QCHAIN_HOME/keypair.json, se reutiliza."
      fi
      MI_DIRECCION="$(qrun qchain address --keypair keypair.json)"
      BUNDLE_JSON="$(qrun qchain bundle --keypair keypair.json)"

      if [ ! -f "$QCHAIN_HOME/config.json" ]; then
        decir "Necesitas un archivo config.json de quien coordina la red"
        echo "Enviale a esa persona:"
        echo "  - tu direccion de IP publica"
        echo "  - este bundle (clave publica, no es secreta):"
        echo "$BUNDLE_JSON"
        echo
        echo "Cuando te devuelvan tu config.json, copialo a:"
        echo "  $QCHAIN_HOME/config.json"
        echo "y volve a correr este script."
        exit 0
      fi
      mkdir -p "$QCHAIN_HOME/data"
      ;;
    *)
      error "opcion invalida"
      ;;
  esac
fi

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
decir "Abriendo puertos"
LISTEN_PORT="$(grep -oP '"listen_addr"\s*:\s*"[^"]*:\K[0-9]+' "$QCHAIN_HOME/config.json" | head -1 || true)"
RPC_PORT="$(grep -oP '"rpc_addr"\s*:\s*"[^"]*:\K[0-9]+' "$QCHAIN_HOME/config.json" | head -1 || true)"
LISTEN_PORT="${LISTEN_PORT:-9000}"
RPC_PORT="${RPC_PORT:-8080}"
if command -v ufw >/dev/null 2>&1; then
  ufw allow OpenSSH || true
  ufw allow "${LISTEN_PORT}/tcp" comment 'qchain p2p' || true
  ufw allow "${RPC_PORT}/tcp" comment 'qchain rpc' || true
  ufw --force enable || true
else
  echo "ufw no esta disponible - si tu proveedor usa un firewall aparte (ej. grupo de seguridad de la nube), abri los puertos $LISTEN_PORT y $RPC_PORT manualmente."
fi

if command -v timedatectl >/dev/null 2>&1; then
  timedatectl set-ntp true || true
fi

# ---------------------------------------------------------------------------
# Servicio systemd
# ---------------------------------------------------------------------------
decir "Instalando el servicio (arranca solo, y se reinicia solo si se cae)"
cp "$SCRIPT_DIR/systemd/qchain-validator.service" /etc/systemd/system/qchain-validator.service
sed -i "s#WorkingDirectory=/opt/qchain#WorkingDirectory=$QCHAIN_HOME#" /etc/systemd/system/qchain-validator.service
systemctl daemon-reload
systemctl enable --now qchain-validator

decir "Listo"
IP_PUBLICA="$(curl -fsSL --max-time 3 https://ifconfig.me 2>/dev/null || echo '<tu-ip>')"
cat <<EOF

Tu nodo esta corriendo.

  Estado de la red (pagina web):  http://$IP_PUBLICA:$RPC_PORT/
  Ver que esta haciendo el nodo:  journalctl -u qchain-validator -f
  Parar el nodo:                  systemctl stop qchain-validator
  Volver a prenderlo:              systemctl start qchain-validator

Tus archivos importantes estan en $QCHAIN_HOME:
  keypair.json   -> tu clave de validador (NO la compartas ni la borres)
  config.json    -> la configuracion de la red
  data/          -> el estado de la cadena (balances, etc), sobrevive reinicios
EOF
if [ -f "$QCHAIN_HOME/wallet.json" ]; then
cat <<EOF

Ademas te creamos una wallet de prueba ya con fondos:
  wallet.json    -> tu billetera de prueba (NO la compartas ni la borres)

Para probarla (reemplaza <direccion-destino> por cualquier direccion):
  docker run --rm -v $QCHAIN_HOME:/qchain -w /qchain qchain:latest \\
    qchain transfer --rpc http://127.0.0.1:$RPC_PORT --keypair wallet.json --to <direccion-destino> --amount 1000000
EOF
fi
