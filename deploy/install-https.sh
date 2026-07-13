#!/usr/bin/env bash
# install-https.sh — pone HTTPS real delante de la wallet, SIN comprar dominio.
#
# Por qué hace falta: la wallet no-custodial (la que NO pide contraseña, con la
# clave viviendo en tu navegador) usa WebCrypto para cifrar tu clave. Los
# navegadores solo habilitan WebCrypto en un "contexto seguro": HTTPS o
# localhost. Sobre http:// plano queda desactivado y la wallet no puede
# funcionar. Este script instala Caddy como proxy HTTPS delante de la wallet y
# saca un certificado real de Let's Encrypt automáticamente.
#
# El truco para no comprar dominio: usa sslip.io, un DNS público y gratuito que
# resuelve CUALQUIER "IP-con-guiones.sslip.io" a esa IP. Ej: si tu VPS es
# 129.80.59.17, el dominio 129-80-59-17.sslip.io apunta ahí sin configurar nada,
# y Let's Encrypt le puede emitir un certificado válido de verdad.
#
# Uso (en la VPS, como root):
#   sudo ./deploy/install-https.sh                 # detecta la IP pública sola
#   sudo ./deploy/install-https.sh --ip 129.80.59.17
#   sudo ./deploy/install-https.sh --dominio wallet.midominio.com  # si SÍ tenés dominio
#   sudo ./deploy/install-https.sh --wallet-port 8090 --email vos@correo.com
#
# IMPORTANTE — el firewall de la nube: Let's Encrypt valida por el puerto 80, y
# el navegador entra por el 443. En Oracle Cloud (y similares) tenés que ABRIR
# 80 y 443 en la Security List de la consola web ADEMÁS del firewall del SO
# (esto último lo hace el script). Si no, el certificado nunca se emite.
set -Eeuo pipefail

IP=""
DOMINIO=""
WALLET_PORT="8090"
EMAIL=""
ASSUME_YES=0

error() { echo "ERROR: $*" >&2; exit 1; }
trap 'error "falló en la línea $LINENO. Revisá el mensaje de arriba."' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --ip) IP="${2:-}"; shift 2 ;;
    --dominio|--domain) DOMINIO="${2:-}"; shift 2 ;;
    --wallet-port) WALLET_PORT="${2:-}"; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '1,30p'; exit 0 ;;
    *) error "opción desconocida: $1 (usá --help)" ;;
  esac
done

[ "$(id -u)" = "0" ] || error "corré esto con sudo (necesita instalar Caddy y abrir puertos)."

# ---------------------------------------------------------------------------
# Resolver el dominio HTTPS
# ---------------------------------------------------------------------------
if [ -z "$DOMINIO" ]; then
  if [ -z "$IP" ]; then
    echo "Detectando la IP pública..."
    IP="$(curl -fsSL --max-time 5 https://ifconfig.me 2>/dev/null || true)"
    [ -n "$IP" ] || IP="$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    [ -n "$IP" ] || error "no pude detectar la IP pública. Pasala a mano con --ip <tu-ip>."
  fi
  # Validación básica de IPv4.
  echo "$IP" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || error "«$IP» no parece una IPv4 válida."
  DOMINIO="$(echo "$IP" | tr '.' '-').sslip.io"
  echo "Usando dominio gratis de sslip.io:  $DOMINIO  ->  $IP"
fi

[ -n "$EMAIL" ] || EMAIL="admin@${DOMINIO}"

echo
echo "  Dominio HTTPS:   https://$DOMINIO"
echo "  Wallet local:    http://127.0.0.1:$WALLET_PORT  (Caddy hace de proxy)"
echo "  Email TLS:       $EMAIL  (solo para avisos de Let's Encrypt)"
echo
if [ "$ASSUME_YES" -ne 1 ]; then
  read -rp "¿Sigo? [s/N] " R; case "$R" in s|S|si|Si|y|Y) ;; *) echo "Cancelado."; exit 0 ;; esac
fi

# ---------------------------------------------------------------------------
# Instalar Caddy si falta (repositorio oficial)
# ---------------------------------------------------------------------------
if ! command -v caddy >/dev/null 2>&1; then
  echo "Instalando Caddy..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl gnupg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
      | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
      | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    apt-get update -y
    apt-get install -y caddy
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y 'dnf-command(copr)'
    dnf copr enable -y @caddy/caddy
    dnf install -y caddy
  else
    error "no reconozco el gestor de paquetes. Instalá Caddy a mano: https://caddyserver.com/docs/install"
  fi
fi

# ---------------------------------------------------------------------------
# Caddyfile: proxy HTTPS -> wallet local. Caddy saca y renueva el cert solo.
# ---------------------------------------------------------------------------
echo "Escribiendo /etc/caddy/Caddyfile..."
cat > /etc/caddy/Caddyfile <<EOF
# Generado por qchain deploy/install-https.sh
{
    email $EMAIL
}

$DOMINIO {
    encode gzip zstd
    reverse_proxy 127.0.0.1:$WALLET_PORT
}
EOF

# ---------------------------------------------------------------------------
# Firewall del SO: abrir 80 (validación TLS) y 443 (tráfico HTTPS).
# El firewall de la NUBE (Oracle Security List, etc.) se abre aparte -> recordatorio al final.
# ---------------------------------------------------------------------------
echo "Abriendo 80 y 443 en el firewall del sistema..."
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp comment 'caddy http-01' || true
  ufw allow 443/tcp comment 'caddy https' || true
elif command -v iptables >/dev/null 2>&1; then
  for P in 80 443; do
    if ! iptables -C INPUT -p tcp --dport "$P" -j ACCEPT 2>/dev/null; then
      iptables -I INPUT 1 -p tcp --dport "$P" -j ACCEPT || true
    fi
  done
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Arrancar/recargar Caddy
# ---------------------------------------------------------------------------
echo "Arrancando Caddy..."
systemctl enable caddy >/dev/null 2>&1 || true
systemctl restart caddy
sleep 2
systemctl is-active --quiet caddy || error "Caddy no arrancó. Mirá: journalctl -u caddy -e --no-pager"

echo
echo "==========================================================================="
echo "  HTTPS instalado."
echo
echo "  Abrí la wallet (sin contraseña, clave en tu navegador):"
echo "      https://$DOMINIO/"
echo
echo "  El certificado tarda ~10-30 segundos la primera vez (Let's Encrypt)."
echo "  Si el navegador da error de certificado, esperá un minuto y recargá."
echo
echo "  >>> FALTA UN PASO EN LA CONSOLA DE TU NUBE <<<"
echo "  Abrí los puertos 80 y 443 (TCP) en la Security List / firewall de la nube"
echo "  (Oracle Cloud: Networking > VCN > Security Lists > Ingress Rules)."
echo "  Sin eso, Let's Encrypt no puede validar y el certificado nunca sale."
echo
echo "  Ver el estado de Caddy:   journalctl -u caddy -e --no-pager"
echo "==========================================================================="
