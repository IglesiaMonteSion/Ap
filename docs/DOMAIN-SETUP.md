# Dominio propio para la wallet y QScan (URL fija con HTTPS)

Guía para pasar de la URL random del quick-tunnel a una **URL fija con tu dominio**
(ej. `wallet.qchain.com`). Esto es el **prerequisito** del puente wallet-connect
(desplegar/interactuar contratos desde QScan firmando con la wallet), porque el
allowlist de origen necesita una URL que no cambie.

## Sobre la estructura de subdominios (importante)

El subdominio va **ANTES** del dominio raíz. Si comprás `qchain.com`:

| Correcto ✅ | Incorrecto ❌ | Por qué |
|---|---|---|
| `wallet.qchain.com` | `qchain.wallet.com` | `qchain.wallet.com` es un subdominio de `wallet.com` (que NO es tuyo) |
| `scan.qchain.com` | `qchain.scan.com` | igual: el prefijo va adelante |

**Estructura recomendada** (como Solana/Ethereum: `explorer.solana.com`, etc.):

| Subdominio | Para qué |
|---|---|
| `qchain.com` | Sitio / landing (opcional) |
| `wallet.qchain.com` | La wallet |
| `scan.qchain.com` | El explorador QScan |
| `faucet.qchain.com` | El faucet (si lo exponés) |

> **No expongas el RPC por un subdominio público.** El RPC no tiene auth (ver
> `PRE-LAUNCH.md`); dejalo en `127.0.0.1`.

## Pasos (una vez que compres el dominio)

### 1. Comprá el dominio
En cualquier registrador (Namecheap, Cloudflare Registrar, Porkbun — ~USD 10/año).

### 2. Agregá el dominio a una cuenta gratis de Cloudflare
- Creá una cuenta en cloudflare.com (gratis).
- "Add a site" → ingresá `qchain.com` → Cloudflare te da 2 **nameservers**.
- En tu registrador, cambiá los nameservers del dominio por los de Cloudflare.
  (Tarda de minutos a unas horas en propagar.)

### 3. Autorizá el túnel en la VPS (una sola vez)
```bash
cloudflared tunnel login
```
Abre un navegador; elegí `qchain.com`. Eso crea `/root/.cloudflared/cert.pem`.

### 4. Levantá el túnel nombrado (URL fija)
```bash
cd ~/qchain && git pull
# Solo la wallet:
sudo ./deploy/install-tunnel.sh --hostname wallet.qchain.com
# Wallet + QScan (QScan corre en 8091 por defecto en install-indexer):
sudo ./deploy/install-tunnel.sh --hostname wallet.qchain.com \
     --qscan-hostname scan.qchain.com --qscan-port 8091
```
El script crea el túnel nombrado, escribe la config de ingress, rutea el DNS
(crea el CNAME del subdominio), e instala el servicio systemd. En 1-2 min:
- `https://wallet.qchain.com/` — la wallet, URL **fija** (sobrevive reinicios).
- `https://scan.qchain.com/` — QScan.

Cloudflare pone el certificado HTTPS. No se abre ningún puerto en el firewall.

### 5. (Cuando exista) apuntá el puente wallet-connect a esta URL
El allowlist de origen del puente wallet-connect usará exactamente
`https://wallet.qchain.com` — fija y verificable, la base de confianza para
firmar desde QScan.

## Quitar / cambiar
```bash
sudo ./deploy/install-tunnel.sh --uninstall        # baja el túnel (no borra el dominio)
```
El quick-tunnel viejo (URL random) sigue disponible corriendo el script **sin**
`--hostname`, por si querés probar sin dominio.

## Qué queda desbloqueado con el dominio fijo
1. Wallet y QScan con URL profesional y estable.
2. El **puente wallet-connect** (firmar desde QScan) — su seguridad depende del
   origen fijo.
3. Biométrico de la wallet (WebAuthn) atado a un dominio estable (hoy se rompe
   cuando la URL del quick-tunnel cambia).
