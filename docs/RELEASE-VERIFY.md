# Cadena de construcción verificable (release-verify)

Objetivo: **antes de un release final debe existir CI verde sobre EL MISMO commit
y sobre los MISMOS artefactos publicados**, y cualquiera debe poder verificar —
sin confiar en el servidor — que el binario que corre, la imagen que despliega y
el JS/WASM que su navegador ejecuta salieron TODOS del commit firmado.

La pieza central es una **provenance** (`provenance.json`) que RELACIONA:

```
commit  ->  version  ->  binarios  ->  imagen de despliegue  ->  wasm de la wallet
```

## Qué corre y dónde

| Control | Dónde | Cuándo |
|---|---|---|
| Tests completos (incl. DST 11/11 + ataques WASM + soundness STARK) | `ci.yml` job `test` | cada push/PR |
| Clippy sin advertencias (`-D warnings`) | `ci.yml` job `test` + `sdk` | cada push/PR |
| `cargo audit` (advisories RustSec) | `ci.yml` job `audit` | cada push/PR |
| SBOM CycloneDX (artefacto) | `ci.yml` job `sbom` | cada push/PR |
| SDK + plantillas a wasm32 | `ci.yml` job `sdk` | cada push/PR |
| **Fuzzing** (cargo-fuzz, 2 targets del wire) | `ci.yml` job `fuzz` | nightly + manual |
| **Sanitizers** (ASan/UBSan sobre los deserializadores) | `ci.yml` job `sanitizers` | nightly + manual |
| **Builds reproducibles** (2 builds → hashes idénticos) | `ci.yml` job `reproducible` | nightly + manual |
| **Gate de release** (build+clippy+tests+audit + tag==version) | `release.yml` job `gate` | al pushear tag `vX.Y.Z` |
| **Binarios + imagen + provenance (+ firma)** | `release.yml` job `provenance` | tras el gate verde |

Los jobs pesados (fuzz/sanitizers/reproducible) corren de noche (`cron 04:00 UTC`)
y a demanda (`workflow_dispatch`), no en cada push, para no volver lento el gate
rápido. El **release** los ata: sus artefactos firmados sólo se producen si el
gate está verde sobre el commit tagueado, y la tag debe coincidir con la versión
del `Cargo.toml`.

## Cómo cortar un release firmado

1. Bumpeá la versión (`deploy/bump-version.sh X.Y.Z`), actualizá notas, commiteá.
2. Asegurate de que el CI esté verde sobre ese commit en la rama.
3. Creá y pusheá la tag (firmada con tu clave GPG):
   ```bash
   deploy/sign-release.sh --tag vX.Y.Z --image qchain:vX.Y.Z   # localmente: SBOM + provenance + manifiesto + firma
   git push origin vX.Y.Z
   ```
   El push de la tag dispara `release.yml`, que **re-corre el gate** sobre ese
   commit y, si pasa, construye los binarios de release + la imagen, genera la
   provenance (atando el digest de la imagen y los hashes de los binarios/wasm),
   y — si el secret `GPG_PRIVATE_KEY` está configurado — firma `provenance.json`
   y `SHA256SUMS`, publicando todo en el GitHub Release.

### El secret de firma (paso humano)

La firma es del maintainer; el CI sólo la aplica si le das la clave:

- **Settings → Secrets and variables → Actions → New repository secret**
  - `GPG_PRIVATE_KEY` = tu clave privada exportada en ASCII armor
    (`gpg --armor --export-secret-keys <KEYID>`).
  - `GPG_PASSPHRASE` (opcional) = la passphrase de esa clave.

Sin el secret, el release igual publica `provenance.json` + `SHA256SUMS` SIN
firma — la **cadena de hashes sigue siendo verificable**, sólo falta la firma
que prueba que fuiste vos. (Mismo patrón inerte que la GitHub Action de auditoría IA.)

## Cómo un verificador comprueba la cadena

```bash
# 1) Verificá la FIRMA de la provenance (que la firmó el maintainer):
gpg --import qchain-release-pubkey.asc          # publicada en el Release
gpg --verify provenance.json.asc provenance.json

# 2) Checkouteá el commit que la provenance declara y verificá TODO lo que tengas:
git checkout <commit-de-la-provenance>
deploy/verify-provenance.sh --provenance provenance.json \
  --bin-dir target/release --image qchain:vX.Y.Z
```

`verify-provenance.sh` recomputa localmente los hashes de: el commit (HEAD), la
versión (`Cargo.toml`), el source (Cargo.lock/Dockerfile/rust-toolchain.toml), los
binarios, los assets de la wallet (HTML/app.js/glue/wasm) y — si le pasás
`--image` y tenés docker — el id de la imagen, y los compara contra la provenance
firmada. Sale `!=0` si algo NO coincide. Un campo `null` (artefacto que no tenés
localmente) se saltea; sólo compara lo presente.

La misma huella del WASM/JS de la wallet la muestra la app en **Ajustes →
'Seguridad · verificación de la app'** (`GET /api/version`) — comparala contra la
provenance firmada para confirmar que el navegador ejecuta exactamente esos bytes.

## Protección de rama + revisión obligatoria (lo TENÉS que activar vos)

Esto NO es código: son **settings del repo en GitHub**, que sólo un admin puede
tocar. El repo ya trae `.github/CODEOWNERS` (reemplazá `@owner` por tu handle real).
Activá en **Settings → Branches → Add branch protection rule** sobre la rama por
defecto:

- ✅ **Require a pull request before merging** (revisión obligatoria antes de fusionar)
  - ✅ **Require approvals** (al menos 1)
  - ✅ **Require review from Code Owners**
- ✅ **Require status checks to pass before merging** → seleccioná los checks del
  CI (`test`, `sdk`, `audit`, `sbom`) → **CI verde sobre el commit antes de fusionar**.
  - ✅ **Require branches to be up to date before merging**
- ✅ **Require signed commits** (opcional pero recomendado, va con la firma GPG).
- ✅ **Do not allow bypassing the above settings** (aplica también a admins).

Vía CLI (necesita un token con permiso de admin del repo):

```bash
gh api -X PUT repos/<owner>/<repo>/branches/<rama>/protection \
  -H "Accept: application/vnd.github+json" \
  -f 'required_pull_request_reviews[require_code_owner_reviews]=true' \
  -F 'required_pull_request_reviews[required_approving_review_count]=1' \
  -f 'required_status_checks[strict]=true' \
  -f 'required_status_checks[contexts][]=test' \
  -f 'required_status_checks[contexts][]=audit' \
  -f 'enforce_admins=true' -f 'restrictions=' 2>/dev/null
```

## Límites honestos

- **Firma = paso humano.** El CI no puede firmar por vos; sin el secret
  `GPG_PRIVATE_KEY` los artefactos salen sin firma (la cadena de hashes igual
  se verifica). La confianza raíz es tu clave pública publicada fuera de banda.
- **Protección de rama / revisión obligatoria = settings del repo.** No se pueden
  activar desde el código; las documentamos y las activás vos en GitHub (arriba).
- **Reproducibilidad bit-for-bit.** El job `reproducible` prueba que DOS builds
  del mismo commit, con el toolchain pinneado + `Cargo.lock` + `--locked` +
  `SOURCE_DATE_EPOCH`, dan binarios con el MISMO sha256 EN EL MISMO entorno. La
  reproducibilidad total ENTRE máquinas distintas (otro SO/CPU) requiere además
  un entorno de build hermético (contenedor idéntico) — el Dockerfile pinneado se
  acerca, pero garantizarlo cross-host es un esfuerzo aparte.
- **Sanitizers acotados.** ASan/UBSan corren sobre los crates de wire PUROS-Rust
  (core/storage/stark), no sobre el workspace completo: un sanitizer sobre todo
  tropieza con `liboqs` en C (firmas PQC), cuyo análisis de canal-lateral /
  memory-safety es un proceso externo formal aparte (#185), no un job de CI.
- **Fuzzing acotado en CI.** Cada target corre 120s por noche (smoke); una
  campaña larga se corre a demanda subiendo `-max_total_time`.
- La firma de la IMAGEN en un registro (cosign/sigstore) no está cableada porque
  hoy la imagen se construye por-host desde el `Dockerfile` (no hay push a un
  registro central); la provenance ata su id/digest local. Si se publica a un
  registro, `cosign sign` + referenciar el digest en la provenance es el follow-up.
