# Builds reproducibles cross-builder (roadmap #9)

**Objetivo:** que dos personas distintas, en máquinas distintas, compilando el
MISMO commit, obtengan binarios **byte-idénticos** (mismo sha256). Eso permite a
cualquiera **auditar independientemente** que los binarios publicados vienen del
código fuente publicado — sin confiar en quien los compiló.

## Qué faltaba (y qué agrega #9)

Ya estaban pinneados los DOS inputs obvios:

- **Toolchain** — `rust-toolchain.toml` fija el compilador exacto (1.94.1).
- **Dependencias** — `Cargo.lock` committeado + `--locked`.

Pero un `cargo build --release` normal **embebe ~4400 rutas absolutas** en el
binario: la ruta `$CARGO_HOME/registry/src/.../crate-x.y.z/...` de CADA
dependencia (vía `file!()`/ubicaciones de panic + debug info) y la ruta
`<workspace>/crates/.../src` de cada crate local. Esas rutas **cambian por
builder** (distinto `$HOME`/`$CARGO_HOME`, distinto directorio de checkout,
Docker `/build` vs `/home/user/...`), así que dos builders honestos del mismo
commit obtenían **sha256 DISTINTO**. El CI viejo compilaba dos veces en el MISMO
path, así que sólo probaba determinismo del compilador, no reproducibilidad
cross-builder.

**#9 cierra ese último input: las RUTAS embebidas.** Con
`--remap-path-prefix` se reescriben las dos rutas absolutas a placeholders
canónicos (`/cargo-registry` y `/qchain-src`) idénticos en todo builder. Esto
**sólo cambia los strings que se ven en un backtrace de panic / debug info**
(dicen `/qchain-src/...` en vez de la ruta real del host) — **nunca** cambia la
lógica, el consenso, el wire ni el estado. El runtime es idéntico en
comportamiento; sólo los **bytes del artefacto** se vuelven deterministas.

Medido: sin remap, dos builds en directorios + `CARGO_HOME` distintos difieren;
con remap a los mismos placeholders, salen **byte-idénticos**.

## La receta

Todo builder reproducible aplica lo mismo (centralizado en
`deploy/reproducible-env.sh`, que se sourcea):

```
SOURCE_DATE_EPOCH=1700000000                       # timestamps fijos
RUSTFLAGS="--remap-path-prefix=$CARGO_HOME/registry=/cargo-registry \
           --remap-path-prefix=<workspace>=/qchain-src"
cargo build --locked --release  (los 7 binarios)
```

más el toolchain pinneado (`rust-toolchain.toml`) y el `Cargo.lock` committeado.

## Cómo compilar reproducible

```bash
# En este host (rápido si el toolchain ya está):
deploy/reproducible-build.sh            # -> reproducible-out/SHA256SUMS

# En el contenedor HERMÉTICO canónico (base pinneada, clang/cmake para liboqs
# fijos, rutas /build + /usr/local/cargo constantes) — el builder de referencia:
deploy/reproducible-build.sh --docker
```

Ambos producen el mismo `SHA256SUMS` para un commit dado.

## Cómo auditar un release publicado (sin confiar en el servidor)

Un tercero **recompila desde el fuente** y compara contra los hashes publicados:

```bash
# contra un SHA256SUMS publicado…
deploy/verify-reproducible.sh --expected SHA256SUMS

# …o contra los hashes de binarios que ya trae la provenance firmada:
deploy/verify-reproducible.sh --provenance provenance.json
```

MATCH (exit 0) = los binarios publicados reproducen desde este fuente.
MISMATCH (exit 1) = **no** vienen de este fuente → no confiar, investigar.

Esto es **más fuerte** que `deploy/verify-provenance.sh` (que re-hashea binarios
que ya tenés): acá se **reconstruyen** desde cero y se confirma que coinciden.

## CI

El job `reproducible` de `ci.yml` (nightly + `workflow_dispatch`) ahora es
**cross-builder de verdad**: compila el builder A en el checkout y el builder B
en OTRO directorio con OTRO `CARGO_HOME`, y **exige hashes idénticos**. Si un
path se filtrara (remap incompleto), el job **falla**. `release.yml` construye
los binarios publicados con la MISMA receta (sourcea `reproducible-env.sh`), así
lo publicado es exactamente lo reproducible.

## Límites honestos

- **Pin del base por digest (una acción del operador):** `Dockerfile.reproducible`
  usa el tag `rust:1.94.1-bookworm` por defecto y acepta
  `--build-arg BASE_DIGEST=sha256:…`. Para reproducibilidad bit-for-bit a través
  del tiempo, pinnear el digest (el `clang`/`cmake` que compilan el C de liboqs
  vienen del base; un rebuild upstream del tag podría mover esos bytes). El
  comando para obtener el digest está documentado en el propio Dockerfile.
- **Cross-arquitectura (ARM vs x86):** un binario ARM y uno x86 **no** son
  byte-idénticos (código máquina distinto) — es un eje aparte. La reproducibilidad
  cross-builder de #9 es **por arquitectura** (dos builders x86 → idénticos; dos
  ARM → idénticos). El determinismo de EJECUCIÓN cross-arquitectura (que un
  contrato WASM dé el mismo resultado en ARM y x86) es otra cosa, ya cerrada por
  #195 (nan_canonicalization).
- No cambia protocolo/consenso/wire/estado — es 100% tooling de build; el runtime
  es byte-idéntico en comportamiento.
