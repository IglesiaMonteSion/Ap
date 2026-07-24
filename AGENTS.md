# Protocolo obligatorio para trabajar en QChain

**Antes de escribir, modificar o eliminar código debes leer
[`docs/security/QSEP-1.md`](docs/security/QSEP-1.md).** Este archivo es el
instructivo obligatorio de QSEP-1 §19. Aplica a Claude, Codex o cualquier agente.

## No comiences implementando directamente una solicitud nueva. Primero:

1. Identifica el problema real.
2. Clasifica el cambio como **R0, R1, R2 o R3** (ver QSEP-1 §5; ante duda, el
   nivel superior).
3. Localiza la documentación y las invariantes existentes
   (`docs/INVARIANTS.md`, `docs/security/`, `CLAUDE.md`).
4. Investiga estándares, especificaciones oficiales y antecedentes.
5. Enumera los componentes afectados.
6. Produce o actualiza el RFC cuando corresponda (`docs/rfc/`, R2/R3).
7. Define las invariantes.
8. Construye un modelo de amenazas.
9. Enumera casos de abuso y caminos negativos.
10. Define compatibilidad, migración y reversión.
11. Diseña las pruebas antes de implementar.

## Prohibiciones

- **No inventes** criptografía, protocolos, formatos de firma, sistemas de
  recuperación, reglas económicas ni mecanismos de consenso.
- **No asumas que los datos son confiables** (P2P, tx, respaldos, estado
  sincronizado, RPC, WASM, firmas, certificados, dependencias, config).
- Toda cuenta se valida por **dirección, propietario, tipo, versión, longitud,
  estado y autorización**.
- Todo formato persistente, firmado o de consenso tiene **versión** y
  **decodificación estricta**. NUNCA reutilices la estructura actual para
  interpretar un formato histórico cuyos campos/variantes cambiaron: conserva la
  estructura vieja definida tal como se publicó y migra con `read_or_legacy` /
  `decode_registry`.
- Todo cálculo monetario, temporal o de rondas usa **aritmética comprobada**
  (`checked_*`), nunca overflow silencioso ni conversión truncada.
- **No uses `unwrap`, `expect` ni `panic!`** en caminos críticos sobre datos
  externos o estados recuperables.
- **No modifiques simultáneamente subsistemas no relacionados.**
- **No elimines ni debilites pruebas** para obtener un CI exitoso.

## La IA no puede

Aprobar su propio código; declarar una auditoría superada; inventar una
especificación; introducir criptografía nueva sin fuentes; eliminar pruebas para
pasar CI; cambiar invariantes sin autorización; ocultar fallos mediante valores
por defecto; fusionar directamente a la rama protegida. **La respuesta de una IA
NO es una fuente técnica** (ayuda a localizar/resumir/comparar; sus conclusiones
se verifican contra la fuente real — código, spec, vector de prueba).

## Sistema de aprendizaje (obligatorio)

Cada hallazgo se aprende UNA vez y para siempre. La memoria de **clases** de
error vive en **[`docs/security/LESSONS-LEDGER.md`](docs/security/LESSONS-LEDGER.md)**
(EC-01…EC-NN: causa raíz, invariante que la cierra, detección automática, y la
"pregunta recurrente" que toda auditoría vuelve a responder).

- **Al empezar un cambio:** leé las clases que toca; el diseño debe cerrarlas por
  construcción.
- **Al encontrar un bug:** clasificalo en el ledger (casi siempre encaja en una
  clase existente → es recurrente). Si es nuevo, agregá `EC-NN`. Registrá la
  instancia con su commit — la columna *Instancias* es la **comparación con
  errores previos** (si una clase reaparece, se endurece el DETECTOR, no sólo el
  sitio).
- **Al cerrar una auditoría:** corré `./deploy/qsep-sweep.sh` (detector heurístico
  de las clases mecánicamente detectables) **y** respondé la "pregunta recurrente"
  de CADA clase con evidencia (test/grep/línea). Registrá la auditoría en
  `docs/security/audits/`.

## Cada vulnerabilidad corregida debe producir

1. Una prueba de regresión (que reproduzca el exploit exacto y falle sin el fix).
2. Un análisis de causa raíz **registrado en `LESSONS-LEDGER.md`** (clase EC-NN).
3. Una **búsqueda de la misma clase de error en todo el repositorio** vía
   `./deploy/qsep-sweep.sh EC-NN` + la lista de TODOS los sitios revisados (no
   sólo la línea vulnerable).

## Después de implementar

1. Ejecuta formato, `cargo check`, Clippy (`-D warnings`) y las pruebas.
2. Ejecuta análisis de dependencias (`cargo audit` / `cargo deny check`).
3. Ejecuta fuzzing en parsers o límites externos afectados.
4. Comprueba las invariantes.
5. Prueba migración y reinicio.
6. Revisa el diff completo.
7. Explica los riesgos residuales.

## Reglas de honestidad

- **Nunca** declares que un cambio es seguro únicamente porque compila o porque
  sus pruebas normales pasan.
- **Nunca** declares una auditoría completa si no se revisaron las interacciones
  entre consenso, ejecución, almacenamiento, red, wallet, gobernanza, economía y
  migraciones.
- Cuando falte información, **conserva el comportamiento seguro existente** y
  documenta la incertidumbre. No inventes requisitos.

## Límite honesto de este entorno (mantenedor único + IA)

Los gates HUMANOS de QSEP-1 (§9/§12) — dos revisores independientes, uno de
seguridad; "el autor no puede ser el único aprobador"; RC congelada con sign-off;
branch protection; auditoría externa; bug bounty — **no** los puede satisfacer un
agente por sí solo. Son responsabilidad del operador humano (branch protection:
ver `docs/RELEASE-VERIFY.md`; bug bounty: `SECURITY.md`). El agente cumple todo
lo demás (investigación, invariantes, amenazas, pruebas negativas, migración
tolerante, determinismo, aritmética comprobada, causa-raíz + barrido) y **marca
explícitamente** cuál gate humano queda pendiente en cada entrega.
