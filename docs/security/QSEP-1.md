# QSEP-1 — Protocolo de Ingeniería y Desarrollo Seguro de QChain

- **Versión:** 1.0
- **Estado:** Obligatorio
- **Aplicación:** Todo el repositorio QChain
- **Regla principal:** Ninguna función, modificación, migración o dependencia
  nueva puede implementarse directamente sin pasar por este protocolo.

> Este archivo es la copia canónica del protocolo. El instructivo obligatorio
> para agentes de IA vive en [`/AGENTS.md`](../../AGENTS.md) y el resumen de
> cumplimiento (qué está hecho / parcial / gap) en
> [`docs/security/README.md`](./README.md).

---

## 1. Objetivo

Establece el procedimiento obligatorio para investigar, diseñar, implementar,
probar, revisar y publicar cualquier cambio en QChain. Su propósito es evitar
que: se programe antes de comprender el problema; se introduzcan
vulnerabilidades por decisiones improvisadas; una corrección local rompa otra
parte del sistema; se inventen mecanismos criptográficos o económicos sin
fundamento; las migraciones dañen estados existentes; una función llegue a
producción sólo porque compila; las vulnerabilidades corregidas reaparezcan.
QChain se construye mediante **seguridad por diseño**, no por correcciones
posteriores.

## 2. Alcance

Aplica obligatoriamente a: funciones nuevas, correcciones, refactorizaciones,
consenso, economía, criptografía, red P2P, transacciones, almacenamiento,
migraciones de estado, gobernanza, tesorería, staking/recompensas, wallet,
recuperación de claves, contratos WASM, RPC/API, firmantes remotos,
dependencias, configuración, génesis, CI/CD, herramientas administrativas, y
**código generado con IA**. Un cambio aparentemente pequeño DEBE seguir el
protocolo cuando pueda afectar seguridad, fondos, consenso, disponibilidad o
compatibilidad.

## 3. Lenguaje obligatorio

- **DEBE**: requisito obligatorio.
- **NO DEBE**: acción prohibida.
- **DEBERÍA**: requisito esperado; toda excepción se justifica.
- **PUEDE**: decisión opcional.
- **BLOQUEANTE**: impide fusionar o publicar.

"Parece seguro", "debería funcionar", "probablemente" o "creo que" **no** son
evidencia técnica.

## 4. Principios inviolables

1. **No se programa primero.** Antes de escribir código se comprende: el
   problema; el comportamiento esperado; las reglas que nunca pueden romperse;
   los posibles atacantes; los datos afectados; la compatibilidad con estados
   anteriores; cómo probarlo; cómo revertirlo.
2. **No se confía sólo en el camino correcto.** Cada función se diseña primero
   contra: entradas/firmas falsas, cuentas sustituidas, operaciones repetidas,
   estados corruptos, datos incompletos, valores extremos, nodos maliciosos,
   interrupciones, versiones antiguas, recursos agotados, orden distinto.
3. **No se inventa criptografía.** Sólo primitivas estandarizadas, bibliotecas
   auditadas y parámetros documentados, salvo necesidad demostrada +
   especificación formal + revisión especializada + implementación de
   referencia + vectores de prueba + auditoría independiente.
4. **La seguridad no depende de la interfaz.** El nodo revalida TODA regla; la
   wallet/RPC/frontend nunca son frontera de seguridad.
5. **Todo dato externo es hostil.** No se confía en mensajes P2P, transacciones,
   respaldos, estados sincronizados, parámetros RPC, datos WASM, firmas,
   certificados, dependencias, configuraciones ni información de otros nodos.
6. **Fallar de forma segura.** Ante duda/corrupción/versión desconocida/estado
   incompatible: rechazar; no modificar parcialmente el estado; registrar lo
   suficiente; no filtrar secretos; mantener determinismo; no continuar con
   datos ambiguos.

## 5. Clasificación de riesgo

Todo cambio se clasifica **antes** de comenzar. Ante duda entre dos niveles se
usa el superior.

- **R0 — mínimo** (docs, comentarios, estilos sin lógica): revisión normal + CI
  básico.
- **R1 — bajo** (auxiliares, telemetría sin secretos, UI, herramientas internas
  no privilegiadas): especificación breve + pruebas unitarias + un revisor.
- **R2 — alto** (RPC, P2P, wallet, persistencia, contratos, auth,
  autorización, firmante remoto, sincronización, cambios grandes de
  dependencias): RFC + modelo de amenazas + invariantes + pruebas negativas +
  integración + dos revisores (uno de seguridad).
- **R3 — crítico** (consenso, selección/peso de validadores, criptografía,
  firmas, formatos firmados, economía, emisión, quema, staking, fees,
  gobernanza, tesorería, génesis, migraciones, serialización de consenso,
  claves, recuperación, WASM privilegiado, actualización de protocolo):
  investigación documentada + RFC formal + invariantes + modelo de amenazas +
  casos de abuso + plan de migración + plan de reversión + property tests +
  fuzzing + dos revisores independientes + revisión de seguridad + testnet + RC
  congelada + aprobación explícita.

## 6. Flujo obligatorio (puertas)

**Puerta 0 — Solicitud (QCR).** Problema real, motivo, afectados, consecuencia
de no hacerlo, tipo, riesgo preliminar, criterio observable de éxito. No se
aceptan solicitudes vagas ("mejorar gobernanza"); se convierten en objetivos
comprobables. *Salida:* el problema está definido, sin solución preconcebida.

**Puerta 1 — Investigación.** Responde: ¿hay estándar/especificación aplicable?
¿cómo lo resuelven sistemas maduros? ¿vulnerabilidades conocidas del mecanismo?
¿supuestos de seguridad? ¿alternativas? ¿implicaciones cripto/económicas/legales?
¿es necesario agregar código, o se resuelve simplificando? **Jerarquía de
fuentes:** estándares oficiales > papers revisados > docs de protocolo >
implementaciones maduras auditadas > informes de auditoría/CVE > docs de
bibliotecas > discusiones verificables > blogs. **La respuesta de una IA NO es
fuente técnica** (ayuda a localizar/resumir; sus conclusiones se verifican).
Expediente: fuentes + versiones + fecha + alternativas + decisión + rechazos +
preguntas abiertas. *Salida:* evidencia suficiente para una solución concreta.

**Puerta 2 — RFC (R2/R3).** Resumen, alcance, actores (incl. atacante externo y
atacante con clave comprometida), flujo normal, estados y transiciones (incl.
Expirada/Cancelada/Rechazada/Corrupta/Incompatible), datos (propietario,
dirección canónica, versión, formato, tamaño máx, campos, quién crea/modifica/lee,
cómo se archiva), autorización (quién firma, qué se firma exactamente, permisos,
umbral, anti-replay, expiración), errores (parte del diseño, no improvisados).
*Salida:* alguien que no escribió el RFC entiende cómo funcionará.

**Puerta 3 — Invariantes.** Lista de reglas que jamás pueden romperse: concretas,
comprobables, independientes de la interfaz, aplicables a todo camino,
convertibles en prueba. Mínimos globales de QChain (ver
[`docs/INVARIANTS.md`](../INVARIANTS.md) para la versión ejecutable):

1. Ninguna cuenta gasta fondos ajenos.
2. Ninguna operación crea QCH fuera de las reglas de emisión.
3. El suministro contabilizado coincide con los estados válidos.
4. Los cálculos monetarios usan aritmética comprobada.
5. Ninguna propuesta se ejecuta sin cumplir estado, votación y plazo.
6. Ninguna operación de tesorería se ejecuta sin el umbral requerido.
7. Una tx válida en otra red NO es válida en QChain (chain_id).
8. Una firma para un propósito NO se usa para otro (dominio).
9. Una operación ya ejecutada NO se ejecuta de nuevo.
10. Un contrato NO modifica estados fuera de sus permisos.
11. Todos los nodos honestos producen el mismo resultado del mismo estado+entradas.
12. Una versión desconocida DEBE ser rechazada.
13. Una migración NO destruye silenciosamente un estado válido.
14. Un error NO deja cambios parciales persistidos.
15. Ninguna entrada externa provoca consumo ilimitado de memoria/CPU/disco/red.

*Regla de prueba:* cada invariante tiene ≥1 prueba positiva y ≥1 que intente
romperlo. *Salida:* matriz invariante→pruebas.

**Puerta 4 — Modelo de amenazas.** Activos, límites de confianza, capacidades
del atacante (sin claves / con wallet / con nodo / con validador / con clave de
tesorería / con acceso parcial a CI / dependencia comprometida / respaldo
malicioso / contrato malicioso / estado histórico manipulado), preguntas
obligatorias (falsificar identidad, sustituir cuenta, alterar datos, replay,
repudio, obtener secretos, escalar privilegios, bloquear red, forzar divergencia,
manipular tiempo/ronda/orden, explotar migración, alcanzar estados no previstos,
reusar firma en otro contexto). Cada función R2/R3 lista ≥5 intentos concretos
de abuso. *Salida:* cada amenaza tiene mitigación, prueba o aceptación explícita.

**Puerta 5 — Compatibilidad y migración.** Versión anterior/nueva, detección de
versión, conversión exacta, datos conservados/cambiados, comportamiento ante
corrupción, compatibilidad entre nodos, punto de activación, reversión, respaldo,
prueba con estados reales. **NUNCA reutilizar la estructura actual para
interpretar formatos históricos cuyos campos/variantes cambiaron** — las
estructuras históricas permanecen definidas exactamente como se publicaron.
Requisitos: identificador inequívoco/magic o versión, longitud validada,
decodificación estricta, migración idempotente, pruebas desde cada versión
soportada, reinicio antes/durante/después, rechazo seguro de versiones
desconocidas. *Salida:* migración ejecutada sobre copias de estados históricos.

**Puerta 6 — Plan de pruebas (antes o junto al código).** Unitarias; negativas
(firmas/propietario/dirección/nonce/versión/estado/datos incorrectos, plazos
vencidos, valores extremos); de invariantes (secuencias generadas); integración;
migración (bytes/DB reales); reinicio en puntos críticos; atomicidad; fuzzing
(decodificadores, P2P, tx, firmas, migraciones, WASM, wallet, RPC,
serialización); diferenciales (dos implementaciones o versión previa vs nueva);
disponibilidad (CPU/mem/disco/colas/tiempo/entradas patológicas/conexiones).
*Salida:* pruebas definidas y vinculadas a requisitos, amenazas e invariantes.

## 7. Implementación segura

Sólo tras superar las puertas aplicables. **Cambios pequeños y enfocados** — no
mezclar gobernanza+economía, tesorería+red, wallet+consenso, refactor amplio +
función nueva, migración + optimización no relacionada. **Aritmética**:
`checked_add/sub/mul/div` y conversiones verificadas en fondos/rondas/tiempos/
pesos/recompensas/límites; sin overflows silenciosos ni truncados. **Límites
explícitos** en todo dato externo (tamaño, cantidad, profundidad, tiempo,
memoria, iteraciones, conexiones, pendientes). **Errores** tipados, con contexto,
sin secretos, sin estados parciales, deterministas; **sin `unwrap`/`expect`/
`panic!`** sobre datos externos o estados recuperables en rutas críticas.
**Determinismo** en consenso/ejecución: sin hora local, orden no determinista de
mapas, aleatoriedad no consensuada, variables del SO, nº de núcleos, red externa
ni punto flotante no controlado. **Serialización** de consenso/firmada: con
versión, dominio, canónica, rechaza campos extra, valida tamaños antes de
asignar, con vectores de prueba, estable durante su versión. **Dominio de
firmas**: incluye según corresponda id de QChain, chain_id, versión, tipo de
mensaje, propósito, id de operación, nonce, caducidad, datos completos — una
firma de voto NO es interpretable como tx/handshake/actualización/tesorería.
**Propiedad y cuentas**: antes de leer/modificar, verificar dirección esperada,
propietario, tipo, versión, magic, longitud, estado, permiso del firmante,
relación con las demás cuentas. **`unsafe`**: evitar/aislar/comentar/documentar
precondiciones/probar/revisión extra. **Código de IA** = no confiable hasta
revisión (ver §19).

## 8. Reglas por subsistema

- **Consenso:** demostrar seguridad, vivacidad, determinismo, resistencia a
  replay/desorden/bizantinos, quorum, transiciones de ronda, persistencia/
  recuperación, compatibilidad entre versiones. Sin activación silenciosa.
- **Economía:** contabilidad formal de emisión/quema/fees/recompensas/staking/
  tesorería/reservas/bloqueado/circulante; ecuación verificable del suministro
  tras cada operación; probar redondeo/polvo/mín/máx/millones/ausencia/exceso/
  último token/reinicio durante liquidación.
- **Gobernanza:** validar dirección canónica, propietario, autor, id único,
  estado, votación, quorum, resultado, timelock, expiración, acción permitida,
  anti-doble-ejecución. Los datos del solicitante NUNCA bastan para declarar
  aprobada una propuesta.
- **Tesorería:** proponente, firmantes, umbral, aprobaciones, cancelación,
  expiración, timelock, nonce, acción exacta, estado final. Una aprobación se
  vincula criptográficamente a una operación única e inmutable.
- **Wallet/recuperación:** entropía, derivación, cifrado, parámetros máximos,
  integridad del respaldo, id de grupo de shares, mezcla accidental, detección
  de contraseña incorrecta, borrado de memoria, phishing, importación maliciosa.
  No afirmar compatibilidad con un estándar por usar su lista de palabras si el
  protocolo difiere.
- **Red P2P:** autenticación, cifrado, identidad del peer, límites, rate limiting,
  replay, duplicados, malformados, descompresión, handshake, incompatibilidad de
  versión, aislamiento de abusivos.
- **WASM/contratos:** propiedad, permisos, gas, memoria, profundidad, tiempo,
  determinismo, atomicidad, conservación de balances, sin cuentas duplicadas
  peligrosas, validación independiente de datos.
- **Firmante remoto:** canal autenticado + cifrado, identidad de cliente,
  allowlist de operaciones, separación de dominios, nonces, caducidad, auditoría,
  rate limiting, denegación por defecto. Alcanzar la dirección de red del
  firmante NUNCA equivale a autorización para firmar.

## 9. Revisión de código

Todo cambio va por pull request. La descripción incluye: problema, solución,
riesgo, RFC, invariantes afectadas, amenazas tratadas, pruebas añadidas,
migración, compatibilidad, rendimiento, plan de reversión, archivos críticos.
El revisor busca ACTIVAMENTE cómo romper el cambio (autorización, propiedad,
orden, atomicidad, persistencia, límites, errores, interacciones, estados
imposibles, migraciones, comportamiento adversarial), no sólo estilo/compilación/
camino feliz. **El autor no puede ser el único aprobador.**

## 10. CI obligatoria

Mínimo por PR:

```
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
cargo deny check
```

Cuando corresponda: `cargo llvm-cov`, `cargo test --doc`, `cargo test --release`,
`cargo miri test`, `cargo fuzz run <target>`. Además: escaneo de secretos y de
dependencias, SBOM, licencias, acciones de CI fijadas por commit, permisos
mínimos de workflows, artefactos firmados, procedencia verificable, protección
de ramas, revisión obligatoria. Una prueba desactivada/ignorada/eliminada se
justifica expresamente.

## 11. Política BLOQUEANTE

No se fusiona/publica cuando: hay un crítico/alto abierto relacionado; falta
prueba negativa; cambia una invariante sin actualizar docs; introduce
serialización sin versión; modifica estado sin migración; usa criptografía
propia no revisada; reduce una validación sin justificación; falla CI; depende
de comportamiento no determinista; contiene `unsafe` no revisado; incluye
secretos; tiene dependencias desconocidas/vulnerables; no hay plan de reversión
para un R3; el mismo autor implementó, auditó y aprobó todo.

## 12. Publicación y activación

**RC congelada** para R3 (sólo se corrigen vulnerabilidades/bloqueantes; cada
corrección reinicia la revisión de las zonas afectadas). **Testnet**: probar
actualización desde versión anterior, nodo nuevo, nodo desactualizado, reinicio,
caída durante migración, red congestionada, peers maliciosos, tx inválidas,
carga sostenida, divergencia, recuperación. **Activación gradual** cuando sea
posible (código incluido pero desactivado → testnet → observación → limitada →
completa → monitoreo). **Reversión** conocida antes de activar (cómo detener,
cómo volver, qué es reversible/irreversible, quién autoriza la emergencia, cómo
se comunica el incidente).

## 13. Tratamiento de vulnerabilidades

Toda vulnerabilidad produce CUATRO resultados: corrección inmediata; prueba de
regresión; análisis de causa raíz; **búsqueda de la misma clase de fallo en todo
el repositorio**. No se considera resuelta si sólo se corrige la línea. Preguntas:
¿qué regla faltaba? ¿qué diseño lo permitió? ¿dónde más se repite? ¿qué
automatización lo detectaría? ¿qué documentación cambia? ¿qué control evita su
reaparición?

**Sistema de aprendizaje (obligatorio).** La causa raíz y la clase de todo
hallazgo se registran en [`LESSONS-LEDGER.md`](LESSONS-LEDGER.md) (memoria de
clases EC-01…EC-NN comparada contra errores previos); el barrido de la clase se
corre con [`../../deploy/qsep-sweep.sh`](../../deploy/qsep-sweep.sh); cada
auditoría se archiva en [`audits/`](audits/) y no se cierra sin correr el sweep y
responder la "pregunta recurrente" de cada clase con evidencia. Si una clase
REAPARECE, la corrección primaria es endurecer el detector/invariante, no sólo el
sitio.

## 14. Estructura documental

```
docs/
  security/
    QSEP-1.md              (este archivo)
    README.md              (mapa de cumplimiento)
    CHANGE-REQUEST-TEMPLATE.md
    INVARIANTS.md -> ../INVARIANTS.md
    threat-model.md
    security-assumptions.md
    incident-response.md -> ../../SECURITY.md + ../RECOVERY-PLAN.md
  rfc/    (TEMPLATE.md + RFC-XXXX por cambio R2/R3)
  adr/    (decisiones de arquitectura)
  audits/ release/ migrations/
```

Estados de un RFC: Draft, Under Review, Approved, Implemented, Rejected,
Superseded.

## 15–18. Plantillas y checklists

- Plantilla de solicitud de cambio: [`CHANGE-REQUEST-TEMPLATE.md`](./CHANGE-REQUEST-TEMPLATE.md).
- Plantilla de RFC: [`../rfc/TEMPLATE.md`](../rfc/TEMPLATE.md).
- **Checklist previa a escribir código (§17):** todas las respuestas deben ser
  "sí" (problema definido, riesgo asignado, investigación con fuentes, diseño
  escrito, actores/permisos, invariantes, modelo de amenazas, casos de abuso,
  límites, formatos versionados, migración diseñada, plan de pruebas, plan de
  reversión, aprobación exigida). Si alguna es "no", aún no se escribe código.
- **Definición de terminado (§18):** una función NO está terminada porque
  compila; lo está cuando cumple su especificación, mantiene invariantes, rechaza
  inválidos, tiene límites, errores seguros, pruebas de ataque, integración,
  fuzzing/migración cuando aplica, docs, revisión independiente, supera CI,
  funciona tras reiniciar, tiene reversión, fue observada en testnet cuando
  corresponde, sin críticos/altos abiertos, y el commit exacto fue congelado y
  revisado.

## 19. Instructivo para agentes de IA

Ver [`/AGENTS.md`](../../AGENTS.md) (copia obligatoria del instructivo; también
resumido al inicio de `CLAUDE.md`).

## 20. Regla final

Secuencia obligatoria:

```
Problema → investigación → especificación → invariantes → amenazas → diseño →
pruebas → código → revisión → testnet → activación → vigilancia
```

Nunca: `Idea → código → producción → auditoría → corrección urgente`. El
protocolo tiene prioridad sobre la velocidad. Cuando una función no pueda
cumplir este proceso, no está lista para incorporarse a QChain.
