# Actualizar el runtime WASM (es un cambio de consenso)

> **La versión de wasmtime es parte de las reglas de consenso de esta red.**
> No es una dependencia más: el *fuel* que consume un contrato se convierte en
> un fee de gas, ese fee se le debita al pagador, y ese débito entra en el
> **state root comprometido**. Si dos validadores corren runtimes que cobran
> distinto por el mismo bytecode, computan roots distintos y **forkean**.

Este documento existe porque esa propiedad no se ve en el `Cargo.toml`. Ahí
wasmtime parece una dependencia normal.

## La cadena, explícita

```
fuel consumido  ──►  gas fee = fuel × gas_price_per_fuel   (ledger.rs)
                ──►  débito al pagador
                ──►  hoja Merkle de esa cuenta
                ──►  STATE ROOT  ──►  consenso
```

`Ledger::run_wasm_instruction` deriva el presupuesto de fuel del `fee_limit`
**firmado** (#206) y cobra el fuel realmente gastado — incluso si el contrato
trapea (esa fue la corrección del bypass de medición de gas). Todo eso hace
que el número que devuelve `WasmCallResult::fuel_consumed` sea, literalmente,
dinero.

## Lo que protege: dos KAT de fuel

En `crates/qchain-execution/src/wasm.rs`:

| Test | Qué pina |
|---|---|
| `fuel_per_contract_is_a_pinned_known_answer_consensus_affecting` | WAT sintético, una superficie de medición por caso: aritmética, loop contado, `memory.grow`, `memory.fill`, `memory.copy`, host call, trap |
| `fuel_for_the_real_sdk_templates_is_pinned_consensus_affecting` | Los **6 templates reales del SDK**, que es el bytecode que un contrato desplegado realmente tiene |

Los dos son known-answer tests con los números **medidos**, no estimados. Si un
bump de runtime cambia cualquiera, fallan mostrando viejo vs nuevo.

**El segundo no es redundante.** `token`, `escrow` y `vault` contienen
`memory.fill` que nadie escribió a mano: LLVM baja el `memset` de Rust a esa
instrucción. O sea que un cambio de medición de bulk-memory les cambia el gas
**sin que cambie una sola línea de código del contrato**. Así es exactamente
como un cambio de fuel llega a producción sin que nadie lo note.

## El delta medido: wasmtime 27 → 47

Motivo del salto: **RUSTSEC-2026-0096** (9.0, crítico) — *miscompiled guest heap
access enables sandbox escape on aarch64 Cranelift*. Alcanzable en esta red:
qchain usa Cranelift (nunca fija `.strategy()`, así que es el default) y ARM
Ampere es un objetivo de despliegue documentado. 47.x además limpia las otras 14
advisories que arrastraba 27.0.0 (`cargo audit` pasa de 15 vulnerabilidades a 0).

Lo que **NO** cambió — verificado, no supuesto:

- aritmética recta, loops contados, host calls, y fuel-hasta-el-trap: **idénticos**
- `memory.grow`: sigue siendo plano
- la superficie de API que usa el proyecto: compiló sin un solo cambio

Lo que **SÍ** cambió:

| Op | wasmtime 27 | wasmtime 47 |
|---|---|---|
| `memory.fill` (64 KiB) | plano (~1 fuel) | **~1 fuel por byte** (65 536) |
| `memory.copy` (64 KiB) | plano (~1 fuel) | **~1 fuel por byte** (65 536) |

Dato de referencia: el caso combinado `memory.grow(16 páginas) + memory.fill(64
KiB)` costaba **7** fuel bajo 27 y **65 543** bajo 47.

Upstream esto es una mejora de seguridad: es la bomba de memoria que este
proyecto tuvo que tapar con `MAX_CONTRACT_MEMORY_BYTES` (RSS de ~9 MB a ~1.96 GB
por 7 unidades de fuel). Ahora el fuel la cobra sola.

**El limitador de 16 MiB se queda igual.** Un precio no es un techo: un contrato
con un `fee_limit` suficientemente grande puede pagar mucha memoria. El límite
duro no se puede pagar; el precio sí.

## Procedimiento de cutover (obligatorio)

Un cambio de fuel **no admite rollout gradual**. Un validador en 27 y otro en 47
ejecutando el mismo contrato con `memory.fill` cobran fees distintos → roots
distintos → fork.

1. **Medir el delta** antes de nada: correr los dos KAT contra el runtime nuevo
   y guardar viejo-vs-nuevo. Si son idénticos, es un update ordinario.
2. Si hay delta, es **cutover coordinado**: todos los validadores actualizan al
   mismo binario, juntos, no de a uno.
3. Verificar en vivo con más de un nodo que una tx que ejecuta un contrato
   converge al **mismo root** en todos.
4. Actualizar los números pinneados en el mismo commit que sube la versión, con
   el delta escrito en las notas de release.

> Un KAT de fuel que falla **no es un test para "actualizar"**. Es el aviso de
> que la red necesita un cutover. Cambiar el número sin el cutover es
> exactamente el fork que el test existe para impedir.

## Cómo fijamos la versión

```toml
wasmtime = "47.0"   # rango MENOR, a propósito
```

Un rango mayor abierto (`"47"`) dejaría que dos operadores resolvieran majors
distintas desde el mismo `Cargo.toml` y forkearan sin que nadie tocara nada. El
`Cargo.lock` committeado + `--locked` (que usa el `Dockerfile` y el gate) es la
garantía real; el rango menor es la segunda barrera.

## Estado de las advisories de wasmtime 27 (evaluación de alcanzabilidad)

Se evaluó cada una contra el uso real antes de decidir la urgencia, en vez de
tratar las 15 como equivalentes:

| Familia | Alcanzable | Por qué |
|---|---|---|
| Winch (incl. RUSTSEC-2026-0095, 9.0) | **No** | nunca se fija `.strategy()` → Cranelift |
| Component model (0091/0092/0093/0085) | **No** | no se usa `Component::` |
| WASI (0046/0021/0020) | **No** | no se usa `WasiCtx` |
| Pooling allocator (0088) | **No** | no se usa |
| SharedMemory (0118) | **No** | no se usa |
| **aarch64 Cranelift heap (0096, 9.0)** | **Sí** | Cranelift + ARM es objetivo de despliegue |
| f64x2.splat x86-64 (0087, 4.1) | **Sí** | Cranelift |

Que la mayoría no fuera alcanzable es la razón por la que esto no era una
emergencia — y que 0096 **sí** lo fuera es la razón por la que igual se hace.
