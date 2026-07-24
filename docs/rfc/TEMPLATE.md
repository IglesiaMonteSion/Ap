# RFC-XXXX: Título

> Copiar este archivo a `docs/rfc/RFC-XXXX-slug.md` para cada cambio R2/R3
> (QSEP-1 §Puerta 2). Un R2/R3 NO se implementa sin un RFC aprobado.

## Estado
Draft | Under Review | Approved | Implemented | Rejected | Superseded

## Resumen
Qué se construirá y por qué (1–2 párrafos).

## Motivación
El problema real. Consecuencia de no hacerlo.

## Investigación y fuentes
Estándares/specs/implementaciones maduras consultadas, con versión y fecha.
Vulnerabilidades conocidas del mecanismo. (Recordatorio QSEP-1 §Puerta 1: la
salida de una IA NO es fuente; verificar contra el original.)

## Alternativas consideradas
Y por qué se rechazaron.

## Diseño propuesto
## Actores y permisos
Incluir atacante externo y atacante con una clave comprometida.

## Estructuras de datos
Por cada estructura: propietario, dirección canónica, versión, formato, tamaño
máx, campos, quién crea/modifica/lee, cómo se archiva.

## Direcciones y propiedad
## Estados y transiciones
Incluir Expirada / Cancelada / Rechazada / Corrupta / Incompatible.

## Formato de serialización
Versión + dominio + canonicalidad + rechazo de campos extra + vectores.

## Dominio de firmas
Qué se firma exactamente (id de QChain, chain_id, versión, tipo, propósito, id de
operación, nonce, caducidad, datos).

## Invariantes
Reglas que jamás pueden romperse + la prueba que las verifica.

## Modelo de amenazas
Activos, límites de confianza, capacidades del atacante.

## Casos de abuso
≥5 intentos concretos de abuso con su mitigación/prueba.

## Límites de recursos
Tamaño, cantidad, profundidad, tiempo, memoria, iteraciones, conexiones.

## Compatibilidad
## Migración
Detección de versión, conversión, corrupción, punto de activación, respaldo.

## Pruebas
Unitarias, negativas, invariantes, integración, migración, reinicio, atomicidad,
fuzzing, diferenciales, disponibilidad.

## Despliegue
Byte-idéntico / gated / coordinado / génesis nuevo. Efecto en `chain_id`.

## Reversión
Cómo detener, cómo volver, qué es reversible/irreversible, quién autoriza.

## Riesgos residuales
Lo que NO cubre este cambio (límite honesto).

## Preguntas pendientes
## Aprobaciones
