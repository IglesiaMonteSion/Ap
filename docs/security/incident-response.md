# Respuesta a incidentes (QSEP-1 §12/§13)

Este archivo es el índice de respuesta; los runbooks operativos completos viven
en:

- **Recuperación operativa** (corrupción de DB, pérdida de nodo/validador,
  rotación de clave de tesorería, restauración desde snapshot/backup, recuperación
  tras ataque): [`../RECOVERY-PLAN.md`](../RECOVERY-PLAN.md).
- **Reporte responsable de vulnerabilidades** (contacto, tiers, safe-harbor,
  scope): [`/SECURITY.md`](../../SECURITY.md).
- **Verificación de release / reversión**: [`../RELEASE-VERIFY.md`](../RELEASE-VERIFY.md).

## Al confirmar una vulnerabilidad (QSEP-1 §13, obligatorio)

Toda vulnerabilidad produce CUATRO resultados, no sólo el parche:

1. **Corrección inmediata** (con clasificación de riesgo R0–R3).
2. **Prueba de regresión** que reproduce el fallo exacto y falla sin el fix.
3. **Análisis de causa raíz**: ¿qué regla/invariante faltaba? ¿qué diseño lo
   permitió?
4. **Barrido de la misma clase** en TODO el repo: ¿dónde más se repite? ¿qué
   automatización (test/fuzz/lint) lo detectaría a futuro?

*Ejemplo:* si aparece una cuenta privilegiada leída sin validar propietario, se
revisan TODAS las lecturas/escrituras de cuentas privilegiadas, no sólo esa
función.

## Reversión de emergencia

Antes de activar cualquier R3 debe conocerse (del RFC): cómo detener la función,
cómo volver a la versión anterior, qué estados son reversibles/irreversibles,
quién autoriza la emergencia, cómo se comunica el incidente. Para una red viva:
`git pull && sudo ./deploy/update-node.sh` (o `--rollback` de `update-node.sh` a
la imagen anterior); una pausa de gobernanza por multisig de guardianes existe
para frenar una ejecución apurada sin tocar fondos (#213).
