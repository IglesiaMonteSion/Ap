# Supuestos de seguridad de QChain (QSEP-1 §4)

Las garantías del sistema valen sólo bajo estos supuestos. Todo cambio que los
altere es R3.

1. **Criptografía.** Ed25519 (RFC 8032), ML-DSA-65 y SLH-DSA (FIPS 204/205 vía
   liboqs), ML-KEM-768 (FIPS 203), SHA3-256 (FIPS 202) son seguros con sus
   parámetros. No se inventa criptografía propia (la única "construcción" es la
   separación de dominios de firma, con vectores de prueba). El nivel de colisión
   de SHA3-256 (128-bit) se acepta formalmente por debajo del nivel de firma
   (~192-bit) — decisión documentada en `ARCHITECTURE.md §2` (#190).
2. **Confianza en el disco propio.** Un nodo confía en su propio `data_dir`
   (quien puede escribirlo ya controla el nodo). Corrupción detectable → fail-loud
   (#217), nunca "correr degradado".
3. **Umbral BFT.** La seguridad de consenso vale mientras < 1/3 del stake sea
   bizantino; la vivacidad mientras > 2/3 esté vivo. Verificado por el DST.
4. **Claves frías offline.** La separación de roles (#193/#20) asume que las
   claves de operador/retiro/tesorería se mantienen fuera de línea; una fuga de la
   clave de consenso (caliente) no puede mover el bono ni gastar lo ganado.
5. **Firmante remoto.** El canal es autenticado+cifrado y el firmante aplica una
   allowlist estricta; alcanzar su dirección de red NO equivale a autorización.
6. **Wallet no-custodial.** La semilla vive en memoria del navegador mientras está
   desbloqueada (límite honesto de toda wallet web); se zeroiza al bloquear (#13)
   y se cifra con Argon2id en reposo (#12).
7. **Determinismo cross-plataforma.** Ningún camino de consenso/ejecución depende
   de reloj/RNG/orden-de-mapa/float no canónico/nº de núcleos.
8. **Confianza débil-subjetiva en state-sync.** Un nodo fresco confía en el par
   fuente salvo que se fije un trust anchor (obligatorio en mainnet, #212).
9. **Gates humanos pendientes.** Auditoría externa formal, bug bounty público,
   revisión humana independiente y una 2ª implementación interoperable son
   supuestos de proceso NO satisfechos aún (pre-mainnet; ver `SECURITY.md`,
   `PRE-LAUNCH.md`).
