//! Separadores de dominio versionados para preimágenes hasheadas/firmadas
//! (auditoría QCH-CRY-001/004, tareas #186/#187).
//!
//! Cada objeto que se hashea o firma antepone una etiqueta de dominio ÚNICA y
//! VERSIONADA a su preimagen, para que una firma/hash de un tipo NUNCA se pueda
//! reinterpretar como la de otro (defensa contra confusión entre protocolos), y
//! para poder rotar el esquema por versión sin ambigüedad.
//!
//! Se congela como parte del consenso de QChain (no depende de ningún borrador
//! externo). Las etiquetas llevan largo fijo y terminan en `-vN`.

/// Preimagen del **identificador canónico de transacción** (txid). Se hashea
/// `TXID_V1 ‖ borsh(Message)` — **sin las firmas** — para que el txid sea
/// estable frente a la maleabilidad de la firma (QCH-CRY-004, tarea #186). El
/// anti-doble-gasto ya depende del `nonce` dentro del `Message`, no del txid.
pub const TXID_V1: &[u8] = b"qchain-txid-v1";
