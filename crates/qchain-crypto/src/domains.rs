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

/// Preimagen de la **FIRMA de una transacción** (QCH-CRY-001/3.6, tarea #187).
/// El pagador firma `TX_SIG_V1 ‖ borsh(Message)` (antes firmaba `borsh(Message)`
/// pelado). El prefijo de dominio hace que una firma de transacción NUNCA pueda
/// reinterpretarse como la de otro objeto (voto/vértice/handshake) — antes la
/// separación era sólo por estructura/longitud (una tx firma un `Message` borsh
/// largo, un voto un digest de 32 B), lo ROBUSTO es la etiqueta explícita. Es
/// **wire-breaking de FIRMA** (no del layout del `Message`): los bytes de la tx
/// son estructuralmente idénticos, sólo cambian los bytes de la firma → cutover
/// coordinado / génesis fresco, sin cambio de consenso/votos/vértices.
pub const TX_SIG_V1: &[u8] = b"qchain-tx-sig-v1";

/// Preimagen de la **FIRMA/ATESTACIÓN sobre un digest de vértice** (tarea #187):
/// se firma `VERTEX_VOTE_V1 ‖ vertex.digest()`. **TODO** signatario de un
/// vértice usa este mismo dominio — el AUTOR en su auto-voto y CADA votante —,
/// porque un voto y la firma-de-autor son el MISMO objeto criptográfico (una
/// atestación sobre el digest del vértice) y un `Certificate` las trata a todas
/// por igual; darles dominios distintos rompería esa uniformidad sin ganar
/// seguridad. La evidencia de equivocación verifica bajo este mismo dominio (sus
/// firmas SON votos del autor sobre dos vértices en conflicto). Wire-breaking de
/// firma de CONSENSO → todos los validadores deben correr un build que lo acuerde
/// (cutover coordinado, mismo patrón que el P2P auth); no cambia el `vertex.digest()`
/// (content-address del DAG), sólo la preimagen que se firma.
pub const VERTEX_VOTE_V1: &[u8] = b"qchain-vertex-vote-v1";

// NOTA: el handshake P2P autenticado (`qchain-network::handshake`) ya usa su
// propio dominio explícito (`b"qchain-p2p-auth-v1"` sobre un transcript de 179 B)
// desde #176, así que ya está separado de tx/voto/vértice por construcción y no
// se toca aquí.
