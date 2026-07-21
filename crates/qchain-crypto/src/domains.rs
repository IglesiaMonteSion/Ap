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

/// Dominio del handshake P2P autenticado (`qchain-network::handshake`, #176): un
/// transcript de ~179 B se firma como `P2P_AUTH_V1 ‖ transcript`. Se expone como
/// constante compartida (antes vivía sólo dentro de `handshake.rs`) para que el
/// firmante remoto pueda hacer una **allowlist ESTRICTA** de `SignRaw`: el
/// firmante de consenso sólo debe firmar bytes crudos que sean EXACTAMENTE un
/// transcript de handshake — cualquier otra cosa (una tx, un dominio futuro, un
/// protocolo nuevo) se rechaza por defecto, en vez de una blacklist que sólo
/// niega los dominios que ya conocemos. Es la separación de dominios llevada a
/// "todo lo no permitido está prohibido".
pub const P2P_AUTH_V1: &[u8] = b"qchain-p2p-auth-v1";

/// **Proof-of-possession de una clave de consenso al registrar un validador v7**
/// (separación de roles de clave, #193-B — la parte on-chain). Cuando una clave
/// FRÍA de operador (el pagador) registra un validador, la clave de CONSENSO
/// (caliente, distinta) firma `VALIDATOR_POP_V1 ‖ operator ‖ withdrawal ‖ moniker`
/// para PROBAR que quien registra realmente posee la clave de consenso y para
/// ATARLA a ese operador/retiro/moniker exactos. Sin esto, un atacante podría
/// registrar la clave de consenso de otro (front-run) o reusar un PoP para otro
/// operador. Es la contraparte on-chain de "consenso ≠ fondos": la clave caliente
/// puede firmar bloques (slasheable) pero jamás controla el bono ni las ganancias,
/// que quedan bajo la clave fría de retiro.
pub const VALIDATOR_POP_V1: &[u8] = b"qchain-v7-validator-pop-v1";
