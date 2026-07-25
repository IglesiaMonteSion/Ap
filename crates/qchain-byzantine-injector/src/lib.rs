//! Builders de mensajes BIZANTINOS — funciones PURAS (sin red) que construyen
//! los mismos `NetMessage` que un validador honesto, salvo por el contenido
//! malicioso. Firmadas con una clave REAL del comité, así que un nodo honesto
//! las procesa hasta el punto donde la defensa correspondiente las detiene.
//!
//! Separar los builders de la I/O es a propósito: cada ataque es una función
//! testeable en `cargo test` sin levantar una red, y el `main` sólo dialoga y
//! envía. Cada builder mapea a UNA defensa concreta que el proyecto ya construyó
//! (referenciada en su doc), y su unit test fija la propiedad que hace al ataque
//! "bien formado" (p. ej. que las dos firmas de la equivocación verifican y los
//! dos vértices comparten (ronda, autor) pero difieren de digest — si no, no es
//! evidencia de equivocación válida y el test lo delata).

use qchain_core::{Batch, Digest, Instruction, Round, Transaction, Vertex, WorkerId};
use qchain_crypto::{Keypair, Pubkey};
use qchain_network::NetMessage;

/// Firma un `Vertex` como su AUTOR — la misma firma que el proposer honesto echa
/// como su auto-voto (#187: `VERTEX_VOTE_V1 ‖ chain_id ‖ digest`). Sin esto el
/// nodo dropea el `VertexProposal` antes de mirar nada (`author_signature does
/// not verify`), así que el ataque nunca llegaría a ejercer su defensa.
fn signed_vertex_proposal(kp: &Keypair, chain_id: &[u8; 32], vertex: Vertex) -> anyhow::Result<NetMessage> {
    let sig = qchain_crypto::sign_vertex_vote(kp, chain_id, &vertex.digest()[..])?;
    Ok(NetMessage::VertexProposal { vertex, author_signature: sig })
}

/// Un `Vertex` honesto en forma (autor = `kp`, ronda dada, con los `parents` y
/// `batch_digests` que se le pasen) — el bloque de construcción de los ataques.
fn vertex(kp: &Keypair, round: Round, parents: Vec<Digest>, batch_digests: Vec<(WorkerId, Digest)>) -> Vertex {
    Vertex { round, author: kp.pubkey(), batch_digests, parents }
}

/// **EQUIVOCACIÓN** (defensa: slashing por equivocación, v6 `staking.rs` #88 +
/// v7 `validator_v7.rs`, más el candado `voted_for` del engine). Dos vértices
/// DISTINTOS para la MISMA (ronda, autor), ambos válidamente firmados por `kp`.
/// Un nodo honesto: (a) NUNCA vota por el segundo (candado anti-doble-voto), y
/// (b) empaqueta la evidencia (`EquivocationEvidence`) que cualquiera puede
/// reportar para quemarle el bono. El fork es imposible: los honestos siguen
/// convergiendo. Los dos difieren por sus `parents` (→ digest distinto), que es
/// suficiente; la detección ocurre por (ronda, autor) + digest, sin necesidad de
/// que los parents sean certificados reales.
pub fn equivocation_pair(kp: &Keypair, chain_id: &[u8; 32], round: Round) -> anyhow::Result<(NetMessage, NetMessage)> {
    let a = signed_vertex_proposal(kp, chain_id, vertex(kp, round, vec![[0xAA; 32]], vec![]))?;
    let b = signed_vertex_proposal(kp, chain_id, vertex(kp, round, vec![[0xBB; 32]], vec![]))?;
    Ok((a, b))
}

/// **WITHHOLDING de disponibilidad de datos** (defensa: el gate de disponibilidad
/// en el voto, v6.3.0, HIGH #175). Un `VertexProposal` que referencia el digest
/// de un batch que el inyector **NUNCA gossipea**. Un nodo honesto DIFIERE su
/// voto hasta tener el batch — y como nunca llega, nunca vota → el vértice jamás
/// junta quórum → jamás puede trabar `take_executable_prefix` en toda la red. El
/// batch es real (para que su digest sea legítimo), pero el ataque es no enviarlo.
/// Devuelve el mensaje y el digest retenido (para el reporte del harness).
pub fn withholding_vertex(kp: &Keypair, chain_id: &[u8; 32], round: Round, worker_id: WorkerId, withheld: &Batch) -> anyhow::Result<(NetMessage, Digest)> {
    let d = withheld.digest();
    let msg = signed_vertex_proposal(kp, chain_id, vertex(kp, round, vec![], vec![(worker_id, d)]))?;
    Ok((msg, d))
}

/// **VÉRTICE SOBRE-DIMENSIONADO** (defensa: cotas estructurales pre-proceso,
/// v7.2.0 #208 + v4.2.2). Un `VertexProposal` VÁLIDAMENTE FIRMADO con MUCHOS más
/// `parents` de los que un vértice legítimo puede tener (≤ n, un cert de r-1 por
/// validador). Sin la cota, un autor bizantino cuya firma verifica haría a cada
/// nodo honesto registrar + reintentar por siempre un pedido de resync por cada
/// digest fabricado (memoria + amplificación de ancho de banda desde un mensaje).
/// El nodo lo dropea por la cota; el ataque prueba que dropea sin explotar.
pub fn oversized_parents_vertex(kp: &Keypair, chain_id: &[u8; 32], round: Round, parent_count: usize) -> anyhow::Result<NetMessage> {
    let parents: Vec<Digest> = (0..parent_count)
        .map(|i| {
            let mut d = [0u8; 32];
            d[..8].copy_from_slice(&(i as u64).to_le_bytes());
            d
        })
        .collect();
    signed_vertex_proposal(kp, chain_id, vertex(kp, round, parents, vec![]))
}

/// **FLOOD de admisión** (defensa: cuota de admisión global + por-pagador +
/// chequeo de solvencia en admisión + tope de verify concurrente, #210/#90). Una
/// `TransactionGossip` de una transferencia REAL FIRMADA desde un pagador SIN
/// FONDOS (`flooder`) — pasa el verify PQC (firma válida) pero la cuota/solvencia
/// la rechazan antes de amplificar. Cada tx usa un nonce creciente para que sean
/// admisiones distintas (no dedup triviales). El nodo debe seguir sano y las tx
/// honestas seguir finalizando.
pub fn flood_tx_gossip(flooder: &Keypair, chain_id: &[u8; 32], nonce: u64, to: &Pubkey) -> anyhow::Result<NetMessage> {
    let ix = Instruction {
        program_id: Pubkey::system_program_id(),
        accounts: vec![flooder.pubkey(), *to],
        data: borsh::to_vec(&qchain_execution_transfer(1))?,
    };
    let tx = Transaction::new_signed(flooder, nonce, *chain_id, 100_000_000, vec![ix])?;
    Ok(NetMessage::TransactionGossip(tx))
}

/// El `SystemInstruction::Transfer { amount }` en bytes, sin depender de
/// `qchain-execution` (evita arrastrar el árbol de ejecución a un tool de red).
/// `Transfer` es el discriminante `1` (`CreateAccount` es el `0`); estable,
/// guardado por los tests de estabilidad de encoding de `qchain-execution` y por
/// el unit test de acá abajo.
fn qchain_execution_transfer(amount: u64) -> TransferIx {
    TransferIx { tag: 1, amount }
}

/// Espejo mínimo del layout borsh de `SystemInstruction::Transfer` (enum
/// discriminante u8 `1` + `u64 amount`). No re-implementa la ejecución, sólo el
/// encoding del argumento del flood.
#[derive(borsh::BorshSerialize)]
struct TransferIx {
    tag: u8,
    amount: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAIN: [u8; 32] = [0x5a; 32];

    fn kp() -> Keypair {
        Keypair::generate().unwrap()
    }

    #[test]
    fn equivocation_pair_is_valid_slashable_evidence() {
        let byz = kp();
        let (a, b) = equivocation_pair(&byz, &CHAIN, 7).unwrap();
        let (NetMessage::VertexProposal { vertex: va, author_signature: sa }, NetMessage::VertexProposal { vertex: vb, author_signature: sb }) = (&a, &b) else {
            panic!("both must be VertexProposal");
        };
        // MISMA (ronda, autor), DISTINTO digest — la definición exacta de
        // evidencia de equivocación; si esto falla, el ataque no prueba nada.
        assert_eq!(va.round, vb.round);
        assert_eq!(va.author, vb.author);
        assert_eq!(va.author, byz.pubkey());
        assert_ne!(va.digest(), vb.digest(), "conflicting vertices must differ in digest");
        // AMBAS firmas verifican como firma-de-autor (si no, el nodo las dropea
        // antes de detectar la equivocación).
        let bundle = byz.public_key_bundle();
        assert!(qchain_crypto::verify_vertex_vote(&bundle, &CHAIN, &va.digest()[..], sa));
        assert!(qchain_crypto::verify_vertex_vote(&bundle, &CHAIN, &vb.digest()[..], sb));
        // Una firma de OTRA red NO verifica acá (#187) — el ataque está atado a
        // la cadena objetivo, no vale en otra incarnación.
        let other = [0x99u8; 32];
        assert!(!qchain_crypto::verify_vertex_vote(&bundle, &other, &va.digest()[..], sa));
    }

    #[test]
    fn withholding_vertex_references_the_batch_it_never_sends() {
        let byz = kp();
        let batch = Batch { transactions: vec![] };
        let (msg, withheld) = withholding_vertex(&byz, &CHAIN, 3, 0, &batch).unwrap();
        let NetMessage::VertexProposal { vertex, author_signature } = &msg else {
            panic!("must be a VertexProposal");
        };
        // El vértice referencia EXACTAMENTE el digest del batch retenido, y sólo
        // ese; el nodo diferirá el voto hasta tenerlo (y nunca lo tendrá).
        assert_eq!(vertex.batch_digests, vec![(0u8, withheld)]);
        assert_eq!(withheld, batch.digest());
        assert!(qchain_crypto::verify_vertex_vote(&byz.public_key_bundle(), &CHAIN, &vertex.digest()[..], author_signature));
    }

    #[test]
    fn oversized_vertex_exceeds_any_plausible_parent_bound_but_stays_authentic() {
        let byz = kp();
        let msg = oversized_parents_vertex(&byz, &CHAIN, 5, 5000).unwrap();
        let NetMessage::VertexProposal { vertex, author_signature } = &msg else {
            panic!("must be a VertexProposal");
        };
        // MUCHO más que `n` (un vértice legítimo referencia ≤ n parents); la
        // firma es AUTÉNTICA, así que sólo la cota estructural puede rechazarlo.
        assert_eq!(vertex.parents.len(), 5000);
        assert!(qchain_crypto::verify_vertex_vote(&byz.public_key_bundle(), &CHAIN, &vertex.digest()[..], author_signature));
    }

    #[test]
    fn flood_tx_is_a_real_signed_transaction_from_an_unfunded_payer() {
        let flooder = kp();
        let victim = kp().pubkey();
        let msg = flood_tx_gossip(&flooder, &CHAIN, 0, &victim).unwrap();
        let NetMessage::TransactionGossip(tx) = &msg else {
            panic!("must be a TransactionGossip");
        };
        // La firma VERIFICA (pasa el verify PQC del nodo) — el ataque no es una
        // tx basura que se cae por parseo, es una tx real que la CUOTA/solvencia
        // rechaza; ejercita el camino caro a propósito.
        assert!(tx.verify_signature());
        assert_eq!(tx.message.payer, flooder.pubkey());
        assert_eq!(tx.message.chain_id, CHAIN);
        // Nonces crecientes producen txs distintas (no un dedup trivial).
        let m2 = flood_tx_gossip(&flooder, &CHAIN, 1, &victim).unwrap();
        let NetMessage::TransactionGossip(tx2) = &m2 else { panic!() };
        assert_ne!(tx.txid(), tx2.txid());
    }

    #[test]
    fn transfer_ix_encoding_matches_the_discriminant() {
        // `Transfer` = discriminante 1 del enum `SystemInstruction` (CreateAccount
        // es el 0). Guardado acá para que si alguien reordena el enum en
        // qchain-execution, este tool (que no depende de ese crate) no empiece a
        // firmar el argumento equivocado en silencio.
        let bytes = borsh::to_vec(&qchain_execution_transfer(7)).unwrap();
        assert_eq!(bytes[0], 1u8, "Transfer debe ser el discriminante 1");
        assert_eq!(&bytes[1..9], &7u64.to_le_bytes());
    }
}
