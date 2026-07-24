use borsh::{BorshDeserialize, BorshSerialize};
use qchain_crypto::{Keypair, MultiSignature, PublicKeyBundle, Pubkey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// A single instruction routed to a program. `accounts` lists the pubkeys
/// the instruction touches, in an order the target program defines and
/// interprets - the Solana-style convention this project's execution model
/// is built on (see `ARCHITECTURE.md` §4 and the `blockchain-core-rust`
/// skill for why: declared account lists are what make conflict detection,
/// and therefore parallel execution, possible).
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<Pubkey>,
    pub data: Vec<u8>,
}

/// The only transaction/message format version this node accepts. It is signed
/// into every `Message` (so it's authenticated) and RE-VERIFIED at committed
/// execution (`Ledger::apply_transaction`) — a byzantine proposer must not be
/// able to smuggle a tx of a different (future/unknown) version into a committed
/// batch (audit v8.6.13 #7 / LESSONS-LEDGER EC-08). Bump only in a coordinated
/// format change, widening the accept-set deliberately.
pub const CURRENT_TX_VERSION: u8 = 1;

/// The signable payload of a transaction. Format per `ARCHITECTURE.md` §2.
///
/// `nonce` (not just a recency anchor) matters more here than in a
/// single-leader chain: DAG-ordered transactions don't have one linear
/// "block height" the way a sequential chain does until Bullshark commits
/// an order, so explicit per-account nonces are the primary replay defense
/// *within* one network - `chain_id` is what stops the identical signed
/// bytes from also being valid on a *different* one.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Message {
    pub version: u8,
    pub payer: Pubkey,
    pub payer_keys: PublicKeyBundle,
    pub nonce: u64,
    /// A real, live-confirmed cross-network replay gap this closes (see
    /// `project-lessons-learned`): this field used to be an unused
    /// recency-anchor placeholder (`recent_cert_ref`, always `[0u8; 32]`
    /// everywhere in this codebase - nothing ever populated it with an
    /// actual certificate digest). Since `nonce` was the *only* real
    /// replay defense, a transaction signed once validated identically on
    /// any other independent network sharing the same validator set and
    /// payer nonce state - confirmed live by replaying one signed transfer
    /// verbatim across two genuinely separate testnet processes. Now the
    /// hash of the network's own genesis data (`NodeConfig::chain_id`,
    /// computed identically by every validator from `validators`+`genesis`,
    /// no coordination round-trip needed) - checked at admission
    /// (`Engine::submit_transaction`/`TransactionGossip`, the same layer
    /// that already gates on signature validity) against the receiving
    /// network's own chain_id. A genuine recency anchor (binding to a
    /// specific recently-seen certificate, not just a network identity) is
    /// still a separate, not-yet-built concern - this only closes the
    /// cross-network case.
    pub chain_id: [u8; 32],
    /// Maximum total fee (base + priority + gas) the payer authorizes.
    pub fee_limit: u64,
    /// Optional tip (in base units, flat) the payer adds ON TOP of the dynamic
    /// base fee to prioritize this transaction under congestion - an EIP-1559-
    /// style priority fee. Goes 100% to the block proposer (`fee_collector`),
    /// never burned, so validators are incentivized to include higher-tip
    /// transactions first. `0` (the default via `new_signed`) means no tip.
    /// Signed as part of the message, so it can't be altered in flight.
    pub priority_fee: u64,
    /// **Expiración de la transacción (max-height)** — tarea #191, QCH-S4. La
    /// última ronda de consenso en la que esta tx puede EJECUTARSE. `0` = SIN
    /// expiración (comportamiento histórico; el default de `new_signed`). Con un
    /// valor `> 0`, la tx se rechaza —tanto en ADMISIÓN como en EJECUCIÓN— si
    /// `current_round > valid_until_round`. Va FIRMADO dentro del mensaje, así
    /// que no se puede alterar en vuelo. Cierra dos problemas reales: (a) una tx
    /// firmada no queda válida para siempre (una que se quedó en un mempool
    /// puede caducar en vez de ejecutarse semanas después a un fee/estado que el
    /// firmante ya no espera), y (b) da una ventana de validez acotada como la
    /// `lastValidBlockHeight` de Solana / el `Expiration` de Cosmos. La
    /// verificación en EJECUCIÓN es determinista (función pura de la ronda
    /// comprometida, idéntica en todo validador) → sin fork; un proposer
    /// Bizantino que incluya una tx ya caducada en un batch la ve rechazada por
    /// todos igual.
    pub valid_until_round: u64,
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug)]
pub struct Transaction {
    pub message: Message,
    pub signature: MultiSignature,
}

impl Transaction {
    pub fn new_signed(
        payer: &Keypair,
        nonce: u64,
        chain_id: [u8; 32],
        fee_limit: u64,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Self> {
        Self::new_signed_with_priority(payer, nonce, chain_id, fee_limit, 0, instructions)
    }

    /// Like `new_signed` but with an explicit priority-fee tip (see
    /// `Message::priority_fee`). `new_signed` is exactly this with tip `0`.
    /// Expiración desactivada (`valid_until_round = 0`) — usar
    /// [`new_signed_full`](Self::new_signed_full) para acotar la validez.
    pub fn new_signed_with_priority(
        payer: &Keypair,
        nonce: u64,
        chain_id: [u8; 32],
        fee_limit: u64,
        priority_fee: u64,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Self> {
        Self::new_signed_full(payer, nonce, chain_id, fee_limit, priority_fee, 0, instructions)
    }

    /// Constructor completo — firma un mensaje con TIP de prioridad y
    /// EXPIRACIÓN explícitos (tarea #191). `valid_until_round = 0` significa sin
    /// expiración; un valor `> 0` es la última ronda en que la tx puede
    /// ejecutarse (rechazada en admisión y ejecución si `current_round` la pasa).
    /// `new_signed`/`new_signed_with_priority` son este mismo con `0`/`0`.
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_full(
        payer: &Keypair,
        nonce: u64,
        chain_id: [u8; 32],
        fee_limit: u64,
        priority_fee: u64,
        valid_until_round: u64,
        instructions: Vec<Instruction>,
    ) -> anyhow::Result<Self> {
        let payer_keys = payer.public_key_bundle();
        let message = Message {
            version: CURRENT_TX_VERSION,
            payer: payer_keys.to_address(),
            payer_keys,
            nonce,
            chain_id,
            fee_limit,
            priority_fee,
            valid_until_round,
            instructions,
        };
        // Envelope etiquetado por dominio (#187): se firma `TX_SIG_V1 ‖ borsh(msg)`
        // (antes se firmaba `borsh(msg)` pelado) → una firma de tx nunca puede
        // reinterpretarse como la de un voto/vértice. Wire-breaking de FIRMA.
        let bytes = borsh::to_vec(&message).expect("message always serializes");
        let signature = qchain_crypto::sign_domain(payer, qchain_crypto::domains::TX_SIG_V1, &bytes)?;
        Ok(Transaction { message, signature })
    }

    /// Checks the attached key bundle hashes to the claimed payer address,
    /// then verifies every signature component of the combo the bundle
    /// resolves to. See `ARCHITECTURE.md` §2's hybrid signature policy and
    /// `qchain_crypto::verify`'s docs for exactly how an incomplete or
    /// substituted combo gets rejected, not silently accepted.
    pub fn verify_signature(&self) -> bool {
        if self.message.payer_keys.to_address() != self.message.payer {
            return false;
        }
        match borsh::to_vec(&self.message) {
            // Verifica sobre `TX_SIG_V1 ‖ borsh(msg)` — el mismo envelope que
            // firma `new_signed_full` (#187).
            Ok(bytes) => qchain_crypto::verify_domain(
                &self.message.payer_keys,
                qchain_crypto::domains::TX_SIG_V1,
                &bytes,
                &self.signature,
            ),
            Err(_) => false,
        }
    }

    /// Which combo the payer's key bundle resolves to (`None` if it doesn't
    /// resolve to any known combo at all). Callers that need this - e.g.
    /// `Ledger::apply_transaction` checking the live on-chain registry's
    /// status for each of the combo's component schemes - should still call
    /// `verify_signature()` first; this alone does not check that the
    /// attached signature actually verifies.
    pub fn resolved_combo(&self) -> Option<qchain_crypto::AlgorithmId> {
        let schemes: Vec<qchain_crypto::AlgorithmId> = self.message.payer_keys.components.iter().map(|c| c.scheme).collect();
        qchain_crypto::combo_from_components(&schemes)
    }

    /// **Identificador canónico de la transacción (txid)** — QCH-CRY-004,
    /// tarea #186. Se hashea SOLO el `Message` canónico (con separador de
    /// dominio `TXID_V1`), **sin las firmas**, así el txid es ESTABLE frente a
    /// la maleabilidad de la firma (un componente ML-DSA re-codificado
    /// válidamente no cambia el txid). El anti-doble-gasto ya depende del
    /// `nonce` dentro del `Message`, no del txid. Es el id que se expone en RPC
    /// y se usa como manija user-facing de la transacción.
    pub fn txid(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(qchain_crypto::domains::TXID_V1);
        if let Ok(bytes) = borsh::to_vec(&self.message) {
            hasher.update(bytes);
        }
        hasher.finalize().into()
    }

    /// Hash de CONTENIDO del sobre firmado (mensaje **+** firmas) — es el
    /// content-address de los bytes exactos, usado como digest de la tx dentro
    /// de un `Batch` de Narwhal: dos codificaciones distintas de firma producen
    /// batches distintos, evitando la maleabilidad del batch. NO usar como txid
    /// user-facing (para eso está [`txid`](Self::txid), que es canónico).
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        if let Ok(bytes) = borsh::to_vec(&self.message) {
            hasher.update(bytes);
        }
        for component in &self.signature.components {
            hasher.update(component.scheme.0.to_le_bytes());
            hasher.update(&component.bytes);
        }
        hasher.finalize().into()
    }

    /// Serialized byte size - what the fee's byte-scaled component prices
    /// (`ARCHITECTURE.md` §5). Dominated by the PQC signature component(s)
    /// and (on first use of an address) the public key bundle - scales up
    /// automatically for a triple-hybrid (SLH-DSA opt-in) combo, since it
    /// sums every signature component's real length rather than assuming a
    /// fixed two-component shape.
    pub fn byte_size(&self) -> usize {
        borsh::to_vec(&self.message).map(|b| b.len()).unwrap_or(0)
            + self.signature.components.iter().map(|c| c.bytes.len()).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ix(payer: Pubkey, to: Pubkey) -> Instruction {
        Instruction {
            program_id: Pubkey::system_program_id(),
            accounts: vec![payer, to],
            data: vec![1, 2, 3],
        }
    }

    #[test]
    fn signed_transaction_verifies() {
        let payer = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        assert!(tx.verify_signature());
    }

    #[test]
    fn tampered_transaction_fails_verification() {
        let payer = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let mut tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        tx.message.nonce = 999;
        assert!(!tx.verify_signature());
    }

    /// QCH-CRY-004 / tarea #186: el txid canónico es función SOLO del mensaje
    /// (estable frente a la maleabilidad de la firma), mientras que el hash de
    /// contenido (para el batch) SÍ cambia si cambian las firmas.
    #[test]
    fn txid_is_canonical_and_ignores_the_signature() {
        let payer = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let mut tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        let txid_before = tx.txid();
        let hash_before = tx.hash();
        // Mutar los BYTES de la firma (simula una re-codificación maleada).
        tx.signature.components[0].bytes[0] ^= 0xff;
        assert_eq!(tx.txid(), txid_before, "el txid NO debe cambiar al cambiar la firma");
        assert_ne!(tx.hash(), hash_before, "el hash de contenido (batch) SÍ cambia con la firma");
        // El txid liga el dominio + el mensaje canónico.
        assert_ne!(tx.txid(), tx.hash(), "txid (canónico) y hash (contenido) son distintos");
    }

    /// #191: `valid_until_round` va FIRMADO — mutar el campo invalida la firma
    /// (un atacante no puede extender ni acortar la ventana de validez en vuelo)
    /// y un round-trip Borsh lo preserva.
    #[test]
    fn valid_until_round_is_signed_and_round_trips() {
        let payer = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let tx = Transaction::new_signed_full(&payer, 0, [0u8; 32], 1_000, 0, 12_345, vec![ix]).unwrap();
        assert!(tx.verify_signature(), "la tx con expiración verifica");
        assert_eq!(tx.message.valid_until_round, 12_345);
        // Round-trip Borsh preserva el campo.
        let bytes = borsh::to_vec(&tx).unwrap();
        let back: Transaction = borsh::from_slice(&bytes).unwrap();
        assert_eq!(back.message.valid_until_round, 12_345);
        // Mutar el campo rompe la firma (está dentro del mensaje firmado).
        let mut tampered = tx.clone();
        tampered.message.valid_until_round = 999_999;
        assert!(!tampered.verify_signature(), "cambiar la expiración debe invalidar la firma");
    }

    /// #192: la deserialización Borsh es CANÓNICA — rechaza bytes sobrantes
    /// (trailing) y una entrada truncada, así un atacante no puede colar bytes
    /// extra tras una tx válida ni presentar dos codificaciones del mismo
    /// contenido (maleabilidad de encoding).
    #[test]
    fn transaction_deserialization_is_canonical_no_trailing_bytes() {
        let payer = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        let bytes = borsh::to_vec(&tx).unwrap();
        // Round-trip exacto OK.
        let round: Transaction = borsh::from_slice(&bytes).unwrap();
        assert_eq!(round.txid(), tx.txid());
        // UN byte extra al final → rechazado (no canónico).
        let mut trailing = bytes.clone();
        trailing.push(0u8);
        assert!(borsh::from_slice::<Transaction>(&trailing).is_err(), "Borsh debe rechazar bytes sobrantes");
        // Truncada → rechazada.
        assert!(borsh::from_slice::<Transaction>(&bytes[..bytes.len() - 1]).is_err(), "una entrada truncada debe rechazarse");
    }

    /// #187: la firma de una transacción real NO verifica como un voto de
    /// vértice sobre los mismos bytes (ni al revés) — la separación tx/consenso
    /// ahora es por dominio explícito, no sólo por longitud/estructura.
    #[test]
    fn tx_signature_is_not_a_vertex_vote() {
        let payer = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        assert!(tx.verify_signature());
        let msg_bytes = borsh::to_vec(&tx.message).unwrap();
        // La firma de la tx (dominio TX_SIG_V1) no verifica como voto de vértice
        // (dominio VERTEX_VOTE_V1) sobre los mismos bytes del mensaje.
        assert!(
            !qchain_crypto::verify_vertex_vote(&tx.message.payer_keys, &msg_bytes, &tx.signature),
            "una firma de tx no debe pasar como voto de vértice"
        );
    }

    #[test]
    fn forged_key_bundle_fails_verification() {
        let payer = Keypair::generate().unwrap();
        let attacker = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let mut tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        tx.message.payer_keys = attacker.public_key_bundle();
        assert!(!tx.verify_signature());
    }

    #[test]
    fn byte_size_reflects_pqc_signature_weight() {
        let payer = Keypair::generate().unwrap();
        let to = Keypair::generate().unwrap().pubkey();
        let ix = sample_ix(payer.pubkey(), to);
        let tx = Transaction::new_signed(&payer, 0, [0u8; 32], 1_000, vec![ix]).unwrap();
        // Dominated by the ~1.9KB ML-DSA-65 pubkey + ~3.3KB signature, not
        // the handful of bytes of instruction data - the exact number this
        // project's fee model has to account for (ARCHITECTURE.md §2).
        assert!(tx.byte_size() > 5_000, "byte_size = {}", tx.byte_size());
    }
}

#[cfg(test)]
mod proptests {
    //! Property-based tests (task #200): invariantes ejercitadas sobre MUCHOS
    //! inputs generados, no unos pocos casos a mano. Complementa el fuzzing de
    //! `fuzz/` (mismo objetivo — el borde de wire nunca panica) con propiedades
    //! de correctitud sobre transacciones firmadas reales.
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Deserializar bytes ARBITRARIOS como Transaction/Message NUNCA debe
        // panicar ni colgarse — devuelve Err o un valor, jamás rompe (robustez
        // del borde de wire, estilo fuzz, corrido en cada CI).
        #[test]
        fn arbitrary_bytes_deserialize_without_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = borsh::from_slice::<Transaction>(&bytes);
            let _ = borsh::from_slice::<Message>(&bytes);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        // Para CUALQUIER combinación de campos escalares, una tx firmada (a)
        // verifica, (b) round-trippea por Borsh preservando todos los campos, y
        // (c) su txid es estable frente a una mutación de la firma (maleabilidad).
        #[test]
        fn signed_tx_roundtrips_and_txid_is_stable(
            nonce in any::<u64>(), fee in any::<u64>(), tip in any::<u64>(),
            valid in any::<u64>(), amount in any::<u64>(),
        ) {
            let payer = Keypair::generate().unwrap();
            let to = Keypair::generate().unwrap().pubkey();
            let ix = Instruction {
                program_id: Pubkey::system_program_id(),
                accounts: vec![payer.pubkey(), to],
                data: amount.to_le_bytes().to_vec(),
            };
            let tx = Transaction::new_signed_full(&payer, nonce, [7u8; 32], fee, tip, valid, vec![ix]).unwrap();
            prop_assert!(tx.verify_signature());
            let bytes = borsh::to_vec(&tx).unwrap();
            let back: Transaction = borsh::from_slice(&bytes).unwrap();
            prop_assert_eq!(back.message.nonce, nonce);
            prop_assert_eq!(back.message.fee_limit, fee);
            prop_assert_eq!(back.message.priority_fee, tip);
            prop_assert_eq!(back.message.valid_until_round, valid);
            prop_assert!(back.verify_signature());
            // txid ignora la firma: mutar la firma no cambia el txid.
            let txid = tx.txid();
            let mut m = tx.clone();
            m.signature.components[0].bytes[0] ^= 0xff;
            prop_assert_eq!(m.txid(), txid);
        }
    }
}
