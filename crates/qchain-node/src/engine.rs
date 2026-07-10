//! Wires storage, execution, and consensus into a running validator
//! (design: `ARCHITECTURE.md` §1/§4). Implements the real Narwhal
//! propose -> vote -> certificate -> broadcast cycle over
//! `qchain-network`'s TCP transport, and drives `qchain-consensus`'s
//! Bullshark ordering to decide what gets executed and when.
//!
//! Phase-1 simplifications, called out explicitly rather than left
//! implicit: no worker tier (a validator gossips its own batch directly
//! alongside its vertex, see `qchain_network::message`), no retry/recovery
//! if a certificate commits before its batch has arrived (the transactions
//! are simply skipped and logged), and no garbage collection of stale vote
//! entries for vertices that never reach quorum. All are noted as phase-2
//! hardening work in the `blockchain-core-rust` skill.
//!
//! **Mempool nonce-ordering bug (found via load testing, see
//! `project-lessons-learned`) - fixed.** The mempool used to be a flat
//! `Vec<Transaction>`, drained wholesale into a batch every round in
//! whatever order transactions happened to arrive. Two transactions from
//! the same account submitted concurrently could land in mempool - and
//! therefore in the same batch - out of nonce order; `try_commit` applies
//! a batch's transactions in order and never retries a failure, so a
//! higher-nonce transaction processed before its lower-nonce predecessor
//! failed with a nonce mismatch and was silently dropped forever. Worse,
//! a transaction that simply hadn't arrived at this validator yet by the
//! time its round's batch was formed suffered the same fate: included
//! without its predecessor, rejected, gone. Fixed by keying the mempool
//! per-account and by nonce (`drain_ready_transactions`) - a transaction
//! only ever enters a batch once every lower nonce for its account is
//! already accounted for, and anything with a gap ahead of it just stays
//! queued for a later round instead of being drained blindly.

use qchain_consensus::{verify_certificate, ConsensusState, DagStore, ValidatorSet};
use qchain_core::{Batch, Certificate, Digest, Round, Transaction, ValidatorId, Vertex};
use qchain_crypto::{MultiSignature, Keypair, Pubkey};
use qchain_execution::Ledger;
use qchain_network::{NetMessage, Network};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use tokio::sync::Mutex;

pub struct EngineState {
    pub ledger: Ledger,
    pub dag: DagStore,
    pub consensus: ConsensusState,
    /// Per-account, nonce-ordered mempool - see the module docs above for
    /// the real bug a flat `Vec` had. Keyed by payer, then by nonce; a
    /// resubmission for a (payer, nonce) pair that's already queued is
    /// ignored, keeping whichever transaction arrived first.
    pub mempool: HashMap<Pubkey, BTreeMap<u64, Transaction>>,
    pub batches: HashMap<Digest, Batch>,
    pub pending_votes: HashMap<Digest, HashMap<ValidatorId, MultiSignature>>,
    pub own_pending_vertex: Option<Vertex>,
    pub next_round: Round,
    pub executed: u64,
    /// Which vertex digest this validator has already voted for, per
    /// (round, author) - the equivocation lock. Without it, a Byzantine
    /// author could get two *different* vertices for the same round each
    /// certified by an overlapping-but-distinct 2f+1 quorum, since with
    /// n=3f+1 stake, any two 2f+1 quorums must share at least f+1
    /// validators; refusing to sign a second, conflicting vertex for a
    /// (round, author) already voted on keeps that overlap below what a
    /// Byzantine minority (at most f) can supply on its own.
    pub voted_for: HashMap<(Round, ValidatorId), Digest>,
}

pub struct Engine {
    pub self_id: ValidatorId,
    pub keypair: Keypair,
    pub validators: ValidatorSet,
    pub network: Network,
    pub state: Mutex<EngineState>,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub validator: String,
    pub next_round: Round,
    pub dag_certificates: usize,
    pub executed_transactions: u64,
}

/// What `GET /stark_proof` hands back to a light client - a real
/// Winterfell proof (hex-encoded via its own `to_bytes`, since `Proof`
/// itself has no serde impl) alongside the public inputs and Merkle
/// bindings needed to call `qchain_stark::verify_batch_bound_to_state`
/// independently.
#[derive(Serialize)]
pub struct StarkProofResponse {
    #[serde(serialize_with = "serialize_proof_as_hex")]
    pub proof: qchain_stark::Proof,
    pub pub_inputs: qchain_stark::PublicInputs,
    pub bindings: Vec<qchain_stark::RowStateBinding>,
    pub row_count: usize,
}

fn serialize_proof_as_hex<S: serde::Serializer>(proof: &qchain_stark::Proof, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(proof.to_bytes()))
}

#[derive(Debug, thiserror::Error)]
pub enum StarkProofError {
    #[error("no transfer receipts captured yet - nothing to prove")]
    NoReceipts,
    #[error("failed to build STARK proof: {0}")]
    Prove(String),
    /// See `Engine::stark_proof`'s doc comment for the real, non-hypothetical
    /// way this fires: a non-transfer transaction executed between two
    /// included transfer receipts, breaking the contiguous root chain
    /// `verify_batch_bound_to_state` requires.
    #[error("captured receipts don't form one contiguous state transition: {0}")]
    ChainBroken(String),
}

/// Pulls every transaction that's actually ready to execute out of the
/// mempool, per account, in nonce order - see the module docs for the real
/// bug this replaces. For each account with queued transactions: first
/// drop anything at or below the account's current on-chain nonce (already
/// applied, whether by this validator or - in a multi-node network - by
/// whichever validator's batch got committed first; it can never apply
/// again), then consume consecutive nonces starting from the account's
/// current nonce for as long as they're present. The first gap stops that
/// account's contribution for this round; everything after the gap stays
/// queued, not silently dropped.
fn drain_ready_transactions(state: &mut EngineState) -> Vec<Transaction> {
    let mut ready = Vec::new();
    let mut empty_accounts = Vec::new();
    for (payer, queue) in state.mempool.iter_mut() {
        let mut expected_nonce = state.ledger.store().get(payer).map(|a| a.nonce).unwrap_or(0);
        while queue.keys().next().is_some_and(|&n| n < expected_nonce) {
            queue.pop_first();
        }
        while let Some(tx) = queue.remove(&expected_nonce) {
            ready.push(tx);
            expected_nonce += 1;
        }
        if queue.is_empty() {
            empty_accounts.push(*payer);
        }
    }
    for payer in empty_accounts {
        state.mempool.remove(&payer);
    }
    ready
}

impl Engine {
    /// Admits a client-submitted transaction into the local mempool once
    /// its hybrid signature checks out. No nonce/balance admission control
    /// here - that happens once for real at execution time
    /// (`Ledger::apply_transaction`); a transaction that turns out invalid
    /// once its batch is ordered is simply skipped (see `try_commit`).
    pub async fn submit_transaction(&self, tx: Transaction) -> anyhow::Result<[u8; 32]> {
        if !tx.verify_signature() {
            anyhow::bail!("invalid transaction signature");
        }
        let hash = tx.hash();
        let mut state = self.state.lock().await;
        state.mempool.entry(tx.message.payer).or_default().entry(tx.message.nonce).or_insert(tx);
        Ok(hash)
    }

    pub async fn get_account(&self, pk: &Pubkey) -> Option<qchain_core::Account> {
        let state = self.state.lock().await;
        state.ledger.store().get(pk)
    }

    /// Current state-tree Merkle root, plus how many `TransferReceipt`s
    /// this validator has captured so far - what a light client polls to
    /// notice the root has advanced before asking for a proof.
    pub async fn merkle_root(&self) -> ([u8; 32], usize) {
        let state = self.state.lock().await;
        (state.ledger.merkle_root(), state.ledger.transfer_receipts().len())
    }

    /// Builds a real `qchain-stark` proof over the most recent `limit`
    /// captured transfer receipts (all of them if `limit` is `None`),
    /// binds it to the real Merkle root transitions those receipts
    /// recorded, and self-verifies via `verify_batch_bound_to_state`
    /// before ever handing it to a caller - a validator should never
    /// serve a proof it hasn't itself confirmed verifies.
    ///
    /// Real limitation, not silently glossed over: `verify_batch_bound_to_state`
    /// requires the bound rows to be one *contiguous* run of state
    /// transitions (each row's `root_after` must equal the next row's
    /// `root_before`). Receipts are only captured for single-instruction
    /// `Transfer` transactions (see `qchain_execution::receipt`'s module
    /// docs) - if any other transaction (staking, governance, a
    /// multi-instruction transaction) executed in between two included
    /// transfers, the real root moved without a receipt recording it, and
    /// self-verification below fails with `RootSequenceMismatch`. That is
    /// surfaced as `StarkProofError::ChainBroken`, not swallowed.
    pub async fn stark_proof(&self, limit: Option<usize>) -> Result<StarkProofResponse, StarkProofError> {
        let receipts: Vec<qchain_execution::TransferReceipt> = {
            let state = self.state.lock().await;
            let all = state.ledger.transfer_receipts();
            match limit {
                Some(n) if n < all.len() => all[all.len() - n..].to_vec(),
                _ => all.to_vec(),
            }
        };
        if receipts.is_empty() {
            return Err(StarkProofError::NoReceipts);
        }

        let steps: Vec<qchain_stark::TransferStep> = receipts
            .iter()
            .map(|r| {
                qchain_stark::TransferStep::conserving(
                    r.from.to_bytes(),
                    r.to.to_bytes(),
                    r.from_before.balance,
                    r.to_before.balance,
                    r.amount,
                    r.fee,
                )
            })
            .collect();
        let bindings: Vec<qchain_stark::RowStateBinding> = receipts
            .iter()
            .map(|r| qchain_stark::RowStateBinding {
                root_before: r.root_before,
                root_after: r.root_after,
                from_before: r.from_before.clone(),
                from_after: r.from_after.clone(),
                to_before: r.to_before.clone(),
                to_after: r.to_after.clone(),
                from_proof_before: r.from_proof_before.clone(),
                from_proof_after: r.from_proof_after.clone(),
                to_proof_before: r.to_proof_before.clone(),
                to_proof_after: r.to_proof_after.clone(),
            })
            .collect();

        let (proof, pub_inputs) = qchain_stark::prove_batch(&steps).map_err(|e| StarkProofError::Prove(e.to_string()))?;
        qchain_stark::verify_batch_bound_to_state(proof.clone(), pub_inputs.clone(), &bindings)
            .map_err(|e| StarkProofError::ChainBroken(e.to_string()))?;

        Ok(StarkProofResponse { proof, pub_inputs, bindings, row_count: receipts.len() })
    }

    pub async fn status(&self) -> StatusResponse {
        let state = self.state.lock().await;
        StatusResponse {
            validator: self.self_id.to_string(),
            next_round: state.next_round,
            dag_certificates: state.dag.len(),
            executed_transactions: state.executed,
        }
    }

    pub async fn handle_message(&self, from: ValidatorId, msg: NetMessage) {
        match msg {
            NetMessage::BatchGossip(batch) => {
                let digest = batch.digest();
                let mut state = self.state.lock().await;
                state.batches.entry(digest).or_insert(batch);
            }
            NetMessage::VertexProposal(vertex) => {
                if vertex.author != from {
                    tracing::warn!("dropping vertex proposal with mismatched author/sender");
                    return;
                }
                self.request_missing_parents(&vertex.parents, from).await;
                let digest = vertex.digest();
                let key = (vertex.round, vertex.author);
                {
                    let mut state = self.state.lock().await;
                    match state.voted_for.get(&key) {
                        Some(existing) if *existing != digest => {
                            tracing::warn!(
                                "refusing to vote for a second, conflicting vertex from {from} at round {} - possible equivocation",
                                vertex.round
                            );
                            return;
                        }
                        Some(_) => {} // already voted for exactly this vertex - re-signing is harmless, fall through
                        None => {
                            state.voted_for.insert(key, digest);
                        }
                    }
                }
                let sig = match self.keypair.sign(&digest[..]) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("failed to sign vote: {e}");
                        return;
                    }
                };
                if let Some(addr) = self.network.addr_of(&from) {
                    if let Err(e) = self.network.send_to(addr, &NetMessage::Vote { vertex_digest: digest, signature: sig }).await {
                        tracing::warn!("failed to send vote to {from}: {e}");
                    }
                }
            }
            NetMessage::Vote { vertex_digest, signature } => {
                if let Some(cert) = self.record_vote(vertex_digest, from, signature).await {
                    self.network.broadcast(&NetMessage::CertificateBroadcast(cert)).await;
                    self.try_commit().await;
                }
            }
            NetMessage::CertificateBroadcast(cert) => {
                if !verify_certificate(&cert, &self.validators) {
                    tracing::warn!("dropping certificate that fails quorum verification");
                    return;
                }
                let parents = cert.vertex.parents.clone();
                {
                    let mut state = self.state.lock().await;
                    state.dag.insert(cert);
                }
                self.request_missing_parents(&parents, from).await;
                self.try_commit().await;
            }
            NetMessage::CertificateRequest { digest } => {
                let found = {
                    let state = self.state.lock().await;
                    state.dag.get(&digest).cloned()
                };
                if let (Some(cert), Some(addr)) = (found, self.network.addr_of(&from)) {
                    if let Err(e) = self.network.send_to(addr, &NetMessage::CertificateResponse(cert)).await {
                        tracing::warn!("failed to send certificate response to {from}: {e}");
                    }
                }
            }
            NetMessage::CertificateResponse(cert) => {
                if !verify_certificate(&cert, &self.validators) {
                    tracing::warn!("dropping certificate response that fails quorum verification");
                    return;
                }
                let parents = cert.vertex.parents.clone();
                {
                    let mut state = self.state.lock().await;
                    state.dag.insert(cert);
                }
                self.request_missing_parents(&parents, from).await;
                self.try_commit().await;
            }
        }
    }

    /// Requests, from `from`, any of `parents` this validator doesn't
    /// already have locally - see `NetMessage::CertificateRequest`'s doc
    /// comment for why this exists: a `CertificateBroadcast` is a one-shot
    /// send with no retry, so without this, a single dropped copy leaves
    /// the missing certificate (and anything in the DAG only reachable
    /// through it) permanently unrecoverable - a real, confirmed
    /// complete-stall liveness bug found via `qchain-simulation` before
    /// this existed (see `project-lessons-learned`), not a hypothetical
    /// gap. `from` is asked because it just sent a message referencing
    /// these digests as parents, so it must have had them itself.
    async fn request_missing_parents(&self, parents: &[Digest], from: ValidatorId) {
        let missing: Vec<Digest> = {
            let state = self.state.lock().await;
            parents.iter().copied().filter(|d| !state.dag.contains(d)).collect()
        };
        if missing.is_empty() {
            return;
        }
        let Some(addr) = self.network.addr_of(&from) else { return };
        for digest in missing {
            if let Err(e) = self.network.send_to(addr, &NetMessage::CertificateRequest { digest }).await {
                tracing::warn!("failed to request missing certificate {digest:?} from {from}: {e}");
            }
        }
    }

    /// Records a vote toward whichever vertex this validator currently has
    /// pending certification. Returns the freshly-formed certificate the
    /// moment quorum stake is reached, `None` otherwise (including when the
    /// vote is for a vertex that isn't this validator's own proposal - only
    /// a vertex's author collects its votes).
    async fn record_vote(&self, vertex_digest: Digest, voter: ValidatorId, sig: MultiSignature) -> Option<Certificate> {
        let mut state = self.state.lock().await;
        state.pending_votes.entry(vertex_digest).or_default().insert(voter, sig);

        let vertex = state.own_pending_vertex.as_ref()?;
        if vertex.digest() != vertex_digest {
            return None;
        }

        let stake: u64 = state.pending_votes[&vertex_digest].keys().map(|id| self.validators.stake_of(id)).sum();
        if stake < self.validators.quorum_threshold() {
            return None;
        }

        let vertex = state.own_pending_vertex.take().unwrap();
        let signatures = state.pending_votes.remove(&vertex_digest).unwrap().into_iter().collect();
        let cert = Certificate { vertex, signatures };
        state.dag.insert(cert.clone());
        Some(cert)
    }

    /// Re-runs Bullshark ordering over the current DAG and executes every
    /// newly-finalized certificate's batch, crediting that certificate's
    /// author as the fee collector - the same deterministic choice every
    /// validator makes, keeping ledger state consistent across the
    /// network.
    async fn try_commit(&self) {
        let mut state = self.state.lock().await;
        let state = &mut *state;
        let newly_ordered = state.consensus.advance(&state.dag, &self.validators);
        for digest in newly_ordered {
            let Some(cert) = state.dag.get(&digest).cloned() else { continue };
            // Not removed on use: an empty (or otherwise coincidentally
            // identical) batch can be the `batch_digest` referenced by
            // more than one certificate, so the cache is keyed by content,
            // not by a single certificate's claim on it. Phase-1
            // limitation: the cache is never pruned, so it grows with the
            // number of distinct batches ever gossiped - fine at testnet
            // scale, a real eviction policy is later work.
            let Some(batch) = state.batches.get(&cert.vertex.batch_digest).cloned() else {
                tracing::warn!("committed certificate references an unseen batch - skipping its transactions");
                continue;
            };
            for tx in &batch.transactions {
                match state.ledger.apply_transaction(tx, &cert.vertex.author, cert.vertex.round) {
                    Ok(_) => state.executed += 1,
                    Err(e) => tracing::warn!("transaction execution failed: {e}"),
                }
            }
        }
    }

    /// Proposes this validator's vertex for the next round, once the
    /// previous round has quorum certificates to reference as parents (or
    /// immediately, for round 0). If a proposal is already pending
    /// certification, re-broadcasts that same vertex instead of no-op -
    /// see the retry note below.
    pub async fn propose_round(&self) {
        // Retry path: a proposal is still waiting on quorum votes.
        // Re-broadcasting it every tick until it certifies is what fixes
        // a real liveness bug found via `qchain-simulation`'s
        // healing-partition scenario (see project-lessons-learned):
        // without this, a single dropped copy of a VertexProposal (e.g.
        // during a transient network partition, or the ordinary
        // connection-refused race at validator startup) stalls this
        // validator - and every later round that depends on its
        // certificate - permanently, since nothing else ever resends it.
        // Idempotent for peers who already voted: the equivocation lock
        // in `handle_message`'s `VertexProposal` arm treats a repeat of
        // the exact same digest as a harmless no-op re-vote.
        let retry_vertex = {
            let state = self.state.lock().await;
            state.own_pending_vertex.clone()
        };
        if let Some(vertex) = retry_vertex {
            self.network.broadcast(&NetMessage::VertexProposal(vertex)).await;
            return;
        }

        let (vertex, batch) = {
            let mut state = self.state.lock().await;
            let round = state.next_round;
            if round > 0 {
                let prev_round = round - 1;
                let stake: u64 =
                    state.dag.certificates_in_round(prev_round).map(|c| self.validators.stake_of(&c.vertex.author)).sum();
                if stake < self.validators.quorum_threshold() {
                    return;
                }
            }

            let txs: Vec<Transaction> = drain_ready_transactions(&mut state);
            let batch = Batch { transactions: txs };
            let batch_digest = batch.digest();
            let parents: Vec<Digest> = if round == 0 {
                vec![]
            } else {
                let mut p: Vec<Digest> = state.dag.certificates_in_round(round - 1).map(|c| c.digest()).collect();
                p.sort();
                p
            };
            let vertex = Vertex { round, author: self.self_id, batch_digest, parents };
            state.batches.insert(batch_digest, batch.clone());
            state.own_pending_vertex = Some(vertex.clone());
            state.next_round = round + 1;
            state.voted_for.insert((round, self.self_id), vertex.digest());
            (vertex, batch)
        };

        self.network.broadcast(&NetMessage::BatchGossip(batch)).await;
        self.network.broadcast(&NetMessage::VertexProposal(vertex.clone())).await;

        let digest = vertex.digest();
        let sig = match self.keypair.sign(&digest[..]) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to self-sign proposed vertex: {e}");
                return;
            }
        };
        if let Some(cert) = self.record_vote(digest, self.self_id, sig).await {
            self.network.broadcast(&NetMessage::CertificateBroadcast(cert)).await;
            self.try_commit().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_core::{Account, Transaction};
    use qchain_crypto::Keypair;
    use qchain_execution::Ledger;
    use qchain_storage::InMemoryStore;

    fn new_state() -> EngineState {
        EngineState {
            ledger: Ledger::new(Box::new(InMemoryStore::new())).unwrap(),
            dag: DagStore::new(),
            consensus: ConsensusState::new(),
            mempool: HashMap::new(),
            batches: HashMap::new(),
            pending_votes: HashMap::new(),
            own_pending_vertex: None,
            next_round: 0,
            executed: 0,
            voted_for: HashMap::new(),
        }
    }

    fn tx(payer: &Keypair, nonce: u64) -> Transaction {
        Transaction::new_signed(payer, nonce, [0u8; 32], 1, vec![]).unwrap()
    }

    /// The exact bug this replaces: two transactions from the same account
    /// arrive out of nonce order (a real race under concurrent submission).
    /// The old flat-`Vec` mempool would include both in whatever order they
    /// landed - if the higher nonce came first in the batch, it failed and
    /// was dropped forever. The fixed mempool must always emit them in
    /// ascending nonce order regardless of arrival/insertion order.
    #[test]
    fn transactions_are_emitted_in_ascending_nonce_order_regardless_of_arrival_order() {
        let mut state = new_state();
        let alice = Keypair::generate().unwrap();
        state.ledger.seed_account(alice.pubkey(), Account::new_wallet(qchain_crypto::Pubkey::system_program_id()));

        // Insert nonce 1 before nonce 0 - simulating the exact race that
        // used to lose a transaction.
        let tx1 = tx(&alice, 1);
        let tx0 = tx(&alice, 0);
        state.mempool.entry(alice.pubkey()).or_default().insert(1, tx1.clone());
        state.mempool.entry(alice.pubkey()).or_default().insert(0, tx0.clone());

        let ready = drain_ready_transactions(&mut state);
        assert_eq!(ready.len(), 2, "both transactions must be included, not just one");
        assert_eq!(ready[0].message.nonce, 0);
        assert_eq!(ready[1].message.nonce, 1);
    }

    /// A transaction whose predecessor hasn't arrived yet must stay queued,
    /// not be dropped - it should surface in a later round once the gap is
    /// filled, rather than vanishing.
    #[test]
    fn a_transaction_with_a_missing_predecessor_stays_queued_instead_of_being_dropped() {
        let mut state = new_state();
        let alice = Keypair::generate().unwrap();
        state.ledger.seed_account(alice.pubkey(), Account::new_wallet(qchain_crypto::Pubkey::system_program_id()));

        // Only nonce 1 has arrived; nonce 0 (the account's current expected
        // nonce) is still missing.
        state.mempool.entry(alice.pubkey()).or_default().insert(1, tx(&alice, 1));

        let ready = drain_ready_transactions(&mut state);
        assert!(ready.is_empty(), "a transaction with a gap ahead of it must not be included yet");
        assert_eq!(state.mempool.get(&alice.pubkey()).map(|q| q.len()), Some(1), "it must remain queued, not be dropped");

        // Once the missing nonce 0 arrives, both become ready together.
        state.mempool.entry(alice.pubkey()).or_default().insert(0, tx(&alice, 0));
        let ready = drain_ready_transactions(&mut state);
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].message.nonce, 0);
        assert_eq!(ready[1].message.nonce, 1);
    }

    /// Entries at or below the account's current on-chain nonce (already
    /// applied, e.g. via another validator's batch in a multi-node
    /// network) must be garbage-collected rather than left to accumulate
    /// or block newer nonces forever.
    #[test]
    fn stale_entries_below_the_current_nonce_are_garbage_collected() {
        let mut state = new_state();
        let alice = Keypair::generate().unwrap();
        // Account's on-chain nonce is already 2 - nonce 0 and 1 are stale.
        state.ledger.seed_account(
            alice.pubkey(),
            Account { nonce: 2, ..Account::new_wallet(qchain_crypto::Pubkey::system_program_id()) },
        );
        state.mempool.entry(alice.pubkey()).or_default().insert(0, tx(&alice, 0));
        state.mempool.entry(alice.pubkey()).or_default().insert(1, tx(&alice, 1));
        state.mempool.entry(alice.pubkey()).or_default().insert(2, tx(&alice, 2));

        let ready = drain_ready_transactions(&mut state);
        assert_eq!(ready.len(), 1, "only the one transaction matching the real current nonce should be ready");
        assert_eq!(ready[0].message.nonce, 2);
        assert!(!state.mempool.contains_key(&alice.pubkey()), "the now-empty per-account queue must be cleaned up too");
    }

    /// Different accounts are independent - a gap in one account's nonce
    /// sequence must not block another account's ready transactions.
    #[test]
    fn independent_accounts_dont_block_each_other() {
        let mut state = new_state();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();
        state.ledger.seed_account(alice.pubkey(), Account::new_wallet(qchain_crypto::Pubkey::system_program_id()));
        state.ledger.seed_account(bob.pubkey(), Account::new_wallet(qchain_crypto::Pubkey::system_program_id()));

        // Alice has a gap (missing nonce 0); Bob is ready at nonce 0.
        state.mempool.entry(alice.pubkey()).or_default().insert(1, tx(&alice, 1));
        state.mempool.entry(bob.pubkey()).or_default().insert(0, tx(&bob, 0));

        let ready = drain_ready_transactions(&mut state);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].message.payer, bob.pubkey());
    }
}
