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

use qchain_consensus::{verify_certificate, ConsensusState, DagStore, ValidatorSet};
use qchain_core::{Batch, Certificate, Digest, Round, Transaction, ValidatorId, Vertex};
use qchain_crypto::{HybridSignature, Keypair, Pubkey};
use qchain_execution::Ledger;
use qchain_network::{NetMessage, Network};
use serde::Serialize;
use std::collections::HashMap;
use tokio::sync::Mutex;

pub struct EngineState {
    pub ledger: Ledger,
    pub dag: DagStore,
    pub consensus: ConsensusState,
    pub mempool: Vec<Transaction>,
    pub batches: HashMap<Digest, Batch>,
    pub pending_votes: HashMap<Digest, HashMap<ValidatorId, HybridSignature>>,
    pub own_pending_vertex: Option<Vertex>,
    pub next_round: Round,
    pub executed: u64,
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
        state.mempool.push(tx);
        Ok(hash)
    }

    pub async fn get_account(&self, pk: &Pubkey) -> Option<qchain_core::Account> {
        let state = self.state.lock().await;
        state.ledger.store().get(pk)
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
                let digest = vertex.digest();
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
                {
                    let mut state = self.state.lock().await;
                    state.dag.insert(cert);
                }
                self.try_commit().await;
            }
        }
    }

    /// Records a vote toward whichever vertex this validator currently has
    /// pending certification. Returns the freshly-formed certificate the
    /// moment quorum stake is reached, `None` otherwise (including when the
    /// vote is for a vertex that isn't this validator's own proposal - only
    /// a vertex's author collects its votes).
    async fn record_vote(&self, vertex_digest: Digest, voter: ValidatorId, sig: HybridSignature) -> Option<Certificate> {
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
                match state.ledger.apply_transaction(tx, &cert.vertex.author) {
                    Ok(_) => state.executed += 1,
                    Err(e) => tracing::warn!("transaction execution failed: {e}"),
                }
            }
        }
    }

    /// Proposes this validator's vertex for the next round, once the
    /// previous round has quorum certificates to reference as parents (or
    /// immediately, for round 0). No-op if a proposal is already pending
    /// certification.
    pub async fn propose_round(&self) {
        let (vertex, batch) = {
            let mut state = self.state.lock().await;
            if state.own_pending_vertex.is_some() {
                return;
            }
            let round = state.next_round;
            if round > 0 {
                let prev_round = round - 1;
                let stake: u64 =
                    state.dag.certificates_in_round(prev_round).map(|c| self.validators.stake_of(&c.vertex.author)).sum();
                if stake < self.validators.quorum_threshold() {
                    return;
                }
            }

            let txs: Vec<Transaction> = state.mempool.drain(..).collect();
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
