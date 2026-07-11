//! Wire messages for the phase-1 P2P layer (design: `ARCHITECTURE.md` §1).
//! Narwhal's full protocol separates "workers" (batch dissemination) from
//! "primaries" (vertex/certificate exchange); this stays a single
//! per-validator process (no separate worker subprocess/port per lane -
//! that's a real deployment-topology simplification, not reopened here),
//! but the *message* layer keeps the two roles distinct: `WorkerBatchGossip`
//! (plus its request/response retry pair) is the worker-tier traffic, sent
//! and handled independently of `VertexProposal`/`Vote`/
//! `CertificateBroadcast` - a primary references multiple workers' batch
//! digests in one vertex (`Vertex::batch_digests`) rather than gossiping a
//! single inline batch alongside its vertex, so batch dissemination can
//! genuinely happen over separate concurrent sends instead of serializing
//! through one channel (see `ARCHITECTURE.md` §2's bandwidth analysis for
//! why this separation exists at all).

use borsh::{BorshDeserialize, BorshSerialize};
use qchain_core::{Batch, Certificate, Digest, ValidatorId, Vertex, WorkerId};
use qchain_crypto::MultiSignature;

#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub enum NetMessage {
    /// One worker lane's batch of transactions, sent independently of the
    /// vertex that will later reference it, so peers can execute it once
    /// the corresponding certificate is ordered.
    WorkerBatchGossip { worker_id: WorkerId, batch: Batch },
    /// A proposer's round vertex, sent to every peer to be voted on -
    /// `author_signature` is the proposer's own signature over
    /// `vertex.digest()` (the same signature it also casts as its own
    /// self-vote, see `qchain-node::engine::propose_round`), verified by
    /// every recipient against the claimed author's registered
    /// `PublicKeyBundle` before anything else happens with the message.
    /// Without this, two conflicting vertices for the same (round, author)
    /// were unattributable - anyone relaying a forged vertex could frame
    /// another validator, and no cryptographic evidence of real
    /// equivocation could ever be constructed (see
    /// `qchain_core::EquivocationEvidence` and `blockchain-security-audit`
    /// #3, which had already named "conflicting signed vertices" as
    /// slashable evidence before this field made that signature exist).
    VertexProposal { vertex: Vertex, author_signature: MultiSignature },
    /// A peer's vote (signature over the vertex digest) sent back to the
    /// vertex's author.
    Vote { vertex_digest: Digest, signature: MultiSignature },
    /// A quorum-certified vertex, broadcast once its author collects 2f+1
    /// vote stake.
    CertificateBroadcast(Certificate),
    /// "I don't have this certificate" - sent when a peer references a
    /// parent digest (in a `VertexProposal` or another `CertificateBroadcast`)
    /// that's missing from the local DAG. `CertificateBroadcast` is a
    /// one-shot send with no retry, so a single dropped copy otherwise
    /// leaves the recipient permanently unable to resolve that digest -
    /// found to be a real, complete-stall liveness bug via
    /// `qchain-simulation` (see `project-lessons-learned`), not a
    /// hypothetical gap.
    CertificateRequest { digest: Digest },
    /// Reply to a `CertificateRequest` - the certificate itself, re-sent
    /// so the requester can insert it into its own DAG and resume.
    CertificateResponse(Certificate),
    /// "I don't have this worker batch" - the exact same real gap
    /// `CertificateRequest` closes, one tier down: `WorkerBatchGossip` is
    /// also a one-shot send, and a lost copy would otherwise leave the
    /// referencing vertex's batch permanently unresolved (its transactions
    /// silently skipped at commit time forever, not just delayed).
    WorkerBatchRequest { worker_id: WorkerId, digest: Digest },
    /// Reply to a `WorkerBatchRequest` - the batch itself.
    WorkerBatchResponse { worker_id: WorkerId, batch: Batch },
}

/// Every message on the wire is wrapped with the sender's validator id -
/// the TCP source address alone isn't a trustworthy identity (phase 1 does
/// not yet authenticate the transport itself, only the application-level
/// signatures inside votes/certificates - see `ARCHITECTURE.md`'s phase-1
/// out-of-scope list for transport-layer auth).
#[derive(Clone, BorshSerialize, BorshDeserialize, Debug)]
pub struct Envelope {
    pub from: ValidatorId,
    pub message: NetMessage,
}
