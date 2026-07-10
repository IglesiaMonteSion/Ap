//! Wire messages for the phase-1 P2P layer (design: `ARCHITECTURE.md` §1).
//! Deliberately small: Narwhal's full protocol separates "workers" (batch
//! dissemination) from "primaries" (vertex/certificate exchange); phase 1
//! collapses that into a single per-validator process that gossips batches
//! directly alongside vertices - real proposal/vote/certificate exchange,
//! without the worker-tier scaling optimization (see the `dag-network`
//! section of `blockchain-core-rust` skill and `ARCHITECTURE.md`'s phase-1
//! out-of-scope list).

use qchain_core::{Batch, Certificate, Digest, ValidatorId, Vertex};
use qchain_crypto::MultiSignature;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum NetMessage {
    /// A proposer's batch of transactions, sent so peers can execute them
    /// later once the corresponding vertex's certificate is ordered.
    BatchGossip(Batch),
    /// A proposer's round vertex, sent to every peer to be voted on.
    VertexProposal(Vertex),
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
}

/// Every message on the wire is wrapped with the sender's validator id -
/// the TCP source address alone isn't a trustworthy identity (phase 1 does
/// not yet authenticate the transport itself, only the application-level
/// signatures inside votes/certificates - see `ARCHITECTURE.md`'s phase-1
/// out-of-scope list for transport-layer auth).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Envelope {
    pub from: ValidatorId,
    pub message: NetMessage,
}
