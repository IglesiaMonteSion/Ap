//! State/snapshot sync: the catch-up path for a validator that fell further
//! behind than `engine::DAG_RETENTION_ROUNDS`. Its peers have garbage-
//! collected the old certificates it would otherwise replay from round 0
//! (see the DAG-pruning work), so there is nothing to fetch per-digest -
//! instead it pulls a *verified* account-state snapshot (`GET /snapshot`)
//! and resumes consensus from the snapshot's round.
//!
//! Trust model (honest, and the same "weak subjectivity" every light client
//! ultimately has - Bitcoin SPV and Ethereum snap-sync included): a snapshot
//! is verified for *internal* consistency (its accounts really do hash to
//! its claimed Merkle root) but the claimed root's *authenticity* is trusted
//! from the source peer, softened two ways: (1) a same-round cross-check
//! across every configured peer refuses to sync if any two disagree on the
//! root at the same round (a fork/attack tell), and (2) an optional operator
//! trust anchor (`state_sync_trusted_root`/`_round`) turns it into a fully
//! verified catch-up against a value obtained independently.
//!
//! **`#194`: the anchor can be made MANDATORY.** With
//! `require_state_sync_trust_anchor` set, this node refuses to state-sync at all
//! unless both anchor fields are pinned and the snapshot matches them — removing
//! weak subjectivity entirely (it never trusts a source peer's claimed root).
//! Default off keeps the opt-in model above byte-identical; on is the
//! production/mainnet setting. It's a node-LOCAL policy (not folded into
//! `chain_id`) and only touches the state-sync path, so a node with local state
//! never reaches it.

use qchain_node::config::NodeConfig;
use qchain_node::engine::{committee_fingerprint, SnapshotMeta, SnapshotPage, StateSnapshot, SNAPSHOT_PAGE_SIZE};
use qchain_storage::compressed::IncrementalCompressedTree;
use qchain_storage::IncrementalStateTree;
use std::time::Duration;

/// Absolute ceiling on how many accounts a snapshot may carry, independent of
/// what the source peer *claims* in `meta.account_count`. The per-page loop
/// already refuses to accumulate past `meta.account_count`, but that number is
/// itself attacker-controlled (a malicious configured peer could announce
/// `usize::MAX` and stream real pages forever, OOMing the syncing node before
/// verification runs). This hard cap - far above any realistic state size -
/// is the number the peer cannot inflate. Node-local, no wire/consensus change.
const MAX_SNAPSHOT_ACCOUNTS: usize = 10_000_000;
/// A single `/snapshot/page` may carry at most `SNAPSHOT_PAGE_SIZE` accounts
/// (the server builds pages that size); anything larger is a malformed/hostile
/// response, rejected before it is accumulated.
const MAX_ACCOUNTS_PER_PAGE: usize = SNAPSHOT_PAGE_SIZE;

/// #194: enforce the operator's trust-anchor requirement BEFORE any network I/O.
/// When `require` is set, a node refuses to state-sync unless BOTH the root and
/// round are pinned (so the snapshot can be checked against a value obtained out
/// of band, never trusting the source peer's claimed root) — the
/// production/mainnet setting. `require=false` (the default) = weak
/// subjectivity, byte-identical to before. Takes just the three relevant fields
/// so it can be unit-tested without a network or async runtime.
pub(crate) fn check_trust_anchor_requirement(require: bool, trusted_root: &Option<String>, trusted_round: &Option<u64>) -> anyhow::Result<()> {
    if require && (trusted_root.is_none() || trusted_round.is_none()) {
        anyhow::bail!(
            "state-sync: `require_state_sync_trust_anchor` is set but no trust anchor is configured — \
             set BOTH `state_sync_trusted_root` and `state_sync_trusted_round` to the pinned (round, root) \
             obtained out of band, or unset the requirement to allow weak-subjectivity sync"
        );
    }
    Ok(())
}

/// Fetch a state snapshot from the configured peers and verify it before the
/// caller installs it. Returns an error (aborting node startup) rather than
/// ever installing unverified or forked state.
pub async fn fetch_verified_snapshot(config: &NodeConfig) -> anyhow::Result<StateSnapshot> {
    let is_mainnet = config.is_mainnet_profile();
    // Authentication is MANDATORY when the operator requires an anchor OR under
    // the mainnet profile (task #212 / #194). In those modes a snapshot is only
    // accepted when its (round, root) is authenticated by a quorum-signed
    // checkpoint OR the out-of-band trust anchor.
    let auth_required = config.require_state_sync_trust_anchor || is_mainnet;

    // Fail fast, before any network I/O, if the anchor is required but missing.
    // Mainnet forces the anchor requirement even if the flag were unset.
    check_trust_anchor_requirement(
        auth_required && is_mainnet, // mainnet: the anchor itself is mandatory
        &config.state_sync_trusted_root,
        &config.state_sync_trusted_round,
    )?;

    // The committee + network identity THIS node treats as authoritative, from
    // its own config (never from a peer). For a fixed-membership network these
    // are what every honest peer also computes; the syncing node verifies the
    // quorum-signed checkpoint against THIS committee.
    let committee = committee_from_config(config);
    let own_chain_id = hex::encode(config.chain_id());
    let own_fingerprint = hex::encode(committee_fingerprint(&committee));
    let min_confirmations = config.state_sync_min_confirmations() as usize;

    // Bounded HTTP client: without an overall + connect timeout, a configured
    // peer that accepts the connection and never finishes hangs node startup
    // forever. Fail fast instead - a stuck peer must not wedge the sync.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    // 1. Gather each peer's snapshot header.
    let mut metas: Vec<(String, SnapshotMeta)> = Vec::new();
    for peer in &config.state_sync_peers {
        let url = format!("{}/snapshot/meta", peer.trim_end_matches('/'));
        match client.get(&url).send().await.and_then(|r| r.error_for_status()) {
            Ok(resp) => match resp.json::<SnapshotMeta>().await {
                // JOINT chain_id / committee check (#212): reject a peer that
                // declares a DIFFERENT chain_id or committee fingerprint than
                // ours outright — it is not serving our network. A pre-#212 peer
                // declares "" for both; in mainnet an empty declaration is
                // rejected (we require the authenticated fields), on a testnet we
                // tolerate it for backward-compat (the legacy weak-subjectivity
                // path still applies below).
                Ok(meta) => {
                    if !meta.chain_id.is_empty() && meta.chain_id != own_chain_id {
                        tracing::warn!("state-sync: peer {peer} declares chain_id {} != ours {own_chain_id} — skipping", meta.chain_id);
                        continue;
                    }
                    if !meta.validator_set_fingerprint.is_empty() && meta.validator_set_fingerprint != own_fingerprint {
                        tracing::warn!("state-sync: peer {peer} declares a different committee fingerprint — skipping");
                        continue;
                    }
                    if is_mainnet && (meta.chain_id.is_empty() || meta.validator_set_fingerprint.is_empty()) {
                        tracing::warn!("state-sync: mainnet requires an authenticated meta (chain_id + committee); peer {peer} sent none — skipping");
                        continue;
                    }
                    metas.push((peer.clone(), meta));
                }
                Err(e) => tracing::warn!("state-sync: bad snapshot meta from {peer}: {e}"),
            },
            Err(e) => tracing::warn!("state-sync: could not reach {peer} for snapshot meta: {e}"),
        }
    }
    if metas.is_empty() {
        anyhow::bail!("state-sync: no configured peer returned an acceptable snapshot meta");
    }

    // Two peers reporting the same round but different roots is a real fork
    // (or a malicious peer) - refuse to sync from that view entirely.
    for (i, (pa, ma)) in metas.iter().enumerate() {
        for (pb, mb) in metas.iter().skip(i + 1) {
            if ma.round == mb.round && ma.merkle_root != mb.merkle_root {
                anyhow::bail!(
                    "state-sync: peers {pa} and {pb} disagree on the root at round {} ({} vs {}) - refusing to sync from a forked view",
                    ma.round,
                    ma.merkle_root,
                    mb.merkle_root
                );
            }
        }
    }

    // 2. MULTI-PEER CONFIRMATION (#212): group peers by their (round, root) and
    //    pick the target confirmed by the most peers. If a trust anchor is set,
    //    the target MUST be the anchored (round, root). Require at least
    //    `min_confirmations` distinct peers agree on the chosen target.
    let target = choose_target(&metas, &config.state_sync_trusted_root, config.state_sync_trusted_round)?;
    let confirming: Vec<&(String, SnapshotMeta)> =
        metas.iter().filter(|(_, m)| m.round == target.0 && m.merkle_root == target.1).collect();
    if confirming.len() < min_confirmations {
        anyhow::bail!(
            "state-sync: only {} peer(s) confirmed (round {}, root {}), need {min_confirmations} — refusing (task #212 multi-peer confirmation)",
            confirming.len(),
            target.0,
            target.1
        );
    }

    // 3. QUORUM-SIGNED CHECKPOINT (#212): union every confirming peer's
    //    self-signed checkpoint over the target (chain_id, round, root),
    //    dedup by validator, verify each signature against THAT member's bundle
    //    in OUR committee, and sum distinct verified stake. A quorum authenticates
    //    the (round, root) without trusting any peer's claimed root.
    let quorum_ok = verify_quorum_checkpoint(&confirming, &committee, &config.chain_id(), &target)?;

    // 4. TRUST ANCHOR (#194): exact match against the operator's pinned value.
    let anchor_ok = match (&config.state_sync_trusted_root, config.state_sync_trusted_round) {
        (Some(r), Some(rd)) => *r == target.1 && rd == target.0,
        _ => false,
    };

    // AUTHENTICATION DECISION. Mainnet: the anchor is MANDATORY (reject a
    // snapshot without it), and the quorum checkpoint is additional defense in
    // depth. Non-mainnet with the require flag: quorum OR anchor. Otherwise
    // (legacy testnet, no anchor, no checkpoints): keep the weak-subjectivity
    // path (internal consistency + cross-check), byte-identical to before — but
    // still surface the quorum result if a checkpoint was present.
    if is_mainnet {
        if !anchor_ok {
            anyhow::bail!("state-sync: mainnet REQUIRES the snapshot to match the pinned trust anchor (round, root) — refusing (task #212)");
        }
        tracing::info!("state-sync[mainnet]: (round {}, root {}) authenticated by trust anchor{}", target.0, target.1, if quorum_ok { " + quorum checkpoint" } else { "" });
    } else if auth_required {
        if !(anchor_ok || quorum_ok) {
            anyhow::bail!("state-sync: (round {}, root {}) is authenticated by NEITHER a quorum-signed checkpoint NOR the trust anchor — refusing (task #212)", target.0, target.1);
        }
        tracing::info!("state-sync: (round {}, root {}) authenticated ({}{}{})", target.0, target.1, if quorum_ok { "quorum" } else { "" }, if quorum_ok && anchor_ok { "+" } else { "" }, if anchor_ok { "anchor" } else { "" });
    } else if quorum_ok {
        tracing::info!("state-sync: (round {}, root {}) additionally confirmed by a quorum-signed checkpoint", target.0, target.1);
    } else {
        tracing::warn!("state-sync: proceeding on the weak-subjectivity path (no anchor, no quorum checkpoint) — set require_state_sync_trust_anchor or state_checkpoints to harden");
    }

    // 5. Download from a confirming peer, then verify internal consistency
    //    against the SAME tree this network runs (root must match target).
    let source = confirming[0].0.trim_end_matches('/');
    let snapshot = fetch_snapshot_paginated(&client, source).await?;
    if snapshot.round != target.0 || snapshot.merkle_root != target.1 {
        anyhow::bail!("state-sync: downloaded snapshot (round {}, root {}) does not match the confirmed target (round {}, root {})", snapshot.round, snapshot.merkle_root, target.0, target.1);
    }
    verify_internal_consistency(&snapshot, config.compressed_state_tree)?;

    Ok(snapshot)
}

/// Build the authoritative committee from THIS node's config validators (fixed
/// membership). The syncing node verifies a quorum checkpoint against this — it
/// never trusts a committee a peer declares. For a rotation network the live
/// committee differs from genesis, so the quorum arm won't verify and the node
/// relies on the mandatory trust anchor instead (documented, #212).
fn committee_from_config(config: &NodeConfig) -> qchain_consensus::ValidatorSet {
    let infos = config
        .validators
        .iter()
        .map(|v| qchain_consensus::ValidatorInfo {
            id: v.pubkey_bundle.to_address(),
            pubkey_bundle: v.pubkey_bundle.clone(),
            stake: v.stake,
        })
        .collect();
    qchain_consensus::ValidatorSet::new(infos)
}

/// Choose the (round, root) target: if a trust anchor is pinned, it MUST be the
/// anchored one (and a peer must report it); otherwise the (round, root)
/// confirmed by the most peers (ties broken by highest round then root string).
fn choose_target(
    metas: &[(String, SnapshotMeta)],
    trusted_root: &Option<String>,
    trusted_round: Option<u64>,
) -> anyhow::Result<(u64, String)> {
    if let (Some(root), Some(round)) = (trusted_root, trusted_round) {
        let matches = metas.iter().any(|(_, m)| m.round == round && &m.merkle_root == root);
        if !matches {
            anyhow::bail!("state-sync: no peer reported the pinned trust anchor (round {round}, root {root}) — refusing");
        }
        return Ok((round, root.clone()));
    }
    let mut counts: std::collections::HashMap<(u64, String), usize> = std::collections::HashMap::new();
    for (_, m) in metas {
        *counts.entry((m.round, m.merkle_root.clone())).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(a.0 .0.cmp(&b.0 .0)).then(a.0 .1.cmp(&b.0 .1)))
        .map(|(k, _)| k)
        .ok_or_else(|| anyhow::anyhow!("state-sync: no snapshot target"))
}

/// Union the confirming peers' self-signed checkpoints over the target
/// `(chain_id, round, root)`, dedup by validator, verify each against that
/// member's bundle in OUR committee, and return whether the distinct verified
/// stake reaches the committee's quorum threshold (task #212).
fn verify_quorum_checkpoint(
    confirming: &[&(String, SnapshotMeta)],
    committee: &qchain_consensus::ValidatorSet,
    chain_id: &[u8; 32],
    target: &(u64, String),
) -> anyhow::Result<bool> {
    let target_root = decode_root(&target.1)?;
    let mut verified: std::collections::HashMap<qchain_core::ValidatorId, u64> = std::collections::HashMap::new();
    for (_, meta) in confirming {
        let Some(cp) = &meta.checkpoint else { continue };
        // The checkpoint must be over the SAME (chain_id, round, root) we chose.
        if cp.round != target.0 || cp.merkle_root != target.1 || cp.chain_id != hex::encode(chain_id) {
            continue;
        }
        for sig in &cp.signatures {
            let Ok(id) = sig.validator.parse::<qchain_core::ValidatorId>() else { continue };
            // Look up the member's bundle in OUR committee — never trust a bundle
            // the message might carry.
            let Some(info) = committee.get(&id) else { continue };
            if qchain_crypto::verify_state_checkpoint(&info.pubkey_bundle, chain_id, target.0, &target_root, &sig.signature) {
                verified.insert(id, info.stake);
            }
        }
    }
    let stake: u64 = verified.values().fold(0u64, |a, s| a.saturating_add(*s));
    Ok(stake >= committee.quorum_threshold())
}

/// Decode a hex 32-byte Merkle root string into bytes.
fn decode_root(root_hex: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(root_hex).map_err(|e| anyhow::anyhow!("bad root hex: {e}"))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| anyhow::anyhow!("root is not 32 bytes"))?;
    Ok(arr)
}

/// Download a full snapshot from `source` by keyset pagination against its
/// cached consistent snapshot: read the header, then page with `after=<last
/// address>` until a short page. Every page must carry the header's root (the
/// server's cached snapshot is immutable within its TTL); if it rotates
/// mid-download the whole download is retried a few times before giving up.
async fn fetch_snapshot_paginated(client: &reqwest::Client, source: &str) -> anyhow::Result<StateSnapshot> {
    const MAX_ATTEMPTS: usize = 3;
    let mut last_err = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match try_fetch_snapshot_paginated(client, source).await {
            Ok(snapshot) => return Ok(snapshot),
            Err(e) => {
                tracing::warn!("state-sync: snapshot download attempt {attempt}/{MAX_ATTEMPTS} failed: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("state-sync: snapshot download failed")))
}

async fn try_fetch_snapshot_paginated(client: &reqwest::Client, source: &str) -> anyhow::Result<StateSnapshot> {
    let meta: SnapshotMeta = client.get(format!("{source}/snapshot/meta")).send().await?.error_for_status()?.json().await?;
    // Reject an absurd announced count up front: `meta.account_count` is
    // attacker-controlled, so cap it against a hard ceiling (not just against
    // itself) before it is ever used as the download bound below.
    if meta.account_count > MAX_SNAPSHOT_ACCOUNTS {
        anyhow::bail!("state-sync: source announced {} accounts, above the {MAX_SNAPSHOT_ACCOUNTS} ceiling", meta.account_count);
    }
    let mut accounts = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let url = match &after {
            Some(a) => format!("{source}/snapshot/page?after={a}"),
            None => format!("{source}/snapshot/page"),
        };
        let page: SnapshotPage = client.get(&url).send().await?.error_for_status()?.json().await?;
        if page.merkle_root != meta.merkle_root {
            anyhow::bail!("the server's cached snapshot rotated mid-download (root {} -> {})", meta.merkle_root, page.merkle_root);
        }
        // A single page can carry at most `SNAPSHOT_PAGE_SIZE` accounts; a larger
        // one is a malformed/hostile response - reject before accumulating it.
        if page.accounts.len() > MAX_ACCOUNTS_PER_PAGE {
            anyhow::bail!("state-sync: page carried {} accounts, above the per-page cap {MAX_ACCOUNTS_PER_PAGE}", page.accounts.len());
        }
        if page.accounts.is_empty() {
            break;
        }
        after = Some(page.accounts.last().expect("page is non-empty").address.to_string());
        accounts.extend(page.accounts);
        // Bound the download by the count the meta already announced: a
        // malicious/buggy source peer could otherwise stream distinct fake
        // accounts forever (each page carrying the same claimed root to pass the
        // rotation check above), driving this node to OOM BEFORE
        // `verify_internal_consistency` ever runs. The real snapshot has exactly
        // `meta.account_count` entries, so anything beyond it is bad input.
        if accounts.len() > meta.account_count {
            anyhow::bail!(
                "state-sync source streamed more accounts ({}) than its snapshot meta announced ({}) - aborting",
                accounts.len(),
                meta.account_count
            );
        }
    }
    Ok(StateSnapshot { round: meta.round, merkle_root: meta.merkle_root, accounts })
}

/// Rebuild the real state tree from a snapshot's accounts and require it to
/// hash to the claimed root - a real proof the accounts are the ones behind
/// that root, using the exact same tree a live `Ledger` maintains (legacy
/// 256-deep or path-compressed, per the network's genesis-level choice). Any
/// account tampered relative to the claimed root fails here.
fn verify_internal_consistency(snapshot: &StateSnapshot, compressed: bool) -> anyhow::Result<()> {
    let rebuilt = if compressed {
        let mut tree = IncrementalCompressedTree::new();
        for acc in &snapshot.accounts {
            tree.note_set(&acc.address, &acc.account);
        }
        hex::encode(tree.root())
    } else {
        let mut tree = IncrementalStateTree::new();
        for acc in &snapshot.accounts {
            tree.note_set(&acc.address, &acc.account);
        }
        hex::encode(tree.root())
    };
    if rebuilt != snapshot.merkle_root {
        anyhow::bail!(
            "state-sync: rebuilt Merkle root {rebuilt} does not match the snapshot's claimed root {} - rejecting a tampered or corrupt snapshot",
            snapshot.merkle_root
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_core::Account;
    use qchain_crypto::Pubkey;
    use qchain_node::engine::SnapshotAccount;

    fn snapshot_of(accounts: Vec<(Pubkey, u64)>) -> StateSnapshot {
        // Build the authentic (legacy) root the same way a real node would,
        // then hand back a snapshot claiming it.
        let mut tree = IncrementalStateTree::new();
        let mut snap_accounts = Vec::new();
        for (pk, balance) in accounts {
            let account = Account { balance, ..Account::new_wallet(Pubkey::system_program_id()) };
            tree.note_set(&pk, &account);
            snap_accounts.push(SnapshotAccount { address: pk, account });
        }
        StateSnapshot { round: 42, merkle_root: hex::encode(tree.root()), accounts: snap_accounts }
    }

    fn compressed_snapshot_of(accounts: Vec<(Pubkey, u64)>) -> StateSnapshot {
        let mut tree = IncrementalCompressedTree::new();
        let mut snap_accounts = Vec::new();
        for (pk, balance) in accounts {
            let account = Account { balance, ..Account::new_wallet(Pubkey::system_program_id()) };
            tree.note_set(&pk, &account);
            snap_accounts.push(SnapshotAccount { address: pk, account });
        }
        StateSnapshot { round: 42, merkle_root: hex::encode(tree.root()), accounts: snap_accounts }
    }

    #[test]
    fn a_snapshot_whose_accounts_hash_to_its_claimed_root_verifies() {
        let snap = snapshot_of(vec![(Pubkey::new([1u8; 32]), 100), (Pubkey::new([2u8; 32]), 250)]);
        assert!(verify_internal_consistency(&snap, false).is_ok(), "an internally-consistent snapshot must verify");
    }

    #[test]
    fn a_snapshot_with_a_tampered_balance_is_rejected() {
        let mut snap = snapshot_of(vec![(Pubkey::new([1u8; 32]), 100), (Pubkey::new([2u8; 32]), 250)]);
        // Flip a balance without recomputing the claimed root - exactly what a
        // malicious peer serving forged state would produce.
        snap.accounts[0].account.balance = 999_999;
        assert!(verify_internal_consistency(&snap, false).is_err(), "a snapshot whose accounts no longer hash to its claimed root must be rejected");
    }

    #[test]
    fn a_snapshot_with_an_extra_injected_account_is_rejected() {
        let mut snap = snapshot_of(vec![(Pubkey::new([1u8; 32]), 100)]);
        snap.accounts.push(SnapshotAccount {
            address: Pubkey::new([9u8; 32]),
            account: Account { balance: 1_000_000, ..Account::new_wallet(Pubkey::system_program_id()) },
        });
        assert!(verify_internal_consistency(&snap, false).is_err(), "injecting an account not covered by the claimed root must be rejected");
    }

    #[test]
    fn compressed_mode_verifies_a_compressed_snapshot_and_rejects_a_legacy_one() {
        // The whole point of finishing compressed state-sync: a snapshot whose
        // claimed root is the COMPRESSED root must verify under `compressed=true`
        // (it was silently rejected before, because the verifier always rebuilt
        // with the legacy tree)...
        let accs = vec![(Pubkey::new([1u8; 32]), 100), (Pubkey::new([2u8; 32]), 250)];
        let comp = compressed_snapshot_of(accs.clone());
        assert!(verify_internal_consistency(&comp, true).is_ok(), "a compressed snapshot must verify in compressed mode");
        // ...and cross-mode is rejected both ways (a node never syncs a snapshot
        // from a network running a different tree - the roots can't match).
        assert!(verify_internal_consistency(&comp, false).is_err(), "a compressed snapshot must not verify as legacy");
        let legacy = snapshot_of(accs);
        assert!(verify_internal_consistency(&legacy, true).is_err(), "a legacy snapshot must not verify as compressed");
    }

    #[test]
    fn compressed_mode_rejects_a_tampered_compressed_snapshot() {
        let mut snap = compressed_snapshot_of(vec![(Pubkey::new([1u8; 32]), 100), (Pubkey::new([2u8; 32]), 250)]);
        snap.accounts[0].account.balance = 999_999;
        assert!(verify_internal_consistency(&snap, true).is_err(), "a tampered compressed snapshot must be rejected");
    }

    /// #194: with `require_state_sync_trust_anchor` on, a node must refuse to
    /// state-sync unless BOTH root and round are pinned (fail fast, before any
    /// network I/O); off = weak subjectivity allowed, unchanged.
    #[test]
    fn a_required_trust_anchor_that_is_missing_or_partial_refuses_sync() {
        let root = || Some("00".repeat(32));
        // Off (the default) => always ok, even with no anchor (weak subjectivity).
        assert!(check_trust_anchor_requirement(false, &None, &None).is_ok(), "off = weak subjectivity, no anchor needed");
        // On + no anchor => refused.
        assert!(check_trust_anchor_requirement(true, &None, &None).is_err(), "requiring the anchor with none set must refuse");
        // On + only the root (no round) => still refused (both are required).
        assert!(check_trust_anchor_requirement(true, &root(), &None).is_err(), "requiring the anchor with only the root set must refuse");
        // On + only the round (no root) => still refused.
        assert!(check_trust_anchor_requirement(true, &None, &Some(42)).is_err(), "requiring the anchor with only the round set must refuse");
        // On + both root and round => allowed to proceed (the fetched snapshot is
        // then still checked to match them exactly downstream).
        assert!(check_trust_anchor_requirement(true, &root(), &Some(42)).is_ok(), "a full pinned anchor satisfies the requirement");
        // Off but a full anchor present => ok (optional hardening path).
        assert!(check_trust_anchor_requirement(false, &root(), &Some(42)).is_ok(), "off with an anchor set is still fine");
    }

    use qchain_consensus::{ValidatorInfo, ValidatorSet};
    use qchain_crypto::Keypair;
    use qchain_node::engine::{CheckpointSig, SignedCheckpoint};

    fn committee_of(keys: &[(&Keypair, u64)]) -> ValidatorSet {
        ValidatorSet::new(keys.iter().map(|(kp, stake)| ValidatorInfo {
            id: kp.pubkey(),
            pubkey_bundle: kp.public_key_bundle(),
            stake: *stake,
        }).collect())
    }

    /// Build a `SnapshotMeta` with a checkpoint self-signed by `signer` over
    /// (chain_id, round, root). `peer` is a dummy URL.
    fn meta_with_checkpoint(chain_id: &[u8; 32], round: u64, root: &[u8; 32], signer: &Keypair) -> (String, SnapshotMeta) {
        let sig = qchain_crypto::sign_state_checkpoint(signer, chain_id, round, root).unwrap();
        let cp = SignedCheckpoint {
            chain_id: hex::encode(chain_id),
            round,
            merkle_root: hex::encode(root),
            signatures: vec![CheckpointSig { validator: signer.pubkey().to_string(), signature: sig }],
        };
        let meta = SnapshotMeta {
            round,
            merkle_root: hex::encode(root),
            account_count: 0,
            chain_id: hex::encode(chain_id),
            validator_set_fingerprint: String::new(),
            checkpoint: Some(cp),
        };
        ("http://peer".into(), meta)
    }

    /// Task #212: the union of confirming peers' self-signed checkpoints reaches
    /// quorum only when enough distinct validator stake has signed the SAME
    /// (chain_id, round, root); a wrong root, a non-member signer, or too few
    /// signers do NOT reach quorum.
    #[test]
    fn quorum_checkpoint_authenticates_only_with_enough_distinct_verified_stake() {
        let chain_id = [7u8; 32];
        let round = 100u64;
        let root = [9u8; 32];
        let a = Keypair::generate().unwrap();
        let b = Keypair::generate().unwrap();
        let c = Keypair::generate().unwrap();
        let outsider = Keypair::generate().unwrap();
        // 3 validators of equal stake → quorum = 3 (strictly > 2/3 of 3 = 2).
        let committee = committee_of(&[(&a, 1), (&b, 1), (&c, 1)]);

        // Only ONE peer/signature → below quorum.
        let m_a = meta_with_checkpoint(&chain_id, round, &root, &a);
        let target = (round, hex::encode(root));
        let confirming1: Vec<&(String, SnapshotMeta)> = vec![&m_a];
        assert!(!verify_quorum_checkpoint(&confirming1, &committee, &chain_id, &target).unwrap(), "one signer of three is below quorum");

        // All THREE distinct members → quorum reached.
        let m_b = meta_with_checkpoint(&chain_id, round, &root, &b);
        let m_c = meta_with_checkpoint(&chain_id, round, &root, &c);
        let confirming3: Vec<&(String, SnapshotMeta)> = vec![&m_a, &m_b, &m_c];
        assert!(verify_quorum_checkpoint(&confirming3, &committee, &chain_id, &target).unwrap(), "three distinct members reach quorum");

        // A NON-member's signature does not count, even with a valid signature.
        let m_out = meta_with_checkpoint(&chain_id, round, &root, &outsider);
        let confirming_out: Vec<&(String, SnapshotMeta)> = vec![&m_a, &m_b, &m_out];
        assert!(!verify_quorum_checkpoint(&confirming_out, &committee, &chain_id, &target).unwrap(), "an outsider's signature must not count toward quorum");

        // A signature over a DIFFERENT root is rejected (does not authenticate the target).
        let other_root = [8u8; 32];
        let m_a_wrong = meta_with_checkpoint(&chain_id, round, &other_root, &a);
        let m_b_wrong = meta_with_checkpoint(&chain_id, round, &other_root, &b);
        let m_c_wrong = meta_with_checkpoint(&chain_id, round, &other_root, &c);
        let confirming_wrong: Vec<&(String, SnapshotMeta)> = vec![&m_a_wrong, &m_b_wrong, &m_c_wrong];
        assert!(!verify_quorum_checkpoint(&confirming_wrong, &committee, &chain_id, &target).unwrap(), "checkpoints over a different root must not authenticate the target");

        // A signature over a different CHAIN_ID is rejected.
        let other_chain = [1u8; 32];
        let m_a_oc = meta_with_checkpoint(&other_chain, round, &root, &a);
        let m_b_oc = meta_with_checkpoint(&other_chain, round, &root, &b);
        let m_c_oc = meta_with_checkpoint(&other_chain, round, &root, &c);
        let confirming_oc: Vec<&(String, SnapshotMeta)> = vec![&m_a_oc, &m_b_oc, &m_c_oc];
        assert!(!verify_quorum_checkpoint(&confirming_oc, &committee, &chain_id, &target).unwrap(), "checkpoints over a different chain_id must not authenticate");
    }

    /// `choose_target` prefers the (round, root) most peers confirm, and is FORCED
    /// to the pinned anchor when one is set (and refuses if no peer reports it).
    #[test]
    fn choose_target_prefers_majority_and_honors_the_anchor() {
        let mk = |round: u64, root: &str| ("p".to_string(), SnapshotMeta { round, merkle_root: root.to_string(), account_count: 0, chain_id: String::new(), validator_set_fingerprint: String::new(), checkpoint: None });
        let metas = vec![mk(10, "aa"), mk(10, "aa"), mk(11, "bb")];
        // Majority (round 10, aa).
        assert_eq!(choose_target(&metas, &None, None).unwrap(), (10, "aa".to_string()));
        // Anchor forces (11, bb) since a peer reports it.
        assert_eq!(choose_target(&metas, &Some("bb".to_string()), Some(11)).unwrap(), (11, "bb".to_string()));
        // Anchor that NO peer reports → refuse.
        assert!(choose_target(&metas, &Some("cc".to_string()), Some(99)).is_err(), "an anchor no peer reports must refuse");
    }
}
