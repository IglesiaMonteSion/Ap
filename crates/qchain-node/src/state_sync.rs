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
use qchain_node::engine::{SnapshotMeta, SnapshotPage, StateSnapshot, SNAPSHOT_PAGE_SIZE};
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
    // Fail fast, before any network I/O, if the operator requires an anchor but
    // none is configured (#194).
    check_trust_anchor_requirement(
        config.require_state_sync_trust_anchor,
        &config.state_sync_trusted_root,
        &config.state_sync_trusted_round,
    )?;

    // Bounded HTTP client: without an overall + connect timeout, a configured
    // peer that accepts the connection and never finishes hangs node startup
    // forever. Fail fast instead - a stuck peer must not wedge the sync.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    // 1. Gather each peer's snapshot header for a cheap fork check.
    let mut metas: Vec<(String, SnapshotMeta)> = Vec::new();
    for peer in &config.state_sync_peers {
        let url = format!("{}/snapshot/meta", peer.trim_end_matches('/'));
        match client.get(&url).send().await.and_then(|r| r.error_for_status()) {
            Ok(resp) => match resp.json::<SnapshotMeta>().await {
                Ok(meta) => metas.push((peer.clone(), meta)),
                Err(e) => tracing::warn!("state-sync: bad snapshot meta from {peer}: {e}"),
            },
            Err(e) => tracing::warn!("state-sync: could not reach {peer} for snapshot meta: {e}"),
        }
    }
    if metas.is_empty() {
        anyhow::bail!("state-sync: no configured peer returned a snapshot meta");
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

    // 2. Pull the snapshot from the first peer that answered, page by page
    //    (bounded response size regardless of state size).
    let source = metas[0].0.trim_end_matches('/');
    let snapshot = fetch_snapshot_paginated(&client, source).await?;

    // 3. Internal consistency: rebuild the real state tree from the accounts
    //    and require it to hash to the claimed root - catches any account
    //    tampering relative to that root. Must use the SAME tree this network
    //    runs (legacy vs compressed is a genesis-level, network-wide choice
    //    folded into `chain_id`); rebuilding with the wrong tree would never
    //    match a peer's claimed root, silently breaking state-sync for a
    //    compressed-tree deployment. A node only ever syncs into its own
    //    network, whose mode it knows from its config.
    verify_internal_consistency(&snapshot, config.compressed_state_tree)?;

    // 4. Optional operator trust anchor: exact match turns "trust the source
    //    peer" into a fully verified catch-up. Most useful for a controlled
    //    recovery where the operator pinned a known `(round, root)` out of
    //    band; against a live, advancing peer leave it unset and rely on the
    //    internal check plus the cross-check above.
    if let Some(trusted_root) = &config.state_sync_trusted_root {
        if &snapshot.merkle_root != trusted_root {
            anyhow::bail!(
                "state-sync: snapshot root {} does not match the configured trusted root {trusted_root}",
                snapshot.merkle_root
            );
        }
        if let Some(trusted_round) = config.state_sync_trusted_round {
            if snapshot.round != trusted_round {
                anyhow::bail!("state-sync: snapshot round {} does not match the configured trusted round {trusted_round}", snapshot.round);
            }
        }
        tracing::info!("state-sync: snapshot matches the configured trust anchor");
    }

    Ok(snapshot)
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
}
