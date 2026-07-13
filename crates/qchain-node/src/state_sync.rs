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

use qchain_node::config::NodeConfig;
use qchain_node::engine::{SnapshotMeta, SnapshotPage, StateSnapshot};
use qchain_storage::IncrementalStateTree;

/// Fetch a state snapshot from the configured peers and verify it before the
/// caller installs it. Returns an error (aborting node startup) rather than
/// ever installing unverified or forked state.
pub async fn fetch_verified_snapshot(config: &NodeConfig) -> anyhow::Result<StateSnapshot> {
    let client = reqwest::Client::new();

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
    //    tampering relative to that root.
    verify_internal_consistency(&snapshot)?;

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
        if page.accounts.is_empty() {
            break;
        }
        after = Some(page.accounts.last().expect("page is non-empty").address.to_string());
        accounts.extend(page.accounts);
    }
    Ok(StateSnapshot { round: meta.round, merkle_root: meta.merkle_root, accounts })
}

/// Rebuild the real state tree from a snapshot's accounts and require it to
/// hash to the claimed root - a real proof the accounts are the ones behind
/// that root, using the exact same `IncrementalStateTree` a live `Ledger`
/// maintains. Any account tampered relative to the claimed root fails here.
fn verify_internal_consistency(snapshot: &StateSnapshot) -> anyhow::Result<()> {
    let mut tree = IncrementalStateTree::new();
    for acc in &snapshot.accounts {
        tree.note_set(&acc.address, &acc.account);
    }
    let rebuilt = hex::encode(tree.root());
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
        // Build the authentic root the same way a real node would, then hand
        // back a snapshot claiming it.
        let mut tree = IncrementalStateTree::new();
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
        assert!(verify_internal_consistency(&snap).is_ok(), "an internally-consistent snapshot must verify");
    }

    #[test]
    fn a_snapshot_with_a_tampered_balance_is_rejected() {
        let mut snap = snapshot_of(vec![(Pubkey::new([1u8; 32]), 100), (Pubkey::new([2u8; 32]), 250)]);
        // Flip a balance without recomputing the claimed root - exactly what a
        // malicious peer serving forged state would produce.
        snap.accounts[0].account.balance = 999_999;
        assert!(verify_internal_consistency(&snap).is_err(), "a snapshot whose accounts no longer hash to its claimed root must be rejected");
    }

    #[test]
    fn a_snapshot_with_an_extra_injected_account_is_rejected() {
        let mut snap = snapshot_of(vec![(Pubkey::new([1u8; 32]), 100)]);
        snap.accounts.push(SnapshotAccount {
            address: Pubkey::new([9u8; 32]),
            account: Account { balance: 1_000_000, ..Account::new_wallet(Pubkey::system_program_id()) },
        });
        assert!(verify_internal_consistency(&snap).is_err(), "injecting an account not covered by the claimed root must be rejected");
    }
}
