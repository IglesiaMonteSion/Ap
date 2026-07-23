//! `qchain-verify-genesis` — reproduce and verify a network's genesis manifest
//! offline (roadmap #7).
//!
//! The genesis manifest is the canonical, publishable record of a launch:
//! chain_id, network fingerprint, the genesis state root, total supply, the
//! full account list, and the folded genesis decisions (economics, hard cap,
//! treasury, guardians, …). It is computed by seeding a fresh in-memory ledger
//! with EXACTLY the code the node runs (`qchain_node::genesis::seed_genesis`),
//! so it can never drift from what a node actually seeds.
//!
//! Usage:
//!   qchain-verify-genesis --config node.json                 # print the manifest (publish this)
//!   qchain-verify-genesis --config node.json --emit m.json   # write the manifest to a file
//!   qchain-verify-genesis --config node.json --manifest m.json  # verify config reproduces m.json
//!
//! The `--manifest` mode is the trust check: an operator about to join/launch a
//! network recomputes the manifest from THEIR OWN config and confirms it matches
//! the published one — same chain_id, same genesis state root, same supply, same
//! accounts — with no trust in the launcher. Exit 0 = match, 2 = mismatch.

use qchain_node::config::NodeConfig;
use qchain_node::genesis::GenesisManifest;

fn main() -> anyhow::Result<()> {
    let mut config_path: Option<String> = None;
    let mut manifest_path: Option<String> = None;
    let mut emit_path: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" | "-c" => config_path = args.next(),
            "--manifest" | "-m" => manifest_path = args.next(),
            "--emit" | "-o" => emit_path = args.next(),
            "-h" | "--help" => {
                println!(
                    "Usage: qchain-verify-genesis --config <node.json> [--manifest <published.json>] [--emit <out.json>]\n\n\
                     Reproduce a network's genesis manifest from a config (offline, deterministic).\n\
                     Default prints the manifest. --emit writes it. --manifest verifies the config\n\
                     reproduces a published manifest byte-for-byte (exit 0 = match, 2 = mismatch)."
                );
                return Ok(());
            }
            other => anyhow::bail!("unexpected argument {other:?} (use --help)"),
        }
    }
    let config_path = config_path.ok_or_else(|| anyhow::anyhow!("missing --config <node.json>"))?;
    let config: NodeConfig = serde_json::from_slice(&std::fs::read(&config_path)?)?;

    // Recompute the manifest from the config via the SAME genesis seeder the
    // node runs.
    let manifest = GenesisManifest::compute(&config)?;

    // Verify mode: compare against a published manifest.
    if let Some(published_path) = &manifest_path {
        let published: GenesisManifest = serde_json::from_slice(&std::fs::read(published_path)?)?;
        let diffs = manifest.diff_against(&published);
        println!("== qchain-verify-genesis (VERIFY) ==");
        println!("config:    {config_path}");
        println!("published: {published_path}");
        println!("recomputed chain_id:            {}", manifest.chain_id);
        println!("recomputed genesis_state_root:  {}", manifest.genesis_state_root);
        println!("recomputed manifest_hash:       {}", manifest.manifest_hash);
        if diffs.is_empty() {
            println!("\n== MATCH — this config reproduces the published genesis exactly. ==");
            return Ok(());
        }
        eprintln!("\n== MISMATCH — this config does NOT reproduce the published genesis: ==");
        for d in &diffs {
            eprintln!("  - {d}");
        }
        eprintln!("Do NOT join/launch: your config would seed a DIFFERENT genesis than published.");
        std::process::exit(2);
    }

    // Emit mode: write the manifest to a file.
    if let Some(out) = &emit_path {
        std::fs::write(out, serde_json::to_vec_pretty(&manifest)?)?;
        println!("genesis manifest written to {out}");
        println!("chain_id:           {}", manifest.chain_id);
        println!("genesis_state_root: {}", manifest.genesis_state_root);
        println!("manifest_hash:      {}", manifest.manifest_hash);
        return Ok(());
    }

    // Default: print the manifest (this is what an operator publishes).
    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}
