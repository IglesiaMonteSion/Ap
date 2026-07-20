//! qchain-indexer — a standalone QScan block explorer for a Qchain network.
//!
//! This is the "indexer" half of separating a validator from an explorer, the
//! way Ethereum separates a validator node from Etherscan: a validator keeps
//! only what it needs to validate (state + recent DAG + its keys) and serves a
//! rolling window; a separate indexer follows the chain over RPC and builds a
//! durable, fully-queryable history + a rich web explorer. Running this does not
//! touch consensus at all — it's a read replica, so it can be exposed publicly,
//! scaled, or restarted without any risk to the validators.
//!
//! Usage:
//!   qchain-indexer --node http://127.0.0.1:9101 --bind 0.0.0.0:9200 \
//!                  --data ./qscan-data --poll-ms 1000

mod api;
mod ingest;
mod store;

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "qchain-indexer", about = "QScan explorer/indexer for a Qchain network")]
struct Args {
    /// RPC base URL of a validator node to follow (e.g. http://127.0.0.1:9101).
    #[arg(long, default_value = "http://127.0.0.1:9101")]
    node: String,
    /// Address to serve the QScan web UI + API on.
    #[arg(long, default_value = "0.0.0.0:9200")]
    bind: String,
    /// Directory for the indexer's own sled database.
    #[arg(long, default_value = "./qscan-data")]
    data: String,
    /// Poll interval in milliseconds.
    #[arg(long, default_value_t = 1000)]
    poll_ms: u64,
    /// Public URL of the non-custodial wallet (e.g. https://wallet.qchainhq.com)
    /// to open for signing when deploying/interacting with a contract from QScan.
    /// None = the deploy/interact UI is hidden (read-only contracts only). The
    /// wallet must be started with `--connect-origin <this-explorer's-origin>` for
    /// the postMessage bridge to accept requests. QScan never sees any key.
    #[arg(long)]
    wallet_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let args = Args::parse();

    let store = Arc::new(store::Store::open(&args.data)?);
    tracing::info!(
        "qscan indexer starting: following node {} -> serving on http://{} (db: {}, {} txs / {} blocks indexed)",
        args.node,
        args.bind,
        args.data,
        store.total_txs(),
        store.total_blocks()
    );

    // Ingestion loop in the background.
    {
        let store = store.clone();
        let node = args.node.clone();
        let poll = args.poll_ms;
        tokio::spawn(async move {
            ingest::run(node, store, poll).await;
        });
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let state = api::ApiState {
        store,
        node: args.node.clone(),
        http,
        node_cache: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        wallet_url: args
            .wallet_url
            .clone()
            .map(|u| u.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty()),
    };
    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    tracing::info!("QScan explorer listening on http://{}", args.bind);
    axum::serve(listener, app).await?;
    Ok(())
}
