use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use supersol_core::{Instruction, Transaction, UNITS_PER_SSOL};
use supersol_crypto::{read_keypair_file, write_keypair_file, Keypair, Pubkey};
use supersol_runtime::SystemInstruction;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::str::FromStr;

const DEFAULT_URL: &str = "http://127.0.0.1:8899";

#[derive(Parser)]
#[command(name = "supersol", about = "SuperSol wallet CLI")]
struct Cli {
    /// JSON-RPC endpoint of the node to talk to.
    #[arg(long, global = true, default_value = DEFAULT_URL)]
    url: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new keypair and save it to a file.
    Keygen {
        #[arg(long, default_value = "id.json")]
        outfile: PathBuf,
    },
    /// Print the base58 address of a keypair file.
    Address { keypair: PathBuf },
    /// Check an address's balance.
    Balance { address: String },
    /// Request devnet faucet funds (node must be started with --enable-faucet).
    Airdrop { address: String, amount_mtc: f64 },
    /// Transfer SSOL from a keypair file to a destination address.
    Transfer {
        from_keypair: PathBuf,
        to: String,
        amount_mtc: f64,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { outfile } => keygen(&outfile),
        Command::Address { keypair } => address(&keypair),
        Command::Balance { address } => balance(&cli.url, &address),
        Command::Airdrop { address, amount_mtc } => airdrop(&cli.url, &address, amount_mtc),
        Command::Transfer {
            from_keypair,
            to,
            amount_mtc,
        } => transfer(&cli.url, &from_keypair, &to, amount_mtc),
    }
}

fn keygen(outfile: &PathBuf) -> anyhow::Result<()> {
    if outfile.exists() {
        bail!("refusing to overwrite existing file: {}", outfile.display());
    }
    let kp = Keypair::generate();
    write_keypair_file(&kp, outfile)?;
    println!("Wrote new keypair to {}", outfile.display());
    println!("Address: {}", kp.pubkey());
    Ok(())
}

fn address(keypair: &PathBuf) -> anyhow::Result<()> {
    let kp = read_keypair_file(keypair).with_context(|| format!("reading keypair file {}", keypair.display()))?;
    println!("{}", kp.pubkey());
    Ok(())
}

/// Accepts either a base58 pubkey directly or the path to a keypair file.
fn resolve_pubkey(s: &str) -> anyhow::Result<Pubkey> {
    if let Ok(pk) = Pubkey::from_str(s) {
        return Ok(pk);
    }
    let path = PathBuf::from(s);
    let kp = read_keypair_file(&path)
        .with_context(|| format!("'{s}' is neither a valid base58 address nor a readable keypair file"))?;
    Ok(kp.pubkey())
}

fn balance(url: &str, address: &str) -> anyhow::Result<()> {
    let pubkey = resolve_pubkey(address)?;
    let result = rpc_call(url, "getBalance", json!([pubkey.to_string()]))?;
    let mtc = result.get("mtc").and_then(Value::as_f64).unwrap_or(0.0);
    let units = result.get("units").and_then(Value::as_u64).unwrap_or(0);
    println!("{mtc} SSOL ({units} photon)");
    Ok(())
}

fn airdrop(url: &str, address: &str, amount_mtc: f64) -> anyhow::Result<()> {
    let pubkey = resolve_pubkey(address)?;
    let units = mtc_to_units(amount_mtc);
    let result = rpc_call(url, "requestAirdrop", json!([pubkey.to_string(), units]))?;
    println!(
        "Airdropped {amount_mtc} SSOL to {pubkey} (signature {})",
        result.get("signature").and_then(Value::as_str).unwrap_or("?")
    );
    Ok(())
}

fn transfer(url: &str, from_keypair: &PathBuf, to: &str, amount_mtc: f64) -> anyhow::Result<()> {
    let from = read_keypair_file(from_keypair)
        .with_context(|| format!("reading keypair file {}", from_keypair.display()))?;
    let to_pubkey = resolve_pubkey(to)?;
    let units = mtc_to_units(amount_mtc);

    let blockhash_hex = rpc_call(url, "getLatestBlockhash", json!([]))?
        .get("blockhash")
        .and_then(Value::as_str)
        .context("node did not return a blockhash")?
        .to_string();
    let blockhash_bytes = hex::decode(&blockhash_hex)?;
    if blockhash_bytes.len() != 32 {
        bail!("unexpected blockhash length");
    }
    let mut recent_blockhash = [0u8; 32];
    recent_blockhash.copy_from_slice(&blockhash_bytes);

    let ix = Instruction {
        program_id: Pubkey::system_program_id(),
        accounts: vec![from.pubkey(), to_pubkey],
        data: borsh::to_vec(&SystemInstruction::Transfer { amount: units })?,
    };
    let tx = Transaction::new_signed(&from, recent_blockhash, vec![ix]);

    let tx_json = serde_json::to_value(&tx)?;
    let result = rpc_call(url, "sendTransaction", json!([tx_json]))?;
    let fee_units = result.get("fee").and_then(Value::as_u64).unwrap_or(0);
    println!(
        "Sent {amount_mtc} SSOL from {} to {to_pubkey} (signature {}, fee {} photon)",
        from.pubkey(),
        result.get("signature").and_then(Value::as_str).unwrap_or("?"),
        fee_units
    );
    Ok(())
}

fn mtc_to_units(amount_mtc: f64) -> u64 {
    (amount_mtc * UNITS_PER_SSOL as f64).round() as u64
}

fn rpc_call(url: &str, method: &str, params: Value) -> anyhow::Result<Value> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let client = reqwest::blocking::Client::new();
    let response: Value = client.post(url).json(&body).send()?.json()?;
    if let Some(error) = response.get("error") {
        let message = error.get("message").and_then(Value::as_str).unwrap_or("unknown error");
        bail!("RPC error: {message}");
    }
    response.get("result").cloned().context("RPC response missing result")
}
