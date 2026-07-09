//! Wallet CLI for the phase-1 testnet: keygen, balance lookups, and signed
//! transfers against a `qchain-node`'s JSON-RPC surface (`ARCHITECTURE.md`
//! §2/§4). Uses the same hybrid Ed25519+ML-DSA-65 keypair model as the rest
//! of the protocol - there is no separate "wallet-only" key format.

use clap::{Parser, Subcommand};
use qchain_core::{Account, Instruction, Transaction};
use qchain_crypto::{Keypair, Pubkey};
use qchain_execution::SystemInstruction;
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "qchain phase-1 testnet wallet")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new hybrid keypair and write it to a file.
    Keygen {
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Print the address a keypair file corresponds to.
    Address {
        #[arg(short, long)]
        keypair: PathBuf,
    },
    /// Print a keypair's public key bundle as JSON - the format
    /// `qchain-node`'s config expects for each entry in `validators`.
    Bundle {
        #[arg(short, long)]
        keypair: PathBuf,
    },
    /// Query an account's balance from a node.
    Balance {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        address: String,
    },
    /// Sign and submit a transfer.
    Transfer {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        /// Overrides the auto-fetched account nonce, for advanced use.
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
}

fn fetch_account(rpc: &str, address: &Pubkey) -> anyhow::Result<Option<Account>> {
    let url = format!("{rpc}/account/{address}");
    let resp = reqwest::blocking::get(&url)?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let account: Account = resp.error_for_status()?.json()?;
    Ok(Some(account))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { out } => {
            let keypair = Keypair::generate()?;
            qchain_crypto::write_keypair_file(&keypair, &out)?;
            println!("wrote keypair to {}", out.display());
            println!("address: {}", keypair.pubkey());
        }
        Command::Address { keypair } => {
            let kp = qchain_crypto::read_keypair_file(&keypair)?;
            println!("{}", kp.pubkey());
        }
        Command::Bundle { keypair } => {
            let kp = qchain_crypto::read_keypair_file(&keypair)?;
            println!("{}", serde_json::to_string(&kp.public_key_bundle())?);
        }
        Command::Balance { rpc, address } => {
            let pk: Pubkey = address.parse()?;
            match fetch_account(&rpc, &pk)? {
                Some(account) => println!("{}", account.balance),
                None => println!("0 (account not found)"),
            }
        }
        Command::Transfer { rpc, keypair, to, amount, nonce, fee_limit } => {
            let payer = qchain_crypto::read_keypair_file(&keypair)?;
            let to_pk: Pubkey = to.parse()?;

            let nonce = match nonce {
                Some(n) => n,
                None => fetch_account(&rpc, &payer.pubkey())?.map(|a| a.nonce).unwrap_or(0),
            };

            let ix = Instruction {
                program_id: Pubkey::system_program_id(),
                accounts: vec![payer.pubkey(), to_pk],
                data: borsh::to_vec(&SystemInstruction::Transfer { amount })?,
            };
            // No recent-certificate anchor is fetched yet (phase-1
            // simplification - see `qchain-node`'s RPC surface): nonce is
            // this transaction's only replay defense for now.
            let tx = Transaction::new_signed(&payer, nonce, [0u8; 32], fee_limit, vec![ix])?;

            let resp = reqwest::blocking::Client::new().post(format!("{rpc}/tx")).json(&tx).send()?;
            if !resp.status().is_success() {
                anyhow::bail!("node rejected transaction: {}", resp.text()?);
            }
            let body: serde_json::Value = resp.json()?;
            println!("submitted: {body}");
        }
    }
    Ok(())
}
