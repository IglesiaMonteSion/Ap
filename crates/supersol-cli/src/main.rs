use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::str::FromStr;
use supersol_core::{Instruction, Transaction, STAKE_PROGRAM_ID, UNITS_PER_SSOL};
use supersol_crypto::{read_keypair_file, write_keypair_file, Keypair, Pubkey};
use supersol_runtime::{StakeInstruction, SystemInstruction};

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
    /// Show the fixed total supply and how it's split between circulating,
    /// treasury, staking pool, and burned.
    Supply,
    /// Lock up SSOL in a new stake account, delegated to a validator
    /// (defaults to whichever validator the node identifies as).
    Stake {
        owner_keypair: PathBuf,
        /// Where to save the newly generated stake account's keypair - keep
        /// this file, you need it to unstake/withdraw later.
        stake_outfile: PathBuf,
        amount_ssol: f64,
        #[arg(long)]
        validator: Option<String>,
    },
    /// Stop a stake account from earning further rewards and unlock it for
    /// withdrawal.
    Unstake {
        owner_keypair: PathBuf,
        stake_account: String,
    },
    /// Withdraw SSOL from a deactivated stake account.
    WithdrawStake {
        owner_keypair: PathBuf,
        stake_account: String,
        destination: String,
        amount_ssol: f64,
    },
    /// Show a stake account's authority, delegated validator, status, and
    /// staked amount.
    StakeInfo { stake_account: String },
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
        Command::Supply => supply(&cli.url),
        Command::Stake {
            owner_keypair,
            stake_outfile,
            amount_ssol,
            validator,
        } => stake(&cli.url, &owner_keypair, &stake_outfile, amount_ssol, validator),
        Command::Unstake {
            owner_keypair,
            stake_account,
        } => unstake(&cli.url, &owner_keypair, &stake_account),
        Command::WithdrawStake {
            owner_keypair,
            stake_account,
            destination,
            amount_ssol,
        } => withdraw_stake(&cli.url, &owner_keypair, &stake_account, &destination, amount_ssol),
        Command::StakeInfo { stake_account } => stake_info(&cli.url, &stake_account),
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
    let ssol = result.get("ssol").and_then(Value::as_f64).unwrap_or(0.0);
    let units = result.get("units").and_then(Value::as_u64).unwrap_or(0);
    println!("{ssol} SSOL ({units} photon)");
    Ok(())
}

fn supply(url: &str) -> anyhow::Result<()> {
    let result = rpc_call(url, "getSupply", json!([]))?;
    let get = |key: &str| result.get(key).and_then(Value::as_f64).unwrap_or(0.0);
    println!("Total supply:       {} SSOL (fixed, never inflates)", get("total_ssol"));
    println!("Circulating:        {} SSOL", get("circulating_ssol"));
    println!("Still in treasury:  {} SSOL", get("treasury_ssol"));
    println!("Staking pool:       {} SSOL", get("staking_pool_ssol"));
    println!("Burned:             {} SSOL", get("burned_ssol"));
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

fn fetch_recent_blockhash(url: &str) -> anyhow::Result<[u8; 32]> {
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
    Ok(recent_blockhash)
}

fn transfer(url: &str, from_keypair: &PathBuf, to: &str, amount_mtc: f64) -> anyhow::Result<()> {
    let from = read_keypair_file(from_keypair)
        .with_context(|| format!("reading keypair file {}", from_keypair.display()))?;
    let to_pubkey = resolve_pubkey(to)?;
    let units = mtc_to_units(amount_mtc);
    let recent_blockhash = fetch_recent_blockhash(url)?;

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
        "Sent {amount_mtc} SSOL from {} to {to_pubkey} (signature {}, fee {} photon burned)",
        from.pubkey(),
        result.get("signature").and_then(Value::as_str).unwrap_or("?"),
        fee_units
    );
    Ok(())
}

fn stake(
    url: &str,
    owner_keypair: &PathBuf,
    stake_outfile: &PathBuf,
    amount_ssol: f64,
    validator_override: Option<String>,
) -> anyhow::Result<()> {
    let owner = read_keypair_file(owner_keypair)
        .with_context(|| format!("reading keypair file {}", owner_keypair.display()))?;
    if stake_outfile.exists() {
        bail!("refusing to overwrite existing file: {}", stake_outfile.display());
    }
    let stake_kp = Keypair::generate();
    let stake_pubkey = stake_kp.pubkey();

    let validator = match validator_override {
        Some(v) => resolve_pubkey(&v)?,
        None => {
            let result = rpc_call(url, "getIdentity", json!([]))?;
            let s = result
                .get("identity")
                .and_then(Value::as_str)
                .context("node did not return its identity")?;
            Pubkey::from_str(s)?
        }
    };

    let units = mtc_to_units(amount_ssol);
    let recent_blockhash = fetch_recent_blockhash(url)?;

    let create_ix = Instruction {
        program_id: Pubkey::system_program_id(),
        accounts: vec![stake_pubkey],
        data: borsh::to_vec(&SystemInstruction::CreateAccount {
            units,
            owner: STAKE_PROGRAM_ID,
        })?,
    };
    let init_ix = Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![stake_pubkey],
        data: borsh::to_vec(&StakeInstruction::Initialize {
            authority: owner.pubkey(),
            validator,
        })?,
    };
    let tx = Transaction::new_signed(&owner, recent_blockhash, vec![create_ix, init_ix]);
    let result = rpc_call(url, "sendTransaction", json!([serde_json::to_value(&tx)?]))?;

    // Only save the stake keypair once the transaction round-trip succeeds,
    // so a failed stake attempt doesn't leave behind a keypair file for an
    // account that was never actually created on-chain.
    write_keypair_file(&stake_kp, stake_outfile)?;

    println!(
        "Staked {amount_ssol} SSOL into {stake_pubkey} delegated to {validator} (signature {})",
        result.get("signature").and_then(Value::as_str).unwrap_or("?")
    );
    println!("Stake account keypair saved to {} - keep it to unstake/withdraw later.", stake_outfile.display());
    Ok(())
}

fn unstake(url: &str, owner_keypair: &PathBuf, stake_account: &str) -> anyhow::Result<()> {
    let owner = read_keypair_file(owner_keypair)
        .with_context(|| format!("reading keypair file {}", owner_keypair.display()))?;
    let stake_pubkey = resolve_pubkey(stake_account)?;
    let recent_blockhash = fetch_recent_blockhash(url)?;

    let ix = Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![stake_pubkey],
        data: borsh::to_vec(&StakeInstruction::Deactivate)?,
    };
    let tx = Transaction::new_signed(&owner, recent_blockhash, vec![ix]);
    let result = rpc_call(url, "sendTransaction", json!([serde_json::to_value(&tx)?]))?;
    println!(
        "Deactivated stake {stake_pubkey} (signature {}). It can now be withdrawn.",
        result.get("signature").and_then(Value::as_str).unwrap_or("?")
    );
    Ok(())
}

fn withdraw_stake(
    url: &str,
    owner_keypair: &PathBuf,
    stake_account: &str,
    destination: &str,
    amount_ssol: f64,
) -> anyhow::Result<()> {
    let owner = read_keypair_file(owner_keypair)
        .with_context(|| format!("reading keypair file {}", owner_keypair.display()))?;
    let stake_pubkey = resolve_pubkey(stake_account)?;
    let dest_pubkey = resolve_pubkey(destination)?;
    let units = mtc_to_units(amount_ssol);
    let recent_blockhash = fetch_recent_blockhash(url)?;

    let ix = Instruction {
        program_id: STAKE_PROGRAM_ID,
        accounts: vec![stake_pubkey, dest_pubkey],
        data: borsh::to_vec(&StakeInstruction::Withdraw { amount: units })?,
    };
    let tx = Transaction::new_signed(&owner, recent_blockhash, vec![ix]);
    let result = rpc_call(url, "sendTransaction", json!([serde_json::to_value(&tx)?]))?;
    println!(
        "Withdrew {amount_ssol} SSOL from {stake_pubkey} to {dest_pubkey} (signature {})",
        result.get("signature").and_then(Value::as_str).unwrap_or("?")
    );
    Ok(())
}

fn stake_info(url: &str, stake_account: &str) -> anyhow::Result<()> {
    let stake_pubkey = resolve_pubkey(stake_account)?;
    let result = rpc_call(url, "getStakeInfo", json!([stake_pubkey.to_string()]))?;
    if result.is_null() {
        println!("No stake account at {stake_pubkey}.");
        return Ok(());
    }
    println!("Authority:   {}", result.get("authority").and_then(Value::as_str).unwrap_or("?"));
    println!("Validator:   {}", result.get("validator").and_then(Value::as_str).unwrap_or("?"));
    println!("Status:      {}", result.get("status").and_then(Value::as_str).unwrap_or("?"));
    println!(
        "Staked:      {} SSOL",
        result.get("staked_ssol").and_then(Value::as_f64).unwrap_or(0.0)
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
