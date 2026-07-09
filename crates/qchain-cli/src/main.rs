//! Wallet CLI for the phase-1/2 testnet: keygen, balance lookups, signed
//! transfers, delegated staking, and governance (propose/vote/finalize/
//! execute) against a `qchain-node`'s JSON-RPC surface (`ARCHITECTURE.md`
//! §2/§4/§5/§6). Uses the same hybrid Ed25519+ML-DSA-65 keypair model as
//! the rest of the protocol - there is no separate "wallet-only" key
//! format, and no separate "governance token" format either: voting power
//! comes straight from a stake account's balance.

use clap::{Parser, Subcommand};
use qchain_core::{Account, Instruction, Transaction};
use qchain_crypto::{AlgorithmId, AlgorithmStatus, Keypair, Pubkey, RegistryEntry};
use qchain_execution::{
    GovernanceInstruction, StakingInstruction, SystemInstruction, GOVERNANCE_PROGRAM_ID, REGISTRY_ACCOUNT_ID, STAKING_PROGRAM_ID,
    STAKING_STATS_ID,
};
use qchain_governance::{Proposal, ProposalAction, ProposalId, VoteChoice};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "qchain testnet wallet: transfers, delegated staking, and governance")]
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
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Bond funds to a validator, opening a new stake account (prints its
    /// address - save it, it's needed for `stake-undelegate` and `vote`).
    StakeDelegate {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        validator: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Close a stake account, returning its funds. No unbonding delay in
    /// this increment (see `qchain-execution`'s `staking` module docs).
    StakeUndelegate {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        stake_account: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Propose activating a new algorithm registry entry.
    ProposeActivate {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal_id: ProposalId,
        #[arg(long)]
        algorithm_id: u16,
        #[arg(long)]
        name: String,
        #[arg(long)]
        pubkey_len: usize,
        #[arg(long)]
        max_sig_len: usize,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Propose deprecating an active algorithm registry entry.
    ProposeDeprecate {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal_id: ProposalId,
        #[arg(long)]
        algorithm_id: u16,
        #[arg(long)]
        retirement_round: u64,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Propose retiring a deprecated algorithm registry entry (only takes
    /// effect once its retirement round has been reached).
    ProposeRetire {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal_id: ProposalId,
        #[arg(long)]
        algorithm_id: u16,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Cast a vote on a proposal, weighted by a stake account's balance.
    Vote {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal: String,
        #[arg(long)]
        stake_account: String,
        /// yes, no, or abstain.
        #[arg(long)]
        choice: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Tally a proposal's votes once its voting period has ended.
    /// Permissionless - any funded keypair can call this.
    Finalize {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Execute a passed proposal once its review time-lock has elapsed.
    /// Permissionless - any funded keypair can call this.
    ExecuteProposal {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Print the on-chain algorithm registry.
    Registry {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
    },
    /// Print a proposal's current state.
    ProposalStatus {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        proposal: String,
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

fn submit_instruction(
    rpc: &str,
    payer: &Keypair,
    program_id: Pubkey,
    accounts: Vec<Pubkey>,
    data: Vec<u8>,
    nonce: Option<u64>,
    fee_limit: u64,
) -> anyhow::Result<serde_json::Value> {
    let nonce = match nonce {
        Some(n) => n,
        None => fetch_account(rpc, &payer.pubkey())?.map(|a| a.nonce).unwrap_or(0),
    };
    let ix = Instruction { program_id, accounts, data };
    // No recent-certificate anchor is fetched yet (phase-1 simplification
    // - see `qchain-node`'s RPC surface): nonce is this transaction's only
    // replay defense for now.
    let tx = Transaction::new_signed(payer, nonce, [0u8; 32], fee_limit, vec![ix])?;

    let resp = reqwest::blocking::Client::new().post(format!("{rpc}/tx")).json(&tx).send()?;
    if !resp.status().is_success() {
        anyhow::bail!("node rejected transaction: {}", resp.text()?);
    }
    Ok(resp.json()?)
}

fn parse_vote_choice(s: &str) -> anyhow::Result<VoteChoice> {
    match s.to_ascii_lowercase().as_str() {
        "yes" | "y" => Ok(VoteChoice::Yes),
        "no" | "n" => Ok(VoteChoice::No),
        "abstain" | "a" => Ok(VoteChoice::Abstain),
        other => anyhow::bail!("unrecognized vote choice '{other}' - use yes, no, or abstain"),
    }
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
            let data = borsh::to_vec(&SystemInstruction::Transfer { amount })?;
            let body = submit_instruction(&rpc, &payer, Pubkey::system_program_id(), vec![payer.pubkey(), to_pk], data, nonce, fee_limit)?;
            println!("submitted: {body}");
        }
        Command::StakeDelegate { rpc, keypair, validator, amount, nonce, fee_limit } => {
            let staker = qchain_crypto::read_keypair_file(&keypair)?;
            let validator_pk: Pubkey = validator.parse()?;
            // The stake account only needs a fresh, unique address - see
            // `StakeAccountData.owner` for the real authorization check.
            // Nobody ever signs *as* this address, so its private key is
            // discarded immediately.
            let stake_pk = Keypair::generate()?.pubkey();
            let data = borsh::to_vec(&StakingInstruction::Delegate { validator: validator_pk, amount })?;
            let body =
                submit_instruction(&rpc, &staker, STAKING_PROGRAM_ID, vec![staker.pubkey(), stake_pk, STAKING_STATS_ID], data, nonce, fee_limit)?;
            println!("submitted: {body}");
            println!("stake account: {stake_pk}");
        }
        Command::StakeUndelegate { rpc, keypair, stake_account, nonce, fee_limit } => {
            let staker = qchain_crypto::read_keypair_file(&keypair)?;
            let stake_pk: Pubkey = stake_account.parse()?;
            let data = borsh::to_vec(&StakingInstruction::Undelegate)?;
            let body = submit_instruction(&rpc, &staker, STAKING_PROGRAM_ID, vec![stake_pk, STAKING_STATS_ID], data, nonce, fee_limit)?;
            println!("submitted: {body}");
        }
        Command::ProposeActivate { rpc, keypair, proposal_id, algorithm_id, name, pubkey_len, max_sig_len, nonce, fee_limit } => {
            let proposer = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk = Keypair::generate()?.pubkey();
            let entry = RegistryEntry {
                id: AlgorithmId(algorithm_id),
                name,
                pubkey_len,
                max_sig_len,
                status: AlgorithmStatus::Active,
                activation_epoch: 0,
            };
            let action = ProposalAction::ActivateAlgorithm(entry);
            let data = borsh::to_vec(&GovernanceInstruction::CreateProposal { id: proposal_id, action })?;
            let body = submit_instruction(&rpc, &proposer, GOVERNANCE_PROGRAM_ID, vec![proposer.pubkey(), proposal_pk], data, nonce, fee_limit)?;
            println!("submitted: {body}");
            println!("proposal account: {proposal_pk}");
        }
        Command::ProposeDeprecate { rpc, keypair, proposal_id, algorithm_id, retirement_round, nonce, fee_limit } => {
            let proposer = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk = Keypair::generate()?.pubkey();
            let action = ProposalAction::DeprecateAlgorithm { id: AlgorithmId(algorithm_id), retirement_round };
            let data = borsh::to_vec(&GovernanceInstruction::CreateProposal { id: proposal_id, action })?;
            let body = submit_instruction(&rpc, &proposer, GOVERNANCE_PROGRAM_ID, vec![proposer.pubkey(), proposal_pk], data, nonce, fee_limit)?;
            println!("submitted: {body}");
            println!("proposal account: {proposal_pk}");
        }
        Command::ProposeRetire { rpc, keypair, proposal_id, algorithm_id, nonce, fee_limit } => {
            let proposer = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk = Keypair::generate()?.pubkey();
            let action = ProposalAction::RetireAlgorithm { id: AlgorithmId(algorithm_id) };
            let data = borsh::to_vec(&GovernanceInstruction::CreateProposal { id: proposal_id, action })?;
            let body = submit_instruction(&rpc, &proposer, GOVERNANCE_PROGRAM_ID, vec![proposer.pubkey(), proposal_pk], data, nonce, fee_limit)?;
            println!("submitted: {body}");
            println!("proposal account: {proposal_pk}");
        }
        Command::Vote { rpc, keypair, proposal, stake_account, choice, nonce, fee_limit } => {
            let voter = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk: Pubkey = proposal.parse()?;
            let stake_pk: Pubkey = stake_account.parse()?;
            let choice = parse_vote_choice(&choice)?;
            let data = borsh::to_vec(&GovernanceInstruction::Vote { choice })?;
            let body = submit_instruction(&rpc, &voter, GOVERNANCE_PROGRAM_ID, vec![proposal_pk, stake_pk], data, nonce, fee_limit)?;
            println!("submitted: {body}");
        }
        Command::Finalize { rpc, keypair, proposal, nonce, fee_limit } => {
            let caller = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk: Pubkey = proposal.parse()?;
            let data = borsh::to_vec(&GovernanceInstruction::Finalize)?;
            let body = submit_instruction(&rpc, &caller, GOVERNANCE_PROGRAM_ID, vec![proposal_pk, STAKING_STATS_ID], data, nonce, fee_limit)?;
            println!("submitted: {body}");
        }
        Command::ExecuteProposal { rpc, keypair, proposal, nonce, fee_limit } => {
            let caller = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk: Pubkey = proposal.parse()?;
            let data = borsh::to_vec(&GovernanceInstruction::Execute)?;
            let body = submit_instruction(&rpc, &caller, GOVERNANCE_PROGRAM_ID, vec![proposal_pk, REGISTRY_ACCOUNT_ID], data, nonce, fee_limit)?;
            println!("submitted: {body}");
        }
        Command::Registry { rpc } => {
            let account = fetch_account(&rpc, &REGISTRY_ACCOUNT_ID)?.ok_or_else(|| anyhow::anyhow!("registry account not found - is genesis seeded?"))?;
            let registry: Vec<RegistryEntry> = borsh::from_slice(&account.data)?;
            for entry in registry {
                println!("id={} name={} status={:?}", entry.id.0, entry.name, entry.status);
            }
        }
        Command::ProposalStatus { rpc, proposal } => {
            let proposal_pk: Pubkey = proposal.parse()?;
            let account = fetch_account(&rpc, &proposal_pk)?.ok_or_else(|| anyhow::anyhow!("proposal account not found"))?;
            let proposal: Proposal = borsh::from_slice(&account.data)?;
            println!("{proposal:#?}");
        }
    }
    Ok(())
}
