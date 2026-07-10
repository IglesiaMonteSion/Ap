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
    EconomicParams, GovernanceInstruction, StakingInstruction, SystemInstruction, GOVERNANCE_PROGRAM_ID, PARAMS_ACCOUNT_ID,
    REGISTRY_ACCOUNT_ID, STAKING_PROGRAM_ID, STAKING_STATS_ID,
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
        /// Opt into the triple hybrid (Ed25519+ML-DSA-65+SLH-DSA) instead
        /// of the default pair - see the `pqc-cryptography` skill for why
        /// this costs materially more in fees (a ~29.8KB signature
        /// component) and is meant for high-value/long-lived accounts,
        /// not everyday wallets. Requires SLH-DSA to actually be `Active`
        /// on the target node's registry before any transaction using it
        /// will be accepted (see `qchain propose-activate`).
        #[arg(long)]
        slh_dsa: bool,
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
    /// Propose a new byte-scaled base fee (Low risk tier: simple
    /// majority, no time-lock).
    ProposeSetBaseFee {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal_id: ProposalId,
        #[arg(long)]
        value: u64,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Propose a new dust-sweep threshold (Low risk tier).
    ProposeSetDustThreshold {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal_id: ProposalId,
        #[arg(long)]
        value: u64,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 1_000_000)]
        fee_limit: u64,
    },
    /// Propose a new WASM gas price (Low risk tier).
    ProposeSetGasPrice {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal_id: ProposalId,
        #[arg(long)]
        value: u64,
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
    /// Print the current on-chain economic parameters.
    Params {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
    },
    /// Print a proposal's current state.
    ProposalStatus {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        proposal: String,
    },
    /// Real network throughput measurement: submits `count` signed
    /// transfers to `rpc` as fast as this process can sign+POST them
    /// (concurrently, across `threads` workers), then polls every node in
    /// `monitor` until they've all executed - reporting submission rate
    /// and true end-to-end (gossip+consensus+execution) throughput. Not a
    /// literature estimate - see `project-lessons-learned`.
    LoadTest {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long, default_value_t = 200)]
        count: u64,
        #[arg(long, default_value_t = 8)]
        threads: usize,
        /// RPC URLs to poll for completion (defaults to just `--rpc`).
        /// Pass multiple times to confirm convergence across nodes.
        #[arg(long = "monitor")]
        monitor: Vec<String>,
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

#[derive(serde::Deserialize)]
struct NodeStatus {
    executed_transactions: u64,
}

fn fetch_executed_count(rpc: &str) -> anyhow::Result<u64> {
    let status: NodeStatus = reqwest::blocking::get(format!("{rpc}/status"))?.error_for_status()?.json()?;
    Ok(status.executed_transactions)
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
        Command::Keygen { out, slh_dsa } => {
            let keypair = if slh_dsa { Keypair::generate_with_slh_dsa()? } else { Keypair::generate()? };
            qchain_crypto::write_keypair_file(&keypair, &out)?;
            println!("wrote keypair to {}", out.display());
            println!("address: {}", keypair.pubkey());
            if slh_dsa {
                println!("combo: triple hybrid (Ed25519+ML-DSA-65+SLH-DSA) - requires SLH-DSA to be Active on the target node's registry");
            }
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
        Command::ProposeSetBaseFee { rpc, keypair, proposal_id, value, nonce, fee_limit } => {
            let proposer = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk = Keypair::generate()?.pubkey();
            let action = ProposalAction::SetBaseFeePerByte(value);
            let data = borsh::to_vec(&GovernanceInstruction::CreateProposal { id: proposal_id, action })?;
            let body = submit_instruction(&rpc, &proposer, GOVERNANCE_PROGRAM_ID, vec![proposer.pubkey(), proposal_pk], data, nonce, fee_limit)?;
            println!("submitted: {body}");
            println!("proposal account: {proposal_pk}");
        }
        Command::ProposeSetDustThreshold { rpc, keypair, proposal_id, value, nonce, fee_limit } => {
            let proposer = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk = Keypair::generate()?.pubkey();
            let action = ProposalAction::SetDustThreshold(value);
            let data = borsh::to_vec(&GovernanceInstruction::CreateProposal { id: proposal_id, action })?;
            let body = submit_instruction(&rpc, &proposer, GOVERNANCE_PROGRAM_ID, vec![proposer.pubkey(), proposal_pk], data, nonce, fee_limit)?;
            println!("submitted: {body}");
            println!("proposal account: {proposal_pk}");
        }
        Command::ProposeSetGasPrice { rpc, keypair, proposal_id, value, nonce, fee_limit } => {
            let proposer = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk = Keypair::generate()?.pubkey();
            let action = ProposalAction::SetGasPricePerFuel(value);
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
            let account = fetch_account(&rpc, &proposal_pk)?.ok_or_else(|| anyhow::anyhow!("proposal account not found"))?;
            let decoded: Proposal = borsh::from_slice(&account.data)?;
            // Execute's target account depends on what kind of action the
            // proposal carries - the registry singleton for a
            // Registry-tier action, the economic-params singleton for a
            // Low-tier one (see `qchain-execution`'s `governance.rs`).
            let target = match decoded.action {
                ProposalAction::ActivateAlgorithm(_) | ProposalAction::DeprecateAlgorithm { .. } | ProposalAction::RetireAlgorithm { .. } => {
                    REGISTRY_ACCOUNT_ID
                }
                ProposalAction::SetBaseFeePerByte(_) | ProposalAction::SetDustThreshold(_) | ProposalAction::SetGasPricePerFuel(_) => {
                    PARAMS_ACCOUNT_ID
                }
            };
            let data = borsh::to_vec(&GovernanceInstruction::Execute)?;
            let body = submit_instruction(&rpc, &caller, GOVERNANCE_PROGRAM_ID, vec![proposal_pk, target], data, nonce, fee_limit)?;
            println!("submitted: {body}");
        }
        Command::Registry { rpc } => {
            let account = fetch_account(&rpc, &REGISTRY_ACCOUNT_ID)?.ok_or_else(|| anyhow::anyhow!("registry account not found - is genesis seeded?"))?;
            let registry: Vec<RegistryEntry> = borsh::from_slice(&account.data)?;
            for entry in registry {
                println!("id={} name={} status={:?}", entry.id.0, entry.name, entry.status);
            }
        }
        Command::Params { rpc } => {
            let account = fetch_account(&rpc, &PARAMS_ACCOUNT_ID)?.ok_or_else(|| anyhow::anyhow!("params account not found - is genesis seeded?"))?;
            let params: EconomicParams = borsh::from_slice(&account.data)?;
            println!("{params:#?}");
        }
        Command::ProposalStatus { rpc, proposal } => {
            let proposal_pk: Pubkey = proposal.parse()?;
            let account = fetch_account(&rpc, &proposal_pk)?.ok_or_else(|| anyhow::anyhow!("proposal account not found"))?;
            let proposal: Proposal = borsh::from_slice(&account.data)?;
            println!("{proposal:#?}");
        }
        Command::LoadTest { rpc, keypair, count, threads, monitor } => {
            let payer = qchain_crypto::read_keypair_file(&keypair)?;
            let to = Keypair::generate()?.pubkey();

            // One fresh, independently-funded account per transaction
            // rather than N transactions from a single payer: this
            // execution model enforces strict per-account nonce order
            // (see `qchain-execution`'s `Ledger`), and concurrent
            // multi-threaded submission from one payer races that order -
            // a transaction that lands even one slot early is rejected
            // and *permanently lost* (never retried), which understates
            // real throughput by measuring a self-inflicted failure mode
            // instead of the network's actual capacity. Funding is a
            // separate, sequential, un-timed setup phase for exactly this
            // reason.
            println!("funding {count} fresh accounts (sequential setup, not timed)...");
            let senders: Vec<Keypair> = (0..count).map(|_| Keypair::generate().unwrap()).collect();
            let start_nonce = fetch_account(&rpc, &payer.pubkey())?.map(|a| a.nonce).unwrap_or(0);
            let fund_amount = 1_000_000u64;
            let client = reqwest::blocking::Client::new();
            for (i, sender) in senders.iter().enumerate() {
                let ix = Instruction {
                    program_id: Pubkey::system_program_id(),
                    accounts: vec![payer.pubkey(), sender.pubkey()],
                    data: borsh::to_vec(&SystemInstruction::Transfer { amount: fund_amount })?,
                };
                let tx = Transaction::new_signed(&payer, start_nonce + i as u64, [0u8; 32], 10_000_000, vec![ix])?;
                let resp = client.post(format!("{rpc}/tx")).json(&tx).send()?;
                if !resp.status().is_success() {
                    anyhow::bail!("funding transaction rejected: {}", resp.text()?);
                }
            }
            print!("  waiting for funding to land...");
            use std::io::Write;
            std::io::stdout().flush().ok();
            let fund_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            loop {
                let last = senders.last().unwrap().pubkey();
                if fetch_account(&rpc, &last)?.map(|a| a.balance).unwrap_or(0) > 0 {
                    break;
                }
                if std::time::Instant::now() > fund_deadline {
                    anyhow::bail!("timed out waiting for funding to land");
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            println!(" done");

            println!("signing {count} transactions (one per funded account)...");
            let sign_start = std::time::Instant::now();
            let txs: Vec<Transaction> = senders
                .iter()
                .map(|sender| {
                    let ix = Instruction {
                        program_id: Pubkey::system_program_id(),
                        accounts: vec![sender.pubkey(), to],
                        data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
                    };
                    Transaction::new_signed(sender, 0, [0u8; 32], fund_amount, vec![ix]).unwrap()
                })
                .collect();
            let sign_elapsed = sign_start.elapsed();
            println!("  {:?} total, {:.0} tx/s", sign_elapsed, count as f64 / sign_elapsed.as_secs_f64());

            let monitors = if monitor.is_empty() { vec![rpc.clone()] } else { monitor };
            let baseline: Vec<u64> = monitors.iter().map(|m| fetch_executed_count(m).unwrap_or(0)).collect();

            let worker_count = threads.max(1);
            let chunk_size = (count as usize).div_ceil(worker_count).max(1);
            println!("submitting {count} independent txs to {rpc} across {worker_count} worker threads...");
            let submit_start = std::time::Instant::now();
            let handles: Vec<_> = txs
                .chunks(chunk_size)
                .map(|chunk| {
                    let chunk = chunk.to_vec();
                    let rpc = rpc.clone();
                    std::thread::spawn(move || {
                        let client = reqwest::blocking::Client::new();
                        let mut failures = 0u64;
                        for tx in &chunk {
                            match client.post(format!("{rpc}/tx")).json(tx).send() {
                                Ok(resp) if resp.status().is_success() => {}
                                Ok(resp) => {
                                    eprintln!("submit rejected: {:?}", resp.text());
                                    failures += 1;
                                }
                                Err(e) => {
                                    eprintln!("submit error: {e}");
                                    failures += 1;
                                }
                            }
                        }
                        failures
                    })
                })
                .collect();
            let failures: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
            let submit_elapsed = submit_start.elapsed();
            println!(
                "  {:?} total, {:.0} tx/s submission rate ({failures} failed to submit)",
                submit_elapsed,
                count as f64 / submit_elapsed.as_secs_f64()
            );

            println!("waiting for execution to converge across {} monitored node(s)...", monitors.len());
            let timeout = std::time::Duration::from_secs(120);
            for (m, base) in monitors.iter().zip(baseline.iter()) {
                let target = base + count - failures;
                loop {
                    let current = fetch_executed_count(m)?;
                    if current >= target {
                        break;
                    }
                    if submit_start.elapsed() > timeout {
                        anyhow::bail!("timed out waiting for {m} to execute {count} transactions (at {current}/{target})");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                let total_elapsed = submit_start.elapsed();
                println!(
                    "  {m}: executed {count} txs end-to-end (submit -> gossip -> consensus -> executed) in {:?} ({:.0} tx/s)",
                    total_elapsed,
                    count as f64 / total_elapsed.as_secs_f64()
                );
            }
        }
    }
    Ok(())
}
