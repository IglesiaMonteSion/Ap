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
    REGISTRY_ACCOUNT_ID, STAKING_PROGRAM_ID, STAKING_REWARDS_POOL_ID, STAKING_STATS_ID, VALIDATOR_REGISTRY_ACCOUNT_ID,
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
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
        /// Optional EIP-1559-style priority tip (base units) paid on top of the
        /// dynamic base fee, 100% to the block proposer, to prioritize this
        /// transfer under congestion. Default 0 (no tip).
        #[arg(long, default_value_t = 0)]
        priority_fee: u64,
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
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
    },
    /// Close a stake account, returning its funds plus any pending reward
    /// (auto-paid, see `qchain-execution`'s `staking` module docs). Rejected
    /// until the position's minimum bonding period has elapsed (see
    /// `StakeAccountData::bonding_until_round`). For a validator's own
    /// self-stake specifically, this is a two-step exit: the first call
    /// only starts an unbonding window (see
    /// `StakeAccountData::unbonding_requested_at_round`) - real funds move
    /// only once a second call is submitted after that window elapses.
    /// An ordinary delegator's position is unaffected and closes instantly
    /// as before.
    StakeUndelegate {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        stake_account: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
    },
    /// Claim this stake position's pending staking reward without closing
    /// it (see `qchain-execution`'s `staking` module docs for the
    /// reward-per-share accrual mechanism).
    ClaimReward {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        stake_account: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
    },
    /// Slash a validator's own self-stake for a proven equivocation.
    /// Fetches real evidence from `GET /equivocation_evidence` (this
    /// validator's own witnessed conflict, or the one matching
    /// `--round`/`--author` if given) and submits it - permissionless,
    /// signed by whoever's reporting it, not necessarily the accused
    /// validator's peer or the stake account's owner. See
    /// `qchain-execution::staking`'s module docs for what "self-stake"
    /// means here and why delegators are never touched.
    ReportEquivocation {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        /// The accused validator's own self-stake account to slash (its
        /// stored `owner` and `validator` must both equal the accused
        /// address).
        #[arg(long)]
        stake_account: String,
        /// Which round's evidence to submit, if this node has witnessed
        /// more than one - omit when there's exactly one.
        #[arg(long)]
        round: Option<u64>,
        /// Which accused validator's evidence to submit, if this node has
        /// witnessed more than one - omit when there's exactly one.
        #[arg(long)]
        author: Option<String>,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
    },
    /// Register (or update) yourself as a validator in the on-chain validator
    /// registry (phase 3). Requires a genuine self-stake account (owner ==
    /// validator == you, amount >= the minimum validator stake) - delegate to
    /// yourself first with `stake-delegate --validator <your own address>`.
    /// Publishes your consensus key bundle and P2P address so peers can
    /// discover and consense with you. Inert this increment: the registry is
    /// populated and queryable, but consensus doesn't read it for membership
    /// yet.
    RegisterValidator {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        /// Your own self-stake account (from `stake-delegate` where the
        /// validator target was your own address).
        #[arg(long)]
        stake_account: String,
        /// Your P2P address other nodes dial, e.g. `203.0.113.7:9000`.
        #[arg(long)]
        address: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
    },
    /// Remove your own entry from the on-chain validator registry. Does not
    /// touch your self-stake (unbond it separately with `stake-undelegate`).
    UnregisterValidator {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 10_000_000)]
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
        #[arg(long, default_value_t = 10_000_000)]
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
        #[arg(long, default_value_t = 10_000_000)]
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
        #[arg(long, default_value_t = 10_000_000)]
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
        #[arg(long, default_value_t = 10_000_000)]
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
        #[arg(long, default_value_t = 10_000_000)]
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
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
    },
    /// Propose a new validator commission (basis points, out of 10,000) on
    /// the staking-reward share of `base_fee` (Low risk tier).
    ProposeSetStakingCommission {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal_id: ProposalId,
        #[arg(long)]
        value: u16,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
    },
    /// Propose a new QCH emission APR (annual, basis points). Low-tier.
    ProposeSetEmissionApr {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        proposal_id: ProposalId,
        #[arg(long)]
        value: u16,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 10_000_000)]
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
        #[arg(long, default_value_t = 10_000_000)]
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
        #[arg(long, default_value_t = 10_000_000)]
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
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
    },
    /// Print the on-chain algorithm registry.
    Registry {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
    },
    /// Regenerate a node config's `validators` array straight from the
    /// on-chain validator registry (phase 3). Fetches every self-registered
    /// validator (bundle + address + stake) and prints the JSON array ready
    /// to paste into each node's config `validators` field - so adding a
    /// newcomer is: they register on-chain (permissionless), then a
    /// coordinator runs this once and redeploys the refreshed config to every
    /// operator (a coordinated restart via deploy/update.sh). No hand-editing,
    /// no collecting each stranger's key bundle by hand. NOTE: this does NOT
    /// change consensus live - the set is still applied via config at (re)start
    /// (fully-automatic mid-epoch rotation is a separate consensus change);
    /// every operator must deploy the SAME generated array, or nodes disagree
    /// on the set.
    GenValidators {
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
    /// Deploy a WASM contract on-chain (`SystemInstruction::DeployProgram`,
    /// see `qchain-execution::native`). Prints the fresh address the
    /// program now lives at - save it, later `call-program` invocations
    /// need it as `--program`. No separate deploy fee: the byte-scaled
    /// base fee already charges proportionally more for larger bytecode.
    DeployProgram {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        /// Path to a compiled `.wasm` module.
        #[arg(long)]
        wasm_file: PathBuf,
        /// Exported function name later `call-program` invocations will
        /// call.
        #[arg(long)]
        entry_point: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
    },
    /// Call a deployed contract. `--args` are packed as little-endian i64s
    /// back to back into the instruction data - the real on-chain calling
    /// convention `run_wasm_instruction` decodes (see its doc comment):
    /// every exported function a contract wants callable this way must
    /// declare all-i64 parameters, matching how the args are packed.
    CallProgram {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        #[arg(short, long)]
        keypair: PathBuf,
        #[arg(long)]
        program: String,
        /// Comma-separated account addresses, in the order the contract
        /// expects to index them via `host_get_balance`/`host_set_balance`.
        #[arg(long, default_value = "")]
        accounts: String,
        /// Comma-separated i64 arguments.
        #[arg(long, default_value = "")]
        args: String,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 10_000_000)]
        fee_limit: u64,
    },
    /// Real light-client verification: fetches a `qchain-stark` proof plus
    /// its Merkle-root bindings from `GET /stark_proof` and checks it
    /// *locally*, independent of the node's own claim - this command
    /// trusts nothing the node says beyond the raw proof bytes and public
    /// inputs, unlike `balance`/`params`/etc., which just print whatever
    /// the node reports.
    ///
    /// Honest limit of local verification alone, not fixed by any check
    /// this command can run: `verify_batch_bound_to_state` proves the
    /// batch is *internally* consistent (real conservation of value, real
    /// Merkle inclusion proofs, roots chaining row to row) - it cannot
    /// prove the very first row's claimed starting root is genuinely this
    /// network's real history, since a single fully malicious node
    /// controls both `/stark_proof` and everything it binds to. Every
    /// light client design has this same "weak subjectivity" gap (Bitcoin
    /// SPV, Ethereum light clients included) - the real mitigation is
    /// asking multiple independently-operated nodes and comparing, the
    /// same trust-reduction `load-test --monitor` already uses for a
    /// different purpose. `--cross-check-rpc` does exactly that here.
    LightClientVerify {
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        /// Verify only the most recent `limit` captured transfer receipts
        /// instead of every one the node has ever recorded.
        #[arg(long)]
        limit: Option<usize>,
        /// Additional, independently-operated nodes to cross-check
        /// against - each fetches and verifies its *own* proof
        /// independently (never trusting `rpc`'s bytes), then this
        /// command compares the resulting final root across all of them.
        /// Pass multiple times for more nodes. See this command's own doc
        /// comment for why this matters: local verification alone can't
        /// tell a single lying node from the real network.
        #[arg(long = "cross-check-rpc")]
        cross_check_rpc: Vec<String>,
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

/// Real, live-confirmed cross-network replay gap this closes (see
/// `qchain_core::Message::chain_id`'s doc comment and
/// `project-lessons-learned`): fetched fresh before signing every
/// transaction, rather than assumed or hardcoded, so a transaction is
/// always bound to whatever network `--rpc` actually points at.
fn fetch_chain_id(rpc: &str) -> anyhow::Result<[u8; 32]> {
    let resp: serde_json::Value = reqwest::blocking::get(format!("{rpc}/chain_id"))?.error_for_status()?.json()?;
    let hex_str = resp["chain_id"].as_str().ok_or_else(|| anyhow::anyhow!("malformed /chain_id response"))?;
    let bytes = hex::decode(hex_str)?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("chain_id must be 32 bytes"))
}

#[derive(serde::Deserialize)]
struct NodeStatus {
    executed_transactions: u64,
}

/// Wire shape of `qchain-node`'s `GET /stark_proof` response - the proof
/// itself travels as a hex string (`qchain_stark::Proof` has no serde impl
/// of its own, see `qchain-node`'s `engine.rs`), everything else uses
/// `qchain-stark`'s own real serde impls directly.
#[derive(serde::Deserialize)]
struct StarkProofWire {
    proof: String,
    pub_inputs: qchain_stark::PublicInputs,
    bindings: Vec<qchain_stark::RowStateBinding>,
    row_count: usize,
}

/// Fetches `/stark_proof` from `rpc`, verifies it entirely locally (never
/// trusting anything the node says beyond the raw proof bytes), and
/// returns the batch's final bound root - the state this node's local
/// verification actually vouches for. See `LightClientVerify`'s own doc
/// comment for why a single call to this function can't, by itself, prove
/// that final root is genuinely this network's real history rather than a
/// self-consistent fake one - callers wanting that assurance should call
/// this against multiple independently-operated nodes and compare results.
fn fetch_and_verify_stark_proof(rpc: &str, limit: Option<usize>) -> anyhow::Result<[u8; 32]> {
    let mut url = format!("{rpc}/stark_proof");
    if let Some(limit) = limit {
        url = format!("{url}?limit={limit}");
    }
    let resp = reqwest::blocking::get(&url)?;
    if !resp.status().is_success() {
        anyhow::bail!("node refused to serve a proof: {}", resp.text()?);
    }
    let wire: StarkProofWire = resp.json()?;

    let proof_bytes = hex::decode(&wire.proof)?;
    let proof = qchain_stark::Proof::from_bytes(&proof_bytes).map_err(|e| anyhow::anyhow!("malformed proof bytes: {e}"))?;
    let final_root = wire.bindings.last().ok_or_else(|| anyhow::anyhow!("proof carries no row bindings"))?.root_after;

    println!("{rpc}: fetched a proof over {} row(s) ({} proof bytes)", wire.row_count, proof_bytes.len());
    qchain_stark::verify_batch_bound_to_state(proof, wire.pub_inputs, &wire.bindings)?;
    Ok(final_root)
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
    submit_instruction_p(rpc, payer, program_id, accounts, data, nonce, fee_limit, 0)
}

/// Like `submit_instruction` but with an explicit EIP-1559-style priority tip
/// (see `Message::priority_fee`) to jump the queue under congestion.
#[allow(clippy::too_many_arguments)]
fn submit_instruction_p(
    rpc: &str,
    payer: &Keypair,
    program_id: Pubkey,
    accounts: Vec<Pubkey>,
    data: Vec<u8>,
    nonce: Option<u64>,
    fee_limit: u64,
    priority_fee: u64,
) -> anyhow::Result<serde_json::Value> {
    let nonce = match nonce {
        Some(n) => n,
        None => fetch_account(rpc, &payer.pubkey())?.map(|a| a.nonce).unwrap_or(0),
    };
    let ix = Instruction { program_id, accounts, data };
    let chain_id = fetch_chain_id(rpc)?;
    let tx = Transaction::new_signed_with_priority(payer, nonce, chain_id, fee_limit, priority_fee, vec![ix])?;

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
        Command::Transfer { rpc, keypair, to, amount, nonce, fee_limit, priority_fee } => {
            let payer = qchain_crypto::read_keypair_file(&keypair)?;
            let to_pk: Pubkey = to.parse()?;
            let data = borsh::to_vec(&SystemInstruction::Transfer { amount })?;
            let body = submit_instruction_p(&rpc, &payer, Pubkey::system_program_id(), vec![payer.pubkey(), to_pk], data, nonce, fee_limit, priority_fee)?;
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
            let body = submit_instruction(
                &rpc,
                &staker,
                STAKING_PROGRAM_ID,
                vec![staker.pubkey(), stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
                data,
                nonce,
                fee_limit,
            )?;
            println!("submitted: {body}");
            println!("stake account: {stake_pk}");
        }
        Command::StakeUndelegate { rpc, keypair, stake_account, nonce, fee_limit } => {
            let staker = qchain_crypto::read_keypair_file(&keypair)?;
            let stake_pk: Pubkey = stake_account.parse()?;
            let data = borsh::to_vec(&StakingInstruction::Undelegate)?;
            let body =
                submit_instruction(&rpc, &staker, STAKING_PROGRAM_ID, vec![stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID], data, nonce, fee_limit)?;
            println!("submitted: {body}");
        }
        Command::ClaimReward { rpc, keypair, stake_account, nonce, fee_limit } => {
            let staker = qchain_crypto::read_keypair_file(&keypair)?;
            let stake_pk: Pubkey = stake_account.parse()?;
            let data = borsh::to_vec(&StakingInstruction::ClaimReward)?;
            let body = submit_instruction(&rpc, &staker, STAKING_PROGRAM_ID, vec![stake_pk, STAKING_REWARDS_POOL_ID], data, nonce, fee_limit)?;
            println!("submitted: {body}");
        }
        Command::ReportEquivocation { rpc, keypair, stake_account, round, author, nonce, fee_limit } => {
            let reporter = qchain_crypto::read_keypair_file(&keypair)?;
            let stake_pk: Pubkey = stake_account.parse()?;
            let author_filter: Option<Pubkey> = author.map(|a| a.parse()).transpose()?;

            let all: Vec<qchain_core::EquivocationEvidence> = reqwest::blocking::get(format!("{rpc}/equivocation_evidence"))?.error_for_status()?.json()?;
            let matching: Vec<_> = all
                .into_iter()
                .filter(|e| round.is_none_or(|r| e.vertex_a.round == r) && author_filter.is_none_or(|a| e.vertex_a.author == a))
                .collect();
            let evidence = match matching.len() {
                0 => anyhow::bail!("this node has no equivocation evidence matching the given filters"),
                1 => matching.into_iter().next().unwrap(),
                n => anyhow::bail!("{n} matching pieces of evidence found - narrow with --round/--author"),
            };
            println!(
                "reporting equivocation by {} at round {} (vertex digests {} vs {})",
                evidence.vertex_a.author,
                evidence.vertex_a.round,
                hex::encode(evidence.vertex_a.digest()),
                hex::encode(evidence.vertex_b.digest())
            );

            let data = borsh::to_vec(&StakingInstruction::ReportEquivocation { evidence: Box::new(evidence) })?;
            // accounts[1] = staking stats, so the slash also decrements the
            // global `total_staked` counter (keeps reward-per-share and
            // governance turnout accounting correct after a slash).
            let body = submit_instruction(&rpc, &reporter, STAKING_PROGRAM_ID, vec![stake_pk, STAKING_STATS_ID], data, nonce, fee_limit)?;
            println!("submitted: {body}");
        }
        Command::RegisterValidator { rpc, keypair, stake_account, address, nonce, fee_limit } => {
            let validator = qchain_crypto::read_keypair_file(&keypair)?;
            let stake_pk: Pubkey = stake_account.parse()?;
            let data = borsh::to_vec(&StakingInstruction::RegisterValidator {
                pubkey_bundle: validator.public_key_bundle(),
                address: address.clone(),
            })?;
            let body = submit_instruction(
                &rpc,
                &validator,
                STAKING_PROGRAM_ID,
                vec![validator.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID, stake_pk],
                data,
                nonce,
                fee_limit,
            )?;
            println!("submitted: {body}");
            println!("registered validator {} at {address}", validator.pubkey());
        }
        Command::UnregisterValidator { rpc, keypair, nonce, fee_limit } => {
            let validator = qchain_crypto::read_keypair_file(&keypair)?;
            let data = borsh::to_vec(&StakingInstruction::UnregisterValidator)?;
            let body = submit_instruction(
                &rpc,
                &validator,
                STAKING_PROGRAM_ID,
                vec![validator.pubkey(), VALIDATOR_REGISTRY_ACCOUNT_ID],
                data,
                nonce,
                fee_limit,
            )?;
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
        Command::ProposeSetStakingCommission { rpc, keypair, proposal_id, value, nonce, fee_limit } => {
            let proposer = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk = Keypair::generate()?.pubkey();
            let action = ProposalAction::SetStakingCommissionBps(value);
            let data = borsh::to_vec(&GovernanceInstruction::CreateProposal { id: proposal_id, action })?;
            let body = submit_instruction(&rpc, &proposer, GOVERNANCE_PROGRAM_ID, vec![proposer.pubkey(), proposal_pk], data, nonce, fee_limit)?;
            println!("submitted: {body}");
            println!("proposal account: {proposal_pk}");
        }
        Command::ProposeSetEmissionApr { rpc, keypair, proposal_id, value, nonce, fee_limit } => {
            let proposer = qchain_crypto::read_keypair_file(&keypair)?;
            let proposal_pk = Keypair::generate()?.pubkey();
            let action = ProposalAction::SetEmissionApr(value);
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
                ProposalAction::SetBaseFeePerByte(_)
                | ProposalAction::SetDustThreshold(_)
                | ProposalAction::SetGasPricePerFuel(_)
                | ProposalAction::SetStakingCommissionBps(_)
                | ProposalAction::SetEmissionApr(_) => PARAMS_ACCOUNT_ID,
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
        Command::GenValidators { rpc } => {
            // Read the live on-chain registry via the node's RPC (includes the
            // pubkey_bundle) and emit a config-ready `validators` array. Each
            // registered entry's `address` string ("ip:port") maps directly to
            // the config's `addr: SocketAddr` (same textual form).
            let resp: serde_json::Value = reqwest::blocking::get(format!("{rpc}/validator_registry"))?.error_for_status()?.json()?;
            let list = resp.get("validators").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            if list.is_empty() {
                eprintln!("the on-chain validator registry is empty - no validators have registered yet (see `qchain register-validator`)");
            }
            let validators: Vec<serde_json::Value> = list
                .iter()
                .filter_map(|v| {
                    let bundle = v.get("pubkey_bundle")?.clone();
                    let addr = v.get("address")?.as_str()?.to_string();
                    let stake = v.get("stake")?.as_u64()?;
                    Some(serde_json::json!({ "pubkey_bundle": bundle, "addr": addr, "stake": stake }))
                })
                .collect();
            // Print just the array - paste it into each node config's
            // `validators` field. Pretty-printed for easy diffing/review.
            println!("{}", serde_json::to_string_pretty(&validators)?);
            eprintln!("\n{} validator(s) from the on-chain registry. Paste this into the `validators` field of EVERY node's config, then redeploy (deploy/update.sh) - all operators must use the same set.", validators.len());
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
            let chain_id = fetch_chain_id(&rpc)?;
            let senders: Vec<Keypair> = (0..count).map(|_| Keypair::generate().unwrap()).collect();
            let start_nonce = fetch_account(&rpc, &payer.pubkey())?.map(|a| a.nonce).unwrap_or(0);
            // Reads the live `base_fee_per_byte` instead of a hardcoded
            // guess - a fixed constant here previously went stale the
            // moment governance (or a fresh calibration, as already
            // happened once - see `ARCHITECTURE.md` §5) moved the real
            // fee, and every measured transaction then failed with
            // "insufficient funds" instead of measuring anything. `* 10`
            // is safety margin (real fee ~1x this per hybrid-signed
            // transfer), not a tight estimate - this only needs to cover
            // "the second transaction's own fee," never the timed path.
            let base_fee_per_byte = fetch_account(&rpc, &PARAMS_ACCOUNT_ID)?
                .and_then(|a| borsh::from_slice::<EconomicParams>(&a.data).ok())
                .map(|p| p.base_fee_per_byte)
                .unwrap_or(180);
            // Headroom for the DYNAMIC (EIP-1559) fee. A hybrid-signed transfer
            // is ~5,571 bytes, so the fee at the current floor is ~5,571 x
            // base_fee_per_byte. But the load-test's own burst is above the
            // per-round fee target, so the base fee RISES while the timed
            // transfers are in flight (up to +12.5%/round, compounding over the
            // few rounds a 300-tx burst spans). Funding at only ~1.08x the floor
            // fee (the old 6000 multiplier vs the 5,571-byte size) left the test
            // accounts stranded the moment the fee ticked up ~8% - every measured
            // transfer then failed with "payer cannot afford this transaction's
            // byte fee", so the tool measured the funding round instead of the
            // real transfers. Fund with ~5x the floor fee (30_000 vs 5,571
            // bytes): enough for the base fee to rise several-fold under the load
            // and still admit the transfer. This is untimed setup, so the extra
            // funding costs nothing measured. The transfer's fee_limit is set to
            // this same amount below, so it never caps a legitimately-risen fee.
            let fund_amount = base_fee_per_byte.saturating_mul(30_000).max(5_000_000);
            let client = reqwest::blocking::Client::new();
            for (i, sender) in senders.iter().enumerate() {
                let ix = Instruction {
                    program_id: Pubkey::system_program_id(),
                    accounts: vec![payer.pubkey(), sender.pubkey()],
                    data: borsh::to_vec(&SystemInstruction::Transfer { amount: fund_amount })?,
                };
                let tx = Transaction::new_signed(&payer, start_nonce + i as u64, chain_id, 10_000_000, vec![ix])?;
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
                    Transaction::new_signed(sender, 0, chain_id, fund_amount, vec![ix]).unwrap()
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
        Command::DeployProgram { rpc, keypair, wasm_file, entry_point, nonce, fee_limit } => {
            let payer = qchain_crypto::read_keypair_file(&keypair)?;
            let module_bytes = std::fs::read(&wasm_file)?;
            // Only needs a fresh, unique address - nobody ever signs *as*
            // a program account (see `native.rs`'s `DeployProgram`), so
            // the private key is discarded immediately, same pattern as
            // `stake-delegate`'s stake account.
            let program_pk = Keypair::generate()?.pubkey();
            let data = borsh::to_vec(&SystemInstruction::DeployProgram { module_bytes, entry_point })?;
            let body = submit_instruction(&rpc, &payer, Pubkey::system_program_id(), vec![program_pk], data, nonce, fee_limit)?;
            println!("submitted: {body}");
            println!("program address: {program_pk}");
        }
        Command::CallProgram { rpc, keypair, program, accounts, args, nonce, fee_limit } => {
            let payer = qchain_crypto::read_keypair_file(&keypair)?;
            let program_pk: Pubkey = program.parse()?;
            let account_pks: Vec<Pubkey> =
                accounts.split(',').filter(|s| !s.is_empty()).map(|s| s.parse()).collect::<Result<_, _>>()?;
            let mut data = Vec::new();
            for arg in args.split(',').filter(|s| !s.is_empty()) {
                data.extend_from_slice(&arg.parse::<i64>()?.to_le_bytes());
            }
            let body = submit_instruction(&rpc, &payer, program_pk, account_pks, data, nonce, fee_limit)?;
            println!("submitted: {body}");
        }
        Command::LightClientVerify { rpc, limit, cross_check_rpc } => {
            let final_root = fetch_and_verify_stark_proof(&rpc, limit)?;
            println!("{rpc}: verified locally: every row's conservation equation, u64 range check, and real Merkle root transition checks out");

            if !cross_check_rpc.is_empty() {
                // Each of these independently fetches and verifies its
                // *own* proof - never the primary's bytes - so a match
                // here means N separately-operated nodes each produced
                // real, locally-verified evidence of the same final
                // state, not just that they returned identical bytes.
                let mut disagreement = false;
                for peer in &cross_check_rpc {
                    match fetch_and_verify_stark_proof(peer, limit) {
                        Ok(peer_root) if peer_root == final_root => {
                            println!("{peer}: verified locally, final root matches {rpc}");
                        }
                        Ok(peer_root) => {
                            disagreement = true;
                            println!("{peer}: verified locally, but its final root ({}) does NOT match {rpc}'s ({}) - possible fork or a lying node", hex::encode(peer_root), hex::encode(final_root));
                        }
                        Err(e) => {
                            disagreement = true;
                            println!("{peer}: failed to independently verify: {e}");
                        }
                    }
                }
                if disagreement {
                    anyhow::bail!("cross-check disagreement - do not trust {rpc} alone, see warnings above");
                }
                println!("all {} node(s) (primary + cross-checked) independently agree on the final state", 1 + cross_check_rpc.len());
            }
        }
    }
    Ok(())
}
