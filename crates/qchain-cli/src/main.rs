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
    /// Mixed, ramping stress test: fans out a growing burst of REAL signed
    /// transactions each step (transfers + optional staking + optional WASM
    /// contract calls) until the network degrades, reporting real end-to-end
    /// throughput, base-fee response, round liveness, and cross-node fork
    /// detection per step. Unlike `load-test` (transfers only, one fixed
    /// count), this ramps the load geometrically to FIND the breaking point
    /// and mixes op types to stress the staking program and the WASM VM too.
    /// Non-destructive (never touches keys or deletes state) but it DOES
    /// congest the target network while running.
    Stress {
        /// Node to submit transactions to.
        #[arg(short, long, default_value = "http://127.0.0.1:8080")]
        rpc: String,
        /// A well-funded keypair (a genesis "bank" wallet or the faucet's) used
        /// to fund the ephemeral worker accounts. Never spent beyond funding.
        #[arg(short, long)]
        keypair: PathBuf,
        /// Nodes to sample each step for round liveness + Merkle-root fork
        /// detection (defaults to just `--rpc`). Pass multiple to catch a fork.
        #[arg(long = "monitor")]
        monitor: Vec<String>,
        /// Number of ephemeral worker accounts = the real submission
        /// concurrency (each worker keeps strict per-account nonce order).
        #[arg(long, default_value_t = 32)]
        workers: usize,
        /// Transactions submitted in the FIRST step; each later step multiplies
        /// this by `growth` (geometric ramp toward the breaking point).
        #[arg(long, default_value_t = 100)]
        base_burst: u64,
        /// Per-step growth factor of the burst size (2 = double each step).
        #[arg(long, default_value_t = 2)]
        growth: u64,
        /// Number of ramp steps.
        #[arg(long, default_value_t = 6)]
        steps: u64,
        /// Percent of each burst that is a staking Delegate op (0 disables;
        /// skipped anyway if no validator is available). The rest split between
        /// transfers and contract calls.
        #[arg(long, default_value_t = 15)]
        stake_pct: u64,
        /// Percent of each burst that is a WASM contract call (0 disables).
        #[arg(long, default_value_t = 15)]
        contract_pct: u64,
        /// Validator address to delegate to for the staking mix. If omitted,
        /// the tool tries `GET /validators` and uses the first one.
        #[arg(long)]
        validator: Option<String>,
        /// If > 0, run a CONTINUOUS mode instead of the geometric ramp: every
        /// worker submits transactions back-to-back for this many seconds (no
        /// per-step settle pause), then the tool waits for the mempool to drain
        /// and reports a full submitted → accepted → executed → still-queued
        /// reconciliation (so you can see exactly whether anything was lost).
        #[arg(long, default_value_t = 0)]
        sustained_secs: u64,
        /// In continuous mode, top up any worker whose balance drops below one
        /// transaction's worth of the (risen) fee, so the dynamic fee can't
        /// strand the load generator before the node itself is the limit.
        #[arg(long, default_value_t = true)]
        refund: bool,
        /// Continuous mode only. If > 0, OFFER this many transactions per second
        /// (paced across workers), bypassing the in-flight throttle — a real
        /// flood that can exceed what the node validates, so you can push the
        /// dynamic fee to its peak and measure the worst-case fee per transfer.
        /// 0 (default) uses the sustainable in-flight throttle instead.
        #[arg(long, default_value_t = 0)]
        offer_rate: u64,
        /// Continuous mode only. Async FIRE-AND-FORGET flood: pre-sign a big pool
        /// of varied txs (transfers + staking + contract calls) and blast them
        /// with high concurrency WITHOUT waiting for each RPC response — the only
        /// way to out-run the node's ~hundreds-of-ms RPC latency under load and
        /// pile THOUSANDS into the mempool at once, spiking the dynamic fee and
        /// letting you see a real backlog. Reports the peak queue depth reached.
        #[arg(long, default_value_t = false)]
        fire_and_forget: bool,
        /// With --fire-and-forget: how many transactions to pre-sign and blast
        /// (the target backlog to try to build). Split across workers.
        #[arg(long, default_value_t = 8000)]
        queue_target: u64,
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

/// One point-in-time health sample of a node for the `stress` ramp: how many
/// transactions it has executed (throughput), the round consensus is on
/// (liveness), the live dynamic base fee (congestion response), and its Merkle
/// root (cross-node fork detection).
#[derive(Clone)]
struct StressSample {
    executed: u64,
    round: u64,
    base_fee: u64,
    root: String,
}

#[derive(serde::Deserialize)]
struct StressStatusWire {
    next_round: u64,
    executed_transactions: u64,
    base_fee_per_byte: u64,
}

#[derive(serde::Deserialize)]
struct RootWire {
    root: String,
}

fn fetch_stress_sample(rpc: &str) -> anyhow::Result<StressSample> {
    let s: StressStatusWire = reqwest::blocking::get(format!("{rpc}/status"))?.error_for_status()?.json()?;
    let r: RootWire = reqwest::blocking::get(format!("{rpc}/root"))?.error_for_status()?.json()?;
    Ok(StressSample { executed: s.executed_transactions, round: s.next_round, base_fee: s.base_fee_per_byte, root: r.root })
}

#[derive(serde::Deserialize)]
struct ValidatorDirWire {
    address: String,
}

/// First validator address from `GET /validators` - used to pick a delegation
/// target for the `stress` staking mix when `--validator` isn't given.
fn fetch_first_validator(rpc: &str) -> anyhow::Result<Option<Pubkey>> {
    let list: Vec<ValidatorDirWire> = reqwest::blocking::get(format!("{rpc}/validators"))?.error_for_status()?.json()?;
    match list.first() {
        Some(v) => Ok(Some(v.address.parse()?)),
        None => Ok(None),
    }
}

/// A minimal no-op WASM contract for the `stress` contract-call mix: takes one
/// i64 (the single little-endian arg the dispatch packs from `ix.data`) and
/// returns 0, touching no balances. It exercises the real deploy + dispatch +
/// module-compile + fuel-metering path per call (the point of the stress) while
/// never tripping the ledger's balance-conservation guard, so every call is a
/// clean success rather than a trap.
const STRESS_NOOP_WAT: &str = r#"(module (func (export "run") (param i64) (result i64) i64.const 0))"#;

/// Deploys `STRESS_NOOP_WAT` from `bank` and waits until the program account
/// exists on-chain, returning its address.
fn deploy_noop_contract(rpc: &str, bank: &Keypair, chain_id: [u8; 32]) -> anyhow::Result<Pubkey> {
    let module_bytes = wat::parse_str(STRESS_NOOP_WAT).map_err(|e| anyhow::anyhow!("compiling stress contract: {e}"))?;
    let program_pk = Keypair::generate()?.pubkey();
    let data = borsh::to_vec(&SystemInstruction::DeployProgram { module_bytes, entry_point: "run".to_string() })?;
    let nonce = fetch_account(rpc, &bank.pubkey())?.map(|a| a.nonce).unwrap_or(0);
    let ix = Instruction { program_id: Pubkey::system_program_id(), accounts: vec![program_pk], data };
    let tx = Transaction::new_signed(bank, nonce, chain_id, 100_000_000, vec![ix])?;
    let client = reqwest::blocking::Client::new();
    let resp = client.post(format!("{rpc}/tx")).json(&tx).send()?;
    if !resp.status().is_success() {
        anyhow::bail!("deploy rejected: {}", resp.text()?);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while fetch_account(rpc, &program_pk)?.is_none() {
        if std::time::Instant::now() > deadline {
            anyhow::bail!("timed out waiting for the stress contract to deploy");
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    Ok(program_pk)
}

/// Builds one stress-load instruction from `payer`, choosing the op type by a
/// cheap deterministic hash of `bucket_seed` so the transfer/staking/contract
/// ratios stay stable. Shared by the ramp and the continuous modes so both mix
/// load identically.
fn build_stress_ix(
    payer: Pubkey,
    recipient: Pubkey,
    program_pk: Option<Pubkey>,
    validator_pk: Option<Pubkey>,
    contract_pct: u64,
    stake_pct: u64,
    bucket_seed: u64,
) -> Instruction {
    let bucket = (bucket_seed.wrapping_mul(2654435761) >> 8) % 100;
    if bucket < contract_pct {
        if let Some(program) = program_pk {
            return Instruction { program_id: program, accounts: vec![payer], data: 0i64.to_le_bytes().to_vec() };
        }
    }
    if bucket < contract_pct + stake_pct {
        if let Some(validator) = validator_pk {
            let stake_pk = Keypair::generate().unwrap().pubkey();
            return Instruction {
                program_id: STAKING_PROGRAM_ID,
                accounts: vec![payer, stake_pk, STAKING_STATS_ID, STAKING_REWARDS_POOL_ID],
                data: borsh::to_vec(&StakingInstruction::Delegate { validator, amount: 1_000_000 }).unwrap(),
            };
        }
    }
    Instruction {
        program_id: Pubkey::system_program_id(),
        accounts: vec![payer, recipient],
        data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 }).unwrap(),
    }
}

/// Async fire-and-forget blast of a pre-signed pool of transactions: fires them
/// all at high concurrency WITHOUT blocking one-per-response, the only way to
/// out-run the node's hundreds-of-ms RPC latency under load and pile a real
/// backlog into the mempool. A sampler tracks the peak queue depth (admitted
/// minus executed) and the peak dynamic base fee reached. Returns
/// `(accepted, failed, peak_backlog, peak_base_fee)`.
fn blast_txs_async(rpc: &str, txs: Vec<Transaction>, baseline_executed: u64) -> (u64, u64, u64, u64) {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(6).enable_all().build() {
        Ok(rt) => rt,
        Err(_) => return (0, 0, 0, 0),
    };
    rt.block_on(async move {
        let client = reqwest::Client::builder().pool_max_idle_per_host(512).build().unwrap_or_default();
        let accepted = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicU64::new(0));
        let peak_backlog = Arc::new(AtomicU64::new(0));
        let peak_fee = Arc::new(AtomicU64::new(0));
        let done = Arc::new(AtomicBool::new(false));

        // Sampler: peak mempool backlog (admitted - executed) and peak base_fee.
        let sampler = {
            let (client, rpc) = (client.clone(), rpc.to_string());
            let (accepted, peak_backlog, peak_fee, done) = (accepted.clone(), peak_backlog.clone(), peak_fee.clone(), done.clone());
            tokio::spawn(async move {
                while !done.load(Ordering::Relaxed) {
                    if let Ok(r) = client.get(format!("{rpc}/status")).send().await {
                        if let Ok(v) = r.json::<serde_json::Value>().await {
                            let executed = v["executed_transactions"].as_u64().unwrap_or(baseline_executed);
                            let exec_delta = executed.saturating_sub(baseline_executed);
                            let backlog = accepted.load(Ordering::Relaxed).saturating_sub(exec_delta);
                            peak_backlog.fetch_max(backlog, Ordering::Relaxed);
                        }
                    }
                    if let Ok(r) = client.get(format!("{rpc}/status")).send().await {
                        if let Ok(v) = r.json::<serde_json::Value>().await {
                            if let Some(bf) = v["base_fee_per_byte"].as_u64() {
                                peak_fee.fetch_max(bf, Ordering::Relaxed);
                            }
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            })
        };

        // Blast with bounded concurrency so we don't exhaust file descriptors.
        let sem = Arc::new(tokio::sync::Semaphore::new(400));
        let mut handles = Vec::new();
        for tx in txs {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let (client, rpc) = (client.clone(), rpc.to_string());
            let (accepted, failed) = (accepted.clone(), failed.clone());
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                match client.post(format!("{rpc}/tx")).json(&tx).timeout(std::time::Duration::from_secs(15)).send().await {
                    Ok(r) if r.status().is_success() => accepted.fetch_add(1, Ordering::Relaxed),
                    _ => failed.fetch_add(1, Ordering::Relaxed),
                };
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        // Drain-wait with the sampler STILL running: the dynamic fee keeps
        // climbing as the backlog drains over many full rounds AFTER the blast
        // finishes, so the real peak fee happens here, not during submission.
        // Poll executed until it stops climbing (drained / wedged) or a timeout.
        let mut last = fetch_stress_sample(rpc).map(|s| s.executed).unwrap_or(0);
        let mut stable = 0;
        let drain_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let now = client.get(format!("{rpc}/status")).send().await.ok();
            let ex = match now {
                Some(r) => r.json::<serde_json::Value>().await.ok().and_then(|v| v["executed_transactions"].as_u64()).unwrap_or(last),
                None => last,
            };
            if ex == last {
                stable += 1;
            } else {
                stable = 0;
            }
            last = ex;
            if stable >= 8 || std::time::Instant::now() > drain_deadline {
                break;
            }
        }
        done.store(true, Ordering::Relaxed);
        let _ = sampler.await;
        (accepted.load(Ordering::Relaxed), failed.load(Ordering::Relaxed), peak_backlog.load(Ordering::Relaxed), peak_fee.load(Ordering::Relaxed))
    })
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
        Command::Stress {
            rpc,
            keypair,
            monitor,
            workers,
            base_burst,
            growth,
            steps,
            stake_pct,
            contract_pct,
            validator,
            sustained_secs,
            refund,
            offer_rate,
            fire_and_forget,
            queue_target,
        } => {
            let bank = qchain_crypto::read_keypair_file(&keypair)?;
            let chain_id = fetch_chain_id(&rpc)?;
            let monitors = if monitor.is_empty() { vec![rpc.clone()] } else { monitor.clone() };
            let workers = workers.max(1);

            // Resolve a delegation target for the staking mix.
            let validator_pk: Option<Pubkey> = match &validator {
                Some(v) => Some(v.parse()?),
                None => fetch_first_validator(&rpc).unwrap_or(None),
            };
            let stake_pct = if validator_pk.is_some() { stake_pct } else { 0 };

            // Deploy the no-op contract used by the contract-call mix.
            let program_pk: Option<Pubkey> = if contract_pct > 0 {
                match deploy_noop_contract(&rpc, &bank, chain_id) {
                    Ok(pk) => {
                        println!("deployed stress contract at {pk}");
                        Some(pk)
                    }
                    Err(e) => {
                        eprintln!("contract deploy failed ({e}); disabling the contract mix");
                        None
                    }
                }
            } else {
                None
            };
            let contract_pct = if program_pk.is_some() { contract_pct } else { 0 };
            let transfer_pct = 100u64.saturating_sub(stake_pct).saturating_sub(contract_pct);
            println!(
                "op mix: {transfer_pct}% transfers, {stake_pct}% staking{}, {contract_pct}% contract calls{}",
                validator_pk.map(|v| format!(" (validator {v})")).unwrap_or_default(),
                program_pk.map(|p| format!(" (program {p})")).unwrap_or_default(),
            );

            let base_fee = fetch_account(&rpc, &PARAMS_ACCOUNT_ID)?
                .and_then(|a| borsh::from_slice::<EconomicParams>(&a.data).ok())
                .map(|p| p.base_fee_per_byte)
                .unwrap_or(180);

            // Fund ephemeral worker accounts (sequential, untimed). Each worker
            // is funded as richly as the bank allows (capped), so the dynamic
            // fee rising under the ramp doesn't strand them prematurely - a
            // worker running out of funds is a real breaking signal we WANT to
            // observe at the top of the ramp, not an artifact of stingy funding.
            let workers_kp: Vec<Keypair> = (0..workers).map(|_| Keypair::generate().unwrap()).collect();
            let bank_balance = fetch_account(&rpc, &bank.pubkey())?.map(|a| a.balance).unwrap_or(0);
            let per_worker = (bank_balance / (workers as u64 + 2))
                .min(2_000_000_000)
                .max(base_fee.saturating_mul(100_000));
            if bank_balance < per_worker.saturating_mul(workers as u64) {
                anyhow::bail!(
                    "bank balance {bank_balance} too low to fund {workers} workers at {per_worker} each - fund the bank or lower --workers"
                );
            }
            println!("funding {workers} workers with {per_worker} units each (untimed setup)...");
            let bank_nonce = fetch_account(&rpc, &bank.pubkey())?.map(|a| a.nonce).unwrap_or(0);
            let client = reqwest::blocking::Client::new();
            for (i, w) in workers_kp.iter().enumerate() {
                let ix = Instruction {
                    program_id: Pubkey::system_program_id(),
                    accounts: vec![bank.pubkey(), w.pubkey()],
                    data: borsh::to_vec(&SystemInstruction::Transfer { amount: per_worker })?,
                };
                let tx = Transaction::new_signed(&bank, bank_nonce + i as u64, chain_id, 200_000_000, vec![ix])?;
                let resp = client.post(format!("{rpc}/tx")).json(&tx).send()?;
                if !resp.status().is_success() {
                    anyhow::bail!("worker funding rejected: {}", resp.text()?);
                }
            }
            print!("  waiting for funding to land...");
            use std::io::Write;
            std::io::stdout().flush().ok();
            let fund_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            loop {
                let last = workers_kp.last().unwrap().pubkey();
                if fetch_account(&rpc, &last)?.map(|a| a.balance).unwrap_or(0) > 0 {
                    break;
                }
                if std::time::Instant::now() > fund_deadline {
                    anyhow::bail!("timed out waiting for worker funding to land");
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            println!(" done\n");

            // Nonce-based executed accounting (refund-proof): a worker's on-chain
            // nonce only advances when one of ITS transactions actually executes,
            // so summing each worker's nonce delta over the whole run counts
            // exactly the worker transactions that committed - never the bank's
            // funding/refund transactions. Captured before the load starts.
            let run_initial_nonces: Vec<u64> = workers_kp
                .iter()
                .map(|w| fetch_account(&rpc, &w.pubkey()).ok().flatten().map(|a| a.nonce).unwrap_or(0))
                .collect();
            let mut total_attempted = 0u64; // signed + POSTed
            let mut total_accepted = 0u64; // admitted to a mempool (RPC returned 2xx)
            let mut total_failed = 0u64; // rejected at admission (RPC returned an error)
            let mut broke = false;

            if sustained_secs > 0 && fire_and_forget {
                // ---- ASYNC FIRE-AND-FORGET FLOOD: pre-sign a big pool of varied
                // txs (untimed), then blast them with high concurrency without
                // waiting per response, to build a real mempool backlog and spike
                // the dynamic fee.
                let per_worker = (queue_target as usize).div_ceil(workers).max(1);
                println!("fire-and-forget: pre-signing {} varied txs ({per_worker}/worker, untimed)...", per_worker * workers);
                let mut pool: Vec<Transaction> = Vec::with_capacity(per_worker * workers);
                let mut gc = 0u64;
                for (wi, w) in workers_kp.iter().enumerate() {
                    let start = fetch_account(&rpc, &w.pubkey())?.map(|a| a.nonce).unwrap_or(0);
                    for j in 0..per_worker {
                        let recipient = workers_kp[(wi + 1) % workers].pubkey();
                        let ix = build_stress_ix(w.pubkey(), recipient, program_pk, validator_pk, contract_pct, stake_pct, gc);
                        gc += 1;
                        pool.push(Transaction::new_signed(w, start + j as u64, chain_id, 1_000_000_000, vec![ix])?);
                    }
                }
                let baseline = fetch_stress_sample(&rpc).map(|s| s.executed).unwrap_or(0);
                println!("blasting {} txs at high concurrency (async, no per-response wait)...", pool.len());
                let (accepted, failed, peak_backlog, peak_fee_bf) = blast_txs_async(&rpc, pool, baseline);
                total_attempted = accepted + failed;
                total_accepted = accepted;
                total_failed = failed;
                println!("  blasted {total_attempted}: {accepted} accepted, {failed} rejected");
                println!("  PICO de cola (mempool backlog): {peak_backlog} transacciones esperando ejecución");

                // Peak fee-per-transfer at the peak base_fee reached by the flood.
                let floor_bf = qchain_execution::params::FEE_MIN_BASE_FEE_PER_BYTE;
                let max_bf = qchain_execution::params::MAX_BASE_FEE_PER_BYTE;
                let peak = peak_fee_bf.max(floor_bf);
                let sample_tx = {
                    let to = Keypair::generate()?.pubkey();
                    let ix = Instruction { program_id: Pubkey::system_program_id(), accounts: vec![bank.pubkey(), to], data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 })? };
                    Transaction::new_signed(&bank, 0, chain_id, 1_000_000_000, vec![ix])?
                };
                let tx_bytes = sample_tx.byte_size() as u64;
                let to_qch = |u: u64| u as f64 / 1e9;
                println!("\n=== fee por transferencia ===");
                println!("  tamaño de una transferencia firmada: {tx_bytes} bytes");
                println!("  base_fee_per_byte en el PICO:        {peak} unidades/byte");
                println!("  fee por transferencia en el PICO:    {} unidades = {:.9} QCH", peak.saturating_mul(tx_bytes), to_qch(peak.saturating_mul(tx_bytes)));
                println!("  (referencia, piso base_fee={floor_bf}: {} unidades = {:.9} QCH)", floor_bf.saturating_mul(tx_bytes), to_qch(floor_bf.saturating_mul(tx_bytes)));
                println!("  (tope duro teórico base_fee={max_bf}: {} unidades = {:.3} QCH)", max_bf.saturating_mul(tx_bytes), to_qch(max_bf.saturating_mul(tx_bytes)));
            } else if sustained_secs > 0 {
                // ---- CONTINUOUS MODE: every worker submits back-to-back for the
                // whole window, no per-step settle. An optional refunder thread
                // tops workers up so the rising fee can't strand the generator
                // before the node itself is the bottleneck.
                let mode = if offer_rate > 0 { format!("FLOOD offering ~{offer_rate} tx/s") } else { "sustainable (in-flight throttled)".to_string() };
                println!("continuous mode: {workers} workers for {sustained_secs}s, {mode} (refund={refund})...");
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(sustained_secs);
                let bank_ref = &bank;
                let workers_ref = &workers_kp;
                let rpc_ref = &rpc;
                let program_ref = program_pk;
                let validator_ref = validator_pk;
                let stop = std::sync::atomic::AtomicBool::new(false);
                let stop_ref = &stop;
                // Peak dynamic base_fee observed during the run - the input to the
                // worst-case fee-per-transfer report below.
                let peak_base_fee = std::sync::atomic::AtomicU64::new(0);
                let peak_ref = &peak_base_fee;
                // Per-worker send interval to hit the offered rate (0 = unpaced).
                let send_interval = if offer_rate > 0 {
                    std::time::Duration::from_secs_f64((workers as f64 / offer_rate as f64).max(0.0))
                } else {
                    std::time::Duration::ZERO
                };
                let results: Vec<(u64, u64, u64)> = std::thread::scope(|scope| {
                    // Sampler: record the peak base_fee every ~250ms.
                    scope.spawn(move || {
                        while !stop_ref.load(std::sync::atomic::Ordering::Relaxed) {
                            if let Some(bf) = fetch_account(rpc_ref, &PARAMS_ACCOUNT_ID).ok().flatten()
                                .and_then(|a| borsh::from_slice::<EconomicParams>(&a.data).ok())
                                .map(|p| p.base_fee_per_byte)
                            {
                                peak_ref.fetch_max(bf, std::sync::atomic::Ordering::Relaxed);
                            }
                            std::thread::sleep(std::time::Duration::from_millis(250));
                        }
                    });
                    // Refunder: single writer of the bank account (no nonce race),
                    // tops up any worker below a per-tx fee estimate every ~1.5s.
                    if refund {
                        scope.spawn(move || {
                            let client = reqwest::blocking::Client::new();
                            let mut bank_nonce = fetch_account(rpc_ref, &bank_ref.pubkey()).ok().flatten().map(|a| a.nonce).unwrap_or(0);
                            while !stop_ref.load(std::sync::atomic::Ordering::Relaxed) {
                                std::thread::sleep(std::time::Duration::from_millis(1500));
                                let bf = fetch_account(rpc_ref, &PARAMS_ACCOUNT_ID).ok().flatten()
                                    .and_then(|a| borsh::from_slice::<EconomicParams>(&a.data).ok())
                                    .map(|p| p.base_fee_per_byte).unwrap_or(180);
                                let one_tx = bf.saturating_mul(6_000).max(2_000_000);
                                let topup = one_tx.saturating_mul(50);
                                for w in workers_ref.iter() {
                                    let bal = fetch_account(rpc_ref, &w.pubkey()).ok().flatten().map(|a| a.balance).unwrap_or(0);
                                    if bal < one_tx.saturating_mul(4) {
                                        let ix = Instruction {
                                            program_id: Pubkey::system_program_id(),
                                            accounts: vec![bank_ref.pubkey(), w.pubkey()],
                                            data: borsh::to_vec(&SystemInstruction::Transfer { amount: topup }).unwrap(),
                                        };
                                        if let Ok(tx) = Transaction::new_signed(bank_ref, bank_nonce, chain_id, 1_000_000_000, vec![ix]) {
                                            if client.post(format!("{rpc_ref}/tx")).json(&tx).send().map(|r| r.status().is_success()).unwrap_or(false) {
                                                bank_nonce += 1;
                                            } else {
                                                bank_nonce = fetch_account(rpc_ref, &bank_ref.pubkey()).ok().flatten().map(|a| a.nonce).unwrap_or(bank_nonce);
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                    let handles: Vec<_> = workers_ref
                        .iter()
                        .enumerate()
                        .map(|(wi, w)| {
                            scope.spawn(move || {
                                // In-flight throttle: never let a worker run more
                                // than MAX_INFLIGHT nonces ahead of its confirmed
                                // on-chain nonce. This makes the OFFERED load track
                                // the node's real EXECUTION rate instead of piling
                                // an unbounded backlog — which otherwise spikes the
                                // dynamic fee so high that queued txs fail (fee >
                                // fee_limit / insufficient funds) and, because the
                                // base fee only decays inside a *successful* tx, the
                                // whole network can wedge at a pinned-high fee. With
                                // the cap the fee stabilizes near equilibrium and
                                // "continuous" means sustainable, not a self-DoS.
                                const MAX_INFLIGHT: u64 = 48;
                                let client = reqwest::blocking::Client::new();
                                let mut confirmed = fetch_account(rpc_ref, &w.pubkey()).ok().flatten().map(|a| a.nonce).unwrap_or(0);
                                let mut nonce = confirmed;
                                let (mut attempted, mut accepted, mut failed) = (0u64, 0u64, 0u64);
                                let mut since_sync = 0u64;
                                let mut counter = wi as u64;
                                while std::time::Instant::now() < deadline {
                                    // FLOOD mode (offer_rate > 0): pace to the offered
                                    // rate and BYPASS the in-flight throttle, so the
                                    // offered load can exceed what the node validates
                                    // and drive the dynamic fee to its peak. Otherwise
                                    // use the throttle for a sustainable measurement.
                                    if offer_rate > 0 {
                                        if !send_interval.is_zero() {
                                            std::thread::sleep(send_interval);
                                        }
                                    } else if nonce.saturating_sub(confirmed) >= MAX_INFLIGHT {
                                        confirmed = fetch_account(rpc_ref, &w.pubkey()).ok().flatten().map(|a| a.nonce).unwrap_or(confirmed);
                                        if nonce.saturating_sub(confirmed) >= MAX_INFLIGHT {
                                            std::thread::sleep(std::time::Duration::from_millis(20));
                                            continue;
                                        }
                                    }
                                    let recipient = workers_ref[(wi + 1) % workers_ref.len()].pubkey();
                                    let ix = build_stress_ix(w.pubkey(), recipient, program_ref, validator_ref, contract_pct, stake_pct, counter);
                                    counter = counter.wrapping_add(workers_ref.len() as u64);
                                    let tx = match Transaction::new_signed(w, nonce, chain_id, 1_000_000_000, vec![ix]) {
                                        Ok(t) => t,
                                        Err(_) => continue,
                                    };
                                    attempted += 1;
                                    match client.post(format!("{rpc_ref}/tx")).json(&tx).send() {
                                        Ok(r) if r.status().is_success() => {
                                            accepted += 1;
                                            nonce += 1;
                                            since_sync += 1;
                                            if since_sync >= 16 {
                                                confirmed = fetch_account(rpc_ref, &w.pubkey()).ok().flatten().map(|a| a.nonce).unwrap_or(confirmed);
                                                since_sync = 0;
                                            }
                                        }
                                        _ => {
                                            failed += 1;
                                            // A rejected tx never consumed its nonce;
                                            // resync to the real on-chain nonce and
                                            // back off so a stranded worker (e.g. its
                                            // balance ran low before a refund lands)
                                            // doesn't spin hot.
                                            confirmed = fetch_account(rpc_ref, &w.pubkey()).ok().flatten().map(|a| a.nonce).unwrap_or(confirmed);
                                            nonce = confirmed;
                                            since_sync = 0;
                                            std::thread::sleep(std::time::Duration::from_millis(40));
                                        }
                                    }
                                }
                                (attempted, accepted, failed)
                            })
                        })
                        .collect();
                    let out: Vec<(u64, u64, u64)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    out
                });
                for (a, ac, f) in results {
                    total_attempted += a;
                    total_accepted += ac;
                    total_failed += f;
                }
                let s = fetch_stress_sample(&rpc).ok();
                println!(
                    "  submitted {total_attempted} ({total_accepted} accepted, {total_failed} rejected at admission); base_fee now {}",
                    s.map(|s| s.base_fee).unwrap_or(0)
                );

                // ---- PEAK FEE-PER-TRANSFER report. fee = base_fee_per_byte ×
                // tx.byte_size() (see qchain-execution::Ledger). Measure the exact
                // byte size of a real signed transfer, then price it at the peak
                // base_fee observed and at the floor for comparison. 1 QCH = 1e9
                // units.
                let floor_bf = qchain_execution::params::FEE_MIN_BASE_FEE_PER_BYTE;
                let max_bf = qchain_execution::params::MAX_BASE_FEE_PER_BYTE;
                let peak = peak_base_fee.load(std::sync::atomic::Ordering::Relaxed).max(floor_bf);
                let sample_tx = {
                    let to = Keypair::generate()?.pubkey();
                    let ix = Instruction { program_id: Pubkey::system_program_id(), accounts: vec![bank.pubkey(), to], data: borsh::to_vec(&SystemInstruction::Transfer { amount: 1 })? };
                    Transaction::new_signed(&bank, 0, chain_id, 1_000_000_000, vec![ix])?
                };
                let tx_bytes = sample_tx.byte_size() as u64;
                let floor_units = floor_bf.saturating_mul(tx_bytes);
                let peak_units = peak.saturating_mul(tx_bytes);
                let max_units = max_bf.saturating_mul(tx_bytes);
                let to_qch = |u: u64| u as f64 / 1e9;
                println!("\n=== fee por transferencia ===");
                println!("  tamaño de una transferencia firmada: {tx_bytes} bytes");
                println!("  base_fee_per_byte en el PICO:        {peak} unidades/byte");
                println!("  fee por transferencia en el PICO:    {peak_units} unidades = {:.9} QCH", to_qch(peak_units));
                println!("  (referencia, piso base_fee={floor_bf}: {floor_units} unidades = {:.9} QCH)", to_qch(floor_units));
                println!("  (tope duro teórico base_fee={max_bf}: {max_units} unidades = {:.3} QCH)", to_qch(max_units));
            } else {

            println!("{:<5} {:>8} {:>10} {:>10} {:>9} {:>7} {:>7} {:>6}", "step", "burst", "submit/s", "exec tx/s", "base_fee", "Δround", "fail", "fork");
            println!("{}", "-".repeat(72));

            for step in 1..=steps {
                let burst = base_burst.saturating_mul(growth.saturating_pow((step - 1) as u32)).max(1);
                let per_worker_txs = (burst as usize).div_ceil(workers).max(1);

                // Fresh on-chain nonce per worker (a rejected tx never consumes
                // its nonce, so re-reading avoids a self-inflicted gap between
                // steps).
                let worker_nonces: Vec<u64> = workers_kp
                    .iter()
                    .map(|w| fetch_account(&rpc, &w.pubkey()).ok().flatten().map(|a| a.nonce).unwrap_or(0))
                    .collect();

                // Pre-sign every tx for this step (untimed), choosing the op type
                // by a cheap deterministic mix so the ratios are stable.
                let mut per_worker_txs_vec: Vec<Vec<Transaction>> = Vec::with_capacity(workers);
                let mut global_ix = 0u64;
                for (wi, w) in workers_kp.iter().enumerate() {
                    let mut txs = Vec::with_capacity(per_worker_txs);
                    for j in 0..per_worker_txs {
                        let nonce = worker_nonces[wi] + j as u64;
                        let recipient = workers_kp[(wi + 1) % workers].pubkey();
                        let ix = build_stress_ix(w.pubkey(), recipient, program_pk, validator_pk, contract_pct, stake_pct, global_ix);
                        global_ix += 1;
                        // Generous fee_limit: only balance/nonce should ever be
                        // the limiting factor, so a failure is a real breaking
                        // signal, never a self-imposed cap on a risen fee.
                        txs.push(Transaction::new_signed(w, nonce, chain_id, 1_000_000_000, vec![ix]).unwrap());
                    }
                    per_worker_txs_vec.push(txs);
                }
                let submitted: u64 = per_worker_txs_vec.iter().map(|v| v.len() as u64).sum();

                let before: Vec<StressSample> = monitors.iter().map(|m| fetch_stress_sample(m).unwrap_or(StressSample { executed: 0, round: 0, base_fee, root: String::new() })).collect();
                let submit_start = std::time::Instant::now();
                let handles: Vec<_> = per_worker_txs_vec
                    .into_iter()
                    .map(|txs| {
                        let rpc = rpc.clone();
                        std::thread::spawn(move || {
                            let client = reqwest::blocking::Client::new();
                            let mut fail = 0u64;
                            for tx in &txs {
                                match client.post(format!("{rpc}/tx")).json(tx).send() {
                                    Ok(r) if r.status().is_success() => {}
                                    _ => fail += 1,
                                }
                            }
                            fail
                        })
                    })
                    .collect();
                let failures: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
                total_attempted += submitted;
                total_failed += failures;
                total_accepted += submitted.saturating_sub(failures);
                let submit_elapsed = submit_start.elapsed();
                let submit_rate = submitted as f64 / submit_elapsed.as_secs_f64().max(1e-9);

                // Let execution settle: poll the primary until its executed count
                // stops climbing (converged / stalled) or a timeout.
                let settle_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                let mut last_exec = before[0].executed;
                let mut stable = 0;
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    let now_exec = fetch_stress_sample(&rpc).map(|s| s.executed).unwrap_or(last_exec);
                    if now_exec == last_exec {
                        stable += 1;
                    } else {
                        stable = 0;
                    }
                    last_exec = now_exec;
                    if stable >= 4 || std::time::Instant::now() > settle_deadline {
                        break;
                    }
                }
                let after: Vec<StressSample> = monitors.iter().map(|m| fetch_stress_sample(m).unwrap_or(StressSample { executed: last_exec, round: 0, base_fee, root: String::new() })).collect();

                let exec_delta = after[0].executed.saturating_sub(before[0].executed);
                let total_elapsed = submit_start.elapsed().as_secs_f64().max(1e-9);
                let exec_tps = exec_delta as f64 / total_elapsed;
                let round_delta = after[0].round.saturating_sub(before[0].round);
                // Fork check: only meaningful once nodes agree on how much they
                // executed (else roots differ merely because one is behind).
                let converged = after.iter().all(|s| s.executed == after[0].executed);
                let roots_agree = after.iter().all(|s| s.root == after[0].root);
                let fork = converged && !roots_agree;
                let fork_str = if monitors.len() < 2 { "n/a" } else if !converged { "..." } else if fork { "FORK" } else { "ok" };

                println!(
                    "{:<5} {:>8} {:>10.0} {:>10.0} {:>9} {:>7} {:>7} {:>6}",
                    step, submitted, submit_rate, exec_tps, after[0].base_fee, round_delta, failures, fork_str
                );

                // Breaking-point detection.
                if round_delta == 0 {
                    println!("\n⚠  BREAKING POINT: consensus stopped advancing at step {step} (round frozen at {}). The node is not committing new rounds under this load.", after[0].round);
                    broke = true;
                    break;
                }
                if fork {
                    println!("\n⚠  BREAKING POINT: nodes CONVERGED on executed count but DISAGREE on the Merkle root at step {step} — a real fork. Roots: {:?}", after.iter().map(|s| &s.root[..s.root.len().min(16)]).collect::<Vec<_>>());
                    broke = true;
                    break;
                }
                if failures * 2 > submitted {
                    println!("\n⚠  DEGRADED: over half the burst failed to submit at step {step} ({failures}/{submitted}) — the RPC/mempool is saturated or workers ran out of funds. Stopping the ramp.");
                    broke = true;
                    break;
                }
            }

            if !broke {
                println!("\n✓ Completed all {steps} steps without a freeze, fork, or mass-failure. The network absorbed the ramp.");
            }
            } // end ramp mode (else branch)

            // ---- RECONCILIATION (both modes): submitted → accepted → executed →
            // still-queued. Wait for the mempool to drain first (executed count
            // stops climbing), then count executed WORKER transactions via each
            // worker's on-chain nonce delta (refund-proof - the bank's funding
            // txs never touch a worker's nonce). This is the real answer to "did
            // any transaction get lost?".
            print!("\nwaiting for the mempool to drain");
            std::io::stdout().flush().ok();
            let drain_deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
            let mut last = fetch_stress_sample(&rpc).map(|s| s.executed).unwrap_or(0);
            let mut stable = 0;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                print!(".");
                std::io::stdout().flush().ok();
                let now = fetch_stress_sample(&rpc).map(|s| s.executed).unwrap_or(last);
                if now == last {
                    stable += 1;
                } else {
                    stable = 0;
                }
                last = now;
                if stable >= 5 || std::time::Instant::now() > drain_deadline {
                    break;
                }
            }
            println!(" done");

            let final_nonces: Vec<u64> = workers_kp
                .iter()
                .map(|w| fetch_account(&rpc, &w.pubkey()).ok().flatten().map(|a| a.nonce).unwrap_or(0))
                .collect();
            let worker_executed: u64 = final_nonces.iter().zip(run_initial_nonces.iter()).map(|(f, i)| f.saturating_sub(*i)).sum();
            let queued_or_lost = total_accepted.saturating_sub(worker_executed);

            println!("\n=== reconciliación de transacciones ===");
            println!("  enviadas (firmadas + POST):        {total_attempted}");
            println!("  aceptadas (admitidas al mempool):  {total_accepted}");
            println!("  rechazadas en admisión:            {total_failed}  (fee/saldo/nonce — el emisor conserva su nonce, se pueden reenviar)");
            println!("  EJECUTADAS (confirmadas on-chain): {worker_executed}");
            println!("  aún en cola / no ejecutadas:       {queued_or_lost}");
            if queued_or_lost == 0 {
                println!("\n✓ CERO transacciones perdidas: cada tx aceptada se ejecutó. Las rechazadas nunca entraron (no se pierden: se reintenta).");
            } else {
                println!("\nℹ  {queued_or_lost} aceptadas no se ejecutaron dentro de la ventana de drenaje. En un nodo sano y en marcha esto son tx TODAVÍA EN COLA que se ejecutarán en rondas siguientes (el mempool no expira por tiempo). Sólo se perderían de verdad si REINICIÁS el nodo (el mempool vive en memoria, no en disco). Volvé a consultar el balance/nonce en unos segundos para confirmar que drenaron.");
            }
            println!("\nNota: 'ejecutadas' se cuenta por el avance de nonce real de cada worker (a prueba de los refondeos). Un base_fee alto que baja solo después es el mecanismo EIP-1559, no una falla.");
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
