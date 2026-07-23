# Security Policy — QChain

QChain is a post-quantum L1 that will custody real value. We take security
seriously and welcome coordinated disclosure from independent researchers.

## Reporting a vulnerability

**Do NOT open a public GitHub issue for a security vulnerability.**

Report privately, one of:

- **GitHub Security Advisory** (preferred): the repository's *Security →
  Advisories → Report a vulnerability* form (private, auditable).
- **Email**: `security@` the project domain (or the maintainer address in the
  repository profile) with the subject `QCHAIN SECURITY`.

Please include:

- A clear description and the impact (what an attacker can achieve).
- Step-by-step reproduction, ideally against a local testnet
  (`deploy/install-node.sh --modo solo`) — never against someone else's node.
- The affected component / commit, and a suggested severity.
- Whether you want public credit after the fix.

We aim to acknowledge within **72 hours** and to keep you updated through triage,
fix, and disclosure.

## Coordinated disclosure

- Give us reasonable time to fix before any public disclosure (target: **90
  days**, or sooner by mutual agreement once a fix ships).
- Do not exfiltrate data, move funds, degrade the network for other users, or
  run automated scans against nodes you do not operate. Testing belongs on your
  own local testnet.
- Acting in good faith under this policy, we will not pursue legal action.

## Bug bounty (reward tiers)

Rewards scale with real, demonstrated impact on a supported release. Amounts are
**guidance**, decided case-by-case at the maintainers' discretion; the first
valid report of an issue is the one rewarded.

| Severity | Guideline reward (USD) | Examples |
|---|---|---|
| **Critical** | up to **10,000** | value can be minted or stolen; consensus can be forked or halted network-wide; the treasury multisig / timelock / caps can be bypassed; a validator's bond can be drained without slashing; supply-cap violation. |
| **High** | up to **5,000** | unauthenticated remote node crash/DoS; a single malicious validator halts execution; permanent single-node brick from a crafted input; governance takeover with no economic stake at risk. |
| **Medium** | up to **1,000** | resource-exhaustion DoS with generous bounds; a fee/economic accounting error that doesn't net-mint; a wallet issue requiring unusual user interaction. |
| **Low** | acknowledgement / swag | best-practice gaps with no direct exploit; hardening suggestions. |

**In scope**: consensus (`qchain-consensus`), execution/economics
(`qchain-execution`), crypto (`qchain-crypto`), storage (`qchain-storage`),
STARK (`qchain-stark`), node/RPC/P2P (`qchain-node`, `qchain-network`), the
wallets (`qchain-wallet`), the CLI, and the deploy tooling.

**Out of scope**: issues that require a privileged position the trust model
already assumes (e.g. write access to a node's own `data_dir` or `keypair.json`;
a >⅓-stake Byzantine coalition against BFT liveness); social engineering;
third-party infrastructure (Cloudflare, the hosting VPS, GitHub); missing
hardening on a node the reporter does not operate; and anything already
documented as a known limitation in `CLAUDE.md` / the architecture docs.

## Supported versions

Security fixes target the **latest tagged release** and the `main` branch. Older
tags are not maintained; upgrade to the latest before reporting.

## Safe-harbor summary

Test only against your own nodes, report privately, don't harm other users or
move funds, give us time to fix — and we'll work with you and credit you.
