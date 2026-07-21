#!/usr/bin/env python3
"""AI security review of a pull request diff — tarea #183, Fase A (dev-time).

Read-only, advisory GitHub Action helper: it sends the PR diff plus this
project's security invariants to the Claude API and posts the findings as a
single (updated-in-place) PR comment. It NEVER gates the PR — a finding is an
advisory comment, not a failure — and it holds no keys of its own: the API key
comes from the `ANTHROPIC_API_KEY` repo secret (env var), never the repo. If
that secret is unset the script is inert (prints a notice and exits 0), so the
workflow can live in the repo without doing anything until the operator opts in.

Security model of the agent itself (see CLAUDE.md's "Agente IA de seguridad"):
read-only over code, no keys in the repo, no destructive power — the worst case
if it misbehaves is a wrong comment, never moving funds or touching consensus.

Stdlib only (urllib/json/subprocess) so the Action needs no `pip install`.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

# Bound the diff we send so a huge PR can't blow up token cost. A diff larger
# than this is truncated with a clear marker (the auditor still sees the head).
MAX_DIFF_CHARS = 200_000
# Cap the model's output; findings should be compact.
MAX_TOKENS = 4000
ANTHROPIC_VERSION = "2023-06-01"
# A balanced default for a per-PR auditor (frequent, wants good judgment without
# top-tier cost). Overridable via the CLAUDE_MODEL env/workflow input.
DEFAULT_MODEL = "claude-sonnet-5"
# Marker so we update our own comment in place instead of spamming a new one per push.
COMMENT_MARKER = "<!-- qchain-ai-security-review -->"

SYSTEM_PROMPT = """\
You are a senior security reviewer for `qchain`, a post-quantum L1 blockchain \
written in Rust. You review a single pull request DIFF and report ONLY real, \
concrete, security-relevant findings introduced or worsened by THIS diff. You \
are advisory: a human decides. Be precise and terse; false positives waste the \
maintainer's time.

Judge the diff against these project invariants (a violation of any is a finding):

1. VALUE CONSERVATION. No path may mint or destroy balance outside the documented \
   emission/fee-burn logic. In WASM execution the ledger boundary must reject a \
   debit unless the caller is the signer or the program owns the account, and the \
   total balance over declared accounts must not grow (no minting). Watch for \
   account aliasing (the same account named twice) defeating a positional sum.
2. DETERMINISM / NO-FORK. Anything that feeds consensus or committed state MUST be \
   a pure function of committed data. Fork risks: wall-clock time, RNG, \
   non-canonicalized f64/NaN, HashMap/HashSet iteration order used to build state, \
   per-node local values (vs the committed round/author). A committee/quorum/leader \
   decision must resolve per-round via the schedule, never mixing two committees.
3. OVERFLOW-SAFETY. Release builds run `overflow-checks = true`, so a plain `+`/`*` \
   that can overflow is a DETERMINISTIC panic = network halt. Arithmetic on \
   attacker- or governance-influenced values must use saturating/checked ops.
4. BOUNDED GROWTH. No unbounded maps/vecs/logs fed by network input (this project \
   has repeatedly hit OOM this way). Every cache/queue/pending-map must be bounded \
   or pruned by a round window.
5. SIGNATURES. Hybrid PQC verify is fail-closed (all components must verify; combo \
   exact). Signed messages are domain-tagged (tx vs vote vs vertex); a signature of \
   one domain must never verify as another. The consensus key must not be usable as \
   a value-signing oracle.
6. SINGLETON ACCOUNT IDS. Instructions that touch protocol singletons (staking \
   stats, reward pool, params, fee state, validator registry, fee pool, treasury) \
   must pin the canonical id, never trust a caller-named account.
7. ADMISSION / DoS. Unauthenticated RPC/P2P surfaces must bound work before \
   expensive verification; cheap checks (chain_id, size cap, sender-in-committee) \
   before the ~150us PQC verify or any lock.
8. chain_id FOLDING. A config field that changes committed state must fold into \
   `chain_id`; a node-local operational flag must NOT.
9. FAIL-LOUD on corrupt on-disk state (never silently treat corrupt as zero/absent).
10. WASM/wallet: no XSS sinks with unescaped user/validator-controlled strings; \
    keys/seeds never leave the wallet; no unbounded request bodies.

Output format: if you find nothing, reply with exactly `No security findings.` \
Otherwise, for each finding output a markdown bullet:
`- **[SEVERITY]** \\`path:line\\` — <one-sentence issue> — <why it matters / the \
concrete failure>`  (SEVERITY ∈ CRITICAL/HIGH/MEDIUM/LOW). Do not restate the diff, \
do not praise, do not suggest style nits. Only real security-relevant findings."""


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def get_diff(base_ref):
    """Diff of the PR against its base. fetch-depth:0 makes origin/<base> present."""
    run(["git", "fetch", "--no-tags", "origin", base_ref])
    for base in (f"origin/{base_ref}", base_ref):
        r = run(["git", "diff", f"{base}...HEAD"])
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout
    # Fallback: diff against the merge-base of HEAD~ (best effort).
    r = run(["git", "diff", "HEAD~1...HEAD"])
    return r.stdout


def call_claude(api_key, model, diff):
    truncated = diff[:MAX_DIFF_CHARS]
    if len(diff) > MAX_DIFF_CHARS:
        truncated += "\n\n[diff truncated for length — reviewed the first part only]"
    body = {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": "Review this pull request diff and report only real "
                "security-relevant findings per your instructions.\n\n"
                "```diff\n" + truncated + "\n```",
            }
        ],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode(),
        headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read())
    parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
    return "".join(parts).strip()


def gh_api(method, path, token, payload=None):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "content-type": "application/json",
            "User-Agent": "qchain-ai-security-review",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


def upsert_comment(repo, pr_number, token, body):
    """Update our own marked comment in place, or create it if absent (no spam)."""
    marked = COMMENT_MARKER + "\n" + body
    existing = gh_api("GET", f"/repos/{repo}/issues/{pr_number}/comments?per_page=100", token)
    for c in existing:
        if COMMENT_MARKER in (c.get("body") or ""):
            gh_api("PATCH", f"/repos/{repo}/issues/comments/{c['id']}", token, {"body": marked})
            return
    gh_api("POST", f"/repos/{repo}/issues/{pr_number}/comments", token, {"body": marked})


def main():
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        print("ANTHROPIC_API_KEY is not set — AI security review is inert. "
              "Add the repo secret to enable it (see docs/AI-SECURITY-REVIEW.md).")
        return 0

    base_ref = os.environ.get("BASE_REF", "").strip()
    repo = os.environ.get("REPO", "").strip()
    pr_number = os.environ.get("PR_NUMBER", "").strip()
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    model = os.environ.get("CLAUDE_MODEL", "").strip() or DEFAULT_MODEL

    diff = get_diff(base_ref) if base_ref else ""
    if not diff.strip():
        print("empty diff — nothing to review.")
        return 0

    try:
        findings = call_claude(api_key, model, diff)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
        # Advisory only: never fail the PR because the API hiccuped.
        print(f"AI security review skipped (API error): {e}")
        return 0

    if not findings:
        findings = "No security findings."

    header = ("### 🔐 AI security review (advisory)\n\n"
              "_Automated review of this PR's diff against qchain's security "
              "invariants. Advisory only — a human decides._\n\n")
    body = header + findings

    if repo and pr_number and token:
        try:
            upsert_comment(repo, pr_number, token, body)
            print("posted/updated the review comment.")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
            print(f"could not post PR comment ({e}); findings below:\n{findings}")
    else:
        print(findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
