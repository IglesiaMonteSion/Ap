//! Node configuration: everything needed to join the phase-1 testnet as one
//! validator - own keypair, the full (fixed, phase-1) validator set with
//! its stake and network addresses, and genesis allocations. JSON, loaded
//! once at startup; there is no dynamic validator-set membership yet (see
//! `ARCHITECTURE.md`'s phase-1 out-of-scope list - that's a governance
//! feature for a later phase).

use qchain_crypto::{Pubkey, PublicKeyBundle};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// Is this IP safe as a PRIVATE validator RPC bind (loopback or a
/// non-globally-routable / RFC1918 / unique-local address)? A mainnet
/// validator must NOT serve its mutating RPC on a publicly routable address
/// (task #211, "RPC del validador en red privada"): public `/simulate` and
/// `/tx` belong on a read-only relay/replica (`install-sim-replica.sh`), never
/// on the box that also runs consensus.
fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        // NOTE: the UNSPECIFIED address (0.0.0.0 / ::) is deliberately NOT
        // allowed — binding a validator's RPC to it exposes the RPC on EVERY
        // interface (publicly reachable), the opposite of "private".
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        // `is_unique_local` (fc00::/7) is stable only recently; check the
        // high-order bits directly so this compiles on the pinned toolchain.
        IpAddr::V6(v6) => v6.is_loopback() || (v6.octets()[0] & 0xfe) == 0xfc,
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub pubkey_bundle: PublicKeyBundle,
    pub addr: SocketAddr,
    pub stake: u64,
    /// Optional human-readable moniker so wallets can show a named list of
    /// validators to delegate to, instead of asking the user to paste a raw
    /// address. Set in the shared genesis config (every node with the same
    /// genesis sees the same name). `skip_serializing_if` keeps the field OUT
    /// of the JSON entirely when absent, so a config written before names
    /// existed serializes byte-for-byte identically - which means `chain_id`
    /// (a hash over `validators`+`genesis`) is UNCHANGED for existing
    /// networks. A network that does set names folds them into its chain_id,
    /// which is fine: setting names is a genesis-level decision for that
    /// network, made once up front.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// **Dirección de RETIRO / operador (fría)** — tarea #193-B (separación de
    /// roles de clave). Cuando está seteada, las comisiones de fee que gana este
    /// validador (su "valor") se acreditan a ESTA dirección en vez de a su
    /// dirección de CONSENSO (la del `pubkey_bundle`). Así la clave de consenso
    /// (online, en el nodo o en el firmante remoto) firma bloques pero NO
    /// controla los fondos: una fuga de la clave de consenso puede equivocar
    /// (slasheable) pero no puede gastar las ganancias, que viven en una
    /// dirección cuya clave FRÍA el operador guarda offline. Como cambia DÓNDE
    /// se acredita el fee (estado), se pliega en el `chain_id` SÓLO cuando está
    /// seteada (`skip_serializing_if` → un config sin ella serializa idéntico, así
    /// una red existente conserva su `chain_id` EXACTO; una red que la usa es una
    /// red separada, decisión de génesis). Determinista: todos los nodos derivan
    /// el mismo mapeo consenso→retiro del mismo config → sin fork.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal_address: Option<Pubkey>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct GenesisAllocation {
    pub address: Pubkey,
    pub balance: u64,
}

#[derive(Serialize, Deserialize)]
pub struct NodeConfig {
    /// Path to this validator's own keypair file (see
    /// `qchain_crypto::write_keypair_file` / the `qchain keygen` CLI
    /// command).
    pub keypair_path: PathBuf,
    /// P2P listen address - must match this validator's `addr` entry in
    /// `validators` below.
    pub listen_addr: SocketAddr,
    /// JSON-RPC listen address for wallet/client traffic.
    pub rpc_addr: SocketAddr,
    /// The full validator set, self included.
    pub validators: Vec<ValidatorConfig>,
    #[serde(default)]
    pub genesis: Vec<GenesisAllocation>,
    /// Milliseconds between round-advancement attempts.
    #[serde(default = "default_round_interval_ms")]
    pub round_interval_ms: u64,
    /// Directory for a real, disk-persistent `SledStore` (see
    /// `qchain-storage`'s `store.rs` module docs for why `sled` rather
    /// than RocksDB). Omitted (the default) keeps the phase-1 behavior of
    /// an `InMemoryStore` that starts empty on every restart - existing
    /// configs from earlier live tests in this session keep working
    /// unchanged.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    /// RPC URLs of peers this node may state-sync from when it starts with
    /// an empty local store (a fresh join, or an operator recovering a
    /// validator that fell further behind than `DAG_RETENTION_ROUNDS` by
    /// wiping `data_dir` and restarting). Empty (the default) keeps the
    /// original behavior exactly: a fresh node seeds genesis and replays
    /// from round 0. When set, the node fetches a verified account-state
    /// snapshot (`GET /snapshot`) instead of replaying pruned history it
    /// could never fetch. See `main.rs`'s state-sync path.
    #[serde(default)]
    pub state_sync_peers: Vec<String>,
    /// Optional out-of-band trust anchor for state-sync (Cosmos-style
    /// `trust_height`/`trust_hash`): if set, a fetched snapshot is accepted
    /// only if its `(round, merkle_root)` matches this exactly - turning
    /// state-sync from "trust the source peer" (weak subjectivity) into a
    /// fully verified catch-up against a value the operator obtained
    /// independently. Hex-encoded 32-byte root.
    #[serde(default)]
    pub state_sync_trusted_root: Option<String>,
    #[serde(default)]
    pub state_sync_trusted_round: Option<u64>,
    /// **Require the trust anchor for state-sync — tarea #194.** When `false`
    /// (the default, byte-identical to every existing config), state-sync
    /// accepts a snapshot on the weak-subjectivity path (internal consistency +
    /// the cross-peer root cross-check), and the anchor above is an *optional*
    /// hardening. When `true`, a node REFUSES to state-sync unless BOTH
    /// `state_sync_trusted_root` and `state_sync_trusted_round` are set AND the
    /// fetched snapshot matches them exactly — i.e. it never trusts a source
    /// peer's claimed root, only a value the operator pinned out of band. This
    /// is the setting a production/mainnet deployment should turn on (an
    /// operator recovering a validator with a wiped `data_dir` pins the known
    /// `(round, root)` first). It is a **node-LOCAL policy** choice — NOT folded
    /// into `chain_id` (two nodes that differ only in this flag are the same
    /// network; it only changes what THIS node accepts when it syncs), and it
    /// only affects the state-sync path (a node with local state never syncs),
    /// so it's inert for the user's running single-validator network.
    #[serde(default)]
    pub require_state_sync_trust_anchor: bool,
    /// **Opt-in dynamic validator rotation (phase 3.3).** When `false` (the
    /// default, and what every existing config resolves to), the validator set
    /// is fixed for the life of the network — exactly the phase-1/2 behavior,
    /// zero change. When `true`, the *active* consensus committee is re-derived
    /// each epoch from the on-chain validator registry (who has staked and
    /// called `register-validator`): a newcomer with enough self-stake enters
    /// the committee automatically at the next epoch boundary, and one that
    /// unregisters or falls below the minimum leaves — no coordinated redeploy.
    ///
    /// **Hard requirement: every node in a network must set this identically.**
    /// It changes how consensus resolves each round's committee, so a mismatch
    /// would fork the network. It is a genesis-level, network-wide decision.
    /// The `validators` list still seeds epoch 0 (the bootstrap committee) and
    /// governs until/unless a viable active set exists on-chain, so a rotation
    /// network still starts exactly from its genesis validators.
    #[serde(default)]
    pub validator_rotation: bool,
    /// Rounds per epoch — only meaningful when `validator_rotation` is `true`.
    /// The granularity at which the active committee may change. Omitted (the
    /// default) uses the standard `EPOCH_ROUNDS` (1024). Exposed mainly so a
    /// test network can use a small value to cross an epoch boundary quickly;
    /// like `validator_rotation`, it must match across all nodes.
    #[serde(default)]
    pub epoch_rounds: Option<u64>,
    /// State-commitment tree. `false` (default, every existing network) is the
    /// legacy 256-deep sparse Merkle tree - byte-identical to phase-1/2, zero
    /// change. `true` selects the O(log n) path-compressed tree (measured ~34x
    /// faster per account write / ~4x higher apply throughput). It changes the
    /// STATE ROOT, so it is a genesis-level HARD FORK: a network choosing it
    /// needs a fresh genesis and CANNOT be an in-place upgrade of an existing
    /// chain. Like `validator_rotation`, every node in a network must set this
    /// identically (it is folded into `chain_id` below, so a mismatched node
    /// computes a different chain_id and its transactions are rejected rather
    /// than silently forking). The STARK light-client (`/stark_proof` +
    /// `light-client-verify`) works in compressed mode too (v5.1.0): a
    /// compressed node captures receipts carrying O(log n) `CompressedProof`s and
    /// serves `compressed_bindings` verified with
    /// `qchain-stark::verify_batch_bound_to_compressed_state`.
    #[serde(default)]
    pub compressed_state_tree: bool,
    /// On-disk storage engine for the account state (only meaningful with a
    /// `data_dir`). `"redb"` (THE DEFAULT — production/mainnet) selects the modern
    /// pure-Rust `RedbStore` (mmap'd, ACID): it commits each round's account
    /// writes AND the executed-round checkpoint AND the economics counters in ONE
    /// atomic, fsync-durable transaction, so a power loss can never leave half the
    /// state saved (the round and the state can never diverge). It also keeps
    /// memory flat under a write burst (fixing sled 0.34's measured multi-GB flood
    /// RSS). `"sled"` is the legacy/dev engine (sled 0.34) — it does NOT commit
    /// state and round in one transaction, so it is NOT for production; kept only
    /// for back-compat. This is a NODE-LOCAL storage choice — it does NOT change
    /// the state root, wire, consensus, or `chain_id`, so it is NOT a hard fork and
    /// nodes on different engines interoperate. A node on `"redb"` whose `data_dir`
    /// still holds a legacy sled state auto-migrates it once on startup (verified:
    /// the migrated account set must be identical), keeping the sled files as a
    /// backup — so an existing network flips to the atomic engine by just
    /// restarting on this version (the field now defaults to `"redb"`).
    #[serde(default = "default_storage_engine")]
    pub storage_engine: String,
    /// Authenticated P2P transport (task #176). `false` (the default, every
    /// existing network) is the phase-1 unauthenticated transport, byte-
    /// identical to before this field existed. `true` runs a per-connection
    /// mutual ML-DSA handshake (reusing the validator key) before any message
    /// flows, so a non-member can't spoof a validator at the transport layer
    /// and only real validators of THIS network can even connect. It is a
    /// NETWORK-LAYER choice, NOT consensus/state: it is deliberately NOT folded
    /// into `chain_id` (two nodes differing only on this flag have the same
    /// chain_id). But it IS wire-breaking — an auth-on node and an auth-off
    /// node cannot complete a connection — so every node in a network must set
    /// it identically, and turning it on is a COORDINATED cutover (all nodes
    /// together). No genesis change and no state change: an existing chain can
    /// flip it on with a coordinated restart, no fresh genesis needed.
    #[serde(default)]
    pub authenticated_transport: bool,
    /// Opt-in **encrypted** transport, on top of `authenticated_transport`.
    /// `false` (default) is the auth-only handshake (v6.4.x): P2P traffic is
    /// public data and flows in the clear. `true` runs an ML-KEM-768 exchange
    /// inside the same handshake, so every message is AEAD-encrypted
    /// (ChaCha20-Poly1305) and the channel is cryptographically bound into the
    /// signed transcript — adding confidentiality and closing the on-path relay
    /// gap the auth-only handshake documents as its honest limit. Requires
    /// `authenticated_transport` (encryption without authentication is
    /// meaningless — there is no verified peer to bind the channel to). Like the
    /// auth flag it is a NETWORK-LAYER choice, NOT consensus/state: NOT folded
    /// into `chain_id`, but wire-breaking (an encrypting node and a non-
    /// encrypting node can't complete a connection), so it is a COORDINATED
    /// cutover — every node sets it identically. No genesis/state change.
    #[serde(default)]
    pub encrypted_transport: bool,
    /// v7 economics (shares+index staking, per-quanto emission, the 45/45/10 fee
    /// split, the 500 QCH validator bond). `false` (default, every existing
    /// network) is the v6 economics — byte-identical, zero change. `true` is a
    /// genesis-level, network-wide HARD FORK (folded into `chain_id` below): a v7
    /// network needs a fresh genesis and every node must set this identically (a
    /// mismatched node computes a different `chain_id` and its transactions are
    /// rejected rather than silently forking). See `docs/ECONOMIC-REDESIGN.md` and
    /// `qchain-execution`'s `economics_v7`/`staking_v7`/`fees_v7`/`validator_v7`.
    #[serde(default)]
    pub economics_v7: bool,
    /// Per-quanto compounding rate in `QUANTO_RATE_SCALE` (1e18) fixed point,
    /// baked at genesis. Only read when `economics_v7` is on; part of the network
    /// config hash. When omitted the node derives it from the compiled-in
    /// `STAKING_TARGET_APY_BPS`/`DEFAULT_QUANTOS_PER_YEAR` — fine for a
    /// same-platform test network, but a production genesis should bake the exact
    /// integer here (via genesis-build), because the derivation uses f64 (`powf`)
    /// which is not bit-identical across platforms, and the chain only ever runs
    /// the integer `advance_staking_index`.
    #[serde(default)]
    pub quanto_rate_fp: Option<u128>,
    /// Rounds per reward quanto (`economics_v7::DEFAULT_ROUNDS_PER_QUANTO` when
    /// omitted). Only read when `economics_v7` is on; part of the network config
    /// hash. Exposed so a test network can use a small value to cross a quanto
    /// boundary quickly.
    #[serde(default)]
    pub rounds_per_quanto: Option<u64>,
    /// v7 genesis treasury authority — base58 pubkey allowed to sign `Release`
    /// (unlock+send) / `SetAuthority` on the locked treasury account. Only read
    /// when `economics_v7` is on AND `treasury_amount` is set. Part of the network
    /// config hash (a different authority is a different genesis → different chain).
    #[serde(default)]
    pub treasury_authority: Option<String>,
    /// v7 genesis treasury amount, in QCH-units (1 QCH = 1e9). Minted LOCKED into
    /// `TREASURY_ACCOUNT_ID` at genesis (owned by the treasury program; only an
    /// approved multisig operation moves it). Only meaningful with `economics_v7`
    /// plus either `treasury_signers` or `treasury_authority`; part of the network
    /// config hash.
    #[serde(default)]
    pub treasury_amount: Option<u64>,

    /// **MULTISIG treasury** (task #222): the M-of-N set of base58 signer addresses
    /// (cold keys) that control the genesis-locked treasury. When set (non-empty),
    /// the treasury is seeded as an M-of-N multisig instead of a single authority —
    /// no single key can release funds or change control. `treasury_threshold` is
    /// M. Requires `treasury_amount`. Part of the network config hash (folded into
    /// `chain_id`). A network that sets `treasury_authority` instead gets a 1-of-1.
    #[serde(default)]
    pub treasury_signers: Vec<String>,
    /// M — distinct signers required to authorize a treasury operation (e.g. 3 for
    /// a 3-of-5). Only meaningful with `treasury_signers`; 0 defaults to a majority
    /// (`floor(N/2)+1`). Part of the network config hash.
    #[serde(default)]
    pub treasury_threshold: u8,
    /// Mandatory delay (rounds) after a treasury operation reaches its approval
    /// threshold before it may execute (the review window). 0 = no timelock. Part
    /// of the network config hash.
    #[serde(default)]
    pub treasury_timelock_rounds: u64,
    /// Per-operation cap on a single treasury release, in whole QCH (0 = no cap).
    /// Part of the network config hash.
    #[serde(default)]
    pub treasury_max_per_release_qch: u64,
    /// Rolling-window cap on treasury releases, in whole QCH (0 = no cap), over
    /// `treasury_window_rounds`. Part of the network config hash.
    #[serde(default)]
    pub treasury_max_per_window_qch: u64,
    /// Length (rounds) of the rolling release-accounting window (0 = disabled).
    /// Part of the network config hash.
    #[serde(default)]
    pub treasury_window_rounds: u64,
    /// **Threshold hierarchy** (roadmap #17): approvals required for a `SetPolicy`
    /// (política tier) and `SetSigners` (firmantes tier) op, respectively. Each
    /// `>=` its predecessor: `treasury_threshold <= policy <= signers <= N`. `0` =
    /// default to `treasury_threshold` (all tiers equal, the pre-#17 behavior).
    /// Part of the network config hash.
    #[serde(default)]
    pub treasury_policy_threshold: u8,
    #[serde(default)]
    pub treasury_signers_threshold: u8,
    /// **Op expiration** (roadmap #17): a pending treasury op is pruned (becomes
    /// non-executable) this many rounds after being proposed. `0` = no expiry (the
    /// pre-#17 default). Must exceed `treasury_timelock_rounds`. Part of the config hash.
    #[serde(default)]
    pub treasury_op_expiry_rounds: u64,
    /// **Administrative-fee wallet** (task #222): base58 destination of the 10%
    /// admin fee share, configured at GENESIS instead of a hidden compile-time
    /// constant. When set it overrides `ids::ADMIN_FEE_WALLET` and is folded into
    /// `chain_id`. Point it at the multisig treasury (or any multisig-controlled
    /// address) so administrative revenue is multisig-protected too. Absent = the
    /// legacy constant (byte-identical for existing networks).
    #[serde(default)]
    pub admin_fee_wallet: Option<String>,

    /// **HARD-CAP supply model** (SPEC §5, task #221 — the "definitive supply"
    /// decision). When `true` (only meaningful with `economics_v7`), staking
    /// emission is DRAWN from the pre-minted `emission_reserve_qch` instead of
    /// minted, so total supply can NEVER exceed the genesis total (the ≤100M cap).
    /// The node ALSO refuses to start if the genesis supply exceeds the cap. Default
    /// `false` = the inflationary v7 model (emission minted, no absolute max). Folded
    /// into `chain_id` when enabled — a fresh-genesis, network-wide decision every
    /// node must set identically. See `docs/ECONOMIC-REDESIGN.md`.
    #[serde(default)]
    pub hard_cap_supply: bool,
    /// The hard cap in whole QCH (default `economics_v7::MAX_SUPPLY_QCH` = 100M when
    /// `hard_cap_supply` is on). The genesis gate enforces `Σ genesis balances ≤`
    /// this. Only meaningful with `hard_cap_supply`; part of the network config hash.
    #[serde(default)]
    pub supply_cap_qch: Option<u64>,
    /// Pre-minted **emission reserve** in whole QCH (default 0), seeded LOCKED into
    /// `EMISSION_RESERVE_ID` at genesis under the hard-cap model. This funds staking
    /// yield: each quanto's emission is drawn from here (a transfer, never a mint).
    /// It is part of the ≤ cap split (treasury + reserve + bonds + allocations ≤
    /// cap). When it empties, staking yield falls to fee income only. Only meaningful
    /// with `economics_v7` + `hard_cap_supply`; part of the network config hash.
    #[serde(default)]
    pub emission_reserve_qch: Option<u64>,
    /// Seed the on-chain SCHEMA MANIFEST (roadmap #19). When `true`, genesis seeds
    /// `SCHEMA_MANIFEST_ID` with the canonical `{singleton -> schema_version}` map
    /// and the node VERIFIES every critical singleton's actual format against the
    /// declared version at startup (fail-loud on a mismatch), instead of relying on
    /// trial-Borsh alone. Default `false` = byte-identical to a pre-#19 network (no
    /// manifest account, no state-root change, exact same `chain_id`). Folded into
    /// `chain_id` only when enabled — a fresh-genesis, network-wide decision every
    /// node must set identically. See `docs/SCHEMA-VERSIONS.md`.
    #[serde(default)]
    pub explicit_schema_versions: bool,
    /// Per-IP RPC rate limit (task #196, QCH-S6): max requests any single client
    /// IP may make in a 10-second window before it's temporarily banned (60 s).
    /// `None`/`0` (the default, and what every existing config resolves to)
    /// disables it entirely — zero overhead, byte-identical behavior, no
    /// interference with a loopback-private RPC or the operator's own tools. Set
    /// it only when EXPOSING the RPC publicly (`--rpc-public`), where a per-IP
    /// cap + temp ban blunts an unauthenticated request flood. It is a
    /// node-LOCAL policy: not folded into `chain_id`, no consensus/wire impact.
    #[serde(default)]
    pub rpc_rate_limit_per_10s: Option<u32>,

    /// Per-IP rate limit **for `POST /simulate` specifically** (QCH-SIMULATE DoS).
    /// `/simulate` is the single most expensive unauthenticated endpoint — each
    /// call runs a hybrid PQC signature verify and can compile+run WASM, and only
    /// a small pool of concurrent simulations exists — so unlike the general
    /// `rpc_rate_limit_per_10s` (opt-in), this limiter is **MANDATORY whenever the
    /// RPC is PUBLIC** (`rpc_addr` non-loopback): the node forces it on with a safe
    /// default and never honours `None`/`0` on a public bind (a value below the
    /// floor is raised to it). On a loopback-private RPC (the default) it stays
    /// opt-in — the operator's own box, negligible risk. Recommended 5–10 per IP
    /// per 10 s. Node-LOCAL policy: not folded into `chain_id`, no consensus/wire
    /// impact. (Per-txid coalescing and the concurrent-WASM cap are always on; see
    /// `rpc.rs`/`engine.rs`.)
    #[serde(default)]
    pub simulate_rate_limit_per_10s: Option<u32>,

    /// Per-IP rate limit **for `POST /tx` specifically** (task #210). `/tx`
    /// receives a SIGNED transaction and runs a hybrid PQC verify per call — the
    /// second-most-expensive unauthenticated endpoint — so like
    /// `simulate_rate_limit_per_10s` this limiter is **MANDATORY whenever the RPC
    /// is reachable by remote clients** (a non-loopback `rpc_addr`, OR a loopback
    /// bind declared behind a trusted proxy): the node forces it on with a safe
    /// default and never honours `None`/`0` on a public bind (a too-low value is
    /// raised to the floor). On a genuinely private loopback RPC it stays opt-in.
    /// A per-txid resubmission cap + a global/per-payer admission quota + a
    /// concurrent-verify cap are ALWAYS on regardless (see `rpc.rs`/`engine.rs`).
    /// Recommended ~10–16 per IP per 10 s. Node-LOCAL: not folded into `chain_id`,
    /// no consensus/wire impact.
    #[serde(default)]
    pub tx_rate_limit_per_10s: Option<u32>,

    /// Set to `true` when this RPC sits behind a TRUSTED reverse proxy on the SAME
    /// host (the Cloudflare named/quick tunnel `cloudflared`, or a local
    /// nginx/Caddy) — i.e. `rpc_addr` stays on loopback and the public entrypoint is
    /// the proxy. Two effects: (1) the mandatory `/simulate` limiter is treated as
    /// PUBLIC and forced on even though `rpc_addr` is loopback (otherwise a tunnelled
    /// RPC — the project's own recommended exposure — would ship with NO `/simulate`
    /// protection); (2) the per-client IP is read from the `X-Forwarded-For` header
    /// **only when the direct TCP peer is loopback** (the local proxy), so rate
    /// limiting meters the real client instead of collapsing the whole internet into
    /// the single proxy IP. Trusting `X-Forwarded-For` is gated on the loopback-peer
    /// check so a client hitting a DIRECT public bind can never spoof it. Leave
    /// `false` for a direct bind or a truly private loopback RPC. Node-LOCAL; not in
    /// `chain_id`.
    #[serde(default)]
    pub rpc_behind_trusted_proxy: bool,

    /// **Firmante remoto / HSM de la clave de consenso** (tarea #193). Cuando es
    /// `Some("<host:puerto>")`, la clave que firma bloques NO se lee de
    /// `keypair_path` ni vive en este proceso: el nodo se conecta a un
    /// `qchain-remote-signer` (proceso aparte / HSM) que sostiene la clave y
    /// firma por socket. `None` (el default, y lo que resuelve todo config
    /// existente) = clave EN-PROCESO leída de `keypair_path`, byte-idéntico a
    /// antes. Es una elección node-LOCAL de operación (qué firmante sirve la
    /// MISMA identidad): **NO se pliega en `chain_id`** — un nodo con la clave
    /// local y otro con la misma clave en un firmante remoto son el MISMO
    /// validador, sin cambio de red/consenso/wire.
    #[serde(default)]
    pub remote_signer: Option<String>,

    /// **Token de autenticación del cliente del firmante remoto (#4.2, auditoría
    /// v8.6.13).** Ruta a un archivo (0600) con el token pre-compartido que
    /// autentica ESTE nodo ante el `qchain-remote-signer` por challenge-response:
    /// el daemon manda un nonce fresco y el nodo prueba que conoce el token antes
    /// de que se firme nada. El MISMO archivo lo lee el daemon
    /// (`--auth-token-file`). `None` (el default) = sin token (sólo aceptable en
    /// loopback/UDS de desarrollo); el perfil **mainnet lo EXIGE** cuando
    /// `remote_signer` está seteado, cerrando "cualquier proceso local puede pedir
    /// firmas sin autenticarse". Node-LOCAL, NO se pliega en `chain_id`.
    #[serde(default)]
    pub remote_signer_auth_token_path: Option<String>,

    /// **Clave de RED (P2P) SEPARADA de la clave de consenso (auditoría #1 del
    /// programa de gestión de claves).** Ruta a un keypair distinto que firma el
    /// handshake P2P por-conexión. Al arrancar, la clave de CONSENSO emite UNA sola
    /// vez un certificado de delegación tipado (`NETWORK_KEY_CERT_V1 ‖ chain_id ‖
    /// validator_id ‖ network_addr`) que ata esta `network_key` a la identidad del
    /// validador; el cert viaja en el handshake y los pares lo verifican contra el
    /// bundle de consenso que el nodo anuncia. A partir de ahí la clave de consenso
    /// NUNCA firma un transcript de handshake — una fuga de la clave de red permite
    /// impersonar la identidad P2P del nodo pero **NO firmar bloques/votos/certs**
    /// (que sólo la clave de consenso firma). Si el archivo no existe se GENERA y
    /// se escribe (0600). `None` (el default, y lo que resuelve todo config
    /// existente) = legacy: el handshake lo firma la clave de consenso (byte-idéntico
    /// al comportamiento previo, interopera con un par legacy). Es node-LOCAL: **NO
    /// se pliega en `chain_id`** (no cambia consenso/estado/wire), y un par con
    /// clave de red separada interopera con un par legacy durante el rollout.
    #[serde(default)]
    pub network_keypair_path: Option<String>,

    /// **Postura de MAINNET (obligatorio auth + cifrado P2P).** `false` (el
    /// default, y lo que resuelve todo config existente) no impone nada — un
    /// testnet corre exactamente como antes. `true` hace OBLIGATORIOS al arrancar
    /// tanto `authenticated_transport` (handshake ML-DSA por conexión) como
    /// `encrypted_transport` (ML-KEM-768 + ChaCha20-Poly1305): el nodo SE DETIENE
    /// con un error claro si `mainnet` está activo pero cualquiera de los dos
    /// falta. Así la autenticación y el cifrado post-cuánticos del transporte
    /// dejan de ser opt-in y pasan a ser un requisito duro para producción, sin
    /// cambiar el default del testnet del usuario. Es una elección node-LOCAL de
    /// operación: **NO se pliega en `chain_id`** (no cambia consenso/estado/wire),
    /// aunque para que la red arranque TODOS los nodos deben tener auth+cifrado
    /// (que ya es un cutover coordinado).
    #[serde(default)]
    pub mainnet: bool,

    /// **Perfil de red obligatorio (`"mainnet"` / `"testnet"`).** El `mainnet: bool`
    /// de arriba sólo exige auth+cifrado; este campo es la POSTURA COMPLETA de
    /// producción: cuando vale `"mainnet"`, el nodo SE NIEGA A ARRANCAR
    /// (`validate_network_profile` fail-stop) si falta CUALQUIERA de las
    /// protecciones duras — `data_dir`, almacenamiento transaccional (`redb`),
    /// transporte P2P autenticado, transporte cifrado, firmante remoto, RPC del
    /// validador en red privada (loopback/RFC1918, nunca ruteable), trust anchor
    /// de state-sync, límites de RPC explícitos (general+`/simulate`+`/tx`),
    /// parámetros económicos explícitos (v7 con la tasa BAKED, no derivada por
    /// f64), y el fingerprint de red que TODOS los nodos deben compartir (se loguea
    /// al arrancar para comparar entre nodos → 'configuración idéntica entre
    /// nodos'). `None` (el default) o `"testnet"` no imponen nada — un testnet
    /// corre exactamente como antes, byte-idéntico. Un valor desconocido se rechaza
    /// al cargar (fail-loud ante un typo). Es una elección node-LOCAL de operación:
    /// **NO se pliega en `chain_id`** (no cambia consenso/estado/wire); acumula
    /// TODOS los faltantes en un solo error para arreglarlos en una pasada.
    #[serde(default)]
    pub network_profile: Option<String>,

    /// **Servir un checkpoint de estado firmado por quórum en `/snapshot/meta`**
    /// (tarea #212). `false` (default) = byte-idéntico: el meta no lleva
    /// checkpoint y el state-sync usa el camino previo (consistencia interna +
    /// cross-check + trust anchor opcional). `true` = el nodo self-firma su
    /// `(chain_id, round, root)` para que un nodo que se sincroniza UNA las
    /// firmas de un quórum de peers confirmantes y AUTENTIQUE la raíz sin confiar
    /// en el par. Se fuerza en el perfil mainnet. Node-LOCAL (no toca
    /// consenso/estado/wire de tx).
    #[serde(default)]
    pub state_checkpoints: bool,

    /// **Mínimo de peers que deben confirmar el MISMO `(round, root, chain_id,
    /// comité)` antes de aceptar un snapshot** (tarea #212). `None`/`0`/`1`
    /// (default) = 1 (comportamiento previo: basta un par, con el cross-check
    /// anti-fork). El perfil mainnet FUERZA `>= 2`. Sube la barra: un solo par
    /// malicioso no basta; varios independientes deben coincidir.
    #[serde(default)]
    pub state_sync_min_confirmations: Option<u32>,

    /// **Emergency governance guardian set** (task #213). Base58 pubkeys that
    /// can, at `governance_guardian_threshold`-of-N, pause/unpause governance
    /// `Execute` on-chain — an emergency brake on any rushed economic change,
    /// structurally unable to move funds. Seeded into `EMERGENCY_ACCOUNT_ID` at
    /// genesis. Empty (default) = the feature is inert. Because it is genesis
    /// STATE that varies by operator config, it is folded into `chain_id` when
    /// set (a network with guardians is a distinct, deliberately-chosen
    /// network) — so an existing network without it keeps its `chain_id`
    /// exactly, and every node of a guarded network must configure the SAME set
    /// or compute a different chain_id.
    #[serde(default)]
    pub governance_guardians: Vec<String>,
    /// Approvals required to flip the emergency pause. Clamped to
    /// `1..=guardians.len()` at genesis; ignored when there are no guardians.
    #[serde(default)]
    pub governance_guardian_threshold: u8,
}

impl NodeConfig {
    /// Parses `governance_guardians` (base58) into pubkeys. Invalid entries are
    /// a hard genesis error — a mis-typed guardian must fail loudly, not be
    /// silently dropped (which could weaken the multisig).
    pub fn guardian_pubkeys(&self) -> anyhow::Result<Vec<Pubkey>> {
        self.governance_guardians
            .iter()
            .map(|s| s.trim().parse::<Pubkey>().map_err(|e| anyhow::anyhow!("invalid governance guardian pubkey {s:?}: {e}")))
            .collect()
    }

    /// Whether to serve/produce quorum-signable state checkpoints (#212): the
    /// explicit flag, OR forced on by the mainnet profile.
    pub fn state_checkpoints(&self) -> bool {
        self.state_checkpoints || self.is_mainnet_profile()
    }

    /// Minimum distinct peers that must confirm the same checkpoint before a
    /// snapshot is accepted (#212). Floor of 1; mainnet raises the floor to 2.
    pub fn state_sync_min_confirmations(&self) -> u32 {
        let base = self.state_sync_min_confirmations.unwrap_or(1).max(1);
        if self.is_mainnet_profile() { base.max(2) } else { base }
    }
}

fn default_storage_engine() -> String {
    // redb is the production/mainnet default: it commits the round's account
    // writes AND the executed-round checkpoint in ONE atomic, fsync-durable
    // transaction (see `RedbStore`), so a power loss can never leave half the
    // state saved. sled 0.34 is NOT used as the production default — it does not
    // commit state and round in one transaction and retains multi-GB under a
    // write burst. An existing config without this field, and a data_dir still
    // holding a legacy sled state, auto-migrates to redb once on startup
    // (verified: the migrated account set must be identical; sled files kept).
    "redb".to_string()
}

fn default_round_interval_ms() -> u64 {
    500
}

impl NodeConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path)?;
        let cfg: NodeConfig = serde_json::from_slice(&bytes)?;
        // Reject a self-inflicted misconfig early with a clear message instead of
        // a cryptic panic later: `tokio::time::interval(Duration::from_millis(0))`
        // panics ("interval period must be non-zero") at node startup.
        if cfg.round_interval_ms == 0 {
            anyhow::bail!("round_interval_ms must be greater than 0");
        }
        Ok(cfg)
    }

    /// A real, live-confirmed cross-network replay gap this closes (see
    /// `project-lessons-learned` and `qchain_core::Message::chain_id`'s doc
    /// comment): the hash of this network's own genesis data - only
    /// `validators`/`genesis`, deliberately excluding per-validator fields
    /// like `listen_addr`/`rpc_addr`/`keypair_path`/`round_interval_ms`/
    /// `data_dir` that legitimately differ between validators of the exact
    /// same network. Every validator loading the same genesis config
    /// computes the identical `chain_id` independently - no coordination
    /// round-trip needed, same principle `qchain-genesis-build` already
    /// relies on for producing per-validator configs from one shared
    /// manifest.
    pub fn chain_id(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut bytes = serde_json::to_vec(&(&self.validators, &self.genesis)).expect("genesis data always serializes");
        // Fold the compressed-state-tree choice in ONLY when it is enabled, so an
        // existing (legacy, `false`) network's chain_id is byte-identical to
        // before this field existed - its live transactions keep verifying. A
        // compressed network gets a distinct chain_id (it is a genuinely
        // separate, hard-forked network, and a legacy node must not accept its
        // transactions or vice versa).
        if self.compressed_state_tree {
            bytes.extend_from_slice(b"compressed-state-tree-v1");
        }
        // Same "fold in only when enabled" discipline: a v6 (default, `false`)
        // network's chain_id is byte-identical to before this field existed. A v7
        // network gets a distinct chain_id — it is a genuinely separate,
        // hard-forked network (fresh genesis, §15), and a v6 node must not accept
        // its transactions or vice versa. The resolved rate + rounds are folded in
        // too (SPEC §17: the economic parameters are part of the network config
        // hash), so a 12%-APY network and an 8%-APY one are distinct chains.
        if self.economics_v7 {
            bytes.extend_from_slice(b"economics-v7-45-45-10");
            bytes.extend_from_slice(&self.quanto_rate_fp().to_le_bytes());
            bytes.extend_from_slice(&self.rounds_per_quanto().to_le_bytes());
            // The genesis treasury (locked supply + its release authority) is part
            // of the genesis state, so it folds into the network identity: a
            // different authority or amount is a genuinely different genesis. Only
            // when a treasury is actually configured, so a v7 network without one
            // keeps its chain_id unchanged.
            if let (Some(auth), Some(amt)) = (&self.treasury_authority, self.treasury_amount) {
                bytes.extend_from_slice(b"treasury-v7");
                bytes.extend_from_slice(auth.as_bytes());
                bytes.extend_from_slice(&amt.to_le_bytes());
            }
            // Multisig treasury (#222): the signer set + threshold + timelock +
            // limits are all part of the genesis identity, folded in ONLY when a
            // multisig is configured (a single-authority or no-treasury network keeps
            // its chain_id unchanged).
            if !self.treasury_signers.is_empty() {
                bytes.extend_from_slice(b"treasury-multisig-v1");
                for s in &self.treasury_signers {
                    bytes.extend_from_slice(s.trim().as_bytes());
                    bytes.push(0);
                }
                bytes.push(self.treasury_threshold);
                bytes.extend_from_slice(&self.treasury_timelock_rounds.to_le_bytes());
                bytes.extend_from_slice(&self.treasury_max_per_release_qch.to_le_bytes());
                bytes.extend_from_slice(&self.treasury_max_per_window_qch.to_le_bytes());
                bytes.extend_from_slice(&self.treasury_window_rounds.to_le_bytes());
                // Threshold hierarchy + op-expiry (roadmap #17): folded ONLY when set,
                // so an existing multisig network that doesn't use the tiers/expiry
                // keeps its exact chain_id (byte-identical).
                if self.treasury_policy_threshold != 0 || self.treasury_signers_threshold != 0 || self.treasury_op_expiry_rounds != 0 {
                    bytes.extend_from_slice(b"treasury-tiers-v1");
                    bytes.push(self.treasury_policy_threshold);
                    bytes.push(self.treasury_signers_threshold);
                    bytes.extend_from_slice(&self.treasury_op_expiry_rounds.to_le_bytes());
                }
            }
            // The administrative-fee wallet is genesis state (it changes where the
            // 10% admin fee is credited = consensus), folded in only when overridden.
            if let Some(admin) = &self.admin_fee_wallet {
                bytes.extend_from_slice(b"admin-fee-wallet-v1");
                bytes.extend_from_slice(admin.trim().as_bytes());
            }
            // Hard-cap supply (§5, #221): the cap + the pre-minted emission reserve
            // are part of the genesis economics identity, so a hard-cap network is a
            // distinct chain. Only folded when enabled, so an inflationary v7 network
            // keeps its chain_id unchanged.
            if self.hard_cap_supply {
                bytes.extend_from_slice(b"hard-cap-supply-v1");
                bytes.extend_from_slice(&self.supply_cap_atoms().to_le_bytes());
                bytes.extend_from_slice(&self.emission_reserve_atoms().to_le_bytes());
            }
        }
        // Explicit schema manifest (roadmap #19): seeding the SCHEMA_MANIFEST
        // singleton adds a genesis account (a new Merkle leaf) → a different
        // genesis state root, so it is part of the network identity. Folded ONLY
        // when enabled, so a network that doesn't opt in keeps its exact chain_id
        // byte-identical. Independent of economics_v7 (any network may opt in).
        if self.explicit_schema_versions {
            bytes.extend_from_slice(b"explicit-schema-versions-v1");
        }
        // Emergency governance guardians (task #213) are genesis STATE that
        // varies by operator config, so they fold into the network identity —
        // but ONLY when configured, so a network without guardians keeps its
        // chain_id byte-identical to before this feature. Fold the (already
        // parsed & ordered) raw base58 strings + threshold; a mismatched
        // guardian set on any node yields a different chain_id (rejected txs),
        // never a silent divergence in who can pause.
        if !self.governance_guardians.is_empty() {
            bytes.extend_from_slice(b"governance-guardians-v1");
            for g in &self.governance_guardians {
                bytes.extend_from_slice(g.trim().as_bytes());
                bytes.push(0);
            }
            bytes.push(self.governance_guardian_threshold);
        }
        Sha3_256::digest(bytes).into()
    }

    /// The resolved per-quanto compounding rate: the genesis-baked config value,
    /// or (when omitted) derived from the compiled-in APY target. The derivation
    /// is off-chain (f64); see `quanto_rate_fp`'s field doc for the determinism
    /// caveat. Only meaningful when `economics_v7` is on.
    pub fn quanto_rate_fp(&self) -> u128 {
        self.quanto_rate_fp.unwrap_or_else(|| {
            qchain_execution::economics_v7::derive_quanto_rate_fp(
                qchain_execution::economics_v7::STAKING_TARGET_APY_BPS,
                qchain_execution::economics_v7::DEFAULT_QUANTOS_PER_YEAR,
            )
        })
    }

    /// The resolved rounds-per-quanto (config override or the standard default).
    /// Only meaningful when `economics_v7` is on.
    pub fn rounds_per_quanto(&self) -> u64 {
        self.rounds_per_quanto.unwrap_or(qchain_execution::economics_v7::DEFAULT_ROUNDS_PER_QUANTO)
    }

    /// The resolved hard supply cap in ATOMS (config `supply_cap_qch` × 1e9, or the
    /// canonical 100M default). Only meaningful when `hard_cap_supply` is on; the
    /// genesis gate enforces `Σ genesis balances ≤` this. `u128` because the total
    /// economy is summed in `u128`; the value itself stays well below `u64::MAX`.
    pub fn supply_cap_atoms(&self) -> u128 {
        match self.supply_cap_qch {
            Some(qch) => qch as u128 * qchain_core::UNITS_PER_QCH as u128,
            None => qchain_execution::economics_v7::MAX_SUPPLY_ATOMS,
        }
    }

    /// The resolved pre-minted emission reserve in ATOMS (config
    /// `emission_reserve_qch` × 1e9, or 0). Seeded into `EMISSION_RESERVE_ID` at
    /// genesis under the hard-cap model. Saturating so a nonsensical huge config
    /// can't wrap; the genesis gate then rejects it for exceeding the cap.
    pub fn emission_reserve_atoms(&self) -> u64 {
        self.emission_reserve_qch.unwrap_or(0).saturating_mul(qchain_core::UNITS_PER_QCH)
    }

    /// The resolved MULTISIG treasury state (task #222), or `None` when no multisig
    /// is configured (the caller then falls back to `treasury_authority` for a
    /// 1-of-1, or seeds no treasury). Parses the base58 signers, resolves the
    /// threshold (0 → majority `floor(N/2)+1`), and converts the QCH limits to
    /// atoms. Only meaningful with `economics_v7`.
    pub fn treasury_multisig_state(&self) -> anyhow::Result<Option<qchain_execution::treasury_v7::TreasuryState>> {
        if self.treasury_signers.is_empty() {
            return Ok(None);
        }
        let mut signers = Vec::with_capacity(self.treasury_signers.len());
        for s in &self.treasury_signers {
            signers.push(
                s.trim()
                    .parse::<qchain_crypto::Pubkey>()
                    .map_err(|e| anyhow::anyhow!("treasury_signers entry '{s}' is not a valid base58 address: {e}"))?,
            );
        }
        let n = signers.len();
        let threshold = if self.treasury_threshold == 0 { (n / 2 + 1) as u8 } else { self.treasury_threshold };
        qchain_execution::treasury_v7::validate_signer_set(&signers, threshold)
            .map_err(|e| anyhow::anyhow!("invalid treasury signer set: {e:?}"))?;
        // Threshold hierarchy (roadmap #17): 0 = default to the base threshold (all
        // tiers equal = pre-#17 behavior). Validated below.
        let policy_threshold = if self.treasury_policy_threshold == 0 { threshold } else { self.treasury_policy_threshold };
        let signers_threshold = if self.treasury_signers_threshold == 0 { threshold } else { self.treasury_signers_threshold };
        if self.treasury_op_expiry_rounds > 0 && self.treasury_op_expiry_rounds <= self.treasury_timelock_rounds {
            return Err(anyhow::anyhow!("treasury_op_expiry_rounds must exceed treasury_timelock_rounds (else an op expires before it can execute)"));
        }
        let units = qchain_core::UNITS_PER_QCH;
        let state = qchain_execution::treasury_v7::TreasuryState {
            signers,
            threshold,
            timelock_rounds: self.treasury_timelock_rounds,
            max_per_release: self.treasury_max_per_release_qch.saturating_mul(units),
            max_per_window: self.treasury_max_per_window_qch.saturating_mul(units),
            window_rounds: self.treasury_window_rounds,
            window_start_round: 0,
            released_in_window: 0,
            next_op_id: 0,
            pending: Vec::new(),
            policy_threshold,
            signers_threshold,
            op_expiry_rounds: self.treasury_op_expiry_rounds,
        };
        qchain_execution::treasury_v7::validate_thresholds(&state)
            .map_err(|e| anyhow::anyhow!("invalid treasury threshold hierarchy: {e:?}"))?;
        Ok(Some(state))
    }

    /// The resolved administrative-fee wallet (task #222): the configured override
    /// parsed to a `Pubkey`, or `None` = use the compiled-in `ids::ADMIN_FEE_WALLET`.
    pub fn admin_fee_wallet_pubkey(&self) -> anyhow::Result<Option<qchain_crypto::Pubkey>> {
        match &self.admin_fee_wallet {
            None => Ok(None),
            Some(s) => Ok(Some(
                s.trim()
                    .parse::<qchain_crypto::Pubkey>()
                    .map_err(|e| anyhow::anyhow!("admin_fee_wallet '{s}' is not a valid base58 address: {e}"))?,
            )),
        }
    }

    /// Rounds per epoch for validator rotation (the config override, or the
    /// standard `EPOCH_ROUNDS` default). Only meaningful when
    /// `validator_rotation` is set.
    pub fn epoch_rounds(&self) -> u64 {
        self.epoch_rounds.unwrap_or(qchain_consensus::schedule::DEFAULT_EPOCH_ROUNDS)
    }

    /// Enforce the MAINNET transport requirement (task #208): when `mainnet` is
    /// set, both authenticated (ML-DSA) AND encrypted (ML-KEM + ChaCha20-Poly1305)
    /// P2P transport are mandatory. Returns an error naming exactly what is
    /// missing so the node can fail-stop at startup instead of silently running a
    /// mainnet with an unauthenticated/plaintext transport. A no-op when `mainnet`
    /// is false (every existing config), so a testnet is unaffected.
    pub fn validate_mainnet_transport(&self) -> anyhow::Result<()> {
        if self.mainnet && !(self.authenticated_transport && self.encrypted_transport) {
            anyhow::bail!(
                "mainnet=true requires BOTH authenticated_transport (ML-DSA) AND encrypted_transport (ML-KEM + ChaCha20-Poly1305) — \
                 got authenticated_transport={}, encrypted_transport={}. Post-quantum P2P authentication and encryption are mandatory for mainnet.",
                self.authenticated_transport,
                self.encrypted_transport,
            );
        }
        Ok(())
    }

    /// `true` when this node is configured for the MAINNET profile — either the
    /// explicit `network_profile: "mainnet"` (the full posture) or the legacy
    /// `mainnet: true` transport flag. A `"testnet"`/`None` profile is not mainnet.
    pub fn is_mainnet_profile(&self) -> bool {
        matches!(self.network_profile.as_deref(), Some("mainnet")) || self.mainnet
    }

    /// **Perfil de red obligatorio — tarea #211.** Cuando el nodo corre bajo el
    /// perfil `"mainnet"` (o el legacy `mainnet: true`), esto EXIGE que TODAS las
    /// protecciones duras de producción estén presentes y hace fail-stop al
    /// arrancar si falta cualquiera — **acumulando TODAS las faltas en un solo
    /// error** para que un operador las arregle en una pasada, en vez de rebotar
    /// una por una. Un perfil `None`/`"testnet"` es un no-op → un testnet corre
    /// exactamente como antes (byte-idéntico). También valida que el string de
    /// perfil sea uno conocido (fail-loud ante un typo como `"mainet"`).
    ///
    /// Las 11 protecciones exigidas (el pedido del usuario, sin omitir nada):
    /// 1. `data_dir` — estado persistente en disco (sin `data_dir` el nodo corre
    ///    in-memory y pierde todo al reiniciar).
    /// 2. Almacenamiento transaccional — `storage_engine == "redb"` (commit atómico
    ///    estado+ronda+economía; `sled` NO commitea en una transacción → prohibido).
    /// 3. Transporte P2P autenticado — `authenticated_transport`.
    /// 4. Transporte cifrado — `encrypted_transport`.
    /// 5. Firmante remoto — `remote_signer` (la clave de consenso fuera del proceso).
    /// 6. RPC del validador en red privada — `rpc_addr` loopback/RFC1918, nunca
    ///    ruteable (el `/simulate`+`/tx` público va en un relay/réplica read-only).
    /// 7. Trust anchor para state-sync — `require_state_sync_trust_anchor`, y si hay
    ///    `state_sync_peers` entonces el `(round, root)` pinneado debe estar seteado.
    /// 8. Límites de RPC — los tres explícitos y > 0 (`rpc_rate_limit_per_10s`,
    ///    `simulate_rate_limit_per_10s`, `tx_rate_limit_per_10s`). Los límites de
    ///    P2P (conexión/IP/timeouts/cuotas) son SIEMPRE activos por construcción.
    /// 9. Parámetros económicos explícitos — `economics_v7` con la tasa BAKED
    ///    (`quanto_rate_fp`, determinista cross-plataforma, no f64) y
    ///    `rounds_per_quanto` fijado.
    /// 10. Configuración idéntica entre nodos — se loguea `network_fingerprint()`
    ///     al arrancar; todos los nodos deben compartirlo (comparación cross-nodo).
    /// 11. TLS en wallet/servicios públicos — el RPC del validador NO se expone
    ///     directo (req 6); la wallet exige TLS/proxy en su propio perfil mainnet
    ///     (ver `qchain-wallet`), y el nodo lo documenta.
    pub fn validate_network_profile(&self) -> anyhow::Result<()> {
        // Reject an unknown profile string outright (a typo must fail loud, not
        // silently fall back to testnet and ship a mainnet with no protections).
        if let Some(p) = self.network_profile.as_deref() {
            if p != "mainnet" && p != "testnet" {
                anyhow::bail!(
                    "network_profile {p:?} is not a known profile — use \"mainnet\" or \"testnet\" (or omit the field for a testnet)."
                );
            }
        }
        if !self.is_mainnet_profile() {
            return Ok(());
        }

        let mut missing: Vec<String> = Vec::new();

        // 1. data_dir (persistent state).
        if self.data_dir.is_none() {
            missing.push("data_dir: set a persistent state directory (an in-memory store loses all state on restart)".into());
        }
        // 2. transactional storage.
        if self.storage_engine != "redb" {
            missing.push(format!(
                "storage_engine: must be \"redb\" (atomic state+round+economics commit), got {:?} — \"sled\" is dev-only and not transactional",
                self.storage_engine
            ));
        }
        // 3. authenticated P2P transport.
        if !self.authenticated_transport {
            missing.push("authenticated_transport: set true (per-connection ML-DSA handshake) — mandatory P2P authentication".into());
        }
        // 4. encrypted P2P transport.
        if !self.encrypted_transport {
            missing.push("encrypted_transport: set true (ML-KEM-768 + ChaCha20-Poly1305) — mandatory P2P confidentiality".into());
        }
        // 5. remote signer (consensus key out of process).
        if self.remote_signer.is_none() {
            missing.push("remote_signer: set \"host:port\" of a qchain-remote-signer/HSM so the block-signing key is NOT in the node process".into());
        } else if let Some(ep) = &self.remote_signer {
            // Audit v8.6.13 #4.2 (CERRADO): the signer socket now authenticates the
            // CLIENT via a pre-shared token challenge-response, and supports a Unix
            // socket (OS-permission isolation). A mainnet validator must (a) reach
            // it over LOOPBACK TCP or a UNIX socket (never a public/LAN TCP
            // address), AND (b) set the auth token — so no local process can
            // request signatures without proving it knows the token. Both are
            // fail-closed.
            let is_unix = qchain_remote_signer::unix_endpoint_path(ep).is_some();
            let host_is_loopback = ep
                .rsplit_once(':')
                .and_then(|(h, _)| h.trim_matches(|c| c == '[' || c == ']').parse::<std::net::IpAddr>().ok())
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
            if !is_unix && !host_is_loopback {
                missing.push(format!(
                    "remote_signer: {ep} must be a LOOPBACK TCP endpoint (e.g. 127.0.0.1:9200) or a UNIX socket (e.g. unix:/run/qchain/signer.sock) on mainnet — a public/LAN address is an exposed signing oracle for the consensus key"
                ));
            }
            if self.remote_signer_auth_token_path.is_none() {
                missing.push(
                    "remote_signer_auth_token_path: set the client auth token file (0600) — on mainnet the signer socket must authenticate the client (challenge-response), not just rely on loopback/OS perms, so no local process can request signatures without the token".into(),
                );
            }
        }
        // 6. validator RPC on a private network.
        if !is_private_or_loopback(self.rpc_addr.ip()) {
            missing.push(format!(
                "rpc_addr: {} is a publicly routable address — a mainnet validator's mutating RPC must bind a private/loopback address; expose a read-only relay/replica (install-sim-replica.sh) for public /simulate and /tx instead",
                self.rpc_addr
            ));
        }
        // 7. trust anchor for state-sync.
        if !self.require_state_sync_trust_anchor {
            missing.push("require_state_sync_trust_anchor: set true — never trust a source peer's claimed root, only a pinned (round, root)".into());
        }
        if !self.state_sync_peers.is_empty()
            && (self.state_sync_trusted_root.is_none() || self.state_sync_trusted_round.is_none())
        {
            missing.push("state_sync_trusted_root + state_sync_trusted_round: pin the out-of-band (round, root) — state_sync_peers is set but the trust anchor is incomplete".into());
        }
        // 8. explicit RPC limits (P2P limits are always-on by construction).
        for (name, v) in [
            ("rpc_rate_limit_per_10s", self.rpc_rate_limit_per_10s),
            ("simulate_rate_limit_per_10s", self.simulate_rate_limit_per_10s),
            ("tx_rate_limit_per_10s", self.tx_rate_limit_per_10s),
        ] {
            if v.unwrap_or(0) == 0 {
                missing.push(format!("{name}: set an explicit positive per-IP rate limit (mandatory RPC DoS bound for mainnet)"));
            }
        }
        // 9. explicit economic parameters.
        if !self.economics_v7 {
            missing.push("economics_v7: set true — a mainnet runs the explicit v7 economics (bond/emission/fee split), not the legacy defaults".into());
        } else {
            if self.quanto_rate_fp.is_none() {
                missing.push("quanto_rate_fp: bake the exact integer rate (deterministic cross-platform) — do not let each node derive it via f64".into());
            }
            if self.rounds_per_quanto.is_none() {
                missing.push("rounds_per_quanto: set the explicit quanto length (part of the network config hash)".into());
            }
        }
        // 10. HARD CAP mandatory (task pre-mainnet #4): a mainnet cannot ship the
        //     inflationary model — the 100M ceiling must be a consensus property.
        if !self.hard_cap_supply {
            missing.push("hard_cap_supply: set true — a mainnet must run the hard-capped supply (no minting; emission drawn from a pre-minted reserve). The inflationary model is dev-only.".into());
        }
        // 11. REAL treasury multisig (task pre-mainnet #1/#10): no single key may
        //     control the funds. Require ≥3 signers, an effective threshold ≥2
        //     (prohibit 1-of-N AND 1-of-1), a positive timelock, and BOTH a
        //     per-operation and a rolling-window release cap.
        let n = self.treasury_signers.len();
        if n < 3 {
            missing.push(format!(
                "treasury_signers: configure a REAL multisig — at least 3 signers (got {n}); no single key may control administrative funds"
            ));
        } else {
            // effective threshold: 0 in config means "majority" = floor(N/2)+1.
            let eff = if self.treasury_threshold == 0 {
                (n / 2 + 1) as u8
            } else {
                self.treasury_threshold
            };
            if eff < 2 {
                missing.push(format!(
                    "treasury_threshold: an effective M-of-N with M≥2 is required on mainnet (got effective M={eff}) — a 1-of-N (or 1-of-1) treasury is a single point of control"
                ));
            }
            if (eff as usize) > n {
                missing.push(format!(
                    "treasury_threshold: M ({eff}) exceeds the number of signers N ({n}) — the treasury could never execute"
                ));
            }
        }
        if self.treasury_timelock_rounds == 0 {
            missing.push("treasury_timelock_rounds: set a positive timelock (review window before a release/authority change may execute)".into());
        }
        if self.treasury_max_per_release_qch == 0 {
            missing.push("treasury_max_per_release_qch: set a positive per-operation release cap".into());
        }
        if self.treasury_max_per_window_qch == 0 || self.treasury_window_rounds == 0 {
            missing.push("treasury_max_per_window_qch + treasury_window_rounds: set a positive rolling-window release cap AND window length".into());
        }
        // 12. Explicit administrative-fee wallet (no hidden constant on mainnet).
        if self.admin_fee_wallet.is_none() {
            missing.push("admin_fee_wallet: set the explicit administrative-fee destination (point it at the multisig treasury) — a mainnet must not fall back to the hidden default constant".into());
        }

        if !missing.is_empty() {
            anyhow::bail!(
                "network_profile=\"mainnet\": REFUSING TO START — {} mandatory protection(s) missing:\n  - {}\n\nFix all of them (see docs/DEPLOY.md 'Perfil mainnet'). Every node in the network must share the same network fingerprint {} (compare across nodes).",
                missing.len(),
                missing.join("\n  - "),
                hex::encode(self.network_fingerprint()),
            );
        }

        Ok(())
    }

    /// **Fingerprint de red — el req 'configuración idéntica entre nodos' (#211).**
    /// Hash SHA3-256 de los campos que TODOS los nodos de una red DEBEN compartir
    /// para no forkear ni fallar el handshake: `chain_id` (que ya pliega
    /// validators+genesis+economics+compressed) + las elecciones network-wide que
    /// NO están en `chain_id` pero igual deben coincidir (auth/cifrado del
    /// transporte, rotación + epoch_rounds, el propio perfil). Se loguea al
    /// arrancar; un operador compara el hex entre nodos — si difieren, un nodo está
    /// mal configurado. NO se pliega en `chain_id` (es diagnóstico, no consenso).
    pub fn network_fingerprint(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"qchain-network-fingerprint-v1");
        h.update(self.chain_id());
        h.update([
            self.authenticated_transport as u8,
            self.encrypted_transport as u8,
            self.validator_rotation as u8,
            self.compressed_state_tree as u8,
            self.economics_v7 as u8,
        ]);
        h.update(self.epoch_rounds().to_le_bytes());
        // The profile string is part of the shared posture (all nodes mainnet, or
        // all testnet — a mixed set is a misconfiguration).
        h.update(self.network_profile.as_deref().unwrap_or("").as_bytes());
        h.update([self.mainnet as u8]);
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_crypto::Keypair;

    /// A v7-economics config (for the hard-cap folding test), from cloned inputs.
    fn config_with_v7(validators: &[ValidatorConfig], genesis: &[GenesisAllocation]) -> NodeConfig {
        let mut c = config_with(validators.to_vec(), genesis.to_vec());
        c.economics_v7 = true;
        c
    }

    fn config_with(validators: Vec<ValidatorConfig>, genesis: Vec<GenesisAllocation>) -> NodeConfig {
        NodeConfig {
            keypair_path: PathBuf::from("keypair.json"),
            listen_addr: "127.0.0.1:35001".parse().unwrap(),
            rpc_addr: "127.0.0.1:28001".parse().unwrap(),
            validators,
            genesis,
            round_interval_ms: 500,
            data_dir: None,
            state_sync_peers: Vec::new(),
            state_sync_trusted_root: None,
            state_sync_trusted_round: None,
            require_state_sync_trust_anchor: false,
            validator_rotation: false,
            epoch_rounds: None,
            compressed_state_tree: false,
            storage_engine: "redb".to_string(),
            authenticated_transport: false,
            encrypted_transport: false,
            economics_v7: false,
            quanto_rate_fp: None,
            rounds_per_quanto: None,
            treasury_authority: None,
            treasury_amount: None,
            treasury_signers: Vec::new(),
            treasury_threshold: 0,
            treasury_timelock_rounds: 0,
            treasury_max_per_release_qch: 0,
            treasury_max_per_window_qch: 0,
            treasury_window_rounds: 0,
            treasury_policy_threshold: 0,
            treasury_signers_threshold: 0,
            treasury_op_expiry_rounds: 0,
            admin_fee_wallet: None,
            hard_cap_supply: false,
            explicit_schema_versions: false,
            supply_cap_qch: None,
            emission_reserve_qch: None,
            rpc_rate_limit_per_10s: None,
            simulate_rate_limit_per_10s: None,
            tx_rate_limit_per_10s: None,
            rpc_behind_trusted_proxy: false,
            remote_signer: None,
            remote_signer_auth_token_path: None,
            network_keypair_path: None,
            mainnet: false,
            network_profile: None,
            state_checkpoints: false,
            state_sync_min_confirmations: None,
            governance_guardians: Vec::new(),
            governance_guardian_threshold: 0,
        }
    }

    /// Every validator of the same real network loads the same
    /// `validators`/`genesis` data but has its own `listen_addr`/
    /// `rpc_addr`/`keypair_path` - `chain_id` must depend only on the
    /// former, or validators of the exact same network would each compute
    /// a different chain_id and reject every real transaction.
    #[test]
    fn chain_id_is_identical_across_validators_of_the_same_network_despite_differing_per_validator_fields() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None, withdrawal_address: None }];
        let genesis = vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 5_000_000 }];

        let mut a = config_with(validators.clone(), genesis.clone());
        let mut b = config_with(validators, genesis);
        a.rpc_addr = "127.0.0.1:28001".parse().unwrap();
        b.rpc_addr = "127.0.0.1:28002".parse().unwrap();
        a.listen_addr = "127.0.0.1:35001".parse().unwrap();
        b.listen_addr = "127.0.0.1:35009".parse().unwrap();

        assert_eq!(a.chain_id(), b.chain_id(), "same genesis data must produce the same chain_id regardless of per-validator network config");
    }

    /// `economics_v7` folds into `chain_id` ONLY when enabled, so a v6 (default,
    /// `false`) network's chain_id is byte-identical to before the field existed —
    /// its live transactions keep verifying. A v7 network gets a distinct chain_id
    /// (a genuinely separate, hard-forked network), and two v7 networks with
    /// different reward rates are distinct chains too.
    #[test]
    fn economics_v7_folds_into_chain_id_only_when_enabled() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None, withdrawal_address: None }];
        let genesis = vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 5_000_000 }];

        let v6 = config_with(validators.clone(), genesis.clone());
        let mut v7 = config_with(validators.clone(), genesis.clone());
        v7.economics_v7 = true;
        // v6 default is byte-identical to a config from before the field existed.
        assert_eq!(v6.chain_id(), config_with(validators.clone(), genesis.clone()).chain_id(), "v6 default unchanged");
        // v7 is a distinct network.
        assert_ne!(v6.chain_id(), v7.chain_id(), "a v7 network has a distinct chain_id");
        // Two v7 networks with different rounds_per_quanto are distinct chains.
        let mut v7_fast = config_with(validators, genesis);
        v7_fast.economics_v7 = true;
        v7_fast.rounds_per_quanto = Some(8);
        assert_ne!(v7.chain_id(), v7_fast.chain_id(), "economic params are part of the config hash");
    }

    /// The HARD-CAP supply model (#221) folds into `chain_id` ONLY when enabled, so
    /// an inflationary v7 network keeps its chain_id unchanged, while a hard-cap
    /// network (and one with a different cap or reserve) is a genuinely distinct
    /// chain. Also confirms the resolvers default the cap to 100M and reserve to 0.
    #[test]
    fn hard_cap_supply_folds_into_chain_id_only_when_enabled() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None, withdrawal_address: None }];
        let genesis = vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 5_000_000 }];

        let mut v7 = config_with(validators.clone(), genesis.clone());
        v7.economics_v7 = true;
        // An inflationary v7 config is byte-identical to before this field existed.
        assert_eq!(v7.chain_id(), config_with_v7(&validators, &genesis).chain_id(), "inflationary v7 chain_id unchanged");

        let mut cap = config_with_v7(&validators, &genesis);
        cap.hard_cap_supply = true;
        assert_ne!(v7.chain_id(), cap.chain_id(), "a hard-cap network is a distinct chain");
        // Defaults: 100M cap, 0 reserve.
        assert_eq!(cap.supply_cap_atoms(), qchain_execution::economics_v7::MAX_SUPPLY_ATOMS);
        assert_eq!(cap.emission_reserve_atoms(), 0);

        // A different cap → a different chain.
        let mut cap2 = config_with_v7(&validators, &genesis);
        cap2.hard_cap_supply = true;
        cap2.supply_cap_qch = Some(50_000_000);
        assert_ne!(cap.chain_id(), cap2.chain_id(), "the cap value is part of the config hash");
        assert_eq!(cap2.supply_cap_atoms(), 50_000_000u128 * qchain_core::UNITS_PER_QCH as u128);

        // A different pre-minted reserve → a different chain.
        let mut cap3 = config_with_v7(&validators, &genesis);
        cap3.hard_cap_supply = true;
        cap3.emission_reserve_qch = Some(40_000_000);
        assert_ne!(cap.chain_id(), cap3.chain_id(), "the emission reserve is part of the config hash");
        assert_eq!(cap3.emission_reserve_atoms(), 40_000_000u64 * qchain_core::UNITS_PER_QCH);
    }

    /// The MULTISIG treasury + admin-fee wallet (task #222) fold into `chain_id`
    /// ONLY when configured, so a network without them keeps its chain_id, and any
    /// change to the signer set / threshold / limits / admin address is a distinct
    /// chain. Also confirms the resolvers parse + default correctly.
    #[test]
    fn multisig_treasury_and_admin_wallet_fold_into_chain_id_only_when_set() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None, withdrawal_address: None }];
        let genesis = vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 5_000_000 }];
        let s: Vec<String> = (0..5).map(|_| Keypair::generate().unwrap().pubkey().to_string()).collect();

        // Build a multisig config from the given threshold/timelock.
        let mk_ms = |threshold: u8, timelock: u64| {
            let mut c = config_with_v7(&validators, &genesis);
            c.treasury_signers = s.clone();
            c.treasury_threshold = threshold;
            c.treasury_amount = Some(1_000_000_000);
            c.treasury_timelock_rounds = timelock;
            c
        };
        let base = config_with_v7(&validators, &genesis);
        let ms = mk_ms(3, 100);
        // A multisig config is a distinct chain from the plain v7 config.
        assert_ne!(base.chain_id(), ms.chain_id(), "a multisig treasury is a distinct chain");
        // The threshold is part of the identity.
        assert_ne!(ms.chain_id(), mk_ms(4, 100).chain_id(), "the threshold is part of the config hash");
        // The timelock/limits are part of the identity.
        assert_ne!(ms.chain_id(), mk_ms(3, 200).chain_id(), "the timelock is part of the config hash");
        // Resolver: builds a valid 3-of-5 state.
        let state = ms.treasury_multisig_state().unwrap().unwrap();
        assert_eq!(state.signers.len(), 5);
        assert_eq!(state.threshold, 3);
        assert_eq!(state.timelock_rounds, 100);

        // The admin-fee wallet folds in only when set.
        let mut aw = config_with_v7(&validators, &genesis);
        aw.admin_fee_wallet = Some(Keypair::generate().unwrap().pubkey().to_string());
        assert_ne!(base.chain_id(), aw.chain_id(), "an admin-fee wallet override is a distinct chain");
        assert!(aw.admin_fee_wallet_pubkey().unwrap().is_some());
        assert!(base.admin_fee_wallet_pubkey().unwrap().is_none(), "no override = the compiled-in constant");
    }

    /// The real, live-confirmed gap this closes (see
    /// `project-lessons-learned`): two genuinely independent networks -
    /// different genesis allocations - must get different chain_ids, or a
    /// transaction signed for one would still validate on the other.
    #[test]
    fn chain_id_differs_across_genuinely_different_networks() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None, withdrawal_address: None }];

        let network_a = config_with(validators.clone(), vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 1 }]);
        let network_b = config_with(validators, vec![GenesisAllocation { address: Keypair::generate().unwrap().pubkey(), balance: 2 }]);

        assert_ne!(network_a.chain_id(), network_b.chain_id(), "genuinely different genesis data must produce different chain_ids");
    }

    /// The whole point of `skip_serializing_if` on `name`: an existing network
    /// (validators with no name) must compute the EXACT same chain_id it did
    /// before the field existed, so adding this feature never breaks a live
    /// deployment. We prove it by checking the serialized bytes carry no
    /// `name` key when name is `None` (byte-identical to the old struct), and
    /// that setting a name does change the bytes (so it folds into chain_id).
    #[test]
    fn name_none_is_omitted_from_serialization_so_chain_id_is_unchanged() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let nameless = ValidatorConfig { pubkey_bundle: bundle.clone(), addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None, withdrawal_address: None };
        let named = ValidatorConfig { name: Some("Alice".into()), ..nameless.clone() };

        let nameless_json = serde_json::to_string(&nameless).unwrap();
        assert!(!nameless_json.contains("name"), "a nameless validator must serialize with no `name` key (byte-identical to pre-name configs, preserving chain_id)");

        let c_nameless = config_with(vec![nameless], vec![]);
        let c_named = config_with(vec![named], vec![]);
        assert_ne!(c_nameless.chain_id(), c_named.chain_id(), "setting a name folds it into the network's own chain_id");
    }

    /// #193-B: a cold withdrawal address is chain_id-safe when unset (a config
    /// without one serializes byte-identical, so an existing network keeps its
    /// exact chain_id), and setting one folds into the network's own chain_id
    /// (so a network that separates the funds key is a distinct chain).
    #[test]
    fn withdrawal_address_none_is_omitted_so_chain_id_is_unchanged() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let plain = ValidatorConfig { pubkey_bundle: bundle.clone(), addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None, withdrawal_address: None };
        let cold = Keypair::generate().unwrap().pubkey();
        let with_withdrawal = ValidatorConfig { withdrawal_address: Some(cold), ..plain.clone() };

        let plain_json = serde_json::to_string(&plain).unwrap();
        assert!(!plain_json.contains("withdrawal_address"), "a validator with no withdrawal address must serialize with no `withdrawal_address` key (byte-identical to pre-#193-B configs, preserving chain_id)");

        let c_plain = config_with(vec![plain], vec![]);
        let c_cold = config_with(vec![with_withdrawal], vec![]);
        assert_ne!(c_plain.chain_id(), c_cold.chain_id(), "setting a withdrawal address folds it into the network's own chain_id");
    }

    /// Task #208: with `mainnet` set, the node must refuse to start unless BOTH
    /// authenticated AND encrypted P2P transport are on; a testnet (`mainnet`
    /// false, the default) is never constrained.
    #[test]
    fn mainnet_requires_authenticated_and_encrypted_transport() {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        let validators = vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None, withdrawal_address: None }];

        // Testnet default: no requirement, always OK.
        let testnet = config_with(validators.clone(), vec![]);
        assert!(testnet.validate_mainnet_transport().is_ok(), "a testnet is never constrained");

        // mainnet with neither / only auth / only encryption → rejected.
        let mut m = config_with(validators.clone(), vec![]);
        m.mainnet = true;
        assert!(m.validate_mainnet_transport().is_err(), "mainnet with plaintext unauth transport must fail-stop");
        m.authenticated_transport = true;
        assert!(m.validate_mainnet_transport().is_err(), "mainnet with auth but no encryption must fail-stop");
        m.authenticated_transport = false;
        m.encrypted_transport = true;
        assert!(m.validate_mainnet_transport().is_err(), "mainnet with encryption but no auth must fail-stop");

        // mainnet with both → OK.
        m.authenticated_transport = true;
        m.encrypted_transport = true;
        assert!(m.validate_mainnet_transport().is_ok(), "mainnet with auth + encryption is allowed");
    }

    fn one_validator() -> Vec<ValidatorConfig> {
        let bundle = Keypair::generate().unwrap().public_key_bundle();
        vec![ValidatorConfig { pubkey_bundle: bundle, addr: "127.0.0.1:35001".parse().unwrap(), stake: 1_000_000, name: None, withdrawal_address: None }]
    }

    /// Roadmap #19: seeding the schema manifest changes the genesis state root,
    /// so `explicit_schema_versions` folds into the chain_id — but ONLY when set,
    /// so a network that doesn't opt in keeps its exact chain_id byte-identical.
    #[test]
    fn explicit_schema_versions_folds_into_chain_id_only_when_set() {
        // One config, flip only the flag: off is byte-identical (the fold adds
        // nothing), on changes the chain_id (a fresh-genesis, distinct network).
        let mut c = config_with(one_validator(), vec![]);
        assert!(!c.explicit_schema_versions, "default is off");
        let off = c.chain_id();
        let off_again = c.chain_id();
        assert_eq!(off, off_again, "chain_id is deterministic");
        c.explicit_schema_versions = true;
        assert_ne!(c.chain_id(), off, "enabling the schema manifest changes the chain_id");
    }

    /// Build a config that satisfies EVERY mainnet-profile requirement, so a test
    /// can then knock out one field at a time and assert it fail-stops.
    fn mainnet_config_with(validators: Vec<ValidatorConfig>) -> NodeConfig {
        let mut c = config_with(validators, vec![]);
        c.network_profile = Some("mainnet".into());
        c.data_dir = Some(PathBuf::from("/var/lib/qchain"));
        c.storage_engine = "redb".into();
        c.authenticated_transport = true;
        c.encrypted_transport = true;
        c.remote_signer = Some("127.0.0.1:9200".into());
        c.remote_signer_auth_token_path = Some("/opt/qchain/signer.token".into()); // #4.2 client auth
        c.rpc_addr = "127.0.0.1:28001".parse().unwrap(); // private
        c.require_state_sync_trust_anchor = true;
        c.rpc_rate_limit_per_10s = Some(64);
        c.simulate_rate_limit_per_10s = Some(8);
        c.tx_rate_limit_per_10s = Some(16);
        c.economics_v7 = true;
        c.quanto_rate_fp = Some(310_537_755_655_371);
        c.rounds_per_quanto = Some(86_400);
        // Pre-mainnet #1/#4/#10: hard cap + a real multisig treasury + explicit admin wallet.
        c.hard_cap_supply = true;
        c.treasury_signers = vec!["s1addr".into(), "s2addr".into(), "s3addr".into(), "s4addr".into(), "s5addr".into()];
        c.treasury_threshold = 3;
        c.treasury_timelock_rounds = 5_760;
        c.treasury_max_per_release_qch = 1_000;
        c.treasury_max_per_window_qch = 5_000;
        c.treasury_window_rounds = 172_800;
        c.admin_fee_wallet = Some("adminwallet".into());
        c
    }

    /// Roadmap #17: the treasury threshold hierarchy + op-expiry resolve from
    /// config (0 = default to the base threshold), validate the ordering, and fold
    /// into `chain_id` ONLY when set (so an existing multisig network is unchanged).
    #[test]
    fn treasury_tier_hierarchy_resolves_validates_and_folds_into_chain_id_only_when_set() {
        let addrs: Vec<String> = (0..5).map(|_| Keypair::generate().unwrap().pubkey().to_string()).collect();
        // NodeConfig isn't Clone, so build a fresh base each time.
        let mk = || {
            let mut base = config_with(one_validator(), vec![]);
            base.economics_v7 = true;
            base.treasury_amount = Some(1_000_000);
            base.treasury_signers = addrs.clone();
            base.treasury_threshold = 2;
            base.treasury_timelock_rounds = 100;
            base
        };

        // Tiers unset (0) default to the base threshold — byte-identical behavior.
        let base = mk();
        let st = base.treasury_multisig_state().unwrap().unwrap();
        assert_eq!((st.threshold, st.policy_threshold, st.signers_threshold), (2, 2, 2));
        assert_eq!(st.op_expiry_rounds, 0);
        // ... and its chain_id equals a config that never mentions the tiers.
        let chain_no_tiers = base.chain_id();

        // Explicit tiers 2 <= 3 <= 4 + a valid expiry resolve and validate.
        let mut tiered = mk();
        tiered.treasury_policy_threshold = 3;
        tiered.treasury_signers_threshold = 4;
        tiered.treasury_op_expiry_rounds = 500;
        let st2 = tiered.treasury_multisig_state().unwrap().unwrap();
        assert_eq!((st2.threshold, st2.policy_threshold, st2.signers_threshold), (2, 3, 4));
        assert_eq!(st2.op_expiry_rounds, 500);
        // Setting the tiers changes the chain_id (a distinct network), but the
        // default (unset) config keeps the exact chain_id it had before #17.
        assert_ne!(tiered.chain_id(), chain_no_tiers, "configured tiers fold into chain_id");

        // A broken ordering (policy < threshold) is rejected.
        let mut bad = mk();
        bad.treasury_policy_threshold = 1; // < threshold 2
        assert!(bad.treasury_multisig_state().is_err(), "policy < threshold must be rejected");

        // An expiry that doesn't exceed the timelock is rejected (footgun guard).
        let mut bad_exp = mk();
        bad_exp.treasury_op_expiry_rounds = 50; // <= timelock 100
        assert!(bad_exp.treasury_multisig_state().is_err(), "expiry <= timelock must be rejected");
    }

    /// Task #211: the mandatory mainnet profile fail-stops when ANY hard
    /// protection is missing, accumulates all failures, and passes when every one
    /// is present — while a testnet is never constrained.
    #[test]
    fn mainnet_profile_requires_every_hard_protection() {
        // Fully-configured mainnet passes.
        let full = mainnet_config_with(one_validator());
        assert!(full.validate_network_profile().is_ok(), "a fully-protected mainnet must start; err: {:?}", full.validate_network_profile().err());

        // A testnet (no profile) is never constrained even with everything off.
        let testnet = config_with(one_validator(), vec![]);
        assert!(testnet.validate_network_profile().is_ok(), "a testnet is never constrained");

        // An unknown profile string fails loud.
        let mut typo = mainnet_config_with(one_validator());
        typo.network_profile = Some("mainet".into());
        assert!(typo.validate_network_profile().is_err(), "an unknown profile string must fail loud");

        // Knock out each protection individually — every one must fail-stop.
        type Knockout = (&'static str, Box<dyn Fn(&mut NodeConfig)>);
        let knockouts: Vec<Knockout> = vec![
            ("data_dir", Box::new(|c: &mut NodeConfig| c.data_dir = None)),
            ("storage_engine", Box::new(|c: &mut NodeConfig| c.storage_engine = "sled".into())),
            ("authenticated_transport", Box::new(|c: &mut NodeConfig| c.authenticated_transport = false)),
            ("encrypted_transport", Box::new(|c: &mut NodeConfig| c.encrypted_transport = false)),
            ("remote_signer", Box::new(|c: &mut NodeConfig| c.remote_signer = None)),
            // Audit v8.6.13 #4: a public/LAN signer endpoint is an unauthenticated
            // signing oracle — mainnet must reject it (loopback only until mTLS).
            ("public remote_signer", Box::new(|c: &mut NodeConfig| c.remote_signer = Some("8.8.8.8:9200".into()))),
            ("LAN remote_signer", Box::new(|c: &mut NodeConfig| c.remote_signer = Some("192.168.1.10:9200".into()))),
            // Audit v8.6.13 #4.2: the signer socket must AUTHENTICATE the client on
            // mainnet — the token file is required (loopback/UDS alone is not enough).
            ("no signer auth token", Box::new(|c: &mut NodeConfig| c.remote_signer_auth_token_path = None)),
            ("public rpc_addr", Box::new(|c: &mut NodeConfig| c.rpc_addr = "8.8.8.8:28001".parse().unwrap())),
            ("trust_anchor", Box::new(|c: &mut NodeConfig| c.require_state_sync_trust_anchor = false)),
            ("rpc_rate_limit", Box::new(|c: &mut NodeConfig| c.rpc_rate_limit_per_10s = None)),
            ("simulate_rate_limit", Box::new(|c: &mut NodeConfig| c.simulate_rate_limit_per_10s = Some(0))),
            ("tx_rate_limit", Box::new(|c: &mut NodeConfig| c.tx_rate_limit_per_10s = None)),
            ("economics_v7", Box::new(|c: &mut NodeConfig| c.economics_v7 = false)),
            ("quanto_rate_fp", Box::new(|c: &mut NodeConfig| c.quanto_rate_fp = None)),
            ("rounds_per_quanto", Box::new(|c: &mut NodeConfig| c.rounds_per_quanto = None)),
            // Pre-mainnet #1/#4/#10:
            ("hard_cap_supply", Box::new(|c: &mut NodeConfig| c.hard_cap_supply = false)),
            ("no treasury signers", Box::new(|c: &mut NodeConfig| c.treasury_signers = vec![])),
            ("too few signers", Box::new(|c: &mut NodeConfig| c.treasury_signers = vec!["a".into(), "b".into()])),
            ("1-of-N threshold", Box::new(|c: &mut NodeConfig| c.treasury_threshold = 1)),
            ("no timelock", Box::new(|c: &mut NodeConfig| c.treasury_timelock_rounds = 0)),
            ("no per-op cap", Box::new(|c: &mut NodeConfig| c.treasury_max_per_release_qch = 0)),
            ("no per-window cap", Box::new(|c: &mut NodeConfig| c.treasury_max_per_window_qch = 0)),
            ("no window length", Box::new(|c: &mut NodeConfig| c.treasury_window_rounds = 0)),
            ("no admin wallet", Box::new(|c: &mut NodeConfig| c.admin_fee_wallet = None)),
        ];
        for (name, knock) in knockouts {
            let mut c = mainnet_config_with(one_validator());
            knock(&mut c);
            assert!(c.validate_network_profile().is_err(), "mainnet with {name} missing must fail-stop");
        }

        // #4.2 — a UNIX-socket signer endpoint (with the token) is accepted on
        // mainnet (OS-permission isolation + challenge-response), same as loopback TCP.
        let mut uds = mainnet_config_with(one_validator());
        uds.remote_signer = Some("unix:/run/qchain/signer.sock".into());
        assert!(uds.validate_network_profile().is_ok(), "a unix-socket signer with a token must be accepted on mainnet; err: {:?}", uds.validate_network_profile().err());
        // ...but a UNIX-socket signer WITHOUT the token still fails.
        uds.remote_signer_auth_token_path = None;
        assert!(uds.validate_network_profile().is_err(), "even a unix-socket signer must carry the client auth token on mainnet");

        // When a state_sync peer is set, the anchor's (round, root) must be pinned.
        let mut sync = mainnet_config_with(one_validator());
        sync.state_sync_peers = vec!["http://127.0.0.1:28002".into()];
        assert!(sync.validate_network_profile().is_err(), "state_sync_peers with no pinned (round,root) must fail-stop");
        sync.state_sync_trusted_root = Some("00".repeat(32));
        sync.state_sync_trusted_round = Some(100);
        assert!(sync.validate_network_profile().is_ok(), "state_sync with a full pinned anchor passes");

        // The legacy `mainnet: true` flag also triggers the full profile.
        let mut legacy = mainnet_config_with(one_validator());
        legacy.network_profile = None;
        legacy.mainnet = true;
        assert!(legacy.validate_network_profile().is_ok(), "legacy mainnet:true satisfied is OK");
        legacy.remote_signer = None;
        assert!(legacy.validate_network_profile().is_err(), "legacy mainnet:true also enforces the full profile");
    }

    /// The network fingerprint changes when a network-wide field changes, and is
    /// identical for two nodes that differ only in per-validator fields.
    #[test]
    fn network_fingerprint_covers_network_wide_config() {
        let validators = one_validator();
        let a = mainnet_config_with(validators.clone());

        // Per-validator field differs (same validators/genesis) → identical.
        let mut b = mainnet_config_with(validators.clone());
        b.rpc_addr = "127.0.0.1:29999".parse().unwrap();
        b.listen_addr = "127.0.0.1:35099".parse().unwrap();
        b.data_dir = Some(PathBuf::from("/other/dir"));
        assert_eq!(a.network_fingerprint(), b.network_fingerprint(), "per-validator fields must not change the fingerprint");

        // A network-wide field differs → fingerprint must change.
        let mut c = mainnet_config_with(validators);
        c.encrypted_transport = false;
        assert_ne!(a.network_fingerprint(), c.network_fingerprint(), "a network-wide field change must change the fingerprint");
    }
}
