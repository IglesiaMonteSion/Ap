use qchain_core::Account;
use qchain_crypto::Pubkey;
use std::collections::BTreeMap;
use std::path::Path;

/// Backend abstraction for account storage. `ARCHITECTURE.md` §3 names
/// RocksDB as the eventual production target; this trait is what makes
/// that swap possible without touching the Merkle tree logic in `tree.rs`.
/// Real persistence now ships as `SledStore` - **not** RocksDB, a
/// deliberate substitution, not a downgrade taken lightly: RocksDB was
/// attempted first (`librocksdb-dev` links fine against the real system
/// library), but `librocksdb-sys`'s `bindgen` step panics
/// ("a `libclang` shared library is not loaded on this thread") in this
/// specific sandboxed build environment - reproduced with the default
/// runtime-dlopen bindgen path, several `LIBCLANG_PATH` candidates found
/// via `strace`, and the `bindgen-static` feature (which itself conflicts
/// with `bindgen-runtime` being pulled in by another default feature) -
/// while `libclang.so` demonstrably loads fine standalone via a plain
/// Python `ctypes.CDLL` call, confirming this is a `clang-sys`/sandboxing
/// interaction, not a missing or broken library. `sled` closes the actual
/// gap this item exists for (a validator's state surviving a restart)
/// with zero C/C++ build surface, so it's not blocked by this. RocksDB
/// remains the documented longer-term target if a future environment
/// doesn't hit this - `StateStore` makes that swap a new impl of this
/// trait, not a rewrite. See `project-lessons-learned` for the full
/// investigation.
pub trait StateStore: Send + Sync {
    fn get(&self, key: &Pubkey) -> Option<Account>;
    fn set(&mut self, key: Pubkey, account: Account);
    fn remove(&mut self, key: &Pubkey);
    fn iter(&self) -> Box<dyn Iterator<Item = (Pubkey, Account)> + '_>;
    /// Force any buffered writes durable to disk. `sled` buffers writes and
    /// flushes on its own timer (~500ms) by default, so between flushes recent
    /// account writes live only in the process's memory and are lost on an
    /// unclean exit (SIGTERM without a handler, OOM, kill -9) - while the plain
    /// `round_checkpoint` file (`std::fs::write`, page-cache-durable across
    /// process death) can already be ahead of them, so a restart can silently
    /// drop committed transactions. A node flushes this (and its sibling sled
    /// logs) on SIGTERM/SIGINT so the documented `systemctl restart` /
    /// `update-node.sh` flow is fully durable. Default `Ok` for the in-memory
    /// store (nothing to persist).
    ///
    /// RETURNS a `Result` (mainnet atomicity work): a failed commit is FATAL for
    /// a ledger — the node HALTS rather than continue on half-written state. It
    /// must never be papered over as a warning. For `RedbStore` a single `flush`
    /// commits the round's account writes AND the staged metadata
    /// (`put_meta`) in ONE atomic, fsync-durable transaction, so account state
    /// and the executed-round checkpoint can never split across a power loss.
    fn flush(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// Stage a small metadata value (the node uses this for the executed-round
    /// checkpoint and the economics counters) to be committed in the SAME atomic
    /// transaction as the account writes at the next [`flush`](Self::flush). This
    /// is what makes account state and the round number impossible to split
    /// across a crash. Default no-op (a store without atomic metadata).
    fn put_meta(&mut self, _key: &str, _value: Vec<u8>) {}

    /// Read back a metadata value previously committed via `put_meta` + `flush`.
    /// Default `None`.
    fn get_meta(&self, _key: &str) -> Option<Vec<u8>> {
        None
    }

    /// True only for a genuinely transactional engine (`RedbStore`) where
    /// `put_meta` values commit ATOMICALLY with the account writes. When true the
    /// node folds the round/economics checkpoint into the state commit (one
    /// all-or-nothing operation); when false it keeps a separate best-effort
    /// checkpoint file (the legacy sled/in-memory, non-production path).
    fn supports_atomic_meta(&self) -> bool {
        false
    }

    /// Whether this store buffers writes in memory and needs the node to
    /// `flush()` it regularly (each committed round), not only on shutdown.
    /// `false` for `sled` (it flushes on its own ~500ms timer) and the in-memory
    /// store; `true` for `RedbStore`, whose durability is a single `flush()`
    /// commit of the round's dirty accounts - keeping RAM flat under a write
    /// burst (the exact sled failure mode this exists to fix) at the cost of
    /// needing an explicit per-round commit. Default `false` so the existing
    /// sled/in-memory paths are completely unchanged.
    fn needs_periodic_flush(&self) -> bool {
        false
    }
}

#[derive(Default)]
pub struct InMemoryStore {
    accounts: BTreeMap<Pubkey, Account>,
    meta: BTreeMap<String, Vec<u8>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for InMemoryStore {
    fn get(&self, key: &Pubkey) -> Option<Account> {
        self.accounts.get(key).cloned()
    }

    fn set(&mut self, key: Pubkey, account: Account) {
        self.accounts.insert(key, account);
    }

    fn remove(&mut self, key: &Pubkey) {
        self.accounts.remove(key);
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (Pubkey, Account)> + '_> {
        Box::new(self.accounts.iter().map(|(k, v)| (*k, v.clone())))
    }

    // In-memory metadata is process-local (nothing survives a restart anyway),
    // so it's a plain map. `supports_atomic_meta` stays false: an in-memory node
    // has no crash to be atomic against, and the node's `round_checkpoint_path`
    // is `None` for it, so it never reaches the atomic-commit path.
    fn put_meta(&mut self, key: &str, value: Vec<u8>) {
        self.meta.insert(key.to_string(), value);
    }

    fn get_meta(&self, key: &str) -> Option<Vec<u8>> {
        self.meta.get(key).cloned()
    }
}

/// Real, disk-persistent `StateStore` backed by `sled` - see this module's
/// doc comment for why `sled` rather than the originally-planned RocksDB.
/// Keys are raw 32-byte `Pubkey`s; values are Borsh-encoded `Account`s
/// (the same encoding this project already uses for wire/state hashing
/// elsewhere, e.g. `qchain_storage::tree::hash_leaf` - not a second,
/// divergent format). `sled`'s own write-ahead log and crash-safety
/// guarantees are what make this actually survive an unclean shutdown,
/// not just a clean one.
pub struct SledStore {
    db: sled::Db,
}

impl SledStore {
    /// Opens (creating if absent) a sled database at `path`. Real
    /// failures here (permissions, a corrupt database, disk full) are
    /// propagated rather than papered over - a validator that can't open
    /// its own state should refuse to start, not silently run in some
    /// degraded mode.
    ///
    /// A full validation pass runs up front: every stored entry is checked
    /// to be a 32-byte key with a Borsh-decodable `Account` value, and any
    /// failure is returned as a descriptive `Err` here at startup rather
    /// than surfacing later as a mid-consensus panic deep in `get`/`iter`.
    /// This is what lets those hot-path methods keep their `expect`s as
    /// genuine post-validation invariants: nothing this store hands back at
    /// runtime can fail to decode, because `open` already proved the whole
    /// database decodes (and only `set` - which only ever writes a freshly
    /// Borsh-encoded `Account` - mutates it afterward). Fail-loud is
    /// deliberate for a ledger: a corrupt on-disk balance must stop the node,
    /// never be silently treated as absent/zero (which could mint or destroy
    /// value) - the same "refuse to run degraded" stance, just reported as a
    /// clean error instead of a panic.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let db = sled::open(path)?;
        for entry in db.iter() {
            let (key_bytes, value_bytes) = entry.map_err(|e| anyhow::anyhow!("reading the state database at {} failed: {e}", path.display()))?;
            if key_bytes.len() != 32 {
                anyhow::bail!("corrupt state database at {}: a key is {} bytes, expected a 32-byte address", path.display(), key_bytes.len());
            }
            borsh::from_slice::<Account>(&value_bytes)
                .map_err(|e| anyhow::anyhow!("corrupt state database at {}: an account value failed to decode ({e}) - refusing to run on damaged state", path.display()))?;
        }
        Ok(SledStore { db })
    }
}

impl StateStore for SledStore {
    fn get(&self, key: &Pubkey) -> Option<Account> {
        let bytes = self.db.get(key.to_bytes()).expect("sled get should not fail on a healthy database")?;
        // Cannot fail: `open` validated every existing value decodes, and the
        // only writer since is `set`, which only writes encoded `Account`s.
        Some(borsh::from_slice(&bytes).expect("a value written by this same store must decode as an Account"))
    }

    fn set(&mut self, key: Pubkey, account: Account) {
        let bytes = borsh::to_vec(&account).expect("Account always serializes");
        self.db.insert(key.to_bytes(), bytes).expect("sled insert should not fail on a healthy database");
    }

    fn remove(&mut self, key: &Pubkey) {
        self.db.remove(key.to_bytes()).expect("sled remove should not fail on a healthy database");
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (Pubkey, Account)> + '_> {
        // All three `expect`s are post-`open`-validation invariants: `open`
        // already proved every key is 32 bytes and every value decodes as an
        // `Account`, and only `set` (which writes only encoded `Account`s at
        // 32-byte keys) has run since.
        Box::new(self.db.iter().map(|entry| {
            let (key_bytes, value_bytes) = entry.expect("sled iteration should not fail on a healthy database");
            let key = Pubkey::new(key_bytes.as_ref().try_into().expect("every key this store ever wrote is exactly 32 bytes"));
            let account = borsh::from_slice(&value_bytes).expect("a value written by this same store must decode as an Account");
            (key, account)
        }))
    }

    fn flush(&self) -> anyhow::Result<()> {
        // Fail-loud (mainnet atomicity work): a flush failure is returned so the
        // node can HALT, never continue on possibly-lost writes. NOTE: sled is
        // the legacy/dev engine — it does NOT commit account writes and the
        // round checkpoint in one transaction (`supports_atomic_meta` is false),
        // so it is not the production/mainnet engine. Use `redb`.
        self.db.flush().map(|_| ()).map_err(|e| anyhow::anyhow!("failed to flush the sled state store: {e}"))
    }
}

/// Modern-engine `StateStore` backed by **redb** (a pure-Rust, ACID, mmap'd
/// embedded key-value store) - the "migrate off sled 0.34" target named in
/// `project-lessons-learned`. Unlike RocksDB (whose `bindgen`/`libclang` step
/// fails in this build environment - see `SledStore`'s docs), redb has zero
/// C/C++ build surface, so it compiles wherever sled does.
///
/// **Why this fixes sled's flood-RAM problem** (measured: a 50k-transfer burst
/// drove sled's RSS to multi-GB and it did not release): sled 0.34's
/// log-structured page cache retains memory proportional to *what was written in
/// a burst*, not to the live account count. `RedbStore` instead keeps the live
/// state as a small in-RAM mirror (`mem`) - bounded by the *number of accounts*
/// (hundreds/thousands here), NOT by burst size - and persists to redb's mmap'd
/// file, whose RSS is OS-managed and reclaimable. A flood re-writes the same
/// bounded set of accounts (the load workers), so RAM stays flat.
///
/// **Durability model**: writes update the in-RAM mirror immediately (so `get`
/// trivially reads-your-writes) and mark the key dirty; `flush()` commits the
/// round's dirty accounts to redb in one transaction. The node calls `flush()`
/// each committed round (see `needs_periodic_flush`), so an unclean crash loses
/// at most the current round's writes - the same bound sled's timer gives, made
/// explicit and ordered ahead of the `round_checkpoint` advance.
///
/// Same fail-loud contract as `SledStore`: `open` validates every stored entry
/// decodes as a 32-byte-keyed `Account` and returns a clean startup error on
/// corruption rather than papering a bad balance over as absent/zero.
pub struct RedbStore {
    db: redb::Database,
    mem: BTreeMap<Pubkey, Account>,
    /// Keys written or removed since the last `flush()`. A dirty key present in
    /// `mem` is an upsert; a dirty key absent from `mem` is a delete. Behind a
    /// `Mutex` purely so `flush(&self)` (per the trait signature) can drain it -
    /// the node only ever touches this store single-threaded under the ledger
    /// lock, so the mutex is never actually contended.
    dirty: std::sync::Mutex<std::collections::HashSet<Pubkey>>,
    /// Staged metadata (executed-round checkpoint, economics counters), mirror +
    /// dirty set, committed in the SAME `flush()` transaction as the accounts so
    /// state and round can never split across a crash (mainnet atomicity work).
    meta_mem: BTreeMap<String, Vec<u8>>,
    meta_dirty: std::sync::Mutex<std::collections::HashSet<String>>,
}

const REDB_ACCOUNTS: redb::TableDefinition<'static, &'static [u8], &'static [u8]> = redb::TableDefinition::new("accounts");
const REDB_META: redb::TableDefinition<'static, &'static [u8], &'static [u8]> = redb::TableDefinition::new("meta");

impl RedbStore {
    /// Opens (creating if absent) a redb database at `path` (a single file, e.g.
    /// `data_dir/state.redb`), loading the full account set into the in-RAM
    /// mirror and validating every entry up front (fail-loud, like `SledStore`).
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let db = redb::Database::create(path).map_err(|e| anyhow::anyhow!("opening the redb state database at {} failed: {e}", path.display()))?;
        let mut mem = BTreeMap::new();
        // A brand-new database has no table yet; treat "table missing" as empty.
        let rtx = db.begin_read().map_err(|e| anyhow::anyhow!("reading the redb state database at {} failed: {e}", path.display()))?;
        match rtx.open_table(REDB_ACCOUNTS) {
            Ok(table) => {
                use redb::ReadableTable;
                let iter = table.iter().map_err(|e| anyhow::anyhow!("iterating the redb state database at {} failed: {e}", path.display()))?;
                for entry in iter {
                    let (k, v) = entry.map_err(|e| anyhow::anyhow!("reading an entry from the redb state database at {} failed: {e}", path.display()))?;
                    let key_bytes = k.value();
                    if key_bytes.len() != 32 {
                        anyhow::bail!("corrupt redb state database at {}: a key is {} bytes, expected a 32-byte address", path.display(), key_bytes.len());
                    }
                    let account = borsh::from_slice::<Account>(v.value())
                        .map_err(|e| anyhow::anyhow!("corrupt redb state database at {}: an account value failed to decode ({e}) - refusing to run on damaged state", path.display()))?;
                    let key = Pubkey::new(key_bytes.try_into().expect("length checked to be 32"));
                    mem.insert(key, account);
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(e) => anyhow::bail!("opening the accounts table in the redb state database at {} failed: {e}", path.display()),
        }
        // Load the metadata table (round checkpoint, economics) into its mirror.
        // A brand-new (or pre-atomic-commit) database has no `meta` table yet;
        // treat "table missing" as empty so an existing redb DB migrates
        // seamlessly (the node then falls back to the legacy checkpoint file).
        let mut meta_mem = BTreeMap::new();
        match rtx.open_table(REDB_META) {
            Ok(table) => {
                use redb::ReadableTable;
                let iter = table.iter().map_err(|e| anyhow::anyhow!("iterating the redb meta table at {} failed: {e}", path.display()))?;
                for entry in iter {
                    let (k, v) = entry.map_err(|e| anyhow::anyhow!("reading a meta entry from {} failed: {e}", path.display()))?;
                    let key = String::from_utf8(k.value().to_vec())
                        .map_err(|e| anyhow::anyhow!("corrupt redb meta key at {}: {e}", path.display()))?;
                    meta_mem.insert(key, v.value().to_vec());
                }
            }
            Err(redb::TableError::TableDoesNotExist(_)) => {}
            Err(e) => anyhow::bail!("opening the meta table in the redb state database at {} failed: {e}", path.display()),
        }
        Ok(RedbStore {
            db,
            mem,
            dirty: std::sync::Mutex::new(std::collections::HashSet::new()),
            meta_mem,
            meta_dirty: std::sync::Mutex::new(std::collections::HashSet::new()),
        })
    }

    /// Number of live accounts (for migration reporting / tests).
    pub fn len(&self) -> usize {
        self.mem.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mem.is_empty()
    }
}

impl StateStore for RedbStore {
    fn get(&self, key: &Pubkey) -> Option<Account> {
        self.mem.get(key).cloned()
    }

    fn set(&mut self, key: Pubkey, account: Account) {
        self.mem.insert(key, account);
        self.dirty.lock().expect("dirty set mutex is never poisoned").insert(key);
    }

    fn remove(&mut self, key: &Pubkey) {
        self.mem.remove(key);
        self.dirty.lock().expect("dirty set mutex is never poisoned").insert(*key);
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (Pubkey, Account)> + '_> {
        Box::new(self.mem.iter().map(|(k, v)| (*k, v.clone())))
    }

    fn put_meta(&mut self, key: &str, value: Vec<u8>) {
        self.meta_mem.insert(key.to_string(), value);
        self.meta_dirty.lock().expect("meta dirty set mutex is never poisoned").insert(key.to_string());
    }

    fn get_meta(&self, key: &str) -> Option<Vec<u8>> {
        self.meta_mem.get(key).cloned()
    }

    fn supports_atomic_meta(&self) -> bool {
        true
    }

    /// ATOMIC per-round commit (mainnet). Every dirty ACCOUNT (payer/receiver
    /// balance+nonce, fee pools, staking, treasury, economic params) AND every
    /// staged META value (the executed-round checkpoint, the economics counters)
    /// commit in ONE redb write transaction, fsync-durable (`Durability::Immediate`).
    /// It is all-or-nothing: a power loss either sees the whole round or none of
    /// it — the account state and the round number can never split. On ANY error
    /// this returns `Err` and does NOT clear the dirty sets; the node treats that
    /// as FATAL and halts (it must never continue on half-written state).
    fn flush(&self) -> anyhow::Result<()> {
        let mut dirty = self.dirty.lock().expect("dirty set mutex is never poisoned");
        let mut meta_dirty = self.meta_dirty.lock().expect("meta dirty set mutex is never poisoned");
        if dirty.is_empty() && meta_dirty.is_empty() {
            return Ok(());
        }
        let mut wtx = self.db.begin_write()?;
        // Fsync the commit so it survives a power loss — the whole point of the
        // atomic-storage guarantee. (Immediate is redb's default, set explicitly.)
        wtx.set_durability(redb::Durability::Immediate);
        {
            let mut table = wtx.open_table(REDB_ACCOUNTS)?;
            for key in dirty.iter() {
                match self.mem.get(key) {
                    Some(account) => {
                        let bytes = borsh::to_vec(account).expect("Account always serializes");
                        table.insert(key.to_bytes().as_slice(), bytes.as_slice())?;
                    }
                    None => {
                        table.remove(key.to_bytes().as_slice())?;
                    }
                }
            }
        }
        {
            let mut mtable = wtx.open_table(REDB_META)?;
            for key in meta_dirty.iter() {
                match self.meta_mem.get(key) {
                    Some(value) => {
                        mtable.insert(key.as_bytes(), value.as_slice())?;
                    }
                    None => {
                        mtable.remove(key.as_bytes())?;
                    }
                }
            }
        }
        wtx.commit()?;
        // Clear only AFTER the commit fsynced, so a failed commit retries the
        // same keys next time (and, since the node halts on the returned Err,
        // never on a half-applied state).
        dirty.clear();
        meta_dirty.clear();
        Ok(())
    }

    fn needs_periodic_flush(&self) -> bool {
        true
    }
}

/// A redb-backed append/keyed blob log - the modern-engine replacement for the
/// node's auxiliary `sled::Db` logs (transfer receipts, worker batches, staking
/// events, DAG certificates, epoch committees). Same measured motivation as
/// `RedbStore`: under a write burst sled 0.34 retains multi-GB it never reclaims
/// (the receipt log alone measured 721MB on disk for a 6000-tx flood, driving
/// RSS), whereas redb reclaims freed pages for reuse so the file tracks the live
/// working set.
///
/// Mirrors just the slice of sled's `Db` API these logs use: `generate_id`
/// (monotonic key, so receipt/staking iteration stays oldest-first), `insert`,
/// `get`, `remove`, `iter`, `len`, `flush`. **Write model** (same as `RedbStore`,
/// so per-insert `fsync` doesn't tank throughput): writes buffer in `pending` and
/// commit in one transaction on `flush()`; `get` consults `pending` (last write
/// wins) before redb. `iter`/`len` read committed state and are only used at boot
/// (pending empty) and right after a `flush` (prune), never mid-round. Best-effort
/// like the sled logs it replaces: a commit failure is logged, the entries stay
/// pending and retry on the next flush.
/// One buffered write: `(key, Some(value))` is an upsert, `(key, None)` a delete.
type PendingWrite = (Vec<u8>, Option<Vec<u8>>);

pub struct RedbLog {
    db: redb::Database,
    pending: std::sync::Mutex<Vec<PendingWrite>>,
    next_id: std::sync::atomic::AtomicU64,
}

const REDB_LOG_TABLE: redb::TableDefinition<'static, &'static [u8], &'static [u8]> = redb::TableDefinition::new("log");

impl RedbLog {
    /// Opens (creating if absent) a redb log at `path`. Initializes the monotonic
    /// id counter past the largest existing 8-byte key so `generate_id` never
    /// collides with a reloaded entry.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let db = redb::Database::create(path).map_err(|e| anyhow::anyhow!("opening the redb log at {} failed: {e}", path.display()))?;
        let mut max_id = 0u64;
        let rtx = db.begin_read().map_err(|e| anyhow::anyhow!("reading the redb log at {} failed: {e}", path.display()))?;
        if let Ok(table) = rtx.open_table(REDB_LOG_TABLE) {
            use redb::ReadableTable;
            let iter = table.iter().map_err(|e| anyhow::anyhow!("iterating the redb log at {} failed: {e}", path.display()))?;
            for entry in iter {
                let (k, _v) = entry.map_err(|e| anyhow::anyhow!("reading the redb log at {} failed: {e}", path.display()))?;
                let kb = k.value();
                if kb.len() == 8 {
                    let id = u64::from_be_bytes(kb.try_into().expect("length checked to be 8"));
                    if id >= max_id {
                        max_id = id + 1;
                    }
                }
            }
        }
        Ok(RedbLog {
            db,
            pending: std::sync::Mutex::new(Vec::new()),
            next_id: std::sync::atomic::AtomicU64::new(max_id),
        })
    }

    /// A fresh monotonic id (big-endian), matching sled's `generate_id` role:
    /// used as the key for receipt/staking entries so iteration is oldest-first.
    pub fn generate_id(&self) -> [u8; 8] {
        self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed).to_be_bytes()
    }

    pub fn insert(&self, key: &[u8], value: Vec<u8>) {
        self.pending.lock().expect("log pending mutex not poisoned").push((key.to_vec(), Some(value)));
    }

    pub fn remove(&self, key: &[u8]) {
        self.pending.lock().expect("log pending mutex not poisoned").push((key.to_vec(), None));
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        // Pending writes (most recent last) shadow committed state.
        {
            let pending = self.pending.lock().expect("log pending mutex not poisoned");
            for (k, v) in pending.iter().rev() {
                if k.as_slice() == key {
                    return v.clone();
                }
            }
        }
        let rtx = self.db.begin_read().ok()?;
        let table = rtx.open_table(REDB_LOG_TABLE).ok()?;
        table.get(key).ok().flatten().map(|g| g.value().to_vec())
    }

    /// Number of committed entries. Assumes `pending` was flushed (callers -
    /// prune - flush first); used only for prune sizing, never a hot path.
    pub fn len(&self) -> usize {
        let Ok(rtx) = self.db.begin_read() else { return 0 };
        let Ok(table) = rtx.open_table(REDB_LOG_TABLE) else { return 0 };
        use redb::ReadableTableMetadata;
        table.len().unwrap_or(0) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every committed (key, value), in key order (oldest-first for the u64-keyed
    /// receipt/staking logs). Used at boot reload and, after a `flush`, by prune.
    pub fn iter(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        let Ok(rtx) = self.db.begin_read() else { return out };
        let Ok(table) = rtx.open_table(REDB_LOG_TABLE) else { return out };
        use redb::ReadableTable;
        if let Ok(iter) = table.iter() {
            for entry in iter.flatten() {
                out.push((entry.0.value().to_vec(), entry.1.value().to_vec()));
            }
        }
        out
    }

    /// Reclaim freed pages by rewriting the file to its live working-set size -
    /// the thing sled 0.34 never does (it retains a burst's pages forever). redb
    /// grows under a write burst too, but `compact` returns the file to ~the live
    /// size afterward. Needs exclusive access (no open transactions), so the node
    /// calls it at boot (before serving) - transient flood growth is reclaimed on
    /// the next restart, and steady-state stays bounded. Returns whether it ran.
    pub fn compact(&mut self) -> bool {
        self.db.compact().unwrap_or(false)
    }

    /// Commit all buffered writes in one transaction, then clear the buffer.
    pub fn flush(&self) {
        let mut pending = self.pending.lock().expect("log pending mutex not poisoned");
        if pending.is_empty() {
            return;
        }
        let commit = || -> anyhow::Result<()> {
            let wtx = self.db.begin_write()?;
            {
                let mut table = wtx.open_table(REDB_LOG_TABLE)?;
                for (k, v) in pending.iter() {
                    match v {
                        Some(val) => {
                            table.insert(k.as_slice(), val.as_slice())?;
                        }
                        None => {
                            table.remove(k.as_slice())?;
                        }
                    }
                }
            }
            wtx.commit()?;
            Ok(())
        };
        match commit() {
            Ok(()) => pending.clear(),
            Err(e) => eprintln!("warning: failed to flush a redb log: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qchain_crypto::AlgorithmId;

    fn sample_account(balance: u64) -> Account {
        Account { balance, nonce: 0, algorithm_id: AlgorithmId(1), owner: Pubkey::new([0u8; 32]), code_hash: [0u8; 32], data: vec![] }
    }

    #[test]
    fn get_returns_none_for_a_key_that_was_never_set() {
        let dir = tempfile::tempdir().unwrap();
        let store = SledStore::open(dir.path()).unwrap();
        assert!(store.get(&Pubkey::new([1u8; 32])).is_none());
    }

    #[test]
    fn set_then_get_roundtrips_the_account() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SledStore::open(dir.path()).unwrap();
        let key = Pubkey::new([1u8; 32]);
        store.set(key, sample_account(100));
        assert_eq!(store.get(&key), Some(sample_account(100)));
    }

    /// `open` must reject a database with an undecodable account value up
    /// front, as a clean error - not defer it to a mid-run panic. Fail-loud
    /// on corrupt own-disk state is deliberate (a silently-dropped balance
    /// could mint or destroy value), but it should be a startup error, not a
    /// panic deep in consensus.
    #[test]
    fn open_rejects_a_database_with_a_corrupt_account_value() {
        let dir = tempfile::tempdir().unwrap();
        {
            // Write a valid 32-byte key with a value that is not a Borsh
            // `Account`, directly via sled (bypassing `set`'s encoding).
            let raw = sled::open(dir.path()).unwrap();
            raw.insert([9u8; 32], b"this is not a borsh-encoded account".to_vec()).unwrap();
            raw.flush().unwrap();
        }
        let result = SledStore::open(dir.path());
        let err = match result {
            Ok(_) => panic!("a corrupt value must make open fail, not succeed"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("corrupt state database"), "the error must clearly name the corruption, got: {err}");
    }

    #[test]
    fn open_accepts_a_clean_database_written_by_set() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = SledStore::open(dir.path()).unwrap();
            store.set(Pubkey::new([1u8; 32]), sample_account(42));
        }
        // Reopening a database this store itself wrote must pass validation.
        let store = SledStore::open(dir.path()).expect("a database written only via set must reopen cleanly");
        assert_eq!(store.get(&Pubkey::new([1u8; 32])), Some(sample_account(42)));
    }

    #[test]
    fn set_overwrites_a_previous_value_for_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SledStore::open(dir.path()).unwrap();
        let key = Pubkey::new([1u8; 32]);
        store.set(key, sample_account(100));
        store.set(key, sample_account(200));
        assert_eq!(store.get(&key), Some(sample_account(200)));
    }

    #[test]
    fn remove_deletes_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SledStore::open(dir.path()).unwrap();
        let key = Pubkey::new([1u8; 32]);
        store.set(key, sample_account(100));
        store.remove(&key);
        assert!(store.get(&key).is_none());
    }

    #[test]
    fn iter_yields_every_key_that_was_set_and_not_removed() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SledStore::open(dir.path()).unwrap();
        let key_a = Pubkey::new([1u8; 32]);
        let key_b = Pubkey::new([2u8; 32]);
        let key_c = Pubkey::new([3u8; 32]);
        store.set(key_a, sample_account(1));
        store.set(key_b, sample_account(2));
        store.set(key_c, sample_account(3));
        store.remove(&key_b);

        let mut entries: Vec<_> = store.iter().collect();
        entries.sort_by_key(|(k, _)| k.to_bytes());
        assert_eq!(entries, vec![(key_a, sample_account(1)), (key_c, sample_account(3))]);
    }

    /// The actual point of this whole module: a validator's state must
    /// survive a real process restart, not just stay readable within the
    /// same `SledStore` instance. Dropping the store and reopening a new
    /// one at the same path is the closest a unit test gets to that
    /// without spawning a second process.
    #[test]
    fn data_survives_dropping_and_reopening_the_store_at_the_same_path() {
        let dir = tempfile::tempdir().unwrap();
        let key = Pubkey::new([9u8; 32]);
        {
            let mut store = SledStore::open(dir.path()).unwrap();
            store.set(key, sample_account(42));
        }
        let reopened = SledStore::open(dir.path()).unwrap();
        assert_eq!(reopened.get(&key), Some(sample_account(42)));
    }

    // ---- RedbStore (the modern-engine migration target) ----

    fn redb_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("state.redb")
    }

    #[test]
    fn redb_set_get_remove_iter_behave_like_the_trait_expects() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = RedbStore::open(&redb_path(dir.path())).unwrap();
        let a = Pubkey::new([1u8; 32]);
        let b = Pubkey::new([2u8; 32]);
        assert!(store.get(&a).is_none());
        store.set(a, sample_account(100));
        store.set(b, sample_account(200));
        assert_eq!(store.get(&a), Some(sample_account(100)));
        store.set(a, sample_account(150)); // overwrite
        assert_eq!(store.get(&a), Some(sample_account(150)));
        store.remove(&b);
        assert!(store.get(&b).is_none());
        let mut entries: Vec<_> = store.iter().collect();
        entries.sort_by_key(|(k, _)| k.to_bytes());
        assert_eq!(entries, vec![(a, sample_account(150))]);
    }

    /// The real point: state must survive a process restart, and it must survive
    /// it via an EXPLICIT `flush()` (redb's write-back model), not sled's timer.
    #[test]
    fn redb_data_survives_flush_then_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let key = Pubkey::new([9u8; 32]);
        {
            let mut store = RedbStore::open(&redb_path(dir.path())).unwrap();
            store.set(key, sample_account(42));
            store.set(Pubkey::new([7u8; 32]), sample_account(7));
            store.remove(&Pubkey::new([7u8; 32])); // a dirty delete must also persist
            store.flush().unwrap(); // durability happens here, not on a timer
        }
        let reopened = RedbStore::open(&redb_path(dir.path())).unwrap();
        assert_eq!(reopened.get(&key), Some(sample_account(42)));
        assert!(reopened.get(&Pubkey::new([7u8; 32])).is_none(), "a flushed delete must not reappear");
        assert_eq!(reopened.len(), 1);
    }

    /// Writes NOT flushed are lost on reopen - the documented durability bound
    /// (at most the current round's writes, since the node flushes each round).
    #[test]
    fn redb_unflushed_writes_are_not_persisted() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = RedbStore::open(&redb_path(dir.path())).unwrap();
            store.set(Pubkey::new([1u8; 32]), sample_account(1));
            // no flush()
        }
        let reopened = RedbStore::open(&redb_path(dir.path())).unwrap();
        assert!(reopened.is_empty(), "unflushed writes must not survive (crash-loss bound)");
    }

    // ---- ATOMIC per-round commit: state + round can never split (mainnet) -----

    /// The whole point of the atomicity work: a round's ACCOUNT writes AND its
    /// executed-round checkpoint commit in ONE transaction, so a crash at ANY
    /// stage of the round leaves either the WHOLE previous round or the WHOLE new
    /// round on disk — never a mix (e.g. the round advanced but the payer's debit
    /// lost, or vice versa). This models a validator that:
    ///   round 1: writes 4 accounts (payer, receiver, fee pool, staking) + round=1, commits;
    ///   round 2: writes the same 4 accounts to new values + round=2, then CRASHES
    ///            before the commit (dropping the store without `flush`).
    /// After the crash the reopened store must show the FULL round-1 state and
    /// round=1 — not a single round-2 write, and definitely not round=2 with
    /// stale accounts.
    #[test]
    fn redb_a_crash_before_commit_keeps_the_whole_previous_round_never_a_partial() {
        let dir = tempfile::tempdir().unwrap();
        let payer = Pubkey::new([1u8; 32]);
        let receiver = Pubkey::new([2u8; 32]);
        let fee_pool = Pubkey::new([3u8; 32]);
        let staking = Pubkey::new([4u8; 32]);
        // Round 1: a full, committed round.
        {
            let mut s = RedbStore::open(&redb_path(dir.path())).unwrap();
            s.set(payer, sample_account(1000));
            s.set(receiver, sample_account(0));
            s.set(fee_pool, sample_account(0));
            s.set(staking, sample_account(0));
            s.put_meta("next_round", 1u64.to_le_bytes().to_vec());
            s.flush().unwrap();
        }
        // Round 2: stage every write + the round advance, then CRASH before flush.
        {
            let mut s = RedbStore::open(&redb_path(dir.path())).unwrap();
            s.set(payer, sample_account(900)); // debited
            s.set(receiver, sample_account(90)); // credited
            s.set(fee_pool, sample_account(10)); // fee
            s.set(staking, sample_account(5)); // reward
            s.put_meta("next_round", 2u64.to_le_bytes().to_vec());
            // <-- power loss here: `s` is dropped WITHOUT flush().
        }
        // Recovery: the entire round-1 state, consistent with round=1. Not one
        // round-2 write survived, and the round did NOT advance.
        let r = RedbStore::open(&redb_path(dir.path())).unwrap();
        assert_eq!(r.get(&payer), Some(sample_account(1000)), "payer must NOT be debited by the uncommitted round");
        assert_eq!(r.get(&receiver), Some(sample_account(0)), "receiver must NOT be credited");
        assert_eq!(r.get(&fee_pool), Some(sample_account(0)));
        assert_eq!(r.get(&staking), Some(sample_account(0)));
        assert_eq!(r.get_meta("next_round"), Some(1u64.to_le_bytes().to_vec()), "the round must NOT have advanced without its state");
    }

    /// The success side: once a round commits, ALL of it is durable together —
    /// every account write AND the round number — and they agree on reopen.
    #[test]
    fn redb_a_committed_round_restores_state_and_round_together() {
        let dir = tempfile::tempdir().unwrap();
        let payer = Pubkey::new([1u8; 32]);
        let receiver = Pubkey::new([2u8; 32]);
        {
            let mut s = RedbStore::open(&redb_path(dir.path())).unwrap();
            s.set(payer, sample_account(900));
            s.set(receiver, sample_account(90));
            s.put_meta("next_round", 7u64.to_le_bytes().to_vec());
            s.put_meta("economics", vec![1, 2, 3, 4]); // opaque economics blob rides along
            s.flush().unwrap();
        }
        let r = RedbStore::open(&redb_path(dir.path())).unwrap();
        assert_eq!(r.get(&payer), Some(sample_account(900)));
        assert_eq!(r.get(&receiver), Some(sample_account(90)));
        assert_eq!(r.get_meta("next_round"), Some(7u64.to_le_bytes().to_vec()));
        assert_eq!(r.get_meta("economics"), Some(vec![1, 2, 3, 4]));
    }

    /// Crashing at each successive stage WITHIN a round all collapse to the same
    /// safe outcome (the previous committed round), because nothing touches disk
    /// until the single `flush`. This walks the stages explicitly: after the
    /// payer write, after the receiver write, after staging the round meta —
    /// each a fresh reopen of a store that never flushed — and every one recovers
    /// round 0 (the genesis-committed baseline), proving no intermediate write
    /// leaks to disk.
    #[test]
    fn redb_kill_at_each_stage_of_a_round_always_recovers_the_last_committed_round() {
        let dir = tempfile::tempdir().unwrap();
        let payer = Pubkey::new([1u8; 32]);
        let receiver = Pubkey::new([2u8; 32]);
        // Baseline committed round 0.
        {
            let mut s = RedbStore::open(&redb_path(dir.path())).unwrap();
            s.set(payer, sample_account(500));
            s.put_meta("next_round", 0u64.to_le_bytes().to_vec());
            s.flush().unwrap();
        }
        // Enumerate the crash stages of the next round; none may reach disk.
        for stage in 0..3u8 {
            {
                let mut s = RedbStore::open(&redb_path(dir.path())).unwrap();
                s.set(payer, sample_account(400)); // stage 0: payer written
                if stage >= 1 {
                    s.set(receiver, sample_account(100));
                }
                if stage >= 2 {
                    s.put_meta("next_round", 1u64.to_le_bytes().to_vec());
                }
                // crash (drop without flush) at this stage
            }
            let r = RedbStore::open(&redb_path(dir.path())).unwrap();
            assert_eq!(r.get(&payer), Some(sample_account(500)), "stage {stage}: payer must be the committed baseline");
            assert!(r.get(&receiver).is_none(), "stage {stage}: receiver write must not leak to disk");
            assert_eq!(r.get_meta("next_round"), Some(0u64.to_le_bytes().to_vec()), "stage {stage}: round must not advance");
        }
    }

    #[test]
    fn redb_open_rejects_a_corrupt_account_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = redb_path(dir.path());
        {
            // Write a valid 32-byte key with a non-Account value directly.
            let db = redb::Database::create(&path).unwrap();
            let wtx = db.begin_write().unwrap();
            {
                let mut t = wtx.open_table(REDB_ACCOUNTS).unwrap();
                t.insert([9u8; 32].as_slice(), b"not a borsh account".as_slice()).unwrap();
            }
            wtx.commit().unwrap();
        }
        let err = match RedbStore::open(&path) {
            Ok(_) => panic!("a corrupt value must make open fail, not succeed"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("corrupt redb state database"), "must name the corruption, got: {err}");
    }

    /// Migration equivalence: the SAME sequence of writes, applied to a `SledStore`
    /// and a `RedbStore`, must yield the IDENTICAL account set - so migrating a
    /// live sled state into redb preserves every balance (and therefore the exact
    /// Merkle root the network agrees on). This is the correctness anchor for the
    /// sled->redb migration path.
    #[test]
    fn redb_log_generate_id_insert_get_iter_remove_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let log = RedbLog::open(&dir.path().join("l.redb")).unwrap();
        // Monotonic ids, oldest-first iteration.
        let mut keys = Vec::new();
        for i in 0..10u64 {
            let id = log.generate_id();
            log.insert(&id, vec![i as u8; 4]);
            keys.push(id);
        }
        // get() sees a pending (unflushed) write.
        assert_eq!(log.get(&keys[3]), Some(vec![3u8; 4]));
        log.flush();
        // Survives flush + reopen, oldest-first.
        drop(log);
        let log = RedbLog::open(&dir.path().join("l.redb")).unwrap();
        let all = log.iter();
        assert_eq!(all.len(), 10);
        assert_eq!(all[0].0, keys[0], "iteration is oldest-first (monotonic key order)");
        assert_eq!(all[9].0, keys[9]);
        // generate_id continues past the reloaded max (no collision).
        let next = log.generate_id();
        assert_eq!(u64::from_be_bytes(next), 10);
        // remove + flush drops it.
        log.remove(&keys[0]);
        log.flush();
        assert!(log.get(&keys[0]).is_none());
        assert_eq!(log.len(), 9);
    }

    /// THE decisive measure-first check for migrating the node's aux logs: does
    /// redb stay near the live working-set size under the receipt log's real
    /// access pattern (append many 32KB entries, flush per "round", prune the
    /// oldest to a cap), or does it bloat like sled (which retained 721MB on disk
    /// for this exact workload)? Reports the on-disk file size; ignored by default.
    #[test]
    #[ignore]
    fn bench_redb_log_size_under_receipt_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipts.redb");
        let log = RedbLog::open(&path).unwrap();
        const TOTAL: usize = 6000;
        const CAP: usize = 5000;
        const PER_ROUND: usize = 180;
        let blob = vec![7u8; 32 * 1024]; // ~32KB, like a real receipt (4 Merkle proofs)
        let mut count = 0usize;
        for i in 0..TOTAL {
            let id = log.generate_id();
            log.insert(&id, blob.clone());
            count += 1;
            if (i + 1) % PER_ROUND == 0 {
                log.flush(); // per-round durability
                // prune oldest beyond CAP (mirrors prune_log_to_last, post-flush)
                if count > CAP {
                    let excess = count - CAP;
                    let old: Vec<Vec<u8>> = log.iter().into_iter().take(excess).map(|(k, _)| k).collect();
                    for k in &old {
                        log.remove(k);
                    }
                    log.flush();
                    count -= excess;
                }
            }
        }
        log.flush();
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let mut log = log;
        let ran = log.compact();
        let size_after = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let logical = CAP * 32 * 1024;
        println!(
            "redb receipt-log after {TOTAL} inserts (32KB each), pruned to {CAP}: file {:.1} MB; after compact() ({ran}): {:.1} MB (logical working set {:.1} MB); sled retained 721 MB and never shrinks",
            size as f64 / 1e6,
            size_after as f64 / 1e6,
            logical as f64 / 1e6
        );
    }

    #[test]
    fn redb_and_sled_hold_identical_state_for_the_same_writes() {
        let sdir = tempfile::tempdir().unwrap();
        let rdir = tempfile::tempdir().unwrap();
        let mut sled = SledStore::open(sdir.path()).unwrap();
        let mut redb = RedbStore::open(&redb_path(rdir.path())).unwrap();
        for i in 0..500u32 {
            let k = Pubkey::new({
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&i.to_le_bytes());
                b
            });
            let acct = sample_account((i as u64 + 1) * 13);
            sled.set(k, acct.clone());
            redb.set(k, acct);
        }
        // Update and remove a few to exercise both paths.
        for i in (0..500u32).step_by(50) {
            let k = Pubkey::new({
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&i.to_le_bytes());
                b
            });
            if i % 100 == 0 {
                sled.remove(&k);
                redb.remove(&k);
            } else {
                sled.set(k, sample_account(999));
                redb.set(k, sample_account(999));
            }
        }
        let mut s: Vec<_> = sled.iter().collect();
        let mut r: Vec<_> = redb.iter().collect();
        s.sort_by_key(|(k, _)| k.to_bytes());
        r.sort_by_key(|(k, _)| k.to_bytes());
        assert_eq!(s, r, "sled and redb must hold identical state for identical writes");
    }
}
