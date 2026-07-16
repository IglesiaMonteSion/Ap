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
    /// `update-node.sh` flow is fully durable. Default no-op for the in-memory
    /// store (nothing to flush).
    fn flush(&self) {}

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

    fn flush(&self) {
        if let Err(e) = self.db.flush() {
            eprintln!("warning: failed to flush the sled state store: {e}");
        }
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
}

const REDB_ACCOUNTS: redb::TableDefinition<'static, &'static [u8], &'static [u8]> = redb::TableDefinition::new("accounts");

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
        Ok(RedbStore { db, mem, dirty: std::sync::Mutex::new(std::collections::HashSet::new()) })
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

    fn flush(&self) {
        let mut dirty = self.dirty.lock().expect("dirty set mutex is never poisoned");
        if dirty.is_empty() {
            return;
        }
        // Commit every dirty key's current mirror state to redb in one
        // transaction: present in `mem` => upsert, absent => delete.
        let commit = || -> anyhow::Result<()> {
            let wtx = self.db.begin_write()?;
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
            wtx.commit()?;
            Ok(())
        };
        match commit() {
            // Clear the dirty set only once the commit succeeded, so a transient
            // failure retries the same keys on the next flush.
            Ok(()) => dirty.clear(),
            // A failed commit is serious for a ledger, but `flush` is also called
            // from the shutdown path - log loudly and keep the keys dirty rather
            // than panic; the node re-derives from the DAG on restart.
            Err(e) => eprintln!("warning: failed to flush the redb state store: {e}"),
        }
    }

    fn needs_periodic_flush(&self) -> bool {
        true
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
            store.flush(); // durability happens here, not on a timer
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
