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
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let db = sled::open(path)?;
        Ok(SledStore { db })
    }
}

impl StateStore for SledStore {
    fn get(&self, key: &Pubkey) -> Option<Account> {
        let bytes = self.db.get(key.to_bytes()).expect("sled get should not fail on a healthy database")?;
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
        Box::new(self.db.iter().map(|entry| {
            let (key_bytes, value_bytes) = entry.expect("sled iteration should not fail on a healthy database");
            let key = Pubkey::new(key_bytes.as_ref().try_into().expect("every key this store ever wrote is exactly 32 bytes"));
            let account = borsh::from_slice(&value_bytes).expect("a value written by this same store must decode as an Account");
            (key, account)
        }))
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
}
