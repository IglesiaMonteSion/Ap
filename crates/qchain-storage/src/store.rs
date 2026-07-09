use qchain_core::Account;
use qchain_crypto::Pubkey;
use std::collections::BTreeMap;

/// Backend abstraction for account storage. `ARCHITECTURE.md` §3 calls for
/// RocksDB in production; this trait is what makes that swap possible
/// without touching the Merkle tree logic in `tree.rs`. Phase 1 (this
/// session) ships only `InMemoryStore` - real persistence is the next
/// concrete increment, not implemented here yet (see
/// `project-lessons-learned` for why: adding RocksDB's C++ build alongside
/// liboqs's in the same session was judged not worth the extra build-time
/// risk for a first working consensus/execution pipeline).
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
