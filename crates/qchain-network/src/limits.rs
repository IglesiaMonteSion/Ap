//! P2P connection limits, per-peer quotas and temporary bans (task #208 —
//! "endurecer completamente el P2P"). This is the runtime accounting the
//! transport consults on every accepted inbound connection so that a malicious
//! peer cannot exhaust a validator's connections, file descriptors, memory or
//! bandwidth. It is **always on** with generous defaults that honest validator
//! traffic never trips — it is a pure DoS backstop at the TCP/connection layer,
//! orthogonal to whether the transport is authenticated/encrypted (the auth-off
//! path is byte-identical on the wire; only rejected-abuse connections behave
//! differently).
//!
//! What it enforces (all bounded, so the limiter can never itself become the OOM
//! it prevents):
//!
//! * **Global connection cap** — a hard ceiling on total live inbound
//!   connections. A fully-connected set of `N` validators gives each node `N-1`
//!   inbound connections, so the default is far above any real validator set.
//! * **Per-IP cap** — bounds how many inbound connections a single source IP may
//!   hold at once, so one host can't open thousands.
//! * **One connection per validator identity** — once a connection authenticates
//!   (auth on), any *older* connection from the same validator id is force-closed
//!   and the fresh one kept. A reconnect after a network blip supersedes a stale
//!   half-open connection instead of being rejected (which would hurt liveness).
//! * **Per-peer bandwidth quota** — a rolling-window byte budget per connection;
//!   a peer that sustains well over it across several windows is temporarily
//!   banned. Generous enough that a legitimate certificate/batch resync burst
//!   never trips it (hysteresis via `abuse_strikes_before_ban`).
//! * **Temporary bans** — an abusive IP/identity is refused new connections for a
//!   cooldown, matching the RPC limiter's temp-ban posture.
//!
//! Timing uses `std::time::Instant` (wall-clock, node-local operational policy —
//! exactly like the RPC rate limiter). None of this feeds consensus or state, so
//! it has no determinism/DST implication.

use qchain_core::ValidatorId;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// Bounds the ban maps so a spray of distinct source IPs/identities can't turn
/// the limiter itself into an OOM (expired entries are GC'd first).
const MAX_BANNED: usize = 100_000;

/// Tunable connection/quota limits. Defaults are generous multiples of real
/// validator traffic so honest peers never trip them; an operator can lower them
/// for a hostile environment.
#[derive(Clone, Debug)]
pub struct P2pLimits {
    /// Hard ceiling on total live inbound connections.
    pub max_inbound_connections: usize,
    /// Max live inbound connections from a single source IP.
    pub max_connections_per_ip: usize,
    /// How long an abusive IP/identity is refused new connections.
    pub ban: Duration,
    /// Rolling window over which per-peer bytes are counted.
    pub bandwidth_window: Duration,
    /// Max wire bytes a single connection may read within one window before it
    /// counts as a strike.
    pub max_bytes_per_window: u64,
    /// Consecutive over-budget windows before the peer is banned (hysteresis, so
    /// a momentary legitimate burst doesn't ban).
    pub abuse_strikes_before_ban: u32,
}

impl Default for P2pLimits {
    fn default() -> Self {
        Self {
            // A fully-connected set of N validators → N-1 inbound each; 2048 is
            // far above any real set this project targets, and the user's live
            // network (n=1..a few) uses a handful.
            max_inbound_connections: 2048,
            // A single peer normally holds exactly one inbound connection; 32
            // gives ample headroom for a reconnect race or several validators
            // legitimately behind one NAT/IP, while bounding a single-host flood.
            max_connections_per_ip: 32,
            ban: Duration::from_secs(60),
            bandwidth_window: Duration::from_secs(10),
            // 128 MiB / 10 s ≈ 12.8 MB/s sustained per peer — a large real
            // certificate/batch resync burst is well under this; a raw byte flood
            // is well over.
            max_bytes_per_window: 128 * 1024 * 1024,
            abuse_strikes_before_ban: 3,
        }
    }
}

/// One live inbound connection registered under a validator identity, with the
/// signal used to force it closed when a fresher connection from the same id
/// supersedes it.
struct ConnHandle {
    seq: u64,
    close: Arc<Notify>,
}

#[derive(Default)]
struct Inner {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
    per_validator: HashMap<ValidatorId, Vec<ConnHandle>>,
    banned_ips: HashMap<IpAddr, Instant>,
    banned_ids: HashMap<ValidatorId, Instant>,
    next_seq: u64,
}

/// Shared inbound-connection accounting. Every method locks a `std::sync::Mutex`
/// for a cheap map op and never holds it across an `await`.
pub struct ConnTracker {
    pub limits: P2pLimits,
    inner: Mutex<Inner>,
}

impl ConnTracker {
    pub fn new(limits: P2pLimits) -> Arc<Self> {
        Arc::new(Self { limits, inner: Mutex::new(Inner::default()) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Admit a freshly-accepted inbound connection from `ip`, or refuse it
    /// (banned IP, global cap, or per-IP cap reached). On success returns an
    /// RAII `IpGuard` that frees the slot(s) when dropped.
    pub fn admit_ip(self: &Arc<Self>, ip: IpAddr) -> Option<IpGuard> {
        let now = Instant::now();
        let mut inner = self.lock();
        // Drop expired bans first so they don't wedge a real reconnect.
        inner.banned_ips.retain(|_, &mut until| now < until);
        if inner.banned_ips.get(&ip).is_some_and(|&until| now < until) {
            return None;
        }
        if inner.total >= self.limits.max_inbound_connections {
            return None;
        }
        let count = inner.per_ip.entry(ip).or_insert(0);
        if *count >= self.limits.max_connections_per_ip {
            return None;
        }
        *count += 1;
        inner.total += 1;
        Some(IpGuard { tracker: self.clone(), ip, validator: None })
    }

    /// Register `guard`'s now-authenticated connection under validator `id`,
    /// force-closing any OLDER connection from the same id (one-per-identity;
    /// the fresh connection wins). Returns this connection's close-notify (the
    /// read loop selects on it), or `None` if `id` is currently banned.
    pub fn bind_validator(self: &Arc<Self>, guard: &mut IpGuard, id: ValidatorId) -> Option<Arc<Notify>> {
        let now = Instant::now();
        let mut inner = self.lock();
        inner.banned_ids.retain(|_, &mut until| now < until);
        if inner.banned_ids.get(&id).is_some_and(|&until| now < until) {
            return None;
        }
        let seq = inner.next_seq;
        inner.next_seq = inner.next_seq.wrapping_add(1);
        let notify = Arc::new(Notify::new());
        let list = inner.per_validator.entry(id).or_default();
        // One connection per identity: signal every existing one to close and
        // remove them, keeping only this fresh connection.
        for h in list.drain(..) {
            h.close.notify_one();
        }
        list.push(ConnHandle { seq, close: notify.clone() });
        guard.validator = Some((id, seq));
        Some(notify)
    }

    /// Temporarily ban an IP (abuse detected). `MAX_BANNED` is a HARD ceiling
    /// (task #18): GC expired entries, then insert only if there is room or the
    /// key already exists (refreshing an existing ban never grows the map). If
    /// still full of live bans, the ban is skipped rather than letting the map
    /// exceed the cap — harmless, since a ban is only minted by sustained abuse
    /// on a live inbound connection (globally capped), so the map can never
    /// realistically stay full, and a skipped ban is simply re-caught.
    pub fn ban_ip(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut inner = self.lock();
        if inner.banned_ips.len() >= MAX_BANNED {
            inner.banned_ips.retain(|_, &mut until| now < until);
            if inner.banned_ips.len() >= MAX_BANNED && !inner.banned_ips.contains_key(&ip) {
                return; // fail-closed: never exceed the ceiling
            }
        }
        inner.banned_ips.insert(ip, now + self.limits.ban);
    }

    /// Temporarily ban a validator identity (abuse detected). Same hard-ceiling
    /// fail-closed discipline as `ban_ip` (task #18).
    pub fn ban_id(&self, id: ValidatorId) {
        let now = Instant::now();
        let mut inner = self.lock();
        if inner.banned_ids.len() >= MAX_BANNED {
            inner.banned_ids.retain(|_, &mut until| now < until);
            if inner.banned_ids.len() >= MAX_BANNED && !inner.banned_ids.contains_key(&id) {
                return; // fail-closed: never exceed the ceiling
            }
        }
        inner.banned_ids.insert(id, now + self.limits.ban);
    }

    /// Current number of live inbound connections (read-only metric).
    pub fn live_connections(&self) -> usize {
        self.lock().total
    }
}

/// RAII guard for one live inbound connection. Frees the global + per-IP slots
/// and de-registers the validator identity (if bound) when dropped — i.e. when
/// the connection's `handle_inbound` returns for any reason.
pub struct IpGuard {
    tracker: Arc<ConnTracker>,
    ip: IpAddr,
    validator: Option<(ValidatorId, u64)>,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        let mut inner = self.tracker.lock();
        inner.total = inner.total.saturating_sub(1);
        if let Some(c) = inner.per_ip.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                inner.per_ip.remove(&self.ip);
            }
        }
        if let Some((id, seq)) = self.validator {
            if let Some(list) = inner.per_validator.get_mut(&id) {
                list.retain(|h| h.seq != seq);
                if list.is_empty() {
                    inner.per_validator.remove(&id);
                }
            }
        }
    }
}

/// Per-connection rolling-window bandwidth meter. `record` returns `false` once
/// the peer has been over budget for `abuse_strikes_before_ban` windows — the
/// caller then bans and drops it.
pub struct BandwidthMeter {
    window: Duration,
    cap: u64,
    max_strikes: u32,
    start: Instant,
    bytes: u64,
    strikes: u32,
}

impl BandwidthMeter {
    pub fn new(limits: &P2pLimits) -> Self {
        Self {
            window: limits.bandwidth_window,
            cap: limits.max_bytes_per_window,
            max_strikes: limits.abuse_strikes_before_ban,
            start: Instant::now(),
            bytes: 0,
            strikes: 0,
        }
    }

    /// Record `n` wire bytes just read. Returns `false` if the peer is now
    /// abusive (should be banned + disconnected).
    pub fn record(&mut self, n: usize) -> bool {
        let now = Instant::now();
        if now.duration_since(self.start) >= self.window {
            self.start = now;
            self.bytes = 0;
        }
        self.bytes = self.bytes.saturating_add(n as u64);
        if self.bytes > self.cap {
            self.strikes = self.strikes.saturating_add(1);
            self.bytes = 0;
            self.start = now;
            if self.strikes >= self.max_strikes {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_limits() -> P2pLimits {
        P2pLimits {
            max_inbound_connections: 3,
            max_connections_per_ip: 2,
            ban: Duration::from_millis(40),
            bandwidth_window: Duration::from_secs(10),
            max_bytes_per_window: 1000,
            abuse_strikes_before_ban: 2,
        }
    }

    #[test]
    fn per_ip_and_global_caps_are_enforced_and_freed_on_drop() {
        let t = ConnTracker::new(tiny_limits());
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        // Two from ip1 (the per-IP cap), then a third from ip1 is refused.
        let g1 = t.admit_ip(ip1).expect("first from ip1 admitted");
        let g2 = t.admit_ip(ip1).expect("second from ip1 admitted");
        assert!(t.admit_ip(ip1).is_none(), "third from ip1 exceeds the per-IP cap");
        // ip2 can still connect (up to the global cap of 3 → one slot left).
        let g3 = t.admit_ip(ip2).expect("ip2 admitted within the global cap");
        assert!(t.admit_ip(ip2).is_none(), "global cap of 3 reached");
        assert_eq!(t.live_connections(), 3);
        // Dropping a guard frees a slot for a new connection.
        drop(g1);
        assert_eq!(t.live_connections(), 2);
        let _g4 = t.admit_ip(ip1).expect("a freed slot admits a new connection");
        drop((g2, g3));
    }

    #[test]
    fn a_banned_ip_is_refused_until_the_ban_expires() {
        let t = ConnTracker::new(tiny_limits());
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        t.ban_ip(ip);
        assert!(t.admit_ip(ip).is_none(), "a banned IP is refused");
        std::thread::sleep(Duration::from_millis(60)); // > 40ms ban
        assert!(t.admit_ip(ip).is_some(), "the ban expires and the IP can reconnect");
    }

    #[tokio::test]
    async fn binding_a_second_connection_for_the_same_id_force_closes_the_first() {
        let t = ConnTracker::new(tiny_limits());
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let id = qchain_crypto::Pubkey::new([7u8; 32]);
        let mut g_old = t.admit_ip(ip).unwrap();
        let close_old = t.bind_validator(&mut g_old, id).expect("first bind ok");
        // A second connection from the same id supersedes the first.
        let mut g_new = t.admit_ip(ip).unwrap();
        let _close_new = t.bind_validator(&mut g_new, id).expect("second bind ok");
        // The old connection's close-notify must have fired (notify_one stores a
        // permit, so this returns immediately).
        tokio::time::timeout(Duration::from_millis(200), close_old.notified())
            .await
            .expect("the superseded (older) connection must be force-closed");
    }

    #[test]
    fn a_banned_validator_id_is_refused() {
        let t = ConnTracker::new(tiny_limits());
        let ip: IpAddr = "10.0.0.6".parse().unwrap();
        let id = qchain_crypto::Pubkey::new([8u8; 32]);
        t.ban_id(id);
        let mut g = t.admit_ip(ip).unwrap();
        assert!(t.bind_validator(&mut g, id).is_none(), "a banned validator id cannot bind a connection");
    }

    #[test]
    fn bandwidth_meter_strikes_then_signals_a_ban() {
        let mut m = BandwidthMeter::new(&tiny_limits()); // cap 1000, 2 strikes
        assert!(m.record(500), "under budget");
        // Exceeds cap → strike 1, still allowed (hysteresis).
        assert!(m.record(600), "first over-budget window is a strike, not a ban");
        // Exceeds cap again → strike 2 == max → ban signal.
        assert!(!m.record(1001), "the second over-budget window trips the ban");
    }
}
