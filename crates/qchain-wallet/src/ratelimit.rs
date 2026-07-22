//! Rate limiting for the wallet's PUBLIC `/api/simulate` proxy, plus trusted
//! client-IP resolution.
//!
//! Why the wallet needs its own limiter (not just the node's): real users don't
//! hit the node directly — they go `client → Cloudflare/nginx → wallet → node`.
//! The wallet is the public edge. If it just forwards to the node over loopback,
//! the node sees every user as `127.0.0.1` and its per-IP limiter collapses them
//! into one bucket (useless), or is off entirely. So the wallet must (1) rate
//! limit `/api/simulate` by the REAL client IP at its own edge, and (2) resolve
//! that real IP and forward it, sanitized, to the node so the node's own per-IP
//! limiter meters real clients too (defense in depth).
//!
//! The counter design mirrors `qchain-node`'s `SimRateLimiter` deliberately —
//! both WINDOW-ONLY (no ban, so users sharing one address behind a proxy, or a
//! victim's txid, can't be locked out), both bounded and GC-throttled (a spray
//! of distinct keys can't force an O(n) sweep per request, and a full-of-live
//! map fails closed on a new key). The wallet adds Cloudflare's canonical
//! `CF-Connecting-IP` header and FAIL-CLOSED semantics when no trustworthy
//! client identity can be established.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const RL_WINDOW: Duration = Duration::from_secs(10);
/// Bound on tracked keys (per IP and per txid) so the limiter can't be an OOM.
const MAX_TRACKED_KEYS: usize = 100_000;

/// Default per-IP `/api/simulate` cap (10 s window) when the wallet is public and
/// the operator didn't set one — the recommended starting value.
pub const DEFAULT_SIM_PER_IP_10S: u32 = 8;
/// Floor a public per-IP cap can never go below (a `0`/absurdly-low config can't
/// neuter the protection on a public wallet).
pub const MIN_SIM_PER_IP_10S: u32 = 5;
/// Per-txid `/api/simulate` cap (10 s window), wallet-wide. Generous — a real
/// wallet simulates a given tx once or twice before sending. Defense in depth on
/// top of the node's own per-txid gate.
pub const SIM_PER_TXID_10S: u32 = 20;

struct Window {
    start: Instant,
    count: u32,
}

/// A bounded per-key sliding-window counter. Window-only (no ban): the excess in
/// a window gets a 429 and the key recovers automatically next window.
struct WindowMap<K> {
    map: HashMap<K, Window>,
    last_gc: Instant,
}

impl<K: std::hash::Hash + Eq> WindowMap<K> {
    fn new() -> Self {
        Self { map: HashMap::new(), last_gc: Instant::now() }
    }

    /// `true` = within `limit` for the current window. Bounded and GC-THROTTLED:
    /// the expired-entry sweep runs at most once per second (so a spray of
    /// distinct keys can't force an O(n) `retain` on every request), and when the
    /// map is full of still-live entries a brand-new key is rejected (fail closed).
    fn allow(&mut self, key: K, limit: u32, now: Instant) -> bool {
        if self.map.len() >= MAX_TRACKED_KEYS && now.duration_since(self.last_gc) >= Duration::from_secs(1) {
            self.map.retain(|_, w| now.duration_since(w.start) < RL_WINDOW);
            self.last_gc = now;
        }
        if self.map.len() >= MAX_TRACKED_KEYS && !self.map.contains_key(&key) {
            return false;
        }
        let w = self.map.entry(key).or_insert(Window { start: now, count: 0 });
        if now.duration_since(w.start) >= RL_WINDOW {
            w.start = now;
            w.count = 0;
        }
        w.count = w.count.saturating_add(1);
        w.count <= limit
    }
}

/// Per-IP + per-txid sliding-window limiter for the wallet's `/api/simulate`.
#[derive(Clone)]
pub struct SimRateLimiter {
    per_ip: Arc<Mutex<WindowMap<IpAddr>>>,
    per_txid: Arc<Mutex<WindowMap<[u8; 32]>>>,
    ip_limit: u32,
    txid_limit: u32,
    trust_proxy: bool,
}

impl SimRateLimiter {
    fn new(ip_limit: u32, txid_limit: u32, trust_proxy: bool) -> Self {
        Self {
            per_ip: Arc::new(Mutex::new(WindowMap::new())),
            per_txid: Arc::new(Mutex::new(WindowMap::new())),
            ip_limit,
            txid_limit,
            trust_proxy,
        }
    }

    /// Build the `/api/simulate` limiter for a wallet. **Mandatory when the wallet
    /// is reachable by remote clients** — a non-loopback bind (`exposed`), OR a
    /// loopback bind behind a trusted same-host proxy (`trust_proxy`, the
    /// Cloudflare-tunnel / nginx case). In that case it is always `Some`, with the
    /// per-IP cap forced to at least `MIN_SIM_PER_IP_10S` (a `None`/`0`/too-low
    /// config is raised to a safe value). On a genuinely private loopback bind it
    /// is opt-in: `Some` only if the operator set a positive value, else `None`.
    pub fn for_wallet(exposed: bool, trust_proxy: bool, configured_per_ip: Option<u32>) -> Option<Self> {
        let public = exposed || trust_proxy;
        let configured = configured_per_ip.filter(|&n| n > 0);
        let ip_limit = if public {
            configured.unwrap_or(DEFAULT_SIM_PER_IP_10S).max(MIN_SIM_PER_IP_10S)
        } else {
            configured?
        };
        Some(Self::new(ip_limit, SIM_PER_TXID_10S, trust_proxy))
    }

    pub fn trust_proxy(&self) -> bool {
        self.trust_proxy
    }

    #[cfg(test)]
    pub fn ip_limit(&self) -> u32 {
        self.ip_limit
    }

    /// `true` = allowed. Per-IP sliding window, window-only (no ban).
    pub fn allow_ip(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        self.per_ip.lock().unwrap_or_else(|e| e.into_inner()).allow(ip, self.ip_limit, now)
    }

    /// `true` = allowed. Per-txid sliding window, window-only.
    pub fn allow_txid(&self, txid: [u8; 32]) -> bool {
        let now = Instant::now();
        self.per_txid.lock().unwrap_or_else(|e| e.into_inner()).allow(txid, self.txid_limit, now)
    }
}

/// Resolve the REAL client IP for rate limiting AND for forwarding to the node.
/// Returns `None` when the wallet is in trusted-proxy mode but no trustworthy
/// client identity could be established — the caller FAILS CLOSED (429) rather
/// than bucketing every user under the proxy's loopback address.
///
/// Rules:
///  - `trust_proxy` && `peer` is loopback (the request arrived via our trusted
///    same-host proxy): read the real client from `CF-Connecting-IP` (Cloudflare's
///    canonical single-value header, not client-appendable through Cloudflare)
///    first, else the RIGHTMOST `X-Forwarded-For` hop (the address our own proxy
///    appended — a client-injected value ends up to the LEFT, so it can't spoof
///    past it). Neither valid → `None` (fail closed). Assumes a SINGLE trusted hop.
///  - `trust_proxy` && `peer` NOT loopback: someone hit the public wallet bind
///    directly, bypassing the proxy → use the `peer` (a real remote); NEVER trust
///    a forwarding header from a direct remote peer.
///  - `!trust_proxy`: a direct public bind (or a private loopback dev box) → use
///    the `peer`.
pub fn resolve_client_ip(trust_proxy: bool, peer: IpAddr, headers: &axum::http::HeaderMap) -> Option<IpAddr> {
    if trust_proxy && peer.is_loopback() {
        if let Some(ip) = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return Some(ip);
        }
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|xff| xff.rsplit(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return Some(ip);
        }
        return None; // fail closed: can't identify the client behind the proxy
    }
    Some(peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn for_wallet_is_mandatory_when_reachable_by_remotes() {
        // Non-loopback public bind: mandatory, default, floored.
        assert_eq!(SimRateLimiter::for_wallet(true, false, None).unwrap().ip_limit(), DEFAULT_SIM_PER_IP_10S);
        assert_eq!(SimRateLimiter::for_wallet(true, false, Some(0)).unwrap().ip_limit(), DEFAULT_SIM_PER_IP_10S, "0 -> default");
        assert_eq!(SimRateLimiter::for_wallet(true, false, Some(2)).unwrap().ip_limit(), MIN_SIM_PER_IP_10S, "too low -> floor");
        assert_eq!(SimRateLimiter::for_wallet(true, false, Some(9)).unwrap().ip_limit(), 9, "honoured above floor");
        // Loopback behind a trusted proxy: also mandatory + records the flag.
        let p = SimRateLimiter::for_wallet(false, true, None).unwrap();
        assert_eq!(p.ip_limit(), DEFAULT_SIM_PER_IP_10S);
        assert!(p.trust_proxy());
        // Genuinely private loopback (no proxy): opt-in.
        assert!(SimRateLimiter::for_wallet(false, false, None).is_none(), "private loopback unset -> off");
        assert!(SimRateLimiter::for_wallet(false, false, Some(0)).is_none());
        assert_eq!(SimRateLimiter::for_wallet(false, false, Some(3)).unwrap().ip_limit(), 3, "opt-in honoured verbatim");
    }

    #[test]
    fn per_ip_and_per_txid_are_window_only() {
        let rl = SimRateLimiter::new(3, 2, false);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(rl.allow_ip(a) && rl.allow_ip(a) && rl.allow_ip(a), "up to cap");
        assert!(!rl.allow_ip(a), "over cap rejected");
        assert!(!rl.allow_ip(a), "still over in this window");
        assert!(rl.allow_ip(b), "a separate IP is unaffected");
        let t1 = [1u8; 32];
        let t2 = [2u8; 32];
        assert!(rl.allow_txid(t1) && rl.allow_txid(t1), "up to txid cap");
        assert!(!rl.allow_txid(t1), "over txid cap");
        assert!(rl.allow_txid(t2), "a different txid unaffected");
    }

    #[test]
    fn resolve_client_ip_trusts_headers_only_from_a_loopback_proxy_and_fails_closed() {
        let loop_peer: IpAddr = "127.0.0.1".parse().unwrap();
        let remote_peer: IpAddr = "198.51.100.2".parse().unwrap();
        let cf: IpAddr = "203.0.113.9".parse().unwrap();
        let xff_ip: IpAddr = "203.0.113.77".parse().unwrap();

        // CF-Connecting-IP from a loopback proxy -> used (preferred over XFF).
        let mut h = axum::http::HeaderMap::new();
        h.insert("cf-connecting-ip", "203.0.113.9".parse().unwrap());
        h.insert("x-forwarded-for", "203.0.113.77".parse().unwrap());
        assert_eq!(resolve_client_ip(true, loop_peer, &h), Some(cf), "CF header preferred");

        // Only XFF present -> rightmost hop used.
        let mut hx = axum::http::HeaderMap::new();
        hx.insert("x-forwarded-for", "1.2.3.4, 203.0.113.77".parse().unwrap());
        assert_eq!(resolve_client_ip(true, loop_peer, &hx), Some(xff_ip), "rightmost XFF hop, spoof-resistant");

        // Trusted mode but NO trustworthy header -> fail closed (None).
        let empty = axum::http::HeaderMap::new();
        assert_eq!(resolve_client_ip(true, loop_peer, &empty), None, "no client identity -> fail closed");
        let mut hbad = axum::http::HeaderMap::new();
        hbad.insert("cf-connecting-ip", "not-an-ip".parse().unwrap());
        assert_eq!(resolve_client_ip(true, loop_peer, &hbad), None, "garbage header -> fail closed");

        // Trusted mode but the direct peer is NOT loopback -> ignore headers, use peer.
        assert_eq!(resolve_client_ip(true, remote_peer, &h), Some(remote_peer), "direct remote: header ignored");

        // Trust off -> always the peer, headers ignored.
        assert_eq!(resolve_client_ip(false, remote_peer, &h), Some(remote_peer));
        assert_eq!(resolve_client_ip(false, loop_peer, &h), Some(loop_peer));
    }
}
