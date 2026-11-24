//! In-memory rate limiting (single node): fixed windows per key. Keys are hashed with the
//! server secret so that no addresses are held in memory in plain text.
//! A restart resets the counters; that is acceptable for a single process.
//!
//! Each scope has its own table with its own size limit, so that flooding an unauthenticated
//! scope (`magic-email` with random addresses) cannot lock out authenticated ones (`ticket`,
//! `token-ip`). Entries whose window has ended are removed when a table is full, at most once
//! per second and scope (a full table must not cost a sweep over all keys per request); if it is
//! still full, only new keys of that scope are refused, known keys keep counting. Evicting known
//! keys instead would let an attacker reset their own counter.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::util::hmac_hex;

/// Maximum number of remembered keys per scope.
const MAX_KEYS: usize = 100_000;

#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub limit: u32,
    pub window_s: i64,
}

/// Window start, count and window length of one key.
type Bucket = (i64, u32, i64);

/// The keys of one scope and the time of its last sweep.
#[derive(Default)]
struct Table {
    buckets: HashMap<String, Bucket>,
    swept_s: i64,
}

pub struct RateLimiter {
    secret: Vec<u8>,
    max_keys: usize,
    scopes: Mutex<HashMap<String, Table>>,
}

impl RateLimiter {
    pub fn new(secret: &[u8]) -> Self {
        Self::with_max(secret, MAX_KEYS)
    }

    fn with_max(secret: &[u8], max_keys: usize) -> Self {
        Self {
            secret: secret.to_vec(),
            max_keys,
            scopes: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one attempt. `false`: limit reached.
    pub fn hit(&self, scope: &str, key: &str, rule: Rule, now_s: i64) -> bool {
        let id = hmac_hex(&self.secret, &[scope.as_bytes(), key.as_bytes()]);
        let Ok(mut scopes) = self.scopes.lock() else {
            return false;
        };
        let table = scopes.entry(scope.to_owned()).or_default();
        let buckets = &mut table.buckets;
        if !buckets.contains_key(&id) && buckets.len() >= self.max_keys {
            if table.swept_s != now_s {
                table.swept_s = now_s;
                buckets.retain(|_, (start, _, window)| now_s - *start < *window);
            }
            if buckets.len() >= self.max_keys {
                return false;
            }
        }
        let entry = buckets.entry(id).or_insert((now_s, 0, rule.window_s));
        if now_s - entry.0 >= rule.window_s {
            *entry = (now_s, 0, rule.window_s);
        }
        if entry.1 >= rule.limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window() {
        let rl = RateLimiter::new(b"s");
        let rule = Rule {
            limit: 2,
            window_s: 60,
        };
        assert!(rl.hit("a", "x", rule, 0));
        assert!(rl.hit("a", "x", rule, 1));
        assert!(!rl.hit("a", "x", rule, 2));
        assert!(rl.hit("a", "y", rule, 2));
        assert!(rl.hit("b", "x", rule, 2));
        assert!(rl.hit("a", "x", rule, 61));
    }

    const RULE: Rule = Rule {
        limit: 5,
        window_s: 60,
    };

    #[test]
    fn a_full_scope_does_not_block_other_scopes() {
        let rl = RateLimiter::with_max(b"s", 3);
        for i in 0..10 {
            rl.hit("magic-email", &format!("spam{i}"), RULE, 0);
        }
        assert!(
            rl.hit("ticket", "member", RULE, 0),
            "ticket scope unaffected"
        );
        assert!(rl.hit("token-ip", "1.2.3.4", RULE, 0));
    }

    #[test]
    fn known_keys_keep_counting_when_the_scope_is_full() {
        let rl = RateLimiter::with_max(b"s", 3);
        assert!(rl.hit("magic-ip", "me", RULE, 0));
        for i in 0..10 {
            rl.hit("magic-ip", &format!("spam{i}"), RULE, 1);
        }
        assert!(
            rl.hit("magic-ip", "me", RULE, 2),
            "an existing key is not refused"
        );
    }

    #[test]
    fn expired_windows_make_room_again() {
        let rl = RateLimiter::with_max(b"s", 3);
        for i in 0..3 {
            assert!(rl.hit("magic-ip", &format!("old{i}"), RULE, 0));
        }
        assert!(
            !rl.hit("magic-ip", "new", RULE, 30),
            "full while windows run"
        );
        assert!(
            rl.hit("magic-ip", "new", RULE, 61),
            "room once the windows have ended"
        );
    }
}
