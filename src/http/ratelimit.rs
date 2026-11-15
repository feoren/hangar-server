//! In-memory rate limiting (single node): fixed windows per key. Keys are hashed with the
//! server secret so that no addresses are held in memory in plain text.
//! A restart resets the counters; that is acceptable for a single process.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::util::hmac_hex;

/// Maximum number of remembered keys; beyond that, stale entries are pruned first, then requests are refused if still full.
const MAX_KEYS: usize = 100_000;

#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub limit: u32,
    pub window_s: i64,
}

pub struct RateLimiter {
    secret: Vec<u8>,
    buckets: Mutex<HashMap<String, (i64, u32)>>,
}

impl RateLimiter {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one attempt. `false`: limit reached.
    pub fn hit(&self, scope: &str, key: &str, rule: Rule, now_s: i64) -> bool {
        let id = hmac_hex(&self.secret, &[scope.as_bytes(), key.as_bytes()]);
        let Ok(mut buckets) = self.buckets.lock() else {
            return false;
        };
        if buckets.len() >= MAX_KEYS {
            buckets.retain(|_, (start, _)| now_s - *start < 3600);
            if buckets.len() >= MAX_KEYS {
                return false;
            }
        }
        let entry = buckets.entry(id).or_insert((now_s, 0));
        if now_s - entry.0 >= rule.window_s {
            *entry = (now_s, 0);
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
}
