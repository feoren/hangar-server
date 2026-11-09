//! Ratenbegrenzung im Speicher (ein Knoten): feste Fenster je Schlüssel. Schlüssel werden mit
//! dem Server-Geheimnis gehasht, damit keine Adressen im Klartext im Speicher liegen.
//! Ein Neustart setzt die Zähler zurück; das ist für einen einzelnen Prozess hinnehmbar.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::util::hmac_hex;

/// Höchstzahl gemerkter Schlüssel; darüber wird zuerst aufgeräumt, dann im Zweifel abgelehnt.
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

    /// Zählt einen Versuch. `false`: Grenze erreicht.
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
    fn fenster() {
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
