//! Decision frames — one row of the tape.
//!
//! A frame is a hash-chained JSON object. The digest construction mirrors
//! the proven lineage of Bad Apple's ledger ({ts,type,data,prev_hash} → hash)
//! with an `FT1:` domain tag so a tape frame can never collide with a
//! ledger entry or any other format.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HASH_SIZE: usize = 32;
/// Domain tag hashed before all frame fields.
pub const DOMAIN: &[u8] = b"FT1:";
/// Current frame format version.
pub const FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub v: u32,
    pub seq: u64,
    pub ts: u64,
    /// Event class — `tool_call`, `query`, `intent`, `kill_switch`, …
    pub kind: String,
    /// Which source wrote the frame: `ledger`, `intent`, `daemon`, …
    pub src: String,
    /// Event payload (already redacted).
    pub body: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
}

impl Frame {
    /// Compute the hash this frame should carry given the chain tip.
    pub fn compute_hash(
        prev: &[u8; HASH_SIZE],
        seq: u64,
        ts: u64,
        kind: &str,
        src: &str,
        body: &serde_json::Value,
    ) -> [u8; HASH_SIZE] {
        let canon = serde_json::to_vec(body).unwrap_or_else(|_| b"null".to_vec());
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(prev);
        h.update(seq.to_le_bytes());
        h.update(ts.to_le_bytes());
        h.update((kind.len() as u32).to_le_bytes());
        h.update(kind.as_bytes());
        h.update((src.len() as u32).to_le_bytes());
        h.update(src.as_bytes());
        h.update((canon.len() as u64).to_le_bytes());
        h.update(&canon);
        let out = h.finalize();
        let mut d = [0u8; HASH_SIZE];
        d.copy_from_slice(&out);
        d
    }

    /// Recompute and compare the stored hash. Also verifies seq/prev linkage
    /// when the expected previous tip is supplied.
    pub fn verify(&self, expected_prev: &[u8; HASH_SIZE]) -> bool {
        let prev = match decode_hash(&self.prev_hash) {
            Some(p) => p,
            None => return false,
        };
        if prev != *expected_prev {
            return false;
        }
        let computed =
            Self::compute_hash(&prev, self.seq, self.ts, &self.kind, &self.src, &self.body);
        hex::encode(computed) == self.hash
    }
}

pub fn decode_hash(s: &str) -> Option<[u8; HASH_SIZE]> {
    match hex::decode(s) {
        Ok(v) if v.len() == HASH_SIZE => v.try_into().ok(),
        _ => None,
    }
}

/// Genesis hash — the chain tip before frame 1.
pub fn genesis_hash() -> [u8; HASH_SIZE] {
    let mut h = Sha256::new();
    h.update(b"flight_tape-genesis-v1");
    let out = h.finalize();
    let mut d = [0u8; HASH_SIZE];
    d.copy_from_slice(&out);
    d
}

// MARK: - Redaction

/// Replaces secrets/PII in frame bodies before they are hashed. The same
/// pattern set as Bad Apple's audit ledger, so tape and ledger redact
/// identically.
pub struct Redactor;

impl Redactor {
    /// Scrub a JSON value in place.
    pub fn scrub(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::String(s) => {
                *s = Self::scrub_str(s);
            }
            serde_json::Value::Array(a) => {
                for item in a.iter_mut() {
                    Self::scrub(item);
                }
            }
            serde_json::Value::Object(m) => {
                for (_, item) in m.iter_mut() {
                    Self::scrub(item);
                }
            }
            _ => {}
        }
    }

    /// Scrub a single string. Returns the redacted copy.
    pub fn scrub_str(s: &str) -> String {
        let mut out = s.to_string();
        for (re, marker) in patterns().iter() {
            out = re.replace_all(&out, *marker).to_string();
        }
        out
    }
}

use std::sync::OnceLock;
static PATTERNS: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();

/// Pattern table — initialized lazily on first scrub.
fn patterns() -> &'static Vec<(regex::Regex, &'static str)> {
    PATTERNS.get_or_init(|| {
        vec![
            // API keys / tokens: long high-entropy runs
            (
                regex::Regex::new(
                    r"(?i)(sk-|xox[baprs]-|ghp_|gho_|github_pat_|glpat-|AKIA)[A-Za-z0-9_\-]{8,}",
                )
                .unwrap(),
                "[REDACTED_KEY]",
            ),
            (
                regex::Regex::new(r"(?i)bearer\s+[A-Za-z0-9_\-\.~\+/]{16,}=*").unwrap(),
                "[REDACTED_BEARER]",
            ),
            // Emails
            (
                regex::Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(),
                "[REDACTED_EMAIL]",
            ),
            // SSN
            (
                regex::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                "[REDACTED_SSN]",
            ),
            // Phone (US-ish)
            (
                regex::Regex::new(r"\b\+?1?[\s\-\.]?\(?\d{3}\)?[\s\-\.]\d{3}[\s\-\.]\d{4}\b")
                    .unwrap(),
                "[REDACTED_PHONE]",
            ),
            // Long hex blobs (keys, hashes)
            (
                regex::Regex::new(r"\b[0-9a-fA-F]{96,}\b").unwrap(),
                "[REDACTED_HASH]",
            ),
        ]
    })
}
