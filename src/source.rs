//! Sources — where frames come from.
//!
//! `LedgerTailer` follows an existing append-only JSONL ledger (Bad Apple's
//! `ledger.jsonl` or any `{type, data}` event stream) and converts new lines
//! to frames. `IntentIngester` drains a drop-stream (`intent.jsonl`) that
//! embedders append to fire-and-forget — Bad Apple's tool-dispatch writes
//! pre-approval intent there.

use crate::{Error, Result};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Follows an append-only JSONL file with a persisted byte offset.
/// Each new line yields `(kind, body)` frames. Survives truncation
/// (log rotation) by resetting to offset 0 when the file shrinks.
pub struct LedgerTailer {
    path: PathBuf,
    offset_path: PathBuf,
    offset: u64,
    /// Map ledger event `type` values to frame `kind`. Identity by default.
    /// `None` → frame kind = the event's `type` field.
    pub kind_map: KindMap,
}

impl LedgerTailer {
    /// `path` is the JSONL to follow. Offsets persist in `<tape_dir>/tailer.offset`.
    pub fn new(path: PathBuf, tape_dir: &Path) -> Result<Self> {
        let offset_path = tape_dir.join("tailer.offset");
        let offset = fs::read_to_string(&offset_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        Ok(Self {
            path,
            offset_path,
            offset,
            kind_map: None,
        })
    }

    /// Drain all new lines into `(kind, body)` pairs. Persists offset.
    /// Returns frames in arrival order.
    pub fn drain(&mut self) -> Result<Vec<(String, Value)>> {
        let mut out = Vec::new();
        if !self.path.exists() {
            return Ok(out);
        }
        let len = fs::metadata(&self.path)?.len();
        if len < self.offset {
            self.offset = 0; // rotated/truncated — restart
        }
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(self.offset))?;
        let mut raw = Vec::new();
        f.read_to_end(&mut raw)?;
        let consumed = raw.len() as u64;

        // If the last byte isn't a newline we may hold a partial line —
        // leave it for next drain.
        let mut usable = raw.as_slice();
        if !raw.is_empty() && raw[raw.len() - 1] != b'\n' {
            if let Some(pos) = raw.iter().rposition(|b| *b == b'\n') {
                usable = &raw[..pos + 1];
            } else {
                usable = &[];
            }
        }
        let advanced = usable.len() as u64;

        for line in usable.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let line = match std::str::from_utf8(line) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let v: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            // Bad Apple ledger shape: {ts, type, data, prev_hash, hash}
            // Generic shape: {kind|type|event, ...body}
            let (kind, body) = extract_kind_body(&v);
            let kind = match &self.kind_map {
                Some(m) => m(&kind),
                None => kind,
            };
            out.push((kind, body));
        }

        self.offset += advanced;
        let _ = consumed;
        let tmp = self.offset_path.with_extension("tmp");
        fs::write(&tmp, self.offset.to_string())?;
        fs::rename(&tmp, &self.offset_path)?;
        Ok(out)
    }
}

/// Optional mapper from ledger event type to frame kind.
pub type KindMap = Option<Box<dyn Fn(&str) -> String + Send>>;

fn extract_kind_body(v: &Value) -> (String, Value) {
    for key in ["type", "kind", "event"] {
        if let Some(k) = v.get(key).and_then(|k| k.as_str()) {
            let body = v.get("data").cloned().unwrap_or_else(|| strip_keys(v, key));
            return (k.to_string(), body);
        }
    }
    ("unknown".into(), v.clone())
}

fn strip_keys(v: &Value, skip: &str) -> Value {
    match v.as_object() {
        Some(m) => {
            let mut m = m.clone();
            m.remove(skip);
            Value::Object(m)
        }
        None => v.clone(),
    }
}

/// Drains a drop-stream file: writers append `{kind, body}` lines and the
/// daemon consumes them, truncating the file after ingestion. Fire-and-forget
/// for the writer — no daemon required to be alive.
pub struct IntentIngester {
    path: PathBuf,
}

impl IntentIngester {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Consume all pending intent lines; returns `(kind, body)` pairs.
    /// Lines are raw frames-lite: `{"kind": "...", ...}` where every field
    /// except kind/src becomes the body.
    pub fn drain(&mut self) -> Result<Vec<(String, Value)>> {
        let mut out = Vec::new();
        if !self.path.exists() {
            return Ok(out);
        }
        let content = fs::read_to_string(&self.path)?;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let (kind, body) = extract_kind_body(&v);
            out.push((kind, body));
        }
        // Truncate — consumed lines don't re-ingest.
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        Ok(out)
    }

    /// Writer-side helper: append one intent line (used by embedders and the
    /// `record` CLI verb). `fields` merge into the object body.
    pub fn write_intent(path: &Path, kind: &str, fields: Value) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut obj = match fields {
            Value::Object(m) => m,
            other => {
                let mut m = serde_json::Map::new();
                m.insert("detail".into(), other);
                m
            }
        };
        obj.insert("kind".into(), Value::String(kind.to_string()));
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        f.write_all(serde_json::to_string(&Value::Object(obj))?.as_bytes())?;
        f.write_all(b"\n")?;
        Ok(())
    }
}

/// Marker for missing-file reads (kept for clarity at call sites).
pub fn err_missing(path: &Path) -> Error {
    Error::Missing(format!("{}", path.display()))
}
