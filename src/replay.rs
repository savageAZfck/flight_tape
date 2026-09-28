//! Replay — render a bundle (or live ring) as a human timeline.

use crate::frame::Frame;
use crate::Result;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Load frames from a bundle dir or a bare frames.jsonl / ring.jsonl path.
pub fn load_frames(path: &Path) -> Result<Vec<Frame>> {
    let file = if path.is_dir() {
        path.join("frames.jsonl")
    } else {
        path.to_path_buf()
    };
    let mut out = Vec::new();
    for line in BufReader::new(fs::File::open(file)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line.trim_end())?);
    }
    Ok(out)
}

/// Render a timeline to a string. `kinds` filters event classes (empty = all).
/// `around` centers the output on a seq and shows ±context frames.
pub fn render(frames: &[Frame], kinds: &[String], around: Option<(u64, usize)>) -> String {
    let filtered: Vec<&Frame> = frames
        .iter()
        .filter(|f| kinds.is_empty() || kinds.iter().any(|k| k == &f.kind))
        .collect();

    let window: Vec<&Frame> = match around {
        Some((seq, ctx)) => {
            let pos = filtered
                .iter()
                .position(|f| f.seq == seq)
                .or_else(|| filtered.iter().position(|f| f.seq > seq));
            match pos {
                Some(p) => {
                    let lo = p.saturating_sub(ctx);
                    let hi = (p + ctx + 1).min(filtered.len());
                    filtered[lo..hi].to_vec()
                }
                None => filtered.clone(),
            }
        }
        None => filtered,
    };

    let mut out = String::new();
    for f in window {
        let body = serde_json::to_string(&f.body).unwrap_or_else(|_| "{}".into());
        let body_short = if body.len() > 160 {
            format!("{}…", &body[..157])
        } else {
            body
        };
        out.push_str(&format!(
            "[seq {:>6} | {} | {:<22} | {:<7}] {}\n",
            f.seq,
            fmt_ts(f.ts),
            f.kind,
            f.src,
            body_short
        ));
    }
    out
}

fn fmt_ts(ts: u64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| ts.to_string())
}
