//! Verify an incident bundle — fully offline, self-contained.

use crate::frame::{decode_hash, genesis_hash, Frame};
use crate::sign;
use crate::{Error, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct VerifyReport {
    pub frames_checked: usize,
    pub chain_ok: bool,
    pub manifest_ok: bool,
    pub signature_ok: bool,
    pub problems: Vec<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.chain_ok && self.manifest_ok && self.signature_ok && self.problems.is_empty()
    }
}

#[derive(Deserialize)]
struct ManifestIn {
    spec: String,
    window: WindowIn,
    head_hash: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct WindowIn {
    first_seq: u64,
    last_seq: u64,
    count: usize,
}

/// Verify a bundle directory (containing frames.jsonl, manifest.json,
/// manifest.sig). Rehashes every frame, checks chain linkage and window
/// bounds against the manifest, then verifies the manifest signature.
pub fn verify_bundle(bundle_dir: &Path) -> Result<VerifyReport> {
    let frames_path = bundle_dir.join("frames.jsonl");
    let manifest_path = bundle_dir.join("manifest.json");
    let sig_path = bundle_dir.join("manifest.sig");

    for p in [&frames_path, &manifest_path, &sig_path] {
        if !p.exists() {
            return Err(Error::Missing(format!("bundle missing {}", p.display())));
        }
    }

    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: ManifestIn = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| Error::Corrupt(format!("manifest parse: {e}")))?;
    let sig_hex = fs::read_to_string(&sig_path)?;

    // Chain replay
    let mut problems = Vec::new();
    let mut count = 0usize;
    let mut first_seq = 0u64;
    let mut last_seq = 0u64;
    let mut tip = genesis_hash();
    let mut chain_ok = true;

    let content = fs::read_to_string(&frames_path)?;
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let frame: Frame = match serde_json::from_str(line) {
            Ok(f) => f,
            Err(e) => {
                problems.push(format!("frame {} unparseable: {}", i + 1, e));
                chain_ok = false;
                break;
            }
        };
        // First frame in a bundle links to prior context we can't see —
        // verify linkage from frame 2 onward, but always check self-hash.
        if count == 0 {
            first_seq = frame.seq;
            let self_ok = {
                let prev = decode_hash(&frame.prev_hash).unwrap_or(tip);
                hex::encode(Frame::compute_hash(
                    &prev,
                    frame.seq,
                    frame.ts,
                    &frame.kind,
                    &frame.src,
                    &frame.body,
                )) == frame.hash
            };
            if !self_ok {
                problems.push(format!("frame {} self-hash mismatch", frame.seq));
                chain_ok = false;
            }
            tip = decode_hash(&frame.hash).unwrap_or(tip);
        } else {
            if frame.seq != last_seq + 1 {
                problems.push(format!("seq gap at {}", frame.seq));
                chain_ok = false;
            }
            if !frame.verify(&tip) {
                problems.push(format!("chain broken at seq {}", frame.seq));
                chain_ok = false;
            }
            tip = decode_hash(&frame.hash).unwrap_or(tip);
        }
        last_seq = frame.seq;
        count += 1;
    }

    // Manifest consistency
    let mut manifest_ok = true;
    if manifest.spec != "flight_tape/0.1" {
        problems.push(format!("unknown spec {}", manifest.spec));
        manifest_ok = false;
    }
    if manifest.window.count != count {
        problems.push(format!(
            "manifest count {} != actual {}",
            manifest.window.count, count
        ));
        manifest_ok = false;
    }
    if manifest.window.first_seq != first_seq || manifest.window.last_seq != last_seq {
        problems.push(format!(
            "manifest window {}..{} != actual {}..{}",
            manifest.window.first_seq, manifest.window.last_seq, first_seq, last_seq
        ));
        manifest_ok = false;
    }
    if manifest.head_hash != hex::encode(tip) {
        problems.push("manifest head_hash != computed chain tip".into());
        manifest_ok = false;
    }

    let signature_ok = sign::verify(&manifest.pubkey, &manifest_bytes, &sig_hex).unwrap_or(false);
    if !signature_ok {
        problems.push("manifest signature invalid".into());
    }

    Ok(VerifyReport {
        frames_checked: count,
        chain_ok,
        manifest_ok,
        signature_ok,
        problems,
    })
}
