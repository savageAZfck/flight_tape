//! Freeze — seal the current ring window into a signed incident bundle.

use crate::ring::Ring;
use crate::sign;
use crate::{Error, Result};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "snapshot")]
use respawned::snapshot;
#[cfg(feature = "snapshot")]
use respawned::store::Store;

/// Why the tape was frozen.
#[derive(Debug, Clone, Serialize)]
pub struct FreezeTrigger {
    /// `kill_switch`, `crash`, or `manual`.
    pub kind: String,
    /// Human detail (reason string, matched event, exit signal).
    pub detail: String,
    pub ts: u64,
}

/// Where a completed bundle landed.
#[derive(Debug)]
pub struct IncidentBundle {
    pub dir: PathBuf,
    pub manifest_path: PathBuf,
    pub frames: usize,
    pub first_seq: u64,
    pub last_seq: u64,
}

/// State roots to snapshot at freeze time (respawn fabric per root).
#[derive(Debug, Clone)]
pub struct StateRoot {
    /// Label recorded in the manifest (`platform`, `learned`, …).
    pub label: String,
    /// Directory to snapshot.
    pub dir: PathBuf,
    /// Path prefixes to exclude from the snapshot manifest (e.g.
    /// `kv_cache`, `generated_images` — heavy, non-decision state).
    pub exclude: Vec<String>,
}

#[derive(Serialize)]
struct ManifestSubject {
    name: String,
    version: String,
    host: String,
}

#[derive(Serialize)]
struct ManifestWindow {
    first_seq: u64,
    last_seq: u64,
    count: usize,
    span_seconds: u64,
}

#[derive(Serialize)]
struct Manifest {
    spec: String,
    subject: ManifestSubject,
    trigger: FreezeTrigger,
    window: ManifestWindow,
    head_hash: String,
    snapshots: std::collections::BTreeMap<String, String>,
    pubkey: String,
    prior_incidents: Vec<String>,
}

/// Freeze the ring into `dir/incidents/<utc>-<last_seq>/`.
///
/// `state_roots` are snapshotted via respawn (feature `snapshot`); their
/// HEAD manifest ids land in the manifest so an auditor can materialize
/// exactly the state the subject held at freeze time.
pub fn freeze(
    ring: &Ring,
    trigger: FreezeTrigger,
    subject_name: &str,
    subject_version: &str,
    state_roots: &[StateRoot],
    prior_incidents: Vec<String>,
) -> Result<IncidentBundle> {
    let frames = ring.frames()?;
    if frames.is_empty() {
        return Err(Error::Missing("ring is empty — nothing to freeze".into()));
    }
    let first = frames.first().unwrap();
    let last = frames.last().unwrap();

    let stamp = chrono::DateTime::from_timestamp(trigger.ts as i64, 0)
        .map(|t| t.format("%Y%m%dT%H%M%SZ").to_string())
        .unwrap_or_else(|| format!("{}", trigger.ts));
    let bundle_dir = ring
        .dir()
        .join("incidents")
        .join(format!("{}-{}", stamp, last.seq));
    fs::create_dir_all(&bundle_dir)?;

    // frames.jsonl — verbatim copy of the window
    let frames_path = bundle_dir.join("frames.jsonl");
    {
        let mut w = fs::File::create(&frames_path)?;
        use std::io::Write;
        for f in &frames {
            w.write_all(serde_json::to_vec(f)?.as_slice())?;
            w.write_all(b"\n")?;
        }
        w.sync_data()?;
    }

    // State snapshots
    let mut snap_ids = std::collections::BTreeMap::new();
    fs::create_dir_all(bundle_dir.join("state"))?;
    for root in state_roots {
        #[cfg(feature = "snapshot")]
        {
            match snapshot_root(root) {
                Ok(head) => {
                    snap_ids.insert(root.label.clone(), head);
                }
                Err(Error::Missing(_)) => {
                    snap_ids.insert(root.label.clone(), "none".into());
                }
                Err(e) => return Err(e),
            }
        }
        #[cfg(not(feature = "snapshot"))]
        {
            let _ = root;
            snap_ids.insert(root.label.clone(), "disabled".into());
        }
    }

    // Load or create the tape signer.
    let key_path = ring.dir().join("tape.key");
    let key = sign::load_or_create(&key_path)?;
    let pubkey = hex::encode(key.verifying_key().to_bytes());

    let host = std::env::var("HOSTNAME")
        .or_else(|_| {
            std::process::Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_default();

    let manifest = Manifest {
        spec: "flight_tape/0.1".into(),
        subject: ManifestSubject {
            name: subject_name.to_string(),
            version: subject_version.to_string(),
            host,
        },
        trigger,
        window: ManifestWindow {
            first_seq: first.seq,
            last_seq: last.seq,
            count: frames.len(),
            span_seconds: last.ts.saturating_sub(first.ts),
        },
        head_hash: ring.head_hex(),
        snapshots: snap_ids,
        pubkey,
        prior_incidents,
    };

    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let manifest_path = bundle_dir.join("manifest.json");
    fs::write(&manifest_path, &manifest_bytes)?;
    let sig = sign::sign(&key, &manifest_bytes);
    fs::write(bundle_dir.join("manifest.sig"), sig + "\n")?;

    Ok(IncidentBundle {
        dir: bundle_dir,
        manifest_path,
        frames: frames.len(),
        first_seq: first.seq,
        last_seq: last.seq,
    })
}

#[cfg(feature = "snapshot")]
fn snapshot_root(root: &StateRoot) -> Result<String> {
    if !root.dir.exists() {
        return Err(Error::Missing(format!(
            "state root {} does not exist",
            root.dir.display()
        )));
    }
    let store = match Store::open(&root.dir) {
        Ok(s) => s,
        Err(respawned::Error::NotInitialized) => Store::init(&root.dir)?,
        Err(e) => return Err(e.into()),
    };
    let id = snapshot::create(&store, &root.dir, "flight_tape incident freeze")?;
    Ok(respawned::hash_hex(&id))
}

/// List prior incident bundle ids (dir names) for chaining.
pub fn list_incidents(dir: &Path) -> Vec<String> {
    let incidents = dir.join("incidents");
    let mut out: Vec<String> = fs::read_dir(&incidents)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}
