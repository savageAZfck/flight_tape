//! Triggers — what freezes the tape.
//!
//! Three sources: frame kinds seen on the tape (kill events), subject
//! liveness transitions (crash), and manual (trigger file or CLI).

use crate::freeze::FreezeTrigger;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct TriggerConfig {
    /// Frame kinds that freeze the tape when seen (e.g. `kill_switch`,
    /// `kill_switch_*`). Matched as prefix.
    pub freeze_kinds: Vec<String>,
    /// Process name to watch for crash detection (empty = disabled).
    /// Alive→dead transition freezes with kind `crash`.
    pub watch_process: Option<String>,
}

impl Default for TriggerConfig {
    fn default() -> Self {
        Self {
            freeze_kinds: vec!["kill_switch".into()],
            watch_process: None,
        }
    }
}

#[derive(Debug)]
pub enum Trigger {
    /// A freeze-kind frame was recorded.
    Kill { frame_kind: String, detail: String },
    /// Watched process transitioned alive → dead.
    Crash { process: String },
    /// Trigger file or CLI request.
    Manual { detail: String },
}

impl Trigger {
    pub fn to_freeze(&self) -> FreezeTrigger {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        match self {
            Trigger::Kill { frame_kind, detail } => FreezeTrigger {
                kind: "kill_switch".into(),
                detail: format!("{frame_kind}: {detail}"),
                ts,
            },
            Trigger::Crash { process } => FreezeTrigger {
                kind: "crash".into(),
                detail: format!("watched process {process} exited"),
                ts,
            },
            Trigger::Manual { detail } => FreezeTrigger {
                kind: "manual".into(),
                detail: detail.clone(),
                ts,
            },
        }
    }
}

/// Check whether a recorded frame kind matches a freeze trigger.
pub fn matches_freeze(
    config: &TriggerConfig,
    kind: &str,
    body: &serde_json::Value,
) -> Option<Trigger> {
    if config
        .freeze_kinds
        .iter()
        .any(|k| kind.starts_with(k.as_str()))
    {
        let detail = serde_json::to_string(body).unwrap_or_default();
        let detail = if detail.len() > 200 {
            format!("{}…", &detail[..200])
        } else {
            detail
        };
        return Some(Trigger::Kill {
            frame_kind: kind.to_string(),
            detail,
        });
    }
    None
}

/// Manual trigger file: `<tape_dir>/FREEZE`. Presence = freeze once.
/// Returns Some(detail) if the file existed (it is consumed).
pub fn check_freeze_file(tape_dir: &Path) -> Option<Trigger> {
    let path: PathBuf = tape_dir.join(crate::FREEZE_FILE);
    if !path.exists() {
        return None;
    }
    let detail = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .trim()
        .to_string();
    let _ = std::fs::remove_file(&path);
    Some(Trigger::Manual {
        detail: if detail.is_empty() {
            "trigger file".into()
        } else {
            detail
        },
    })
}

/// Is `name` running? macOS/Linux: scan /proc or pgrep.
#[cfg(target_family = "unix")]
pub fn process_alive(name: &str) -> bool {
    std::process::Command::new("pgrep")
        .arg("-x")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(target_family = "unix"))]
pub fn process_alive(_name: &str) -> bool {
    true // can't check — assume alive, never crash-trigger
}
