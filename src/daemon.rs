//! The recorder daemon — owns the ring, drains sources, evaluates triggers,
//! freezes bundles. One process per tape; it must outlive the subject it
//! records (that's the point of it being separate).

use crate::freeze::{self, FreezeTrigger, IncidentBundle, StateRoot};
use crate::ring::{Ring, RingConfig};
use crate::source::{IntentIngester, LedgerTailer};
use crate::trigger::{self, Trigger, TriggerConfig};
use crate::Result;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub struct DaemonConfig {
    /// Tape directory (holds ring.jsonl, incidents/, tape.key).
    pub tape_dir: PathBuf,
    /// Ledgers to tail (Bad Apple ledger.jsonl, others).
    pub ledger_sources: Vec<PathBuf>,
    /// Intent drop-stream path (`<tape_dir>/intent.jsonl`).
    pub intent_path: PathBuf,
    /// Subject identity recorded in bundle manifests.
    pub subject_name: String,
    pub subject_version: String,
    /// State roots snapshotted at freeze.
    pub state_roots: Vec<StateRoot>,
    /// Poll interval.
    pub poll: Duration,
    pub ring: RingConfig,
    pub triggers: TriggerConfig,
}

pub struct Daemon {
    ring: Ring,
    config: DaemonConfig,
    tailers: Vec<LedgerTailer>,
    intents: IntentIngester,
    /// Liveness of the watched process on the previous poll.
    subject_was_alive: bool,
    /// Stop flag (signal handler or supervisor sets it).
    stop: Option<std::sync::Arc<AtomicBool>>,
}

impl Daemon {
    pub fn open(config: DaemonConfig) -> Result<Self> {
        let ring = Ring::open(&config.tape_dir, config.ring.clone())?;
        let mut tailers = Vec::new();
        for src in &config.ledger_sources {
            tailers.push(LedgerTailer::new(src.clone(), &config.tape_dir)?);
        }
        let intents = IntentIngester::new(config.intent_path.clone());
        let subject_was_alive = config
            .triggers
            .watch_process
            .as_deref()
            .map(trigger::process_alive)
            .unwrap_or(true);
        Ok(Self {
            ring,
            config,
            tailers,
            intents,
            subject_was_alive,
            stop: None,
        })
    }

    /// Install a stop flag — flipped by a signal handler (signal-hook),
    /// supervisor, or embedder thread.
    pub fn with_stop(mut self, stop: std::sync::Arc<AtomicBool>) -> Self {
        self.stop = Some(stop);
        self
    }

    /// One poll cycle: drain sources → write frames → check triggers.
    /// Returns bundles frozen this cycle.
    pub fn poll_once(&mut self) -> Result<Vec<IncidentBundle>> {
        let mut bundles = Vec::new();

        // Manual trigger file wins — freeze even if no new frames arrived.
        if let Some(t) = trigger::check_freeze_file(&self.config.tape_dir) {
            if let Some(b) = self.try_freeze(t.to_freeze())? {
                bundles.push(b);
            }
        }

        // Drain ledger sources into a pending list (avoids borrowing self
        // twice when a freeze fires mid-drain)
        let mut ledger_frames = Vec::new();
        for tailer in self.tailers.iter_mut() {
            ledger_frames.extend(tailer.drain()?);
        }
        let mut intent_frames = self.intents.drain()?;

        for (kind, body) in ledger_frames {
            self.ring.record(&kind, "ledger", body.clone())?;
            if let Some(t) = trigger::matches_freeze(&self.config.triggers, &kind, &body) {
                if let Some(b) = self.try_freeze(t.to_freeze())? {
                    bundles.push(b);
                }
            }
        }
        for (kind, body) in intent_frames.drain(..) {
            self.ring.record(&kind, "intent", body)?;
        }

        // Crash detection — alive→dead transition
        if let Some(proc_name) = &self.config.triggers.watch_process {
            let alive = trigger::process_alive(proc_name);
            if self.subject_was_alive && !alive {
                if let Some(b) = self.try_freeze(
                    Trigger::Crash {
                        process: proc_name.clone(),
                    }
                    .to_freeze(),
                )? {
                    bundles.push(b);
                }
            }
            self.subject_was_alive = alive;
        }

        self.ring.write_head()?;
        Ok(bundles)
    }

    /// Freeze now, out-of-band (CLI `freeze` path uses this on its own
    /// short-lived Daemon, or the trigger file route).
    pub fn freeze_now(&mut self, trigger: FreezeTrigger) -> Result<IncidentBundle> {
        self.try_freeze(trigger)?
            .ok_or_else(|| crate::Error::Missing("ring empty".into()))
    }

    fn try_freeze(&mut self, trig: FreezeTrigger) -> Result<Option<IncidentBundle>> {
        if self.ring.is_empty() {
            return Ok(None);
        }
        let prior = freeze::list_incidents(&self.config.tape_dir);
        let bundle = freeze::freeze(
            &self.ring,
            trig,
            &self.config.subject_name,
            &self.config.subject_version,
            &self.config.state_roots,
            prior,
        )?;
        // Marker frame on the tape itself: the freeze is part of the record.
        self.ring.record(
            "tape.freeze",
            "daemon",
            serde_json::json!({
                "bundle": bundle.dir.display().to_string(),
                "frames": bundle.frames,
                "window": [bundle.first_seq, bundle.last_seq],
            }),
        )?;
        Ok(Some(bundle))
    }

    /// Run the poll loop until the stop flag flips.
    pub fn run(&mut self) -> Result<()> {
        loop {
            self.poll_once()?;
            if let Some(stop) = &self.stop {
                if stop.load(Ordering::SeqCst) {
                    return Ok(());
                }
            }
            std::thread::sleep(self.config.poll);
        }
    }
}
