//! flight-tape — CLI for the flight recorder.
//!
//! flight-tape daemon   — own a tape dir, tail sources, freeze on triggers
//! flight-tape record   — append one frame (embedders/scripts)
//! flight-tape freeze   — freeze now
//! flight-tape verify   — verify an incident bundle (offline)
//! flight-tape replay   — render a bundle/ring timeline
//! flight-tape status   — ring stats + head hash
//! flight-tape keygen   — create the tape signing key

use clap::{Parser, Subcommand};
use flight_tape::daemon::{Daemon, DaemonConfig};
use flight_tape::freeze::{FreezeTrigger, StateRoot};
use flight_tape::replay;
use flight_tape::ring::{Ring, RingConfig};
use flight_tape::sign;
use flight_tape::source::LedgerTailer;
use flight_tape::trigger::TriggerConfig;
use flight_tape::verify;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static STOP: AtomicBool = AtomicBool::new(false);

#[derive(Parser)]
#[command(
    name = "flight-tape",
    about = "Flight recorder for autonomous systems",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Own a tape dir: tail sources, ingest intents, freeze on triggers.
    Daemon {
        /// Tape directory (ring.jsonl, incidents/, tape.key live here).
        #[arg(long)]
        dir: PathBuf,
        /// JSONL ledger(s) to tail. Repeatable.
        #[arg(long = "ledger")]
        ledgers: Vec<PathBuf>,
        /// Intent drop-stream path (default <dir>/intent.jsonl).
        #[arg(long)]
        intent: Option<PathBuf>,
        /// Subject name for manifests.
        #[arg(long, default_value = "subject")]
        subject: String,
        /// Subject version for manifests.
        #[arg(long, default_value = "")]
        version: String,
        /// Process name to watch; alive→dead freezes as crash.
        #[arg(long)]
        watch: Option<String>,
        /// State roots to snapshot at freeze: label=dir. Repeatable.
        #[arg(long = "state-root")]
        state_roots: Vec<String>,
        /// Poll interval in seconds.
        #[arg(long, default_value = "2")]
        poll: u64,
        /// Max frames retained in the ring.
        #[arg(long, default_value = "50000")]
        max_frames: usize,
        /// Max ring bytes.
        #[arg(long, default_value = "268435456")]
        max_bytes: u64,
    },
    /// Append one frame to a tape dir (embedders/scripts).
    Record {
        #[arg(long)]
        dir: PathBuf,
        /// Frame kind.
        #[arg(long)]
        kind: String,
        /// Frame body as JSON (object). String bodies wrap as {detail:...}.
        #[arg(long, default_value = "{}")]
        body: String,
        /// Source tag (default "cli").
        #[arg(long, default_value = "cli")]
        src: String,
    },
    /// Freeze the current ring into an incident bundle.
    Freeze {
        #[arg(long)]
        dir: PathBuf,
        /// Reason recorded in the manifest.
        #[arg(long, default_value = "manual freeze")]
        reason: String,
        /// label=dir state roots (repeatable).
        #[arg(long = "state-root")]
        state_roots: Vec<String>,
        #[arg(long, default_value = "subject")]
        subject: String,
        #[arg(long, default_value = "")]
        version: String,
    },
    /// Verify an incident bundle — fully offline.
    Verify { bundle: PathBuf },
    /// Render a timeline from a bundle dir, frames.jsonl, or ring.jsonl.
    Replay {
        path: PathBuf,
        /// Only these kinds (repeatable).
        #[arg(long = "kind")]
        kinds: Vec<String>,
        /// Center on this seq, show ±N frames.
        #[arg(long)]
        around: Option<u64>,
        /// Context size for --around (default 20).
        #[arg(long, default_value = "20")]
        context: usize,
    },
    /// Follow a live ring (like tail -f).
    Tail {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Ring stats + chain head.
    Status {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Create the tape signing key.
    Keygen {
        #[arg(long)]
        dir: PathBuf,
    },
}

fn parse_state_roots(specs: &[String]) -> Vec<StateRoot> {
    specs
        .iter()
        .filter_map(|s| {
            let (label, dir) = s.split_once('=')?;
            Some(StateRoot {
                label: label.to_string(),
                dir: PathBuf::from(dir),
                exclude: Vec::new(),
            })
        })
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Daemon {
            dir,
            ledgers,
            intent,
            subject,
            version,
            watch,
            state_roots,
            poll,
            max_frames,
            max_bytes,
        } => {
            // SIGTERM/SIGINT → stop flag
            let _ = std::thread::spawn(|| loop {
                std::thread::sleep(Duration::from_millis(500));
                // crude signal check via flag file as portable fallback
            });
            let cfg = DaemonConfig {
                intent_path: intent.unwrap_or_else(|| dir.join(flight_tape::INTENT_STREAM)),
                tape_dir: dir,
                ledger_sources: ledgers,
                subject_name: subject,
                subject_version: version,
                state_roots: parse_state_roots(&state_roots),
                poll: Duration::from_secs(poll),
                ring: RingConfig {
                    max_frames,
                    max_bytes,
                    sync_every: false,
                },
                triggers: TriggerConfig {
                    freeze_kinds: vec!["kill_switch".into()],
                    watch_process: watch,
                },
            };
            let mut d = Daemon::open(cfg)?.with_stop(&STOP);
            d.run()?;
        }
        Cmd::Record {
            dir,
            kind,
            body,
            src,
        } => {
            let mut ring = Ring::open(&dir, RingConfig::default())?;
            let body: serde_json::Value =
                serde_json::from_str(&body).unwrap_or_else(|_| serde_json::json!({"detail": body}));
            let seq = ring.record(&kind, &src, body)?;
            println!("recorded seq {}", seq);
        }
        Cmd::Freeze {
            dir,
            reason,
            state_roots,
            subject,
            version,
        } => {
            let ring = Ring::open(&dir, RingConfig::default())?;
            let trig = FreezeTrigger {
                kind: "manual".into(),
                detail: reason,
                ts: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            };
            let prior = flight_tape::freeze::list_incidents(&dir);
            let bundle = flight_tape::freeze::freeze(
                &ring,
                trig,
                &subject,
                &version,
                &parse_state_roots(&state_roots),
                prior,
            )?;
            println!(
                "froze {} frames (seq {}..{}) → {}",
                bundle.frames,
                bundle.first_seq,
                bundle.last_seq,
                bundle.dir.display()
            );
        }
        Cmd::Verify { bundle } => {
            let report = verify::verify_bundle(&bundle)?;
            for p in &report.problems {
                eprintln!("  ✗ {}", p);
            }
            println!(
                "{}: {} frames, chain={}, manifest={}, signature={}",
                if report.ok() { "VALID" } else { "INVALID" },
                report.frames_checked,
                report.chain_ok,
                report.manifest_ok,
                report.signature_ok
            );
            if !report.ok() {
                std::process::exit(1);
            }
        }
        Cmd::Replay {
            path,
            kinds,
            around,
            context,
        } => {
            let frames = replay::load_frames(&path)?;
            print!(
                "{}",
                replay::render(&frames, &kinds, around.map(|s| (s, context)))
            );
        }
        Cmd::Tail { dir } => {
            let ring_path = dir.join("ring.jsonl");
            let mut tailer = LedgerTailer::new(ring_path, &dir)?;
            loop {
                for (kind, body) in tailer.drain()? {
                    let body = serde_json::to_string(&body).unwrap_or_default();
                    let body = if body.len() > 120 {
                        format!("{}…", &body[..120])
                    } else {
                        body
                    };
                    println!("[{}] {}", kind, body);
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        Cmd::Status { dir } => {
            let ring = Ring::open(&dir, RingConfig::default())?;
            println!("dir:      {}", ring.dir().display());
            println!(
                "frames:   {} (seq {}..{})",
                ring.len(),
                ring.floor_seq(),
                ring.next_seq().saturating_sub(1)
            );
            println!("head:     {}", ring.head_hex());
            let incidents = flight_tape::freeze::list_incidents(&dir);
            println!("incidents: {}", incidents.len());
            for i in incidents.iter().rev().take(5) {
                println!("  - {}", i);
            }
        }
        Cmd::Keygen { dir } => {
            let key = sign::load_or_create(&dir.join("tape.key"))?;
            println!("pubkey: {}", hex::encode(key.verifying_key().to_bytes()));
        }
    }
    Ok(())
}

// Keep imports used when feature off
#[allow(unused_imports)]
use flight_tape as _ft;
