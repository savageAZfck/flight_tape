//! End-to-end: daemon tails a ledger, freezes on kill event, bundle verifies.

use flight_tape::daemon::{Daemon, DaemonConfig};
use flight_tape::frame::genesis_hash;
use flight_tape::freeze::StateRoot;
use flight_tape::ring::{Ring, RingConfig};
use flight_tape::source::IntentIngester;
use flight_tape::trigger::TriggerConfig;
use flight_tape::verify::verify_bundle;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

fn write_ledger(path: &PathBuf, events: &[(&str, &str)]) {
    use std::fmt::Write as _;
    let mut out = String::new();
    for (t, d) in events {
        let _ = writeln!(
            out,
            "{{\"ts\":\"2026-09-28T00:00:00Z\",\"type\":\"{}\",\"data\":{}}}",
            t, d
        );
    }
    fs::write(path, out).unwrap();
}

fn daemon_cfg(tape_dir: PathBuf, ledger: PathBuf) -> DaemonConfig {
    DaemonConfig {
        tape_dir: tape_dir.clone(),
        ledger_sources: vec![ledger],
        intent_path: tape_dir.join("intent.jsonl"),
        subject_name: "test-subject".into(),
        subject_version: "0.0.0".into(),
        state_roots: vec![],
        poll: Duration::from_millis(10),
        ring: RingConfig {
            max_frames: 1000,
            max_bytes: 1024 * 1024,
            sync_every: false,
        },
        triggers: TriggerConfig::default(),
    }
}

#[test]
fn end_to_end_freeze_and_verify() {
    let tmp = TempDir::new().unwrap();
    let tape_dir = tmp.path().join("tape");
    let ledger = tmp.path().join("ledger.jsonl");
    write_ledger(
        &ledger,
        &[
            ("query", r#"{"prompt":"hi"}"#),
            ("response", r#"{"text":"hello"}"#),
            ("tool_call", r#"{"tool":"read_file"}"#),
        ],
    );

    let mut d = Daemon::open(daemon_cfg(tape_dir.clone(), ledger.clone())).unwrap();
    let bundles = d.poll_once().unwrap();
    assert!(bundles.is_empty());
    assert_eq!(d.poll_once().unwrap().len(), 0);

    // Kill-switch lands on the ledger → freeze
    fs::write(&ledger, format!(
        "{}{{\"ts\":\"2026-09-28T00:00:01Z\",\"type\":\"kill_switch\",\"data\":{{\"reason\":\"test kill\"}}}}\n",
        fs::read_to_string(&ledger).unwrap()
    )).unwrap();
    let bundles = d.poll_once().unwrap();
    assert_eq!(bundles.len(), 1);
    let bundle = &bundles[0];
    assert_eq!(bundle.frames, 4); // 3 events + kill_switch frame
    let report = verify_bundle(&bundle.dir).unwrap();
    assert!(report.ok(), "bundle invalid: {:?}", report.problems);

    // Freeze marker got recorded on the ring (drop daemon first — it holds the lock)
    drop(d);
    let ring = Ring::open(&tape_dir, RingConfig::default()).unwrap();
    assert_eq!(ring.len(), 5); // 4 ledger frames + tape.freeze marker
}

#[test]
fn tampered_bundle_fails() {
    let tmp = TempDir::new().unwrap();
    let tape_dir = tmp.path().join("tape");
    let ledger = tmp.path().join("ledger.jsonl");
    write_ledger(&ledger, &[("query", r#"{"prompt":"x"}"#)]);

    let mut d = Daemon::open(daemon_cfg(tape_dir.clone(), ledger)).unwrap();
    d.poll_once().unwrap();
    let bundle = d
        .freeze_now(flight_tape::freeze::FreezeTrigger {
            kind: "manual".into(),
            detail: "test".into(),
            ts: 1759000000,
        })
        .unwrap();

    assert!(verify_bundle(&bundle.dir).unwrap().ok());

    // Flip a byte in a frame body
    let frames_path = bundle.dir.join("frames.jsonl");
    let mut content = fs::read_to_string(&frames_path).unwrap();
    content = content.replacen("\"prompt\":\"x\"", "\"prompt\":\"y\"", 1);
    fs::write(&frames_path, content).unwrap();

    let report = verify_bundle(&bundle.dir).unwrap();
    assert!(!report.ok());
    assert!(!report.chain_ok);
}

#[test]
fn ring_compaction_keeps_chain() {
    let tmp = TempDir::new().unwrap();
    let cfg = RingConfig {
        max_frames: 10,
        max_bytes: 1024 * 1024,
        sync_every: false,
    };
    let mut ring = Ring::open(tmp.path(), cfg).unwrap();
    for i in 0..25 {
        ring.record("tick", "test", json!({"i": i})).unwrap();
    }
    assert_eq!(ring.len(), 10);
    // Window retains chain internally — verify retained slice self-consistency
    let frames = ring.frames().unwrap();
    assert_eq!(frames.len(), 10);
    assert_eq!(frames[0].seq, 16);
    assert_eq!(frames[9].seq, 25);
    let mut tip = flight_tape::frame::decode_hash(&frames[0].hash).unwrap();
    for f in &frames[1..] {
        assert!(f.verify(&tip));
        tip = flight_tape::frame::decode_hash(&f.hash).unwrap();
    }
}

#[test]
fn torn_tail_recovers() {
    let tmp = TempDir::new().unwrap();
    let ring_path = tmp.path().join("ring.jsonl");
    {
        let mut ring = Ring::open(tmp.path(), RingConfig::default()).unwrap();
        ring.record("a", "t", json!({})).unwrap();
        ring.record("b", "t", json!({})).unwrap();
    }
    // Simulate torn write: append garbage then reopen
    fs::write(
        &ring_path,
        format!(
            "{}garbage-without-newline",
            fs::read_to_string(&ring_path).unwrap()
        ),
    )
    .unwrap();
    // write without trailing newline → partial line; also try newline-terminated garbage
    fs::write(
        &ring_path,
        format!(
            "{}garbage\n",
            fs::read_to_string(&ring_path).unwrap().trim_end()
        ),
    )
    .unwrap();
    let ring = Ring::open(tmp.path(), RingConfig::default()).unwrap();
    // Garbage tail truncated; 2 valid frames remain
    assert_eq!(ring.len(), 2);
}

#[test]
fn intent_ingest() {
    let tmp = TempDir::new().unwrap();
    let stream = tmp.path().join("intent.jsonl");
    IntentIngester::write_intent(
        &stream,
        "intent",
        json!({"tool":"write_file","approved":false}),
    )
    .unwrap();
    IntentIngester::write_intent(&stream, "intent", json!({"tool":"run_shell"})).unwrap();

    let mut ing = IntentIngester::new(stream.clone());
    let drained = ing.drain().unwrap();
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].0, "intent");
    assert_eq!(drained[0].1["tool"], "write_file");
    // File truncated after drain
    assert_eq!(ing.drain().unwrap().len(), 0);
}

#[test]
fn redaction_applies() {
    let tmp = TempDir::new().unwrap();
    let mut ring = Ring::open(tmp.path(), RingConfig::default()).unwrap();
    ring.record(
        "leak",
        "test",
        json!({"key": "sk-abc123def456ghi789", "email": "a@b.com"}),
    )
    .unwrap();
    let frames = ring.frames().unwrap();
    let body = serde_json::to_string(&frames[0].body).unwrap();
    assert!(body.contains("[REDACTED_KEY]"));
    assert!(body.contains("[REDACTED_EMAIL]"));
    assert!(!body.contains("sk-abc123"));
}

#[test]
fn genesis_is_deterministic() {
    assert_eq!(genesis_hash(), genesis_hash());
}

#[test]
fn snapshot_root_records() {
    let tmp = TempDir::new().unwrap();
    let state = tmp.path().join("state");
    fs::create_dir_all(&state).unwrap();
    fs::write(state.join("x.txt"), "hello").unwrap();
    let root = StateRoot {
        label: "test".into(),
        dir: state.clone(),
        exclude: vec![],
    };
    let head = {
        // snapshot_root is private — exercise via freeze with a state root
        let tape_dir = tmp.path().join("tape");
        let mut ring = Ring::open(&tape_dir, RingConfig::default()).unwrap();
        ring.record("e", "t", json!({})).unwrap();
        let bundle = flight_tape::freeze::freeze(
            &ring,
            flight_tape::freeze::FreezeTrigger {
                kind: "manual".into(),
                detail: "t".into(),
                ts: 1,
            },
            "s",
            "0",
            &[root],
            vec![],
        )
        .unwrap();

        fs::read_to_string(bundle.dir.join("manifest.json")).unwrap()
    };
    assert!(head.contains("\"test\""));
}
