# flight_tape

Flight recorder for autonomous systems.

A daemon (or embedded library) that maintains a **bounded, hash-chained ring of decision frames** — every query, tool call, approval, denial, intent — and on a trigger (kill event, subject crash, manual) **freezes** the current window into a signed incident bundle: the tape, a respawn snapshot of state, and an Ed25519-signed manifest. Verification is fully offline.

Part of the open trust stack for sovereign AI:

- **touchstone** — public conformance spec, signed attestations, scoreboard
- **sovereign_ledger** — hardened hash-chained audit ledger
- **respawned** — state snapshots and rollback
- **edge_gate** — egress perimeter
- **flight_tape** — incident forensics (this crate)

Reference organism: [Bad Apple](https://github.com/savageAZfck/Bad_Apple), a local-first personal AGI.

## Install

```bash
cargo install flight_tape
# or as a library: cargo add flight_tape
```

## Quick start

```bash
# run a tape against any append-only JSONL ledger ({type,data} shape)
flight-tape daemon --dir /var/lib/myagent/tape \
    --ledger /var/lib/myagent/ledger.jsonl \
    --subject myagent --version 1.0.0 \
    --watch myagent-engine \
    --state-root platform=/var/lib/myagent \
    --state-root learned=$HOME/.myagent

# freeze right now
flight-tape freeze --dir /var/lib/myagent/tape --reason "anomaly"

# verify a bundle — offline, no subject access
flight-tape verify /var/lib/myagent/tape/incidents/<id>

# replay the last hour's decisions
flight-tape replay /var/lib/myagent/tape/incidents/<id>
flight-tape replay /var/lib/myagent/tape/incidents/<id> --around 412 --context 30
```

## How it works

The tape is a bounded ring (`ring.jsonl`): frames hash-chain into each other, old frames compact out past the bounds, and the chain survives compaction — a freeze cites `first_seq..last_seq` of one continuous chain.

Three ways frames arrive:

1. **Ledger tail** — the daemon follows an append-only JSONL event log with a persisted offset (handles rotation/truncation).
2. **Intent stream** — embedders append `{"kind":"intent",...}` to `intent.jsonl`; the daemon drains it. Fire-and-forget for writers.
3. **Embedded** — link the crate and call `ring.record()` directly.

Freeze triggers: a freeze-kind frame lands on the tape (`kill_switch` by default, configurable), a watched process exits, a `FREEZE` trigger file appears, or `freeze` is invoked manually.

## Why a tape

Post-incident, the question is never "was it smart" — it's *show me the decisions leading up to it*. An append-only ledger answers "what did it do" but grows forever and holds no bounded, sealed, *ready-to-hand-over* artifact. The tape is the ring buffer aviation solved decades ago: always recording, bounded by design, and the crash copies the last N seconds into a sealed box with a signature.

Refused intents — what the system *tried* and wasn't allowed — are recorded beside allowed actions, and the distinction survives audit (`src` field).

## Features

- `snapshot` (default) — freeze captures respawn state snapshots. `--no-default-features` for frames-only bundles.
- Ring compaction, torn-write recovery, per-process flock, fsync policy.
- Redaction identical to Bad Apple's audit ledger (keys, emails, SSNs, phones, long tokens) applied to every frame before hashing.

## Verify without trust

`flight-tape verify` needs only the bundle — frames.jsonl + manifest.json + manifest.sig. Rehashes every frame, checks linkage and window bounds, verifies the Ed25519 signature. No daemon, no subject, no network.

## License

MIT — © 2026 Adam Clark
