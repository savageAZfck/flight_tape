# flight_tape/0.1 — wire format

## Frame

One JSON object per line in `ring.jsonl` and bundle `frames.jsonl`:

```json
{"v":1,"seq":42,"ts":1759000000,"kind":"tool_call","src":"ledger",
 "body":{...},"prev_hash":"<64 hex>","hash":"<64 hex>"}
```

- `v` — format version (1)
- `seq` — monotonically increasing, starts at 1
- `ts` — unix seconds
- `kind` — event class, free-form (`query`, `tool_call`, `intent`, `kill_switch`, `tape.freeze`, …)
- `src` — provenance (`ledger`, `intent`, `cli`, `daemon`)
- `body` — redacted JSON payload
- `hash` — `SHA-256("FT1:" || prev_hash_raw || seq:u64le || ts:u64le || kind_len:u32le || kind || src_len:u32le || src || body_json_len:u64le || body_json)`
- `body_json` is compact `serde_json` serialization (no whitespace, key order preserved)
- genesis `prev_hash` = `SHA-256("flight_tape-genesis-v1")`

## Ring bounds

The ring keeps at most `max_frames` frames and `max_bytes` bytes (defaults 50k / 256 MiB). Compaction rewrites the file keeping the retained tail; `seq`/`prev_hash` are untouched — verification of a compacted window starts mid-chain (the floor frame's `prev_hash` cites dropped context; all retained linkage still verifies).

## Trigger file

`<tape_dir>/FREEZE` — presence freezes the tape once, contents become the manifest `detail`. Consumed on read.

## Intent stream

`<tape_dir>/intent.jsonl` — drop-stream for pre-ledger intent frames. Writers append `{"kind":"intent",...}`; the daemon drains and truncates. Fire-and-forget; no daemon needed at write time.

## Incident bundle

`incidents/<YYYYMMDDTHHMMSSZ>-<last_seq>/`:

- `frames.jsonl` — the frozen window, verbatim
- `manifest.json` — signed document
- `manifest.sig` — Ed25519 signature (hex) over the canonical manifest bytes
- `state/` — respawn snapshot ids per state root

manifest.json:

```json
{"spec":"flight_tape/0.1",
 "subject":{"name":"...","version":"...","host":"..."},
 "trigger":{"kind":"kill_switch|crash|manual","detail":"...","ts":...},
 "window":{"first_seq":..,"last_seq":..,"count":..,"span_seconds":..},
 "head_hash":"<chain tip at freeze>",
 "snapshots":{"<label>":"<respawn head hex>"},
 "pubkey":"<ed25519 hex>",
 "prior_incidents":["<bundle dir name>", ...]}
```

Verification (`flight-tape verify <bundle>`): rehash every frame, check seq linkage and self-hash, compare manifest window/count/head_hash, verify signature. Fails on any mismatch. No subject access required.
