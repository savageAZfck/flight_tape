# Threat model — flight_tape

## What a bundle proves

- The recorded sequence of frames, in order, is what the tape contained at freeze time (hash chain + signature over the manifest).
- The stated window bounds and chain tip match the frames in the bundle.
- The signer held `tape.key` at freeze time.
- State snapshot ids (respawn HEADs) name the exact content the subject's state roots held — replayable offline if the auditor has the state.

## What it cannot prove

- **That frames are true.** The tape records what sources emit. An embedded writer (intent stream) that lies writes a false tape; a compromise *before* the tape means fabricated history. Ledger-sourced frames carry the ledger's HMAC lineage — manifest `src` per frame preserves which trust layer each row came through.
- **Completeness beyond the window.** The ring is bounded. Events older than the window at freeze time are gone by design — incident bundles chain (`prior_incidents`) so history order is provable, but a dropped event that never reached the tape is invisible.
- **Key security.** `tape.key` (0600, tape dir) signs bundles. A stolen key produces forgeable bundles. Same trust model as the subject's own signing keys — rotate on suspicion (`flight-tape keygen` overwrites), treat old bundles as signed by the old key.
- **Signer of last resort.** Bundles are signed by the machine being audited. For high-assurance use, anchor bundle manifests into an external ledger (sovereign_ledger seal events) or publish them — an incident bundle copied to a public scoreboard can't be rewritten without breaking the signature.

## Adversary assumptions

- An adversary who can modify frames.jsonl post-freeze fails verification (chain + manifest + signature all break).
- An adversary controlling the daemon can silence the tape (stop recording) — detectable: the head.hash sidecar stops advancing; silence itself is evidence.
- An adversary controlling the *subject* but not the daemon gets its actions recorded — including refused intents, which are often more informative than allowed ones.

## Data handling

Frame bodies pass through redaction before hashing (API keys, bearer tokens, emails, SSNs, phones, long hex blobs). Ledger-sourced frames arrive already redacted (upstream) and are scrubbed again — defense in depth. Intent frames bypass the ledger, so the tape's own redaction is the only pass.
