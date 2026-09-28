# Security

## Reporting

Open an issue at https://github.com/savageAZfck/flight_tape/issues or email the maintainer (see Cargo.toml authors). For vulnerabilities in the signing path, prefer private contact before public disclosure.

## Scope

- Chain integrity, torn-write recovery, redaction coverage, and signature verification are in-scope security properties.
- `tape.key` handling: the file is created 0600; keep the tape directory root-/owner-only.
- The trust boundary is documented in THREAT_MODEL.md — read it before relying on bundles in adversarial settings.

## Verifying releases

Crate sources are auditable; crates.io metadata includes repository linkage. A bundle signed by a compromised tape.key is forgeable — rotate keys on suspicion and cross-anchor high-value bundles into an external ledger or public record.
