//! flight_tape — a flight recorder for autonomous systems.
//!
//! A bounded, hash-chained ring of decision frames is appended continuously
//! by a daemon or an embedding process. On a trigger (kill event, crash,
//! manual) the current window is frozen into a signed incident bundle:
//! the frame tape plus state snapshots and an Ed25519-signed manifest.
//! Bundles verify offline — no access to the subject is needed.

pub mod daemon;
pub mod frame;
pub mod freeze;
pub mod replay;
pub mod ring;
pub mod sign;
pub mod source;
pub mod trigger;
pub mod verify;

pub use daemon::{Daemon, DaemonConfig};
pub use frame::{Frame, Redactor};
pub use freeze::{FreezeTrigger, IncidentBundle};
pub use ring::{Ring, RingConfig};
pub use source::{IntentIngester, LedgerTailer};
pub use trigger::{Trigger, TriggerConfig};
pub use verify::{verify_bundle, VerifyReport};

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    InvalidFrame(usize, String),
    BrokenChain(u64),
    Corrupt(String),
    Lock(String),
    Sign(String),
    Missing(String),
    #[cfg(feature = "snapshot")]
    Snapshot(respawned::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Serialization(e) => write!(f, "serialization error: {e}"),
            Error::InvalidFrame(n, e) => write!(f, "invalid frame {n}: {e}"),
            Error::BrokenChain(s) => write!(f, "broken chain at seq {s}"),
            Error::Corrupt(m) => write!(f, "corrupt tape: {m}"),
            Error::Lock(m) => write!(f, "lock error: {m}"),
            Error::Sign(m) => write!(f, "signing error: {m}"),
            Error::Missing(m) => write!(f, "missing: {m}"),
            #[cfg(feature = "snapshot")]
            Error::Snapshot(e) => write!(f, "snapshot error: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serialization(e)
    }
}

#[cfg(feature = "snapshot")]
impl From<respawned::Error> for Error {
    fn from(e: respawned::Error) -> Self {
        Error::Snapshot(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Default state dir name under a subject's data root.
pub const TAPE_DIR: &str = "tape";
/// Intent drop-stream filename — writers append intent frames here and the
/// daemon drains it into the ring.
pub const INTENT_STREAM: &str = "intent.jsonl";
/// Touching this file inside the tape dir triggers a manual freeze.
pub const FREEZE_FILE: &str = "FREEZE";
