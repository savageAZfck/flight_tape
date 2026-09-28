//! The ring — a bounded, hash-chained append window.
//!
//! `ring.jsonl` holds the most recent frames. When either bound is exceeded
//! (max_frames or max_bytes) the file is compacted to the retained tail;
//! `seq` and `prev_hash` chain across compactions, so a freeze bundle can
//! cite `first_seq..last_seq` as a slice of one continuous chain.

use crate::frame::{decode_hash, genesis_hash, Frame, Redactor, HASH_SIZE};
use crate::{Error, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(target_family = "unix")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;
#[cfg(target_family = "unix")]
use std::os::unix::io::AsRawFd;

#[derive(Debug, Clone)]
pub struct RingConfig {
    /// Retain at most this many frames.
    pub max_frames: usize,
    /// Retain at most this many bytes.
    pub max_bytes: u64,
    /// fsync after every append (slower, survives power loss).
    pub sync_every: bool,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            max_frames: 50_000,
            max_bytes: 256 * 1024 * 1024,
            sync_every: false,
        }
    }
}

/// A bounded hash-chained append log.
pub struct Ring {
    dir: PathBuf,
    path: PathBuf,
    config: RingConfig,
    /// Chain tip.
    last_hash: [u8; HASH_SIZE],
    /// Next sequence number.
    next_seq: u64,
    /// Oldest seq currently retained (first seq in the file).
    floor_seq: u64,
    /// Current frame count in the file.
    count: usize,
    /// Current file size.
    bytes: u64,
    _lock: File,
}

impl Ring {
    /// Open or create the ring inside `dir` (`dir/ring.jsonl`).
    pub fn open<P: AsRef<Path>>(dir: P, config: RingConfig) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let path = dir.join("ring.jsonl");

        // Hold an advisory lock for the handle's lifetime — two writers on
        // one ring serialize rather than race.
        let lock_path = dir.join("ring.lock");
        let _lock = open_lock(&lock_path)?;

        if path.exists() {
            #[cfg(target_family = "unix")]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }

        let mut ring = Self {
            dir,
            path,
            config,
            last_hash: genesis_hash(),
            next_seq: 1,
            floor_seq: 1,
            count: 0,
            bytes: 0,
            _lock,
        };
        ring.recover()?;
        Ok(ring)
    }

    /// Scan the file: validate chain, drop a torn tail, restore counters.
    fn recover(&mut self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let file = File::open(&self.path)?;
        let mut reader = BufReader::new(file);
        let mut valid_len: u64 = 0;
        let mut offset: u64 = 0;
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                offset += n as u64;
                continue;
            }
            let frame: Frame = match serde_json::from_str(trimmed) {
                Ok(f) => f,
                Err(_) => break, // torn write — truncate here
            };
            if frame.seq != self.next_seq || !frame.verify(&self.last_hash) {
                break; // corrupt tail — truncate to last good frame
            }
            self.last_hash = decode_hash(&frame.hash).unwrap();
            self.next_seq = frame.seq + 1;
            self.count += 1;
            offset += n as u64;
            valid_len = offset;
        }
        drop(reader);
        let file = OpenOptions::new().write(true).open(&self.path)?;
        file.set_len(valid_len)?;
        self.bytes = valid_len;
        // floor_seq: first frame in file. If compacted, the file begins at
        // some seq > 1 — recover it by peeking the first line.
        if self.count > 0 {
            let f = File::open(&self.path)?;
            let mut r = BufReader::new(f);
            let mut first = String::new();
            r.read_line(&mut first)?;
            if let Ok(fr) = serde_json::from_str::<Frame>(first.trim_end()) {
                self.floor_seq = fr.seq;
            }
        } else {
            self.floor_seq = self.next_seq;
        }
        Ok(())
    }

    /// Append a frame. `body` is redacted, chained, and flushed.
    /// Returns the frame's seq.
    pub fn record(&mut self, kind: &str, src: &str, mut body: serde_json::Value) -> Result<u64> {
        Redactor::scrub(&mut body);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let seq = self.next_seq;
        let hash = Frame::compute_hash(&self.last_hash, seq, ts, kind, src, &body);
        let frame = Frame {
            v: crate::frame::FORMAT_VERSION,
            seq,
            ts,
            kind: kind.to_string(),
            src: src.to_string(),
            body,
            prev_hash: hex::encode(self.last_hash),
            hash: hex::encode(hash),
        };
        let mut line = serde_json::to_vec(&frame)?;
        line.push(b'\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(&line)?;
        if self.config.sync_every {
            f.sync_data()?;
        }
        self.last_hash = hash;
        self.next_seq += 1;
        self.count += 1;
        self.bytes += line.len() as u64;
        self.maybe_compact()?;
        Ok(seq)
    }

    /// Compact the ring when bounds are exceeded: rewrite the file keeping
    /// only the tail within limits. Chain stays intact — prev_hash values
    /// still link into the same continuous chain (verification of a compacted
    /// file begins mid-chain: floor's prev_hash is cited as "prior context").
    fn maybe_compact(&mut self) -> Result<()> {
        if self.count <= self.config.max_frames && self.bytes <= self.config.max_bytes {
            return Ok(());
        }
        // Read all frames, keep the newest that fit bounds.
        let f = File::open(&self.path)?;
        let mut frames: Vec<String> = Vec::with_capacity(self.count);
        for line in BufReader::new(f).lines() {
            let line = line?;
            if !line.trim().is_empty() {
                frames.push(line);
            }
        }
        let mut kept: Vec<&String> = Vec::new();
        let mut size: u64 = 0;
        for l in frames.iter().rev() {
            let lsz = l.len() as u64 + 1;
            if kept.len() >= self.config.max_frames || size + lsz > self.config.max_bytes {
                break;
            }
            kept.push(l);
            size += lsz;
        }
        kept.reverse();
        if kept.len() == frames.len() {
            return Ok(());
        }
        let tmp = self.dir.join(".ring.tmp");
        {
            let mut w = File::create(&tmp)?;
            for l in &kept {
                w.write_all(l.as_bytes())?;
                w.write_all(b"\n")?;
            }
            w.sync_data()?;
        }
        fs::rename(&tmp, &self.path)?;
        self.count = kept.len();
        self.bytes = size;
        if let Some(first) = kept.first() {
            if let Ok(fr) = serde_json::from_str::<Frame>(first) {
                self.floor_seq = fr.seq;
            }
        }
        Ok(())
    }

    /// Read all currently retained frames (oldest → newest).
    pub fn frames(&self) -> Result<Vec<Frame>> {
        let mut out = Vec::new();
        if !self.path.exists() {
            return Ok(out);
        }
        for line in BufReader::new(File::open(&self.path)?).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(line.trim_end())?);
        }
        Ok(out)
    }

    /// Frames in `[first_seq, last_seq]` inclusive.
    pub fn window(&self, first_seq: u64, last_seq: u64) -> Result<Vec<Frame>> {
        Ok(self
            .frames()?
            .into_iter()
            .filter(|f| f.seq >= first_seq && f.seq <= last_seq)
            .collect())
    }

    pub fn head(&self) -> [u8; HASH_SIZE] {
        self.last_hash
    }
    pub fn head_hex(&self) -> String {
        hex::encode(self.last_hash)
    }
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
    pub fn floor_seq(&self) -> u64 {
        self.floor_seq
    }
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Atomically rewrite the head sidecar (`head.hash`) — lets a watcher
    /// check liveness/tip without parsing the ring.
    pub fn write_head(&self) -> Result<()> {
        let tmp = self.dir.join(".head.tmp");
        fs::write(&tmp, self.head_hex())?;
        fs::rename(&tmp, self.dir.join("head.hash"))?;
        Ok(())
    }
}

#[cfg(target_family = "unix")]
fn open_lock(path: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(Error::Lock("ring locked by another process".into()));
    }
    Ok(f)
}

#[cfg(not(target_family = "unix"))]
fn open_lock(_path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(_path)?)
}

/// Seek helper kept for embedders (unused internally today).
#[allow(dead_code)]
fn seek_end(f: &mut File) -> std::io::Result<u64> {
    f.seek(SeekFrom::End(0))
}
