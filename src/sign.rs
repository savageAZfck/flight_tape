//! Ed25519 signing for incident bundles.
//!
//! The signer key lives at `<tape dir>/tape.key` (0600, hex-encoded seed).
//! Every freeze bundle carries the signer's pubkey in its manifest, so
//! verification needs nothing but the bundle itself.

use crate::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::fs;
use std::path::Path;

#[cfg(target_family = "unix")]
use std::os::unix::fs::PermissionsExt;

/// Load or create the tape signing key at `path`.
pub fn load_or_create(path: &Path) -> Result<SigningKey> {
    if path.exists() {
        let hex_str = fs::read_to_string(path)?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| Error::Sign(format!("bad tape.key hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Sign("tape.key must be 32 bytes".into()))?;
        return Ok(SigningKey::from_bytes(&arr));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut seed = [0u8; 32];
    use rand::Rng;
    rand::rngs::OsRng.fill(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    fs::write(path, hex::encode(seed))?;
    #[cfg(target_family = "unix")]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(key)
}

/// Sign `msg`, returning the signature as hex.
pub fn sign(key: &SigningKey, msg: &[u8]) -> String {
    let sig: Signature = key.sign(msg);
    hex::encode(sig.to_bytes())
}

/// Verify `sig_hex` over `msg` under `pubkey_hex`.
pub fn verify(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> Result<bool> {
    let pk_bytes =
        hex::decode(pubkey_hex).map_err(|e| Error::Sign(format!("bad pubkey hex: {e}")))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| Error::Sign("pubkey must be 32 bytes".into()))?;
    let vk =
        VerifyingKey::from_bytes(&pk_arr).map_err(|e| Error::Sign(format!("bad pubkey: {e}")))?;
    let sig_bytes =
        hex::decode(sig_hex.trim()).map_err(|e| Error::Sign(format!("bad signature hex: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| Error::Sign("signature must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_arr);
    Ok(vk.verify(msg, &sig).is_ok())
}
