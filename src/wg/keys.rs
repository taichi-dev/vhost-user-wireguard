// SPDX-License-Identifier: MIT OR Apache-2.0

//! WireGuard key loading and parsing utilities.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::error::WgError;

/// Load a WireGuard private key from a file.
///
/// Checks that the file has mode 0600 (no world or group read bits).
pub fn load_private_key(path: &Path) -> Result<x25519_dalek::StaticSecret, WgError> {
    check_key_file_mode(path)?;
    let contents = std::fs::read_to_string(path).map_err(|e| WgError::KeyFileRead {
        path: path.to_owned(),
        source: e,
    })?;
    parse_private_key_base64(contents.trim())
}

/// Load a WireGuard preshared key from a file.
///
/// Checks that the file has mode 0600 (no world or group read bits).
pub fn load_preshared_key(path: &Path) -> Result<[u8; 32], WgError> {
    check_key_file_mode(path)?;
    let contents = std::fs::read_to_string(path).map_err(|e| WgError::KeyFileRead {
        path: path.to_owned(),
        source: e,
    })?;
    parse_preshared_key_base64(contents.trim())
}

/// Parse a WireGuard private key from a base64-encoded string.
pub fn parse_private_key_base64(s: &str) -> Result<x25519_dalek::StaticSecret, WgError> {
    let bytes = STANDARD.decode(s.trim())?;
    let length = bytes.len();
    // `try_into` for `Vec<u8> -> [u8; 32]` only succeeds when length == 32, so
    // surface the size mismatch as `WgError::KeyLength` rather than panicking.
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| WgError::KeyLength { length })?;
    Ok(x25519_dalek::StaticSecret::from(arr))
}

/// Parse a WireGuard preshared key from a base64-encoded string.
pub fn parse_preshared_key_base64(s: &str) -> Result<[u8; 32], WgError> {
    let bytes = STANDARD.decode(s.trim())?;
    let length = bytes.len();
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| WgError::KeyLength { length })?;
    Ok(arr)
}

/// Return a short fingerprint of a public key: first 8 base64 chars + "...".
pub fn key_fingerprint(public_key: &x25519_dalek::PublicKey) -> String {
    let encoded = STANDARD.encode(public_key.as_bytes());
    format!("{}...", &encoded[..8])
}

/// Check that a key file has no world or group read bits set.
fn check_key_file_mode(path: &Path) -> Result<(), WgError> {
    let stat = rustix::fs::stat(path).map_err(|e| WgError::KeyFileRead {
        path: path.to_owned(),
        source: std::io::Error::from_raw_os_error(e.raw_os_error()),
    })?;
    // rustix exposes st_mode as u32 on both backends (libc + linux_raw), so no
    // conversion is required.
    let mode = stat.st_mode;
    if mode & 0o077 != 0 {
        return Err(WgError::KeyFileMode {
            path: path.to_owned(),
            mode: mode & 0o777,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// Generate a valid 32-byte base64 key string.
    fn valid_key_b64() -> String {
        STANDARD.encode([0u8; 32])
    }

    fn write_key_file(mode: u32) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(valid_key_b64().as_bytes()).unwrap();
        f.flush().unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        f
    }

    #[test]
    fn test_parse_valid_private_key() {
        assert!(parse_private_key_base64(&valid_key_b64()).is_ok());
    }

    #[test]
    fn test_parse_invalid_base64() {
        let result = parse_private_key_base64("not-valid-base64!!!");
        assert!(matches!(result, Err(WgError::KeyBase64(_))));
    }

    #[test]
    fn test_parse_wrong_length() {
        let short = STANDARD.encode([0u8; 16]);
        let result = parse_private_key_base64(&short);
        assert!(matches!(result, Err(WgError::KeyLength { length: 16 })));
    }

    #[test]
    fn test_load_secure_mode() {
        let f = write_key_file(0o600);
        assert!(load_private_key(f.path()).is_ok());
    }

    #[test]
    fn test_reject_world_readable() {
        let f = write_key_file(0o644);
        let result = load_private_key(f.path());
        assert!(matches!(
            result,
            Err(WgError::KeyFileMode { mode: 0o644, .. })
        ));
    }

    #[test]
    fn test_reject_group_readable() {
        let f = write_key_file(0o640);
        let result = load_private_key(f.path());
        assert!(matches!(result, Err(WgError::KeyFileMode { .. })));
    }

    #[test]
    fn test_load_missing_file() {
        let result = load_private_key(Path::new("/nonexistent/path/to/key.pem"));
        assert!(matches!(result, Err(WgError::KeyFileRead { .. })));
    }

    #[test]
    fn test_fingerprint_is_short() {
        let secret = x25519_dalek::StaticSecret::from([1u8; 32]);
        let public = x25519_dalek::PublicKey::from(&secret);
        let fp = key_fingerprint(&public);
        assert_eq!(fp.len(), 11, "fingerprint should be 11 chars, got: {fp}");
        assert!(
            fp.ends_with("..."),
            "fingerprint should end with '...', got: {fp}"
        );
    }

    #[test]
    fn test_fingerprint_no_key_bytes() {
        let secret = x25519_dalek::StaticSecret::from([2u8; 32]);
        let public = x25519_dalek::PublicKey::from(&secret);
        let fp = key_fingerprint(&public);
        let full = STANDARD.encode(public.as_bytes());
        assert_eq!(&fp[..8], &full[..8]);
        assert_ne!(fp, full, "fingerprint should be truncated");
    }
}
