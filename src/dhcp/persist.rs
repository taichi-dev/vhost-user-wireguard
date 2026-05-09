// SPDX-License-Identifier: MIT OR Apache-2.0

//! Atomic-write JSON lease persistence.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;

use crate::dhcp::lease::Lease;
use crate::error::DhcpError;

/// Serializable snapshot of all DHCP leases.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LeaseSnapshot {
    pub version: u32,
    pub leases: Vec<Lease>,
}

/// Handles atomic-write JSON persistence of DHCP leases.
pub struct LeaseFile {
    path: PathBuf,
}

impl LeaseFile {
    /// Create a new LeaseFile handle for the given path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Load leases from disk.
    ///
    /// - If the file doesn't exist, returns an empty snapshot.
    /// - If the file is corrupt JSON, renames it to `<path>.corrupt.<unix_ts>` and returns empty.
    /// - If the version is not 1, returns `Err(DhcpError::LeaseFileVersion)`.
    pub fn load(&self) -> Result<LeaseSnapshot, DhcpError> {
        if !self.path.exists() {
            return Ok(LeaseSnapshot {
                version: 1,
                leases: vec![],
            });
        }

        let mut content = String::new();
        File::open(&self.path)
            .and_then(|mut f| f.read_to_string(&mut content))
            .map_err(|e| DhcpError::LeaseFileIo {
                path: self.path.clone(),
                source: e,
            })?;

        let snap: LeaseSnapshot = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let corrupt_path = self.path.with_extension(format!("corrupt.{ts}"));
                if let Err(rename_err) = fs::rename(&self.path, &corrupt_path) {
                    warn!(
                        path = %self.path.display(),
                        error = %rename_err,
                        "lease_file_corrupt_rename_failed"
                    );
                } else {
                    warn!(
                        path = %self.path.display(),
                        corrupt_path = %corrupt_path.display(),
                        json_error = %e,
                        "lease_file_corrupt_renamed"
                    );
                }
                return Ok(LeaseSnapshot {
                    version: 1,
                    leases: vec![],
                });
            }
        };

        if snap.version != 1 {
            return Err(DhcpError::LeaseFileVersion {
                version: snap.version,
            });
        }

        Ok(snap)
    }

    /// Save leases to disk atomically via temp file + rename.
    ///
    /// - Ensures parent directory exists (mode 0700).
    /// - Writes to `<path>.tmp`, fsyncs, then renames to `<path>`.
    /// - Fsyncs the parent directory after rename.
    pub fn save(&self, snap: &LeaseSnapshot) -> Result<(), DhcpError> {
        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| DhcpError::LeaseFileIo {
                        path: parent.to_path_buf(),
                        source: e,
                    })?;
            }
        }

        let tmp_path = self.path.with_extension("tmp");

        let json = serde_json::to_string_pretty(snap)?;

        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| {
                warn!(
                    path = %tmp_path.display(),
                    error = %e,
                    "lease_checkpoint_failed"
                );
                DhcpError::LeaseFileIo {
                    path: tmp_path.clone(),
                    source: e,
                }
            })?;

        tmp_file.write_all(json.as_bytes()).map_err(|e| {
            warn!(
                path = %tmp_path.display(),
                error = %e,
                "lease_checkpoint_failed"
            );
            DhcpError::LeaseFileIo {
                path: tmp_path.clone(),
                source: e,
            }
        })?;

        tmp_file.sync_all().map_err(|e| {
            warn!(
                path = %tmp_path.display(),
                error = %e,
                "lease_checkpoint_failed"
            );
            DhcpError::LeaseFileIo {
                path: tmp_path.clone(),
                source: e,
            }
        })?;

        drop(tmp_file);

        fs::rename(&tmp_path, &self.path).map_err(|e| {
            warn!(
                src = %tmp_path.display(),
                dst = %self.path.display(),
                error = %e,
                "lease_checkpoint_failed"
            );
            DhcpError::LeaseFileIo {
                path: self.path.clone(),
                source: e,
            }
        })?;

        // Fsync the parent directory.
        if let Some(parent) = self.path.parent() {
            let dir = File::open(parent).map_err(|e| DhcpError::LeaseFileIo {
                path: parent.to_path_buf(),
                source: e,
            })?;
            dir.sync_all().map_err(|e| DhcpError::LeaseFileIo {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, UNIX_EPOCH};

    use tempfile::TempDir;

    use super::*;
    use crate::dhcp::lease::{Lease, LeaseState};

    fn make_lease(mac_byte: u8, ip: Ipv4Addr) -> Lease {
        Lease {
            mac: [mac_byte, 0, 0, 0, 0, 0],
            ip,
            state: LeaseState::Bound {
                expires_at: UNIX_EPOCH + Duration::from_secs(9999999),
            },
            hostname: Some(format!("host-{mac_byte}")),
        }
    }

    fn make_snapshot(leases: Vec<Lease>) -> LeaseSnapshot {
        LeaseSnapshot { version: 1, leases }
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("leases.json");
        let lf = LeaseFile::new(path);

        let leases = vec![
            make_lease(1, Ipv4Addr::new(10, 0, 0, 1)),
            make_lease(2, Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let snap = make_snapshot(leases.clone());

        lf.save(&snap).expect("save should succeed");
        let loaded = lf.load().expect("load should succeed");

        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.leases.len(), 2);
        assert_eq!(loaded.leases[0].mac, leases[0].mac);
        assert_eq!(loaded.leases[0].ip, leases[0].ip);
        assert_eq!(loaded.leases[1].mac, leases[1].mac);
        assert_eq!(loaded.leases[1].ip, leases[1].ip);
    }

    #[test]
    fn test_load_missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.json");
        let lf = LeaseFile::new(path);

        let snap = lf.load().expect("load should succeed for missing file");
        assert_eq!(snap.version, 1);
        assert!(snap.leases.is_empty());
    }

    #[test]
    fn test_load_corrupt_json_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("leases.json");

        // Write garbage JSON.
        fs::write(&path, b"this is not valid json!!!").unwrap();

        let lf = LeaseFile::new(path.clone());
        let snap = lf.load().expect("load should return Ok for corrupt JSON");

        assert_eq!(snap.version, 1);
        assert!(snap.leases.is_empty());

        // Original file should be gone (renamed to .corrupt.*).
        assert!(!path.exists(), "original file should have been renamed");

        // A .corrupt.* file should exist.
        let corrupt_files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
            .collect();
        assert!(!corrupt_files.is_empty(), "corrupt file should exist");
    }

    #[test]
    fn test_load_wrong_version() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("leases.json");

        // Write JSON with version=99.
        let bad_json = r#"{"version":99,"leases":[]}"#;
        fs::write(&path, bad_json).unwrap();

        let lf = LeaseFile::new(path);
        let result = lf.load();

        assert!(
            matches!(result, Err(DhcpError::LeaseFileVersion { version: 99 })),
            "expected LeaseFileVersion error, got: {result:?}"
        );
    }

    #[test]
    fn test_atomic_write() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("leases.json");
        let lf = LeaseFile::new(path.clone());

        let snap = make_snapshot(vec![make_lease(5, Ipv4Addr::new(10, 0, 0, 5))]);
        lf.save(&snap).expect("save should succeed");

        // Temp file should not exist after save.
        let tmp_path = path.with_extension("tmp");
        assert!(
            !tmp_path.exists(),
            "temp file should not exist after atomic rename"
        );

        // Final file should exist.
        assert!(path.exists(), "final file should exist after save");
    }
}
