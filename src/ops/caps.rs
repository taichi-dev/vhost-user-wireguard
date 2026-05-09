// SPDX-License-Identifier: MIT OR Apache-2.0

//! Capability dropping and privilege reduction.
//!
//! This module provides two operations:
//! - [`drop_privileges`]: Change user and/or group identity.
//! - [`drop_capabilities`]: Clear all Linux capabilities and set `no_new_privs`.

use std::fs;

use caps::CapSet;
use rustix::thread::{Gid, Uid, set_no_new_privs, set_thread_gid, set_thread_uid};

use crate::error::PrivilegeError;

/// Look up a group name in `/etc/group` and return its GID.
fn lookup_gid(name: &str) -> Result<Gid, PrivilegeError> {
    let content = fs::read_to_string("/etc/group")
        .map_err(|e| PrivilegeError::Caps(format!("cannot read /etc/group: {e}")))?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[0] == name {
            let gid: u32 = parts[2].parse().map_err(|_| PrivilegeError::UnknownGroup {
                name: name.to_string(),
            })?;
            // SAFETY: gid was parsed from /etc/group, which is the
            // authoritative source for valid group identifiers.
            return Ok(unsafe { Gid::from_raw(gid) });
        }
    }

    Err(PrivilegeError::UnknownGroup {
        name: name.to_string(),
    })
}

/// Look up a user name in `/etc/passwd` and return its UID.
fn lookup_uid(name: &str) -> Result<Uid, PrivilegeError> {
    let content = fs::read_to_string("/etc/passwd")
        .map_err(|e| PrivilegeError::Caps(format!("cannot read /etc/passwd: {e}")))?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[0] == name {
            let uid: u32 = parts[2].parse().map_err(|_| PrivilegeError::UnknownUser {
                name: name.to_string(),
            })?;
            // SAFETY: uid was parsed from /etc/passwd, which is the
            // authoritative source for valid user identifiers.
            return Ok(unsafe { Uid::from_raw(uid) });
        }
    }

    Err(PrivilegeError::UnknownUser {
        name: name.to_string(),
    })
}

/// Drop privileges by changing the group and/or user identity.
///
/// `setgid` is called **before** `setuid` because a non-root process cannot
/// change its group after dropping the ability to change its UID.
///
/// If both `user` and `group` are `None`, this is a no-op.
///
/// # Errors
///
/// Returns [`PrivilegeError::UnknownGroup`] if the group name is not found
/// in `/etc/group`.
/// Returns [`PrivilegeError::UnknownUser`] if the user name is not found
/// in `/etc/passwd`.
/// Returns [`PrivilegeError::Setgid`] if the `setgid` syscall fails.
/// Returns [`PrivilegeError::Setuid`] if the `setuid` syscall fails.
pub fn drop_privileges(user: Option<&str>, group: Option<&str>) -> Result<(), PrivilegeError> {
    // setgid must come before setuid (can't setgid after dropping root).
    if let Some(group_name) = group {
        let gid = lookup_gid(group_name)?;
        set_thread_gid(gid).map_err(|e| PrivilegeError::Setgid {
            gid: gid.as_raw(),
            source: e.into(),
        })?;
    }

    if let Some(user_name) = user {
        let uid = lookup_uid(user_name)?;
        set_thread_uid(uid).map_err(|e| PrivilegeError::Setuid {
            uid: uid.as_raw(),
            source: e.into(),
        })?;
    }

    Ok(())
}

/// Drop all Linux capabilities and set `no_new_privs`.
///
/// This clears the Effective, Permitted, and Inheritable capability sets,
/// then sets `PR_SET_NO_NEW_PRIVS` so that neither the current process nor
/// its future children can ever regain privileges.
///
/// # Errors
///
/// Returns [`PrivilegeError::Caps`] if any of the `caps::clear` calls fail.
/// Returns [`PrivilegeError::Prctl`] if the `prctl(PR_SET_NO_NEW_PRIVS)` call
/// fails.
pub fn drop_capabilities() -> Result<(), PrivilegeError> {
    caps::clear(None, CapSet::Effective).map_err(|e| PrivilegeError::Caps(e.to_string()))?;
    caps::clear(None, CapSet::Permitted).map_err(|e| PrivilegeError::Caps(e.to_string()))?;
    caps::clear(None, CapSet::Inheritable).map_err(|e| PrivilegeError::Caps(e.to_string()))?;

    set_no_new_privs(true).map_err(|e| PrivilegeError::Prctl { source: e.into() })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drop_capabilities_no_panic() {
        // May return Err if not running as root; the important thing is
        // that it doesn't panic.
        let _result = drop_capabilities();
    }

    #[test]
    fn test_drop_privileges_no_user_no_group() {
        assert!(drop_privileges(None, None).is_ok());
    }

    #[test]
    fn test_drop_privileges_unknown_user() {
        let result = drop_privileges(Some("nonexistent_user_xyz"), None);
        assert!(result.is_err());
        assert!(matches!(result, Err(PrivilegeError::UnknownUser { .. })));
    }

    #[test]
    fn test_drop_privileges_unknown_group() {
        let result = drop_privileges(None, Some("nonexistent_group_xyz"));
        assert!(result.is_err());
        assert!(matches!(result, Err(PrivilegeError::UnknownGroup { .. })));
    }
}
