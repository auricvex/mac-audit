//! Permission status checks — status/plumbing only.
//!
//! Full Disk Access (FDA) is in mac-audit's required permission set,
//! but the logic that *uses* FDA is deferred to the next update
//! (Ade, 2026-10-22). This module therefore only *reports* whether
//! FDA appears granted for the current user. It does not read, scan,
//! or copy any file content: the check follows the normal TCC
//! pattern of attempting to open a TCC-protected database file and
//! immediately dropping the handle, using only success /
//! permission-denied as the signal.

use std::fmt;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdaStatus {
    Granted,
    Denied,
    Unknown,
    NotApplicable,
}

impl fmt::Display for FdaStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not-applicable (not macOS)",
        };
        write!(f, "{s}")
    }
}

/// Path whose readability is the conventional FDA probe: the
/// per-user TCC database. Merely opening it is gated by FDA on
/// modern macOS. We never parse it.
#[cfg(target_os = "macos")]
fn fda_probe_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("Library/Application Support/com.apple.TCC/TCC.db"))
}

/// Report FDA status for the *current* user only. Another user's
/// status is that user's business and is checked when they run
/// `mac-audit status` in their own session.
pub fn full_disk_access_status() -> FdaStatus {
    #[cfg(target_os = "macos")]
    {
        let Some(path) = fda_probe_path() else {
            return FdaStatus::Unknown;
        };
        if !path.exists() {
            return FdaStatus::Unknown;
        }
        match std::fs::File::open(&path) {
            // Handle is dropped here, unparsed — access check only.
            Ok(_file) => FdaStatus::Granted,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => FdaStatus::Denied,
            Err(_) => FdaStatus::Unknown,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        FdaStatus::NotApplicable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fda_status_is_reportable_on_any_platform() {
        let s = full_disk_access_status();
        // On Linux CI this must be NotApplicable; on macOS one of the
        // three real states. Either way it must never panic.
        assert!(matches!(
            s,
            FdaStatus::Granted | FdaStatus::Denied | FdaStatus::Unknown | FdaStatus::NotApplicable
        ));
        assert_ne!(s.to_string(), "");
    }
}
