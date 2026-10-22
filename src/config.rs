//! Minimal `key = value` configuration. No silent defaults that
//! widen scope: consent is required and cannot be disabled by config.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    /// Append-only audit log location.
    pub log_path: PathBuf,
    /// GitHub repo that is the *only* update source. `owner/name`.
    pub update_repo: String,
    /// Hours between update checks.
    pub update_interval_hours: u64,
    /// Hard requirement, not a toggle: every user must know mac-audit is
    /// running and grant their own permissions. Parsing a config that
    /// tries to set this to `false` is an error (see `parse`).
    pub consent_required: bool,
    /// Remote shell is DEFERRED (Ade, 2026-10-22): required in the
    /// roadmap, not built in v0. This flag exists only so the surface
    /// is explicit — parsing `remote_shell_enabled = true` is an
    /// error in v0, and `mac-audit shell` is a fail-closed stub.
    pub remote_shell_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_path: PathBuf::from("/usr/local/var/mac-audit/audit.log"),
            update_repo: "auricvex/mac-audit".to_string(),
            update_interval_hours: 24,
            consent_required: true,
            remote_shell_enabled: false,
        }
    }
}

impl Config {
    /// Parse `key = value` lines. Unknown keys and any attempt to
    /// disable consent are rejected — fail closed, never silently.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut cfg = Self::default();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("line {}: expected `key = value`", lineno + 1))?;
            match key.trim() {
                "log_path" => cfg.log_path = PathBuf::from(value.trim()),
                "update_repo" => cfg.update_repo = value.trim().to_string(),
                "update_interval_hours" => {
                    cfg.update_interval_hours = value
                        .trim()
                        .parse()
                        .map_err(|_| format!("line {}: bad number", lineno + 1))?;
                }
                "remote_shell_enabled" => {
                    if value.trim() != "false" {
                        return Err(
                            "remote_shell_enabled cannot be turned on in v0: remote shell is deferred to the next update (see docs/DESIGN.md)"
                                .to_string(),
                        );
                    }
                    cfg.remote_shell_enabled = false;
                }
                "consent_required" => {
                    if value.trim() != "true" {
                        return Err(
                            "consent_required cannot be disabled: mac-audit is transparent by design"
                                .to_string(),
                        );
                    }
                    cfg.consent_required = true;
                }
                other => return Err(format!("line {}: unknown key `{other}`", lineno + 1)),
            }
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let cfg = Config::default();
        assert!(cfg.consent_required);
        assert_eq!(cfg.update_repo, "auricvex/mac-audit");
        assert_eq!(cfg.update_interval_hours, 24);
    }

    #[test]
    fn parse_overrides_and_rejects_disabling_consent() {
        let cfg = Config::parse("update_interval_hours = 12\nlog_path = /tmp/j.log\n").unwrap();
        assert_eq!(cfg.update_interval_hours, 12);
        assert_eq!(cfg.log_path, PathBuf::from("/tmp/j.log"));
        assert!(Config::parse("consent_required = false\n").is_err());
        assert!(Config::parse("bogus_key = 1\n").is_err());
        // Remote shell cannot be enabled in v0, in either direction of test:
        assert!(!cfg.remote_shell_enabled);
        assert!(Config::parse("remote_shell_enabled = true\n").is_err());
        assert!(Config::parse("remote_shell_enabled = false\n").is_ok());
    }
}
