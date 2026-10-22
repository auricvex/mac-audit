//! launchd plist generation. Labels are explicit and searchable so
//! any user can find mac-audit in LaunchDaemons/LaunchAgents, in
//! Background Items, and with `launchctl list | grep mac-audit`.

pub const DAEMON_LABEL: &str = "dev.ademr.macaudit.daemon";
pub const AGENT_LABEL: &str = "dev.ademr.macaudit.agent";
pub const BINARY_PATH: &str = "/usr/local/bin/mac-audit";

const BANNER: &str = "mac-audit — transparent, consent-based audit agent. \
Every user of this Mac can run `mac-audit status`. It does NOT record camera, \
microphone, keystrokes, or screen content.";

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// System daemon: runs at boot as root, no GUI, no TCC-protected
/// content. Records system-level events only (boot, daemon start).
pub fn daemon_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- {BANNER} -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{DAEMON_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/usr/local/var/mac-audit/daemon.out.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/mac-audit/daemon.err.log</string>
</dict>
</plist>
"#,
        xml_escape(BINARY_PATH)
    )
}

/// Per-user agent: one instance per logged-in user, only in that
/// user's Aqua session. That user is prompted for their own
/// permissions and can remove it from Login Items / Background Items.
pub fn agent_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- {BANNER} -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>agent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>StandardOutPath</key>
    <string>/usr/local/var/mac-audit/agent.out.log</string>
    <key>StandardErrorPath</key>
    <string>/usr/local/var/mac-audit/agent.err.log</string>
</dict>
</plist>
"#,
        xml_escape(BINARY_PATH)
    )
}

/// Plain-language permissions matrix, printed by
/// `mac-audit install --dry-run` before anything is written.
///
/// Full Disk Access is in the required permission set (Ade,
/// 2026-10-22), but the logic that *uses* it is deferred to the
/// next update: v0 only wires the request + `mac-audit status`
/// reporting. v0 does NOT read, scan, or copy file content with it.
pub fn permissions_summary() -> &'static str {
    "\
Permissions matrix (per user, granted by that user in their own session):\n\
  REQUIRED:\n\
  - Full Disk Access — requested per user in System Settings >\n\
    Privacy & Security > Full Disk Access. v0 STATUS ONLY: install\n\
    asks for it and `mac-audit status` reports granted/denied.\n\
    The logic that uses Full Disk Access is DEFERRED to the next\n\
    update — v0 does not read, scan, or copy file content with it.\n\
    A user may refuse or revoke it at any time; mac-audit then\n\
    reports 'denied' and continues without it.\n\
  NOT REQUESTED — never, in any version planned:\n\
  - Camera, Microphone, Screen Recording, Input Monitoring\n\
    (no keylogging), Accessibility.\n\
Visibility:\n\
  - Daemon appears in /Library/LaunchDaemons (label dev.ademr.macaudit.daemon)\n\
  - Agent appears in Background Items / Login Items (label dev.ademr.macaudit.agent)\n\
  - Any user can run `mac-audit status` and `mac-audit log verify`\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_plist_has_correct_label_and_transparency() {
        let p = daemon_plist();
        assert!(p.contains(DAEMON_LABEL));
        assert!(p.contains("transparent, consent-based"));
        assert!(p.contains("<key>RunAtLoad</key>"));
        assert!(p.contains("daemon"));
    }

    #[test]
    fn agent_plist_is_per_user_aqua_session() {
        let p = agent_plist();
        assert!(p.contains(AGENT_LABEL));
        assert!(p.contains("LimitLoadToSessionType"));
        assert!(p.contains("Aqua"));
    }

    #[test]
    fn permissions_summary_includes_fda_deferred_and_exclusions() {
        let s = permissions_summary();
        assert!(s.contains("Full Disk Access"));
        assert!(s.contains("DEFERRED"));
        assert!(s.contains("does not read, scan, or copy"));
        assert!(s.contains("Camera"));
        assert!(s.contains("Input Monitoring"));
    }
}
