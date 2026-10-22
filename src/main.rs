//! mac-audit CLI. Single binary, subcommands:
//! `daemon`, `agent`, `status`, `install`, `uninstall`,
//! `log show|verify`, `update check`, `shell` (disabled stub).

use mac_audit::audit;
use mac_audit::config::Config;
use mac_audit::event::EventKind;
use mac_audit::permissions;
use mac_audit::plist;
use mac_audit::update::{self, Manifest};
use std::path::PathBuf;
use std::process::ExitCode;

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn log_path() -> PathBuf {
    std::env::var_os("MAC_AUDIT_LOG").map_or_else(|| Config::default().log_path, PathBuf::from)
}

fn usage() -> &'static str {
    "\
mac-audit — transparent, consent-based audit agent for macOS

USAGE:
  mac-audit daemon                 Run the system daemon (system events only)
  mac-audit agent                  Run the per-user agent (own session only)
  mac-audit status                 Show visibility, version, FDA status, log check
  mac-audit install --dry-run      Print plists + permissions; write nothing (default)
  mac-audit uninstall [--dry-run]  Print/explain removal (dry-run by default)
  mac-audit log show               Print audit log entries
  mac-audit log verify             Verify the hash chain (detects tampering)
  mac-audit update check [file]    Verify a release manifest file; never installs in v0
  mac-audit shell                  Remote shell — NOT enabled in this version
"
}

fn cmd_daemon() -> ExitCode {
    let path = log_path();
    let user = "root".to_string();
    match audit::append(&path, EventKind::SystemBoot.as_str(), &user, "daemon") {
        Ok(e) => {
            println!(
                "mac-audit daemon: recorded {} at seq {} — log: {}",
                e.event,
                e.seq,
                path.display()
            );
            println!("mac-audit daemon: scaffold build — event loop beyond startup recording is a TODO for the macOS build (LaunchDaemon label {})", plist::DAEMON_LABEL);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "mac-audit daemon: cannot write audit log {}: {e}",
                path.display()
            );
            ExitCode::FAILURE
        }
    }
}

fn cmd_agent() -> ExitCode {
    let path = log_path();
    let user = current_user();
    match audit::append(&path, EventKind::AgentStart.as_str(), &user, "agent") {
        Ok(e) => {
            println!(
                "mac-audit agent: user {user} — recorded {} at seq {}",
                e.event, e.seq
            );
            println!(
                "mac-audit agent: this session only. Full Disk Access for {user}: {}",
                permissions::full_disk_access_status()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mac-audit agent: cannot write audit log: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_status() -> ExitCode {
    let path = log_path();
    println!("mac-audit {}", mac_audit::version());
    println!("transparent: yes — visible in Background Items / Login Items");
    println!("daemon label: {}", plist::DAEMON_LABEL);
    println!("agent label:  {}", plist::AGENT_LABEL);
    println!("user: {}", current_user());
    println!(
        "Full Disk Access (current user): {}",
        permissions::full_disk_access_status()
    );
    println!("  ^ v0 reports FDA status only; logic using FDA is deferred.");
    println!("remote shell: disabled in this version (see `mac-audit shell`)");
    println!("audit log: {}", path.display());
    match audit::verify_chain(&path) {
        Ok(n) => println!("audit log chain: OK ({n} entries)"),
        Err(e) => println!("audit log chain: FAILED — {e}"),
    }
    #[cfg(target_os = "macos")]
    println!("platform: macOS");
    #[cfg(not(target_os = "macos"))]
    println!("platform: not macOS (scaffold/dev build) — FDA/TCC checks are macOS-only");
    ExitCode::SUCCESS
}

fn cmd_install(args: &[String]) -> ExitCode {
    // v0 is dry-run by design: printing exactly what *would* happen
    // is the product. `--apply` is refused so this scaffold binary
    // can never silently install itself.
    if args.iter().any(|a| a == "--apply") {
        eprintln!("mac-audit install: --apply is not implemented in the v0 scaffold.");
        eprintln!("Review the --dry-run output, then install the plists manually if you agree.");
        return ExitCode::FAILURE;
    }
    println!("mac-audit install --dry-run — NOTHING will be written.\n");
    println!("{}", plist::permissions_summary());
    println!(
        "\n--- /Library/LaunchDaemons/{}.plist ---\n{}",
        plist::DAEMON_LABEL,
        plist::daemon_plist()
    );
    println!(
        "\n--- /Library/LaunchAgents/{}.plist ---\n{}",
        plist::AGENT_LABEL,
        plist::agent_plist()
    );
    println!("\nPer-user step (each user, in their own session):");
    println!("  System Settings > Privacy & Security > Full Disk Access —");
    println!("  each user decides for their own account. No other user,");
    println!("  and no admin, can grant it on their behalf inside mac-audit.");
    ExitCode::SUCCESS
}

fn cmd_uninstall(_args: &[String]) -> ExitCode {
    println!("mac-audit uninstall --dry-run — NOTHING will be removed.\n");
    println!("To remove mac-audit completely (any admin user may do this):");
    println!("  1. launchctl bootout system/{}", plist::DAEMON_LABEL);
    println!("  2. launchctl bootout gui/$UID/{}", plist::AGENT_LABEL);
    println!(
        "  3. Delete /Library/LaunchDaemons/{}.plist",
        plist::DAEMON_LABEL
    );
    println!(
        "  4. Delete /Library/LaunchAgents/{}.plist",
        plist::AGENT_LABEL
    );
    println!("  5. Delete /usr/local/bin/mac-audit and /usr/local/var/mac-audit/");
    println!("  6. System Settings > Privacy & Security > Full Disk Access — remove mac-audit.");
    ExitCode::SUCCESS
}

fn cmd_log(args: &[String]) -> ExitCode {
    let path = log_path();
    match args.first().map(String::as_str) {
        Some("verify") => match audit::verify_chain(&path) {
            Ok(n) => {
                println!("OK — {n} entries, hash chain intact");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("FAILED — {e}");
                ExitCode::FAILURE
            }
        },
        Some("show") => match audit::read_entries(&path) {
            Ok(entries) => {
                for e in &entries {
                    println!(
                        "#{seq} {ts} {event} actor={actor} subject={subject} hash={hash:.12}…",
                        seq = e.seq,
                        ts = e.ts,
                        event = e.event,
                        actor = e.actor,
                        subject = e.subject,
                        hash = e.hash
                    );
                }
                if entries.is_empty() {
                    println!("(audit log is empty)");
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("cannot read audit log: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("usage: mac-audit log <show|verify>");
            ExitCode::FAILURE
        }
    }
}

fn cmd_update(args: &[String]) -> ExitCode {
    if args.first().map(String::as_str) != Some("check") {
        eprintln!("usage: mac-audit update check [manifest.json]");
        return ExitCode::FAILURE;
    }
    let cfg = Config::default();
    let Some(manifest_path) = args.get(1) else {
        println!(
            "update source: https://github.com/{}/releases (only source allowed)",
            cfg.update_repo
        );
        println!("no manifest supplied — pass a downloaded manifest.json to verify it offline.");
        println!("v0 never installs updates: signature verification is not yet configured (fail closed).");
        return ExitCode::SUCCESS;
    };
    let Ok(text) = std::fs::read_to_string(manifest_path) else {
        eprintln!("cannot read manifest: {manifest_path}");
        return ExitCode::FAILURE;
    };
    let manifest: Manifest = match serde_json::from_str(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("bad manifest: {e}");
            return ExitCode::FAILURE;
        }
    };
    match update::is_newer(&manifest.version, mac_audit::version()) {
        Ok(true) => println!(
            "manifest version {} is newer than {}",
            manifest.version,
            mac_audit::version()
        ),
        Ok(false) => println!(
            "manifest version {} is not newer than {}",
            manifest.version,
            mac_audit::version()
        ),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    }
    println!("install: REFUSED in v0 — artifact verification requires Ade's signing key (see docs/DESIGN.md). Manifest was parsed only; nothing was downloaded or installed.");
    let _ = audit::append(
        &log_path(),
        EventKind::UpdateCheck.as_str(),
        &current_user(),
        &manifest.version,
    );
    ExitCode::SUCCESS
}

fn cmd_shell() -> ExitCode {
    eprintln!("mac-audit shell: remote shell is NOT enabled in this version.");
    eprintln!("It is deferred to the next update. The future design uses macOS");
    eprintln!("built-in Remote Login / OpenSSH (key-only, per-user, visible in");
    eprintln!("System Settings > General > Sharing) — see docs/DESIGN.md.");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("daemon") => cmd_daemon(),
        Some("agent") => cmd_agent(),
        Some("status") => cmd_status(),
        Some("install") => cmd_install(&args[1..]),
        Some("uninstall") => cmd_uninstall(&args[1..]),
        Some("log") => cmd_log(&args[1..]),
        Some("update") => cmd_update(&args[1..]),
        Some("shell") => cmd_shell(),
        _ => {
            println!("{usage}", usage = usage());
            ExitCode::SUCCESS
        }
    }
}
