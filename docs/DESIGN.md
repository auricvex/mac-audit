# Mac Audit — Design

**Product:** `mac-audit` — a transparent, consent-based macOS audit
agent in Rust, for Ade's MacBook Air M3 running macOS 27.
**Status:** v0.1 scaffold. Compiles and is CI-tested on Linux and
macOS runners. **Not yet tested on a real Mac** (see Limitations).

## 1. The boundary that defines the product

Mac Audit exists because the owner of a shared household Mac wants
to know what happens on *the machine*. The original covert version
of this idea was declined and replaced, at Ade's own revision
(2026-10-22), with this rule, which is a hard product requirement:

> Every user account is prompted for its **own** TCC permissions and
> **knows** it is being tracked.

Everything below follows from that. Transparency is not a skin:
labels, plists, Background Items visibility, documentation, and the
`mac-audit status` command all say the same thing the agent does.

## 2. What Mac Audit deliberately does NOT do

- No covert or hidden operation. No attempt to hide from Activity
  Monitor, `launchctl`, Background Items, or System Settings.
- No camera. No microphone. No screen capture or recording.
- No keylogging and no Input Monitoring capture of any kind.
- No reading another user's private files or content.
- No bypassing TCC, SIP, Gatekeeper, Secure Boot, or code signing.
  No kernel, kext, System Extension, or custom-kernel work.
- No inbound listener. No remote-control / RAT functionality.
  The only outbound network behaviour in the design is an update
  check against this project's own GitHub repo.
- No arbitrary remote code: updates must verify (see §7) and the
  v0 scaffold refuses to install anything at all.

## 3. Architecture

One Rust binary, `mac-audit`, small modules:

| Module | Responsibility |
|---|---|
| `main.rs` | CLI dispatch only |
| `audit.rs` | Tamper-evident append-only log (hash chain) |
| `config.rs` | `key = value` config; unsafe widenings are parse errors |
| `event.rs` | Event kinds — names only, never content |
| `permissions.rs` | Full Disk Access *status* check (see §5) |
| `plist.rs` | LaunchDaemon / LaunchAgent plist generation + permissions matrix |
| `update.rs` | Version compare, release-manifest verification, fail-closed signature stub |

### Subcommands

```
mac-audit daemon               system daemon entry point
mac-audit agent                per-user agent entry point
mac-audit status               visibility, version, FDA status, log check — any user
mac-audit install --dry-run    prints plists + permissions, writes nothing (v0: dry-run only;
                               --apply is refused, fail closed)
mac-audit uninstall            prints complete removal steps (dry-run by default)
mac-audit log show | verify    inspect / verify the hash chain
mac-audit update check [file]  parse+report a release manifest; never installs in v0
mac-audit shell                DISABLED stub — remote shell deferred (see §8)
```

### Daemon vs agent (why two processes)

macOS splits these worlds and Mac Audit respects the split:

- **LaunchDaemon** (`dev.ademr.macaudit.daemon`, in
  `/Library/LaunchDaemons`): one instance, runs at boot as root,
  no GUI, no access to any user's TCC-protected content. Records
  *system* events only: boot, daemon start, update checks.
- **LaunchAgent** (`dev.ademr.macaudit.agent`, in
  `/Library/LaunchAgents`): one instance **per logged-in user**,
  `LimitLoadToSessionType = Aqua`. Records session events only for
  *that* user, who consented and can remove it from Background
  Items / Login Items.

A root daemon cannot legitimately "reach into" a user session, and
Mac Audit does not try.

## 4. Event model

Events are **names, timestamps, and account names only**:

`system.boot`, `daemon.start`, `agent.start`, `session.login`,
`session.logout`, `session.lock`, `session.unlock`,
`session.user_switch`, `app.launch`, `app.install`,
`process.exec` (process *name* only), `update.check`.

Session-scoped events are recorded only inside a consenting user's
own session, by that user's agent. There is no event type for file
content, typed text, screen pixels, or audio — by construction,
not by policy flag.

*Scaffold note:* v0 records `system.boot` (daemon start) and
`agent.start` for real. Live wiring of login/lock/app-launch
notifications (NSWorkspace / unified-log observers) is the next
macOS-side step and is marked TODO in code where relevant.

## 5. Permissions matrix (per user)

| Permission | Status in v0 | Who grants it | Notes |
|---|---|---|---|
| Full Disk Access | **Required — plumbing/status only** | Each user, for their own account, in System Settings > Privacy & Security > Full Disk Access | `mac-audit status` reports granted/denied per current user. **The logic that uses FDA is deferred to the next update by Ade's order: v0 does not read, scan, or copy file content with it.** |
| Camera | Never requested | — | Excluded by design |
| Microphone | Never requested | — | Excluded by design |
| Screen Recording | Never requested | — | Excluded by design |
| Input Monitoring | Never requested | — | No keylogging, ever |
| Accessibility | Not requested in v0 | — | Would be per-user opt-in if ever proposed |
| Background Items | Visible | Each user sees it | Agent appears in Login Items / Background Items; macOS notifies on new background items |

**FDA status check pattern** (`permissions.rs`): the normal TCC
probe — attempt to open the current user's TCC database file
(`~/Library/Application Support/com.apple.TCC/TCC.db`), map
success → granted, `PermissionDenied` → denied, anything else →
unknown, and drop the handle immediately. The file is never parsed,
read into the log, or copied. On non-macOS it reports
not-applicable, which is what Linux CI exercises.

Refusal is a supported state: if a user declines or revokes FDA,
Mac Audit reports `denied` and continues with system/session
events only. One user (or an admin) granting FDA does **not** grant
it for another account — TCC grants are per-user.

## 6. Tamper-evident audit log

Append-only JSON-lines log. Each entry contains `seq`, `ts`,
`prev_hash`, `event`, `actor`, `subject`, and `hash`, where
`hash = SHA-256(seq | ts | prev_hash | event | actor | subject)`.
The genesis entry chains from an all-zero hash.

`mac-audit log verify` recomputes the chain: editing an entry,
deleting one, or reordering entries is detected and reported with
the failing sequence number. The log path defaults to
`/usr/local/var/mac-audit/audit.log` and can be overridden with the
`MAC_AUDIT_LOG` environment variable (used by tests/dev).

Honest limit: hash chaining detects tampering *after the fact*. It
does not prevent a user with root from deleting the whole log —
see the threat model.

## 7. Update trust model

- **Sole source:** releases of the public repo
  `github.com/auricvex/mac-audit`. Manifest URLs outside
  `https://github.com/auricvex/mac-audit/releases/` are rejected.
- **Manifest:** `{ version, url, sha256, signature }`.
- **Verification order:** repo URL → SHA-256 of artifact matches
  manifest → signature present → signature valid.
- **Fail closed, deliberately:** signature verification is a
  scaffold stub awaiting Ade's signing key (TODO in
  `update.rs::verify_signature`). Until a real verifier is wired,
  **every** update is refused, including well-formed ones, and
  `mac-audit update check` installs nothing. A stub that accepted
  updates would be a remote-code-execution hole; this one cannot.
- Update checks and their outcomes are recorded as `update.check`
  audit events.
- Release CI (`.github/workflows/release.yml`) builds an
  `aarch64-apple-darwin` tarball plus a SHA-256 manifest on `v*`
  tags. The manifest's `signature` field is empty until Ade's
  signing step exists — which, by the rule above, means those
  artifacts are *not* installable by the updater yet. That gap is
  intentional and documented, not hidden.

## 8. Remote shell — REQUIRED but DEFERRED (not built in v0)

Ade requires an SSH-like remote shell, and ruled (2026-10-22) that
its logic is **deferred to the next update**. In v0:

- There is **no** listener, **no** shell, **no** command-execution
  channel in the agent. None.
- `mac-audit shell` is a disabled stub: it prints that remote shell
  is not enabled in this version and exits non-zero.
- Config carries `remote_shell_enabled = false`; setting it to
  `true` is a parse error in v0.

### Intended future approach (design constraints, pre-committed)

Prefer **macOS built-in Remote Login / OpenSSH** over any custom
in-agent shell:

- Enable Remote Login visibly, by the owner, in
  System Settings > General > Sharing — never silently by the agent.
- **Key-only** authentication (`PasswordAuthentication no`),
  per-user accounts, per-user `authorized_keys`. No shared shell
  account, no agent-held master credential.
- Each user who can be logged into remotely knows it: Sharing
  settings show Remote Login state to the session user, and the
  agent records session start/end in the audit log (account + time
  only, not session content).
- A custom in-agent shell would need its own justification against
  this design before it could replace the OpenSSH route — the
  default answer is OpenSSH.

## 9. Threat model

**In scope:** a household member with a standard account, or with
the owner's credentials, uses the Mac in ways the owner wants a
reliable record of (logins, app installs, session times).

**Honest limits:**

- **An admin can uninstall Mac Audit.** Any admin can bootout the
  daemon, delete the plists/binary/log, and revoke FDA. Mac Audit
  makes removal *visible in the log up to the moment of removal*
  and the removal steps are documented in the open — it does not
  and cannot make itself undeletable, and does not try.
- A root user can delete or rewrite the whole audit log; the hash
  chain makes *partial* edits detectable, not wholesale deletion.
- Mac Audit is not a forensic or anti-theft product and does not
  protect data at rest — that's FileVault's job, which should be on.
- The strongest control remains account hygiene: unique passwords,
  standard (non-admin) accounts for other users, FileVault on.

## 10. Limitations of this scaffold

- **Not tested on a real Mac.** Developed on a Linux VM; the macOS
  build is verified by the `macos-latest` CI job only. plist
  loading, TCC prompts, and Background Items behaviour must be
  confirmed on Ade's M3 before any real install.
- Not code-signed or notarized — Ade's Developer ID and notarization
  setup are his to provide; Gatekeeper will (correctly) treat an
  unsigned build as untrusted.
- Update signature verification awaits Ade's signing key (§7).
- Live event observers (login/lock/app launch) are not wired yet (§4).
- FDA-using logic and remote shell are deferred by design (§5, §8).
