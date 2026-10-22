# Mac Audit

**Transparent, consent-based macOS audit agent — written in Rust.**

Mac Audit records system and session *events* on a Mac (boots,
logins, lock/unlock, app launches/installs — names and times only)
in a tamper-evident, hash-chained log, so the owner of a shared
machine has a reliable record of what happened on it.

> **Every user of this Mac knows Mac Audit is running, and every
> user grants their own permissions.** It is visible in Background
> Items / Login Items, its launchd labels are
> `dev.ademr.macaudit.daemon` and `dev.ademr.macaudit.agent`, and
> any user can run `mac-audit status`. There is no hidden mode.

## What it does NOT do

- No camera, no microphone, no screen capture/recording
- No keylogging or Input Monitoring
- No reading another user's private files or content
- No covert operation, no TCC/SIP/Gatekeeper bypass, no kernel work
- No inbound remote-control listener

Full design, threat model, and limits: [docs/DESIGN.md](docs/DESIGN.md).
Research notes with sources: [docs/RESEARCH.md](docs/RESEARCH.md).

## Quick start (scaffold v0.1)

```sh
cargo build --release
./target/release/mac-audit status
./target/release/mac-audit install --dry-run   # prints plists + permissions, writes nothing
./install.sh                                   # same dry-run, via script
```

`install --dry-run` is the whole install story in v0: `--apply`
is refused on purpose, so this binary can never install itself
silently. Review the dry-run output, then place the plists
manually if every affected user agrees.

## Permissions (per user, own session)

- **Full Disk Access — required, status-only in v0.** Each user is
  asked in System Settings > Privacy & Security > Full Disk
  Access, and `mac-audit status` reports granted/denied for the
  current user. *The logic that uses FDA is deferred to the next
  update: v0 does not read, scan, or copy file content with it.*
- Camera / Microphone / Screen Recording / Input Monitoring /
  Accessibility: **not requested**.

## Deferred to the next update (by design, not omission)

1. **Logic that uses Full Disk Access** — v0 has the permission
   plumbing and status reporting only.
2. **Remote shell (SSH-like)** — required, but not built in v0.
   `mac-audit shell` is a disabled, fail-closed stub and
   `remote_shell_enabled = true` is a config error. The future
   design prefers macOS built-in Remote Login / OpenSSH (key-only,
   per-user, enabled visibly in Sharing settings) — see
   [docs/DESIGN.md §8](docs/DESIGN.md).
3. **Update signing** — updates may only come from this repo's
   releases and must pass SHA-256 + signature verification.
   The verifier is a fail-closed stub until the owner's signing
   key is installed, so v0 installs no updates. Ever.

## Audit log

Append-only, SHA-256 hash-chained:

```sh
mac-audit log show
mac-audit log verify   # detects edits, deletions, reordering
```

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs the same on Ubuntu and macOS. Releases (`v*` tags) build
an `aarch64-apple-darwin` tarball + SHA-256 manifest.

## Status / honesty

v0.1 scaffold: built and CI-tested on Linux + macOS runners,
**not yet tested on a real Mac**, not code-signed or notarized.
An admin user can uninstall Mac Audit — that is stated, not
hidden; see the threat model in the design doc.

## License

MIT — see [LICENSE](LICENSE).
