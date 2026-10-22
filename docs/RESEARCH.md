# Mac Audit — Research Notes

Verified 2026-10-22 via web search against Apple Platform Security,
Apple Developer documentation, Kandji, ESET, Jamf, and Sparkle
sources. Items that could not be pinned to a citable source are
labelled **UNVERIFIED**. Product conclusions for Mac Audit are at
the end of each section.

## 1. macOS 27 "Golden Gate" and the MacBook Air M3

- macOS 27 is named **Golden Gate**, is Apple-silicon only
  (support ends for Intel Macs), and MacBook Air models with M1
  and later — including the M3 Air — are supported.
  - Apple Support, "How to upgrade to macOS 27 Golden Gate"
    (published 2026-09-14): *"macOS 27 is compatible with any Mac
    with Apple silicon, which includes any Mac with an M-series
    chip or A-series chip."* — https://support.apple.com/en-us/127455
  - https://www.macrumors.com/2026/06/08/macos-golden-gate-macs-compatible/
  - https://9to5mac.com/2026/09/09/apple-confirms-macos-27-golden-gate-launch-date-september-14/
  - https://tidbits.com/2026/07/20/the-real-system-requirements-for-%EF%A3%BFos-27/
- Apple Developer releases page lists macOS 27 releases, distinct
  from macOS 26 Tahoe.
  - https://developer.apple.com/news/releases/
- Note: Apple states compatibility by chip family (above), not by
  naming the M3 Air individually; M3 support follows directly from
  Apple's blanket Apple-silicon statement.

**Conclusion:** targeting macOS 27 on an M3 Air is a supported,
current platform. Nothing in Mac Audit targets legacy/Intel paths.

## 2. TCC is per-user — and some grants no profile can make

- TCC permissions are stored **per user** (`~/Library/Application
  Support/com.apple.TCC/TCC.db`) and separately for the system.
  - https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive
- PPPC/MDM payloads can **allow, deny, or leave standard-user
  approval** for Accessibility, Full Disk Access, Automation,
  and similar. Exact quote (Kandji): *"The following permissions
  cannot be granted via a PPPC configuration profile: Camera,
  Microphone, Contacts, Calendars, Reminders, Photos, and
  Screen Recording & System Audio."* Exact quote (ESET):
  *"Apple does not allow MDM to grant Camera, microphone, and
  Screen Recording permissions from macOS 11 (Big Sur) onwards."*
  - https://support.kandji.io/kb/mdm-privacy-preferences-policy-control-pppc-profiles-considerations
  - https://help.eset.com/protect_install/13/en-US/pppc_profiles.html
- In current macOS the related standard-user setting for screen
  capture is worded *"Allow standard users to allow access to
  screen and audio recording"* — the user still grants it, per user.
  - https://support.apple.com/en-gb/guide/deployment/dep89821f564/web
- **UNVERIFIED:** that a PPPC profile can flip Full Disk Access to
  "Allowed" on recent macOS was asserted by Kandji/Jamf material
  with a version caveat; treat FDA as **user-granted on the target
  machine until proven otherwise on Ade's Mac**.

**Conclusion:** this is the technical fact Mac Audit's consent
model is built on. One admin cannot silently grant permissions for
another account. Mac Audit v0 therefore asks each user for their
own Full Disk Access (status-only in v0 — the logic using it is
deferred; see DESIGN.md §5) and never asks for Camera, Microphone,
or Screen Recording at all.

## 3. LaunchDaemon vs LaunchAgent

- Apple: *"A daemon is a program that runs in the background…
  Daemons are managed by launchd… You can install a daemon using
  Service Management"* (`SMAppService.daemon(plistName:)` registers
  a bundled LaunchDaemon plist).
  *"A user agent is essentially a daemon that runs as a specific
  user… similar to a daemon, but it can display user interface
  elements… most commonly used to provide a system-wide
  application menu."*
  - https://developer.apple.com/documentation/servicemanagement
  - https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
- Daemon properties (Apple archive): executes independent of user
  login; runs before login; cannot use AppKit / connect to the
  Window Server; *must* be owned by root, plist not group/world
  writable. Agents run in the per-user launchd context (Aqua
  session).
  - (same Apple BPSystemStartup archive as above)

**Conclusion:** Mac Audit's split is the platform's split — a root
daemon for system events and a per-user agent (`LimitLoadToSessionType
= Aqua`) for session events. The daemon does not and cannot reach
into user sessions.

## 4. SMAppService / Background Task Management visibility

- Apple requires a user-visible explanation for login items:
  developers must provide a purpose string shown in
  *"System Settings > General > Login Items"*; users enable/disable
  items there, and are notified when background items are added.
  - https://developer.apple.com/documentation/servicemanagement/updating-your-app-to-use-the-new-service-management-api
- Jamf documents a `Background Service Management` payload whose
  purpose is *"Allowing standard users to enable and disable
  background items in System Settings"* — confirming the user is
  the one flipping the switch.
  - https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Configuration_Profiles.html

**Conclusion:** modern macOS makes background persistence a
user-visible, user-revocable setting. Mac Audit leans into that
(labelled plists, purpose strings, documented uninstall) instead
of treating it as an obstacle.

## 5. Signed System Volume / Secure Boot — why no kernel route

- Apple Platform Security, in substance: in **Permissive Security**
  *"a custom kernel must be built, signed, and booted by a user,
  physically present during recoveryOS startup,"* and Full Security
  runs an SSV snapshot whose seal is verified at boot; signature
  failures boot to recoveryOS.
  - https://support.apple.com/guide/security/boot-process-secac71d5623/web
  - https://support.apple.com/guide/security/signed-system-volume-security-sealed-system-volume-sece3a9374f4/web
- **UNVERIFIED / out of scope:** a supported runtime method to
  patch XNU on a booted daily-driver Mac (sources describe XNU
  debugging as a two-machine research activity for participants in
  Apple's Security Research Device programme — a different
  platform, not the retail M3 Air).
  - https://developer.apple.com/support/kernel-programming/

**Conclusion:** there is no practical, supportable kernel route on
a daily-driver M3 Air, and Mac Audit does not attempt one. All
functionality lives in ordinary, signed userspace under launchd.

## 6. Signed, auto-updating macOS agents — the legitimate pattern

- Sparkle (`appcast.xml` + Enclosure + EdDSA/Ed25519): *"You must
  use signs to verify the authenticity of updates… EdDSA signatures
  are generated with the private key and verified with the public
  key embedded in the app itself"*; verification fails closed when
  the public key is absent from `Info.plist`.
  - https://sparkle-project.org/documentation/
  - https://sparkle-project.org/documentation/security/
- Kandji documents the inventories a legitimate agent must live
  with — PPPC, System Extensions, Login Items, Approved Kernel
  Extensions all appear as managed, user-visible inventory.
  - https://support.kandji.io/
- **UNVERIFIED here:** exact SHA-256 sidecar conventions used by
  tools like `hdiutil`/Homebrew; Mac Audit's own manifest format
  is documented in DESIGN.md §7 instead of borrowed.

**Conclusion:** the legitimate pattern is: signed release → public
manifest with hash + signature → embedded public key verifies →
**fail closed** on any mismatch. Mac Audit follows that shape with
its own minimal manifest, and because Ade's signing key is not yet
installed in the scaffold, its updater refuses every update in v0
(see `update.rs::verify_signature`).

## 7. Rust on `aarch64-apple-darwin`

- The Rust reference lists `aarch64-apple-darwin` as a **Tier 2
  target with host tools** ("fully bootstrapped and automated
  testing ensures tests are run in CI"); `x86_64-apple-darwin`
  is Tier 2 and there is a dedicated macOS platform-support page.
  - https://doc.rust-lang.org/rustc/platform-support.html
  - https://doc.rust-lang.org/stable/rustc/platform-support/apple-darwin.html

**Conclusion:** standard `cargo build --target aarch64-apple-darwin`
on a `macos-latest` runner is the release path (see
`.github/workflows/release.yml`). Local development happens on a
Linux VM, so the macOS CI job — not local testing — is the real
macOS build check, and on-device behaviour remains to be verified
on Ade's Mac.
