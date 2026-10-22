//! mac-audit — transparent, consent-based audit agent.
//!
//! Hard product boundaries (see `docs/DESIGN.md`):
//! - No covert operation. The agent is visible in Background Items,
//!   its plists are labelled, and any user can run `mac-audit status`.
//! - No camera, microphone, keylogging, screen capture, or reading
//!   another user's private content. Ever.
//! - No TCC / SIP / Gatekeeper bypass. Each user grants (or refuses)
//!   their own permissions, in their own session.
//! - Updates are fetched only from this project's own GitHub repo,
//!   are hash- and signature-checked, and fail closed.
//! - Full Disk Access is requested + reported in v0 only; the logic
//!   using it is deferred. Remote shell is a disabled stub in v0;
//!   its future design prefers macOS built-in Remote Login/OpenSSH.

pub mod audit;
pub mod config;
pub mod event;
pub mod permissions;
pub mod plist;
pub mod update;

/// Current mac-audit version (from Cargo).
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
