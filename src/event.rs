//! Event model. Events carry *names only*: which account, what kind
//! of system event, and the name of an app/process. Never keystrokes,
//! never file content, never screen or audio data.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    SystemBoot,
    DaemonStart,
    AgentStart,
    SessionLogin,
    SessionLogout,
    SessionLock,
    SessionUnlock,
    SessionUserSwitch,
    AppLaunch,
    AppInstall,
    ProcessExec,
    UpdateCheck,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SystemBoot => "system.boot",
            Self::DaemonStart => "daemon.start",
            Self::AgentStart => "agent.start",
            Self::SessionLogin => "session.login",
            Self::SessionLogout => "session.logout",
            Self::SessionLock => "session.lock",
            Self::SessionUnlock => "session.unlock",
            Self::SessionUserSwitch => "session.user_switch",
            Self::AppLaunch => "app.launch",
            Self::AppInstall => "app.install",
            Self::ProcessExec => "process.exec",
            Self::UpdateCheck => "update.check",
        }
    }

    /// Kinds the per-user agent may record — only inside a session
    /// whose user has consented and granted their own permissions.
    pub fn is_session_scoped(self) -> bool {
        matches!(
            self,
            Self::SessionLogin
                | Self::SessionLogout
                | Self::SessionLock
                | Self::SessionUnlock
                | Self::AppLaunch
                | Self::AppInstall
                | Self::ProcessExec
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_names_are_stable() {
        assert_eq!(EventKind::SessionLogin.as_str(), "session.login");
        assert_eq!(EventKind::UpdateCheck.as_str(), "update.check");
        assert!(EventKind::AppLaunch.is_session_scoped());
        assert!(!EventKind::SystemBoot.is_session_scoped());
    }
}
