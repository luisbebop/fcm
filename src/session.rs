// Session management module for persistent console sessions
//
// Manages tmux sessions on VMs via SSH. The daemon tracks active sessions
// and can create/list/kill sessions on demand.

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Session error types
#[derive(Debug)]
pub enum SessionError {
    /// Session not found
    NotFound(String),
    /// VM not found or not running
    #[allow(dead_code)] // Matched in daemon.rs but not constructed yet
    VmNotAvailable(String),
    /// SSH connection failed
    #[allow(dead_code)] // Matched in daemon.rs but not constructed yet
    SshError(String),
    /// Tmux command failed
    TmuxError(String),
    /// IO error
    Io(std::io::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::NotFound(id) => write!(f, "Session '{}' not found", id),
            SessionError::VmNotAvailable(vm) => write!(f, "VM '{}' not available", vm),
            SessionError::SshError(msg) => write!(f, "SSH error: {}", msg),
            SessionError::TmuxError(msg) => write!(f, "Tmux error: {}", msg),
            SessionError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<std::io::Error> for SessionError {
    fn from(e: std::io::Error) -> Self {
        SessionError::Io(e)
    }
}

/// Information about an active session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Unique session ID
    pub id: String,
    /// VM ID this session belongs to
    pub vm_id: String,
    /// Tmux session name (same as id)
    pub tmux_session: String,
    /// Creation timestamp (unix epoch seconds)
    pub created_at: u64,
    /// Whether this is the default session for the VM
    pub is_default: bool,
}

/// Get the canonical session name for a VM (one session per VM)
pub fn vm_session_name(vm_id: &str) -> String {
    format!("console-{}", vm_id)
}

/// Generate a random 6-character session ID
fn generate_session_id() -> String {
    let mut rng = rand::thread_rng();
    (0..6)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// Get current timestamp in seconds since epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Session manager tracks all active sessions across VMs
#[derive(Clone)]
pub struct SessionManager {
    /// Map of session_id -> SessionInfo
    sessions: Arc<Mutex<HashMap<String, SessionInfo>>>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        SessionManager {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get or create the console session for a VM
    ///
    /// Each VM has exactly one console session. This method:
    /// 1. Returns existing session if tracked in memory
    /// 2. Checks if tmux session exists on VM and registers it
    /// 3. Creates new tmux session if needed
    ///
    /// This ensures the session persists across client disconnects.
    pub fn get_or_create_console(
        &self,
        vm_id: &str,
        vm_ip: &str,
    ) -> Result<SessionInfo, SessionError> {
        let tmux_session = vm_session_name(vm_id);
        let session_id = vm_id.to_string(); // Use VM ID as session ID for simplicity

        // Check if we already have this session in memory
        {
            let sessions = self.sessions.lock().unwrap();
            if let Some(session) = sessions.get(&session_id) {
                return Ok(session.clone());
            }
        }

        // Check if tmux session exists on the VM (from previous daemon run or survived disconnect)
        let active_sessions = list_tmux_sessions(vm_ip).unwrap_or_default();
        let session_exists = active_sessions.contains(&tmux_session);

        if !session_exists {
            // Create tmux session on VM via SSH
            create_tmux_session(vm_ip, &tmux_session)?;
        }

        // Register session in memory
        let session = SessionInfo {
            id: session_id.clone(),
            vm_id: vm_id.to_string(),
            tmux_session,
            created_at: current_timestamp(),
            is_default: true,
        };

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id, session.clone());
        Ok(session)
    }

    /// Create a new session on a VM (legacy - use get_or_create_console instead)
    ///
    /// If is_default is true, creates or returns the default session.
    /// Otherwise creates a new named session.
    pub fn create_session(
        &self,
        vm_id: &str,
        vm_ip: &str,
        is_default: bool,
    ) -> Result<SessionInfo, SessionError> {
        // For default sessions, use the new unified approach
        if is_default {
            return self.get_or_create_console(vm_id, vm_ip);
        }

        let mut sessions = self.sessions.lock().unwrap();

        // Generate new session ID
        let session_id = generate_session_id();
        let tmux_session = format!("fcm-{}", session_id);

        // Create tmux session on VM via SSH
        create_tmux_session(vm_ip, &tmux_session)?;

        let session = SessionInfo {
            id: session_id.clone(),
            vm_id: vm_id.to_string(),
            tmux_session,
            created_at: current_timestamp(),
            is_default,
        };

        sessions.insert(session_id, session.clone());
        Ok(session)
    }

    /// Get a session by ID (kept for potential future use)
    #[allow(dead_code)]
    pub fn get_session(&self, session_id: &str) -> Option<SessionInfo> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(session_id).cloned()
    }

    /// List all sessions for a VM
    pub fn list_sessions(&self, vm_id: &str) -> Vec<SessionInfo> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .values()
            .filter(|s| s.vm_id == vm_id)
            .cloned()
            .collect()
    }

    /// Kill a session
    pub fn kill_session(&self, session_id: &str, vm_ip: &str) -> Result<(), SessionError> {
        let mut sessions = self.sessions.lock().unwrap();

        let session = sessions
            .get(session_id)
            .ok_or_else(|| SessionError::NotFound(session_id.to_string()))?
            .clone();

        // Kill tmux session on VM
        kill_tmux_session(vm_ip, &session.tmux_session)?;

        sessions.remove(session_id);
        Ok(())
    }

    /// Remove all sessions for a VM (called when VM is stopped/destroyed)
    pub fn remove_vm_sessions(&self, vm_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.vm_id != vm_id);
    }

    /// Sync sessions with actual tmux state on VM
    /// Removes sessions that no longer exist in tmux
    /// If unable to list tmux sessions (SSH error), skip syncing to preserve state
    pub fn sync_sessions(&self, vm_id: &str, vm_ip: &str) {
        // Only sync if we can successfully list tmux sessions
        // If listing fails, keep existing sessions rather than removing all
        let active_tmux = match list_tmux_sessions(vm_ip) {
            Ok(sessions) => sessions,
            Err(_) => return, // Skip sync if we can't reach the VM
        };
        let mut sessions = self.sessions.lock().unwrap();

        sessions.retain(|_, session| {
            if session.vm_id != vm_id {
                return true;
            }
            active_tmux.contains(&session.tmux_session)
        });
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a tmux session on a VM via SSH with clean configuration
fn create_tmux_session(vm_ip: &str, session_name: &str) -> Result<(), SessionError> {
    // Create session first
    let output = Command::new("sshpass")
        .args([
            "-p", "root",
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            &format!("root@{}", vm_ip),
            "tmux", "new-session", "-d", "-s", session_name,
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "duplicate session" error - session already exists
        if !stderr.contains("duplicate session") {
            return Err(SessionError::TmuxError(stderr.to_string()));
        }
    }

    // Configure session for clean UX:
    // - status off: no status bar at bottom
    // - destroy-unattached off: keep session when client disconnects
    // - mouse on: enable mouse scroll and selection
    let options = [
        ("status", "off"),
        ("destroy-unattached", "off"),
        ("mouse", "on"),
    ];

    for (option, value) in options {
        let _ = Command::new("sshpass")
            .args([
                "-p", "root",
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=5",
                &format!("root@{}", vm_ip),
                "tmux", "set-option", "-t", session_name, option, value,
            ])
            .output();
    }

    Ok(())
}

/// List tmux sessions on a VM via SSH
fn list_tmux_sessions(vm_ip: &str) -> Result<Vec<String>, SessionError> {
    let output = Command::new("sshpass")
        .args([
            "-p", "root",
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            &format!("root@{}", vm_ip),
            "tmux", "list-sessions", "-F", "#{session_name}",
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "no server running" means no sessions, not an error
        if stderr.contains("no server running") || stderr.contains("no sessions") {
            return Ok(Vec::new());
        }
        return Err(SessionError::TmuxError(stderr.to_string()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().map(|s| s.to_string()).collect())
}

/// Kill a tmux session on a VM via SSH
fn kill_tmux_session(vm_ip: &str, session_name: &str) -> Result<(), SessionError> {
    let output = Command::new("sshpass")
        .args([
            "-p", "root",
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            &format!("root@{}", vm_ip),
            "tmux", "kill-session", "-t", session_name,
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "session not found" - already gone
        if !stderr.contains("session not found") && !stderr.contains("no server running") {
            return Err(SessionError::TmuxError(stderr.to_string()));
        }
    }

    Ok(())
}

/// Spawn an SSH process that attaches to a tmux session
/// Returns the child process for I/O proxying
pub fn attach_to_session(vm_ip: &str, session_name: &str, cols: u16, rows: u16) -> Result<Child, SessionError> {
    // First resize the tmux window to match client terminal size
    let _ = Command::new("sshpass")
        .args([
            "-p", "root",
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            &format!("root@{}", vm_ip),
            "tmux", "resize-window", "-t", session_name, "-x", &cols.to_string(), "-y", &rows.to_string(),
        ])
        .output();

    // Now attach to the session
    let child = Command::new("sshpass")
        .args([
            "-p", "root",
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            "-t", "-t", // Force PTY allocation
            &format!("root@{}", vm_ip),
            "tmux", "attach-session", "-t", session_name,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    Ok(child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_session_id_length() {
        let id = generate_session_id();
        assert_eq!(id.len(), 6);
    }

    #[test]
    fn test_generate_session_id_alphanumeric() {
        let id = generate_session_id();
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_session_id_lowercase() {
        let id = generate_session_id();
        assert!(id.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()));
    }

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        // Should be a reasonable timestamp (after 2020)
        assert!(ts > 1577836800);
    }

    #[test]
    fn test_session_manager_new() {
        let manager = SessionManager::new();
        let sessions = manager.sessions.lock().unwrap();
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_session_info_serialization() {
        let session = SessionInfo {
            id: "abc123".to_string(),
            vm_id: "vm001".to_string(),
            tmux_session: "fcm-abc123".to_string(),
            created_at: 1700000000,
            is_default: true,
        };
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("vm001"));
        assert!(json.contains("fcm-abc123"));
    }

    #[test]
    fn test_session_info_deserialization() {
        let json = r#"{
            "id": "xyz789",
            "vm_id": "vm002",
            "tmux_session": "fcm-xyz789",
            "created_at": 1700000000,
            "is_default": false
        }"#;
        let session: SessionInfo = serde_json::from_str(json).unwrap();
        assert_eq!(session.id, "xyz789");
        assert_eq!(session.vm_id, "vm002");
        assert_eq!(session.tmux_session, "fcm-xyz789");
        assert!(!session.is_default);
    }

    #[test]
    fn test_session_error_display() {
        assert!(SessionError::NotFound("abc".to_string()).to_string().contains("abc"));
        assert!(SessionError::VmNotAvailable("vm1".to_string()).to_string().contains("vm1"));
        assert!(SessionError::SshError("timeout".to_string()).to_string().contains("timeout"));
        assert!(SessionError::TmuxError("failed".to_string()).to_string().contains("failed"));
    }

    #[test]
    fn test_session_manager_list_empty() {
        let manager = SessionManager::new();
        let sessions = manager.list_sessions("nonexistent");
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_session_manager_get_nonexistent() {
        let manager = SessionManager::new();
        assert!(manager.get_session("nonexistent").is_none());
    }

    #[test]
    fn test_vm_session_name() {
        assert_eq!(vm_session_name("abc123"), "console-abc123");
        assert_eq!(vm_session_name("test-vm"), "console-test-vm");
    }

    #[test]
    fn test_session_manager_remove_vm_sessions() {
        let manager = SessionManager::new();

        // Manually insert a session for testing
        {
            let mut sessions = manager.sessions.lock().unwrap();
            sessions.insert(
                "test1".to_string(),
                SessionInfo {
                    id: "test1".to_string(),
                    vm_id: "vm1".to_string(),
                    tmux_session: "fcm-test1".to_string(),
                    created_at: current_timestamp(),
                    is_default: false,
                },
            );
            sessions.insert(
                "test2".to_string(),
                SessionInfo {
                    id: "test2".to_string(),
                    vm_id: "vm2".to_string(),
                    tmux_session: "fcm-test2".to_string(),
                    created_at: current_timestamp(),
                    is_default: false,
                },
            );
        }

        // Remove sessions for vm1
        manager.remove_vm_sessions("vm1");

        // Check that vm1 sessions are gone but vm2 sessions remain
        assert!(manager.get_session("test1").is_none());
        assert!(manager.get_session("test2").is_some());
    }
}
