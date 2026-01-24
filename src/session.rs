// Session management module for persistent console sessions
//
// Tracks active console sessions in memory for cleanup when VMs are stopped/destroyed.
// The actual console I/O is handled via direct PTY proxy to Firecracker's serial console.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Session error types
#[derive(Debug)]
pub enum SessionError {
    /// Session not found
    #[allow(dead_code)] // Used in Display impl for error messages
    NotFound(String),
    /// VM not found or not running
    #[allow(dead_code)] // Used in Display impl for error messages
    VmNotAvailable(String),
    /// IO error
    #[allow(dead_code)] // Used for error conversion
    Io(std::io::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::NotFound(id) => write!(f, "Session '{}' not found", id),
            SessionError::VmNotAvailable(vm) => write!(f, "VM '{}' not available", vm),
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
    /// Unique session ID (same as VM ID)
    pub id: String,
    /// VM ID this session belongs to
    pub vm_id: String,
    /// Session name for display
    pub session_name: String,
    /// Creation timestamp (unix epoch seconds)
    pub created_at: u64,
    /// Whether this is the default session for the VM
    pub is_default: bool,
}

/// Get the canonical session name for a VM (one session per VM)
pub fn vm_session_name(vm_id: &str) -> String {
    format!("console-{}", vm_id)
}

/// Get current timestamp in seconds since epoch
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Session manager tracks active console sessions
#[derive(Clone)]
pub struct SessionManager {
    /// Map of vm_id -> SessionInfo
    sessions: Arc<Mutex<HashMap<String, SessionInfo>>>,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new() -> Self {
        SessionManager {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get or create session info for a VM
    ///
    /// This registers the session in memory for tracking.
    /// The actual console connection is handled via direct PTY proxy to Firecracker.
    #[allow(dead_code)]
    pub fn get_or_create_console(
        &self,
        vm_id: &str,
        _vm_ip: &str,
    ) -> Result<SessionInfo, SessionError> {
        let session_name = vm_session_name(vm_id);
        let session_id = vm_id.to_string();

        // Check if we already have this session in memory
        {
            let sessions = self.sessions.lock().unwrap();
            if let Some(session) = sessions.get(&session_id) {
                return Ok(session.clone());
            }
        }

        // Register new session
        let session = SessionInfo {
            id: session_id.clone(),
            vm_id: vm_id.to_string(),
            session_name,
            created_at: current_timestamp(),
            is_default: true,
        };

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id, session.clone());
        Ok(session)
    }

    /// Get a session by ID
    #[allow(dead_code)]
    pub fn get_session(&self, session_id: &str) -> Option<SessionInfo> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(session_id).cloned()
    }

    /// Remove all sessions for a VM (called when VM is stopped/destroyed)
    pub fn remove_vm_sessions(&self, vm_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, s| s.vm_id != vm_id);
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            session_name: "console-vm001".to_string(),
            created_at: 1700000000,
            is_default: true,
        };
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("vm001"));
        assert!(json.contains("console-vm001"));
    }

    #[test]
    fn test_session_info_deserialization() {
        let json = r#"{
            "id": "xyz789",
            "vm_id": "vm002",
            "session_name": "console-vm002",
            "created_at": 1700000000,
            "is_default": false
        }"#;
        let session: SessionInfo = serde_json::from_str(json).unwrap();
        assert_eq!(session.id, "xyz789");
        assert_eq!(session.vm_id, "vm002");
        assert_eq!(session.session_name, "console-vm002");
        assert!(!session.is_default);
    }

    #[test]
    fn test_session_error_display() {
        assert!(SessionError::NotFound("abc".to_string()).to_string().contains("abc"));
        assert!(SessionError::VmNotAvailable("vm1".to_string()).to_string().contains("vm1"));
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
                    session_name: "console-vm1".to_string(),
                    created_at: current_timestamp(),
                    is_default: false,
                },
            );
            sessions.insert(
                "test2".to_string(),
                SessionInfo {
                    id: "test2".to_string(),
                    vm_id: "vm2".to_string(),
                    session_name: "console-vm2".to_string(),
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
