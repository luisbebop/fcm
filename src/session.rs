// Session management module for persistent console sessions
//
// Connects to fcm-agent on VMs via TCP for PTY management.
// The fcm-agent handles PTY spawning, I/O, and shell respawning directly.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Port that fcm-agent listens on inside VMs
pub const AGENT_PORT: u16 = 7779;

/// Session error types
#[derive(Debug)]
pub enum SessionError {
    /// Session not found
    #[allow(dead_code)] // Used in Display impl for error messages
    NotFound(String),
    /// VM not found or not running
    #[allow(dead_code)] // Matched in daemon.rs but not constructed yet
    VmNotAvailable(String),
    /// Connection to fcm-agent failed
    ConnectionFailed(String),
    /// IO error
    Io(std::io::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::NotFound(id) => write!(f, "Session '{}' not found", id),
            SessionError::VmNotAvailable(vm) => write!(f, "VM '{}' not available", vm),
            SessionError::ConnectionFailed(msg) => write!(f, "Connection to fcm-agent failed: {}", msg),
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
    /// The actual connection is made separately via connect_to_agent().
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

    /// Create a new session on a VM (legacy API - redirects to get_or_create_console)
    pub fn create_session(
        &self,
        vm_id: &str,
        vm_ip: &str,
        _is_default: bool,
    ) -> Result<SessionInfo, SessionError> {
        self.get_or_create_console(vm_id, vm_ip)
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

/// Connect to fcm-agent on a VM
///
/// Returns a TCP stream for bidirectional communication.
/// The caller is responsible for the JSON-framed protocol:
/// - Send: {"stdin":"base64data"} or {"resize":{"cols":N,"rows":N}}
/// - Recv: {"stdout":"base64data"} or {"exit":N}
pub fn connect_to_agent(vm_ip: &str) -> Result<TcpStream, SessionError> {
    let addr = format!("{}:{}", vm_ip, AGENT_PORT);

    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| SessionError::ConnectionFailed(format!("Invalid address: {}", e)))?,
        Duration::from_secs(5),
    ).map_err(|e| SessionError::ConnectionFailed(format!("Cannot connect to {}: {}", addr, e)))?;

    // Set TCP_NODELAY for low latency
    stream.set_nodelay(true).ok();

    Ok(stream)
}

/// Send initial resize message to fcm-agent
pub fn send_resize(stream: &mut TcpStream, cols: u16, rows: u16) -> io::Result<()> {
    let msg = format!("{{\"resize\":{{\"cols\":{},\"rows\":{}}}}}\n", cols, rows);
    stream.write_all(msg.as_bytes())?;
    stream.flush()
}

/// Base64 encode data for JSON protocol
pub fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        result.push(CHARS[b0 >> 2] as char);
        result.push(CHARS[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Base64 decode data from JSON protocol
pub fn base64_decode(s: &str) -> Vec<u8> {
    fn char_to_val(c: char) -> u8 {
        match c {
            'A'..='Z' => c as u8 - b'A',
            'a'..='z' => c as u8 - b'a' + 26,
            '0'..='9' => c as u8 - b'0' + 52,
            '+' => 62,
            '/' => 63,
            _ => 0,
        }
    }
    let chars: Vec<char> = s.chars().filter(|c| *c != '=').collect();
    let mut result = Vec::new();
    for chunk in chars.chunks(4) {
        if chunk.len() >= 2 {
            let b0 = char_to_val(chunk[0]);
            let b1 = char_to_val(chunk[1]);
            result.push((b0 << 2) | (b1 >> 4));
        }
        if chunk.len() >= 3 {
            let b1 = char_to_val(chunk[1]);
            let b2 = char_to_val(chunk[2]);
            result.push((b1 << 4) | (b2 >> 2));
        }
        if chunk.len() >= 4 {
            let b2 = char_to_val(chunk[2]);
            let b3 = char_to_val(chunk[3]);
            result.push((b2 << 6) | b3);
        }
    }
    result
}

/// Extract "stdout" value from JSON message
pub fn extract_stdout(json: &str) -> Option<String> {
    extract_json_string(json, "stdout")
}

/// Extract "stdin" value from JSON message
#[allow(dead_code)] // Used in tests
pub fn extract_stdin(json: &str) -> Option<String> {
    extract_json_string(json, "stdin")
}

/// Extract "exit" code from JSON message
#[allow(dead_code)] // Used in tests and for future client-side use
pub fn extract_exit_code(json: &str) -> Option<i32> {
    if !json.contains("\"exit\"") {
        return None;
    }
    extract_json_number(json, "exit").map(|n| n as i32)
}

/// Extract string value from JSON
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\":\"", key);
    if let Some(start) = json.find(&pattern) {
        let value_start = start + pattern.len();
        if let Some(end) = json[value_start..].find('"') {
            return Some(json[value_start..value_start + end].to_string());
        }
    }
    None
}

/// Extract number value from JSON
#[allow(dead_code)] // Used by extract_exit_code
fn extract_json_number(json: &str, key: &str) -> Option<u32> {
    let pattern = format!("\"{}\":", key);
    if let Some(start) = json.find(&pattern) {
        let value_start = start + pattern.len();
        let rest = &json[value_start..];
        let mut num_str = String::new();
        for c in rest.chars() {
            if c.is_ascii_digit() {
                num_str.push(c);
            } else if !num_str.is_empty() {
                break;
            }
        }
        return num_str.parse().ok();
    }
    None
}

/// Create stdin message for fcm-agent
pub fn make_stdin_message(data: &[u8]) -> String {
    format!("{{\"stdin\":\"{}\"}}\n", base64_encode(data))
}

/// Create resize message for fcm-agent
#[allow(dead_code)] // Used in tests and for future client-side use
pub fn make_resize_message(cols: u16, rows: u16) -> String {
    format!("{{\"resize\":{{\"cols\":{},\"rows\":{}}}}}\n", cols, rows)
}

/// Agent connection wrapper for easier I/O
#[allow(dead_code)] // Convenience wrapper for future use
pub struct AgentConnection {
    pub stream: TcpStream,
    pub reader: BufReader<TcpStream>,
}

#[allow(dead_code)] // Convenience wrapper for future use
impl AgentConnection {
    /// Create new connection to fcm-agent
    pub fn connect(vm_ip: &str) -> Result<Self, SessionError> {
        let stream = connect_to_agent(vm_ip)?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self { stream, reader })
    }

    /// Send resize to set initial terminal size
    pub fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        send_resize(&mut self.stream, cols, rows)
    }

    /// Send stdin data to agent
    pub fn send_stdin(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(make_stdin_message(data).as_bytes())?;
        self.stream.flush()
    }

    /// Read a line from agent (JSON message)
    pub fn read_line(&mut self, buf: &mut String) -> io::Result<usize> {
        self.reader.read_line(buf)
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
        assert!(SessionError::ConnectionFailed("timeout".to_string()).to_string().contains("timeout"));
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

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("SGVsbG8="), b"Hello");
        assert_eq!(base64_decode(""), b"");
        assert_eq!(base64_decode("YQ=="), b"a");
        assert_eq!(base64_decode("YWI="), b"ab");
        assert_eq!(base64_decode("YWJj"), b"abc");
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World! \x00\x01\x02\xff";
        assert_eq!(base64_decode(&base64_encode(data)), data);
    }

    #[test]
    fn test_extract_stdout() {
        assert_eq!(extract_stdout(r#"{"stdout":"SGVsbG8="}"#), Some("SGVsbG8=".to_string()));
        assert_eq!(extract_stdout(r#"{"exit":0}"#), None);
    }

    #[test]
    fn test_extract_stdin() {
        assert_eq!(extract_stdin(r#"{"stdin":"SGVsbG8="}"#), Some("SGVsbG8=".to_string()));
        assert_eq!(extract_stdin(r#"{"exit":0}"#), None);
    }

    #[test]
    fn test_extract_exit_code() {
        assert_eq!(extract_exit_code(r#"{"exit":0}"#), Some(0));
        assert_eq!(extract_exit_code(r#"{"exit":127}"#), Some(127));
        assert_eq!(extract_exit_code(r#"{"stdout":"data"}"#), None);
    }

    #[test]
    fn test_make_stdin_message() {
        let msg = make_stdin_message(b"ls\n");
        assert!(msg.contains("stdin"));
        assert!(msg.ends_with('\n'));
    }

    #[test]
    fn test_make_resize_message() {
        let msg = make_resize_message(120, 40);
        assert_eq!(msg, "{\"resize\":{\"cols\":120,\"rows\":40}}\n");
    }

    #[test]
    fn test_agent_port() {
        assert_eq!(AGENT_PORT, 7779);
    }
}
