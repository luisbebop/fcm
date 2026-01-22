// Terminal streaming client for persistent console sessions
//
// This module handles the client-side terminal streaming:
// 1. Connects to daemon's terminal server (port 7778)
// 2. Sends authentication JSON
// 3. Puts terminal in raw mode for proper TTY experience
// 4. Proxies stdin/stdout to the TCP connection

use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Default daemon terminal port
const DEFAULT_TERMINAL_PORT: u16 = 7778;

/// Console error types
#[derive(Debug)]
pub enum ConsoleError {
    /// Connection failed
    ConnectionFailed(String),
    /// Authentication failed
    AuthFailed(String),
    /// IO error
    Io(io::Error),
    /// Terminal setup failed
    TerminalError(String),
    /// Session error from daemon
    SessionError(String),
}

impl std::fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsoleError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            ConsoleError::AuthFailed(msg) => write!(f, "Authentication failed: {}", msg),
            ConsoleError::Io(e) => write!(f, "IO error: {}", e),
            ConsoleError::TerminalError(msg) => write!(f, "Terminal error: {}", msg),
            ConsoleError::SessionError(msg) => write!(f, "Session error: {}", msg),
        }
    }
}

impl Error for ConsoleError {}

impl From<io::Error> for ConsoleError {
    fn from(e: io::Error) -> Self {
        ConsoleError::Io(e)
    }
}

/// Request to connect to a console session
#[derive(Debug, Serialize)]
struct ConnectRequest {
    vm: String,
    session: String,
    token: String,
}

/// Response from daemon after connect request
#[derive(Debug, Deserialize)]
struct ConnectResponse {
    success: bool,
    error: Option<String>,
}

/// Get the terminal server host from FCM_HOST env var or default
fn terminal_host() -> String {
    if let Ok(host) = env::var("FCM_HOST") {
        // Extract hostname from FCM_HOST (remove scheme and port)
        let host = host
            .trim_start_matches("http://")
            .trim_start_matches("https://");

        // Split off port if present
        let hostname = host.split(':').next().unwrap_or(host);
        hostname.to_string()
    } else {
        "127.0.0.1".to_string()
    }
}

/// Get the client token file path (~/.fcm-token)
fn token_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".fcm-token")
}

/// Load auth token from environment or file
fn load_token() -> Result<String, ConsoleError> {
    // First try FCM_TOKEN env var
    if let Ok(token) = env::var("FCM_TOKEN") {
        if !token.is_empty() {
            return Ok(token);
        }
    }

    // Then try ~/.fcm-token file
    let path = token_path();
    if path.exists() {
        let token = fs::read_to_string(&path)
            .map_err(ConsoleError::Io)?
            .trim()
            .to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }

    Err(ConsoleError::AuthFailed(
        "No auth token found. Set FCM_TOKEN env var or create ~/.fcm-token".to_string(),
    ))
}

/// Terminal settings wrapper for raw mode
struct RawTerminal {
    original_termios: libc::termios,
    fd: i32,
}

impl RawTerminal {
    /// Enable raw mode on stdin
    fn enable() -> Result<Self, ConsoleError> {
        let fd = io::stdin().as_raw_fd();

        // Get current terminal settings
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
            return Err(ConsoleError::TerminalError(
                "Failed to get terminal attributes".to_string(),
            ));
        }

        let original_termios = termios;

        // Disable canonical mode, echo, and signals
        termios.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
        // Disable input processing
        termios.c_iflag &= !(libc::IXON | libc::IXOFF | libc::ICRNL | libc::INLCR);
        // Disable output processing
        termios.c_oflag &= !libc::OPOST;
        // Set minimum bytes and timeout for read
        termios.c_cc[libc::VMIN] = 1;
        termios.c_cc[libc::VTIME] = 0;

        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &termios) } != 0 {
            return Err(ConsoleError::TerminalError(
                "Failed to set terminal to raw mode".to_string(),
            ));
        }

        Ok(RawTerminal {
            original_termios,
            fd,
        })
    }

    /// Restore original terminal settings
    fn restore(&self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original_termios);
        }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Check if stdin is a TTY
fn is_tty() -> bool {
    unsafe { libc::isatty(io::stdin().as_raw_fd()) == 1 }
}

/// Connect to a console session on a VM
///
/// This function:
/// 1. Connects to the daemon's terminal server
/// 2. Authenticates with the provided token
/// 3. Enters raw terminal mode
/// 4. Proxies stdin/stdout to the TCP connection
/// 5. Restores terminal on exit
pub fn connect(vm: &str, session: &str) -> Result<(), ConsoleError> {
    let host = terminal_host();
    let addr = format!("{}:{}", host, DEFAULT_TERMINAL_PORT);

    println!("Connecting to {}...", addr);

    // Connect to daemon terminal server
    let mut stream = TcpStream::connect(&addr).map_err(|e| {
        ConsoleError::ConnectionFailed(format!(
            "Cannot connect to terminal server at {}: {}",
            addr, e
        ))
    })?;

    stream.set_nodelay(true)?;

    // Load and send authentication
    let token = load_token()?;
    let request = ConnectRequest {
        vm: vm.to_string(),
        session: session.to_string(),
        token,
    };

    let request_json = serde_json::to_string(&request)
        .map_err(|e| ConsoleError::AuthFailed(format!("Failed to serialize request: {}", e)))?;

    // Send request with newline delimiter
    stream.write_all(request_json.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    // Read response
    let mut response_buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        response_buf.push(byte[0]);
    }

    let response: ConnectResponse = serde_json::from_slice(&response_buf)
        .map_err(|e| ConsoleError::AuthFailed(format!("Invalid response from daemon: {}", e)))?;

    if !response.success {
        return Err(ConsoleError::SessionError(
            response.error.unwrap_or_else(|| "Unknown error".to_string()),
        ));
    }

    println!("Connected to session '{}' on VM '{}'\r", session, vm);
    println!("Press Ctrl+] to disconnect\r");
    println!("\r");

    // Check if we're in a TTY
    if !is_tty() {
        return Err(ConsoleError::TerminalError(
            "stdin is not a terminal".to_string(),
        ));
    }

    // Enter raw terminal mode
    let _raw_terminal = RawTerminal::enable()?;

    // Set up flag for clean shutdown
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // Clone stream for the reader thread
    let mut read_stream = stream.try_clone()?;

    // Spawn thread to read from socket and write to stdout
    let reader_handle = thread::spawn(move || {
        let mut stdout = io::stdout();
        let mut buf = [0u8; 4096];

        while running_clone.load(Ordering::Relaxed) {
            // Set read timeout to allow checking the running flag
            if read_stream
                .set_read_timeout(Some(Duration::from_millis(100)))
                .is_err()
            {
                break;
            }

            match read_stream.read(&mut buf) {
                Ok(0) => {
                    // Connection closed
                    break;
                }
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    if stdout.flush().is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Timeout, continue checking running flag
                    continue;
                }
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
                    // Timeout, continue checking running flag
                    continue;
                }
                Err(_) => {
                    break;
                }
            }
        }
    });

    // Main thread reads from stdin and writes to socket
    let mut stdin = io::stdin();
    let mut buf = [0u8; 1024];

    while running.load(Ordering::Relaxed) {
        match stdin.read(&mut buf) {
            Ok(0) => {
                // EOF
                break;
            }
            Ok(n) => {
                // Check for Ctrl+] (0x1d) to disconnect
                if buf[..n].contains(&0x1d) {
                    println!("\r\nDisconnecting...\r");
                    break;
                }

                if stream.write_all(&buf[..n]).is_err() {
                    break;
                }
                if stream.flush().is_err() {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(_) => {
                break;
            }
        }
    }

    // Signal reader thread to stop and wait for it
    running.store(false, Ordering::Relaxed);
    let _ = reader_handle.join();

    // Terminal will be restored when _raw_terminal is dropped
    println!("\r\nSession detached.\r");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_host_default() {
        env::remove_var("FCM_HOST");
        assert_eq!(terminal_host(), "127.0.0.1");
    }

    #[test]
    fn test_terminal_host_from_env() {
        env::set_var("FCM_HOST", "192.168.1.100:7777");
        assert_eq!(terminal_host(), "192.168.1.100");
        env::remove_var("FCM_HOST");
    }

    #[test]
    fn test_terminal_host_with_scheme() {
        env::set_var("FCM_HOST", "http://10.0.0.5:7777");
        assert_eq!(terminal_host(), "10.0.0.5");
        env::remove_var("FCM_HOST");
    }

    #[test]
    fn test_token_path() {
        let path = token_path();
        assert!(path.ends_with(".fcm-token"));
    }

    #[test]
    fn test_connect_request_serialization() {
        let request = ConnectRequest {
            vm: "test-vm".to_string(),
            session: "abc123".to_string(),
            token: "secret-token".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("test-vm"));
        assert!(json.contains("abc123"));
        assert!(json.contains("secret-token"));
    }

    #[test]
    fn test_connect_response_deserialization_success() {
        let json = r#"{"success": true, "error": null}"#;
        let response: ConnectResponse = serde_json::from_str(json).unwrap();
        assert!(response.success);
        assert!(response.error.is_none());
    }

    #[test]
    fn test_connect_response_deserialization_error() {
        let json = r#"{"success": false, "error": "Session not found"}"#;
        let response: ConnectResponse = serde_json::from_str(json).unwrap();
        assert!(!response.success);
        assert_eq!(response.error.unwrap(), "Session not found");
    }

    #[test]
    fn test_console_error_display() {
        assert!(ConsoleError::ConnectionFailed("timeout".to_string())
            .to_string()
            .contains("timeout"));
        assert!(ConsoleError::AuthFailed("invalid token".to_string())
            .to_string()
            .contains("invalid token"));
        assert!(ConsoleError::TerminalError("not a tty".to_string())
            .to_string()
            .contains("not a tty"));
        assert!(ConsoleError::SessionError("not found".to_string())
            .to_string()
            .contains("not found"));
    }

    #[test]
    fn test_load_token_from_env() {
        env::set_var("FCM_TOKEN", "test_console_token");
        let token = load_token().unwrap();
        assert_eq!(token, "test_console_token");
        env::remove_var("FCM_TOKEN");
    }
}
