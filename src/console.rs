// Terminal streaming client for persistent console sessions
//
// This module handles the client-side terminal streaming:
// 1. Connects to daemon via WebSocket over TLS (wss://)
// 2. Sends auth token in HTTP header during upgrade
// 3. Passes VM name, terminal size, env vars in URL query params
// 4. Uses Binary frames for terminal I/O, Text frames for resize

use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tungstenite::protocol::Message;

/// Global flag set by SIGWINCH signal handler when terminal is resized
static RESIZE_PENDING: AtomicBool = AtomicBool::new(false);

/// OSC sequence state machine for parsing terminal title sequences
/// Detects: \x1b]0;{title}\x07 or \x1b]0;{title}\x1b\\
#[derive(Debug, Clone)]
enum OscState {
    /// Normal output, no OSC sequence in progress
    Normal,
    /// Saw ESC (\x1b), waiting for ]
    Escape,
    /// Saw ESC ], waiting for 0
    OscStart,
    /// Saw ESC ]0, waiting for ;
    OscZero,
    /// Collecting title text after ESC ]0;
    CollectingTitle(Vec<u8>),
    /// Saw ESC inside title (possible ST terminator \x1b\\)
    TitleEscape(Vec<u8>),
}

/// Process binary data and rewrite OSC title sequences with "fcm: " prefix
/// Returns the processed data to write to stdout
fn process_osc_titles(data: &[u8], state: &mut OscState) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len() + 32);

    for &byte in data {
        match state {
            OscState::Normal => {
                if byte == 0x1b {
                    // ESC - might be start of OSC sequence
                    *state = OscState::Escape;
                } else {
                    output.push(byte);
                }
            }
            OscState::Escape => {
                if byte == b']' {
                    // ESC ] - OSC sequence start
                    *state = OscState::OscStart;
                } else {
                    // Not an OSC, emit ESC and this byte
                    output.push(0x1b);
                    output.push(byte);
                    *state = OscState::Normal;
                }
            }
            OscState::OscStart => {
                if byte == b'0' || byte == b'2' {
                    // ESC ]0 or ESC ]2 - window title
                    *state = OscState::OscZero;
                } else {
                    // Different OSC code, pass through
                    output.extend_from_slice(&[0x1b, b']', byte]);
                    *state = OscState::Normal;
                }
            }
            OscState::OscZero => {
                if byte == b';' {
                    // ESC ]0; - now collecting title
                    *state = OscState::CollectingTitle(Vec::new());
                } else {
                    // Malformed, pass through
                    output.extend_from_slice(&[0x1b, b']', b'0', byte]);
                    *state = OscState::Normal;
                }
            }
            OscState::CollectingTitle(ref mut title) => {
                if byte == 0x07 {
                    // BEL - end of title (ST)
                    emit_prefixed_title(&mut output, title);
                    *state = OscState::Normal;
                } else if byte == 0x1b {
                    // ESC - might be ST (\x1b\\)
                    *state = OscState::TitleEscape(std::mem::take(title));
                } else {
                    title.push(byte);
                }
            }
            OscState::TitleEscape(ref mut title) => {
                if byte == b'\\' {
                    // \x1b\\ - String Terminator
                    emit_prefixed_title(&mut output, title);
                    *state = OscState::Normal;
                } else {
                    // Not ST, the ESC was part of title (unusual but handle it)
                    title.push(0x1b);
                    title.push(byte);
                    *state = OscState::CollectingTitle(std::mem::take(title));
                }
            }
        }
    }

    output
}

/// Emit an OSC title sequence with "fcm: " prefix
fn emit_prefixed_title(output: &mut Vec<u8>, title: &[u8]) {
    // Build: \x1b]0;fcm: {title}\x07
    output.push(0x1b);
    output.push(b']');
    output.push(b'0');
    output.push(b';');
    output.extend_from_slice(b"fcm: ");
    output.extend_from_slice(title);
    output.push(0x07);
}

/// SIGWINCH signal handler - sets the resize pending flag
extern "C" fn sigwinch_handler(_: libc::c_int) {
    RESIZE_PENDING.store(true, Ordering::SeqCst);
}

/// Install SIGWINCH signal handler
fn install_sigwinch_handler() {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = sigwinch_handler as usize;
        action.sa_flags = 0; // No SA_RESTART - we want EINTR so we can detect resize
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGWINCH, &action, std::ptr::null_mut());
    }
}

/// Create a resize message in JSON format (per PRD spec: Text frame with JSON)
fn make_resize_message(cols: u16, rows: u16) -> String {
    format!("{{\"type\":\"resize\",\"cols\":{},\"rows\":{}}}", cols, rows)
}

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
    /// Session error from daemon (reserved for future use)
    #[allow(dead_code)]
    SessionError(String),
    /// WebSocket error (reserved for future use)
    #[allow(dead_code)]
    WebSocket(String),
}

impl std::fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsoleError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            ConsoleError::AuthFailed(msg) => write!(f, "Authentication failed: {}", msg),
            ConsoleError::Io(e) => write!(f, "IO error: {}", e),
            ConsoleError::TerminalError(msg) => write!(f, "Terminal error: {}", msg),
            ConsoleError::SessionError(msg) => write!(f, "Session error: {}", msg),
            ConsoleError::WebSocket(msg) => write!(f, "WebSocket error: {}", msg),
        }
    }
}

impl Error for ConsoleError {}

impl From<io::Error> for ConsoleError {
    fn from(e: io::Error) -> Self {
        ConsoleError::Io(e)
    }
}

/// URL encode a string
fn url_encode(s: &str) -> String {
    let mut encoded = String::new();
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => encoded.push(c),
            _ => {
                for byte in c.to_string().as_bytes() {
                    encoded.push_str(&format!("%{:02X}", byte));
                }
            }
        }
    }
    encoded
}

/// Get the WebSocket URL base for console connections
/// Uses FCM_HOST env var to determine the server
fn get_websocket_url_base() -> String {
    if let Ok(host) = env::var("FCM_HOST") {
        // Extract hostname from FCM_HOST (remove scheme and port)
        let host = host
            .trim_start_matches("http://")
            .trim_start_matches("https://");

        // For FCM_HOST, the fcm domain uses the IP with dashes
        // e.g., FCM_HOST=64.34.93.45:7777 -> fcm.64-34-93-45.sslip.io
        let hostname = host.split(':').next().unwrap_or(host);

        // Replace dots with dashes for sslip.io format
        let ip_dashed = hostname.replace('.', "-");
        format!("wss://fcm.{}.sslip.io/console", ip_dashed)
    } else {
        // Local development - use localhost without TLS
        "ws://127.0.0.1:7778/console".to_string()
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

/// Get the HTTP API base URL for file uploads
fn get_api_url_base() -> String {
    if let Ok(host) = env::var("FCM_HOST") {
        // Extract hostname from FCM_HOST (remove scheme and port)
        let host = host
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let hostname = host.split(':').next().unwrap_or(host);

        // Replace dots with dashes for sslip.io format
        let ip_dashed = hostname.replace('.', "-");
        format!("https://fcm.{}.sslip.io", ip_dashed)
    } else {
        // Local development
        "http://127.0.0.1:7777".to_string()
    }
}

/// Upload terminfo file to VM (optional, improves terminal compatibility)
///
/// Reads local terminfo for the given TERM type and uploads it to the VM.
/// This ensures the VM has proper terminfo for the client's terminal.
pub fn upload_terminfo(vm: &str, term: &str) -> Result<(), ConsoleError> {
    let token = load_token()?;

    // Find local terminfo file
    // Common paths: /usr/share/terminfo/{first-char}/{term}
    //              /lib/terminfo/{first-char}/{term}
    let first_char = term.chars().next().unwrap_or('x');
    let terminfo_paths = [
        format!("/usr/share/terminfo/{}/{}", first_char, term),
        format!("/lib/terminfo/{}/{}", first_char, term),
        format!("/usr/lib/terminfo/{}/{}", first_char, term),
    ];

    let terminfo_data = terminfo_paths
        .iter()
        .find_map(|path| fs::read(path).ok())
        .ok_or_else(|| {
            ConsoleError::TerminalError(format!(
                "Cannot find terminfo for '{}' in standard paths",
                term
            ))
        })?;

    // Upload to VM
    let api_base = get_api_url_base();
    let dest_path = format!("/usr/share/terminfo/{}/{}", first_char, term);
    let url = format!(
        "{}/vms/{}/fs?path={}",
        api_base,
        url_encode(vm),
        url_encode(&dest_path)
    );

    let response = ureq::put(&url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&terminfo_data);

    match response {
        Ok(resp) if resp.status() == 200 => Ok(()),
        Ok(resp) => Err(ConsoleError::ConnectionFailed(format!(
            "Failed to upload terminfo: HTTP {}",
            resp.status()
        ))),
        Err(e) => Err(ConsoleError::ConnectionFailed(format!(
            "Failed to upload terminfo: {}",
            e
        ))),
    }
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

/// Get terminal size (cols, rows)
fn get_terminal_size() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let fd = io::stdout().as_raw_fd();

    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 {
        (ws.ws_col, ws.ws_row)
    } else {
        // Default fallback
        (80, 24)
    }
}

/// Connect to a console session on a VM via WebSocket
///
/// This function:
/// 1. Connects to the daemon via WebSocket over TLS (wss://)
/// 2. Passes auth token in HTTP header during upgrade
/// 3. Passes VM name, terminal size in URL query params
/// 4. Enters raw terminal mode
/// 5. Proxies stdin/stdout using WebSocket Binary frames
/// 6. Restores terminal on exit
pub fn connect(vm: &str) -> Result<(), ConsoleError> {
    // Simple output - just show VM name, hide technical details
    print!("Connecting to {}...", vm);
    io::stdout().flush()?;

    // Load auth token
    let token = load_token()?;
    let (cols, rows) = get_terminal_size();

    // Gather environment variables to pass
    let term = env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string());
    let colorterm = env::var("COLORTERM").ok();
    let lang = env::var("LANG").ok();

    // Upload terminfo to VM for better terminal compatibility
    // Best-effort - if it fails, we continue anyway
    let _ = upload_terminfo(vm, &term);

    // Build WebSocket URL with query params
    let base_url = get_websocket_url_base();
    let mut url = format!(
        "{}?vm={}&cols={}&rows={}&env=TERM={}&env=SHELL={}",
        base_url,
        url_encode(vm),
        cols,
        rows,
        url_encode(&term),
        url_encode(&shell)
    );
    if let Some(ct) = colorterm {
        url.push_str(&format!("&env=COLORTERM={}", url_encode(&ct)));
    }
    if let Some(l) = lang {
        url.push_str(&format!("&env=LANG={}", url_encode(&l)));
    }

    // Build WebSocket request with Authorization header
    // Use IntoClientRequest to get proper WebSocket headers, then add our custom header
    use tungstenite::client::IntoClientRequest;
    let mut request = url
        .into_client_request()
        .map_err(|e| ConsoleError::ConnectionFailed(format!("Failed to build request: {}", e)))?;
    request
        .headers_mut()
        .insert("Authorization", format!("Bearer {}", token).parse().unwrap());

    // Connect to WebSocket server (with TLS for wss://)
    let (websocket, response) = tungstenite::connect(request)
        .map_err(|e| ConsoleError::ConnectionFailed(format!("WebSocket connection failed: {}", e)))?;

    // Check response status
    if response.status() != 101 {
        println!(" failed");
        return Err(ConsoleError::AuthFailed(format!("HTTP {}", response.status())));
    }

    // Simple connected message
    println!(" connected\r");
    println!("\r");

    // Check if we're in a TTY
    if !is_tty() {
        return Err(ConsoleError::TerminalError(
            "stdin is not a terminal".to_string(),
        ));
    }

    // Install SIGWINCH handler to detect terminal resize
    install_sigwinch_handler();
    RESIZE_PENDING.store(false, Ordering::SeqCst);

    // Enter raw terminal mode
    let _raw_terminal = RawTerminal::enable()?;

    // Set up flag for clean shutdown
    let running = Arc::new(AtomicBool::new(true));
    let running_for_reader = Arc::clone(&running);

    // Wrap websocket in Arc<Mutex> for thread-safe access
    let ws = Arc::new(Mutex::new(websocket));
    let ws_for_reader = Arc::clone(&ws);

    // Spawn thread to read from WebSocket and write to stdout
    let reader_handle = thread::spawn(move || {
        let mut stdout = io::stdout();
        let mut osc_state = OscState::Normal;

        while running_for_reader.load(Ordering::Relaxed) {
            // Read from WebSocket
            let msg = {
                let mut ws = match ws_for_reader.lock() {
                    Ok(ws) => ws,
                    Err(_) => break,
                };
                match ws.read() {
                    Ok(msg) => msg,
                    Err(tungstenite::Error::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(tungstenite::Error::Io(ref e)) if e.kind() == io::ErrorKind::TimedOut => {
                        continue;
                    }
                    Err(_) => break,
                }
            };

            match msg {
                Message::Binary(data) => {
                    // Process OSC title sequences and add "fcm: " prefix
                    let processed = process_osc_titles(&data, &mut osc_state);
                    if stdout.write_all(&processed).is_err() {
                        break;
                    }
                    if stdout.flush().is_err() {
                        break;
                    }
                }
                Message::Close(_) => {
                    break;
                }
                Message::Ping(data) => {
                    let mut ws = match ws_for_reader.lock() {
                        Ok(ws) => ws,
                        Err(_) => break,
                    };
                    let _ = ws.send(Message::Pong(data));
                }
                _ => {}
            }
        }
    });

    // Track last known terminal size
    let mut last_size = (cols, rows);

    // Main thread reads from stdin and sends to WebSocket
    let mut stdin = io::stdin();
    let mut buf = [0u8; 1024];

    while running.load(Ordering::Relaxed) {
        // Check if terminal was resized (SIGWINCH received)
        if RESIZE_PENDING.swap(false, Ordering::SeqCst) {
            let (new_cols, new_rows) = get_terminal_size();
            if (new_cols, new_rows) != last_size {
                last_size = (new_cols, new_rows);
                // Send resize message as Text frame
                let resize_msg = make_resize_message(new_cols, new_rows);
                let mut ws = match ws.lock() {
                    Ok(ws) => ws,
                    Err(_) => break,
                };
                if ws.send(Message::Text(resize_msg)).is_err() {
                    break;
                }
                if ws.flush().is_err() {
                    break;
                }
            }
        }

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

                // Send as Binary frame
                let mut ws_lock = match ws.lock() {
                    Ok(ws) => ws,
                    Err(_) => break,
                };
                if ws_lock.send(Message::Binary(buf[..n].to_vec())).is_err() {
                    break;
                }
                if ws_lock.flush().is_err() {
                    break;
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {
                // Signal received (likely SIGWINCH), loop will check RESIZE_PENDING
                continue;
            }
            Err(_) => {
                break;
            }
        }
    }

    // Signal reader thread to stop and wait for it
    running.store(false, Ordering::Relaxed);

    // Close WebSocket connection
    if let Ok(mut ws) = ws.lock() {
        let _ = ws.close(None);
    }

    let _ = reader_handle.join();

    // Terminal will be restored when _raw_terminal is dropped
    println!("\r");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_url_default() {
        env::remove_var("FCM_HOST");
        let url = get_websocket_url_base();
        assert_eq!(url, "ws://127.0.0.1:7778/console");
    }

    #[test]
    fn test_websocket_url_from_env() {
        env::set_var("FCM_HOST", "192.168.1.100:7777");
        let url = get_websocket_url_base();
        assert!(url.contains("fcm.192-168-1-100.sslip.io"));
        assert!(url.starts_with("wss://"));
        env::remove_var("FCM_HOST");
    }

    #[test]
    fn test_websocket_url_with_scheme() {
        env::set_var("FCM_HOST", "http://10.0.0.5:7777");
        let url = get_websocket_url_base();
        assert!(url.contains("fcm.10-0-0-5.sslip.io"));
        assert!(url.starts_with("wss://"));
        env::remove_var("FCM_HOST");
    }

    #[test]
    fn test_token_path() {
        let path = token_path();
        assert!(path.ends_with(".fcm-token"));
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("test=value"), "test%3Dvalue");
        assert_eq!(url_encode("/bin/zsh"), "%2Fbin%2Fzsh");
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
        assert!(ConsoleError::WebSocket("protocol error".to_string())
            .to_string()
            .contains("protocol error"));
    }

    #[test]
    fn test_load_token_from_env() {
        env::set_var("FCM_TOKEN", "test_console_token");
        let token = load_token().unwrap();
        assert_eq!(token, "test_console_token");
        env::remove_var("FCM_TOKEN");
    }

    #[test]
    fn test_make_resize_message() {
        let msg = make_resize_message(120, 40);
        assert_eq!(msg, r#"{"type":"resize","cols":120,"rows":40}"#);

        let msg2 = make_resize_message(80, 24);
        assert_eq!(msg2, r#"{"type":"resize","cols":80,"rows":24}"#);
    }

    #[test]
    fn test_osc_title_simple() {
        // Test OSC title with BEL terminator: \x1b]0;my-title\x07
        let mut state = OscState::Normal;
        let input = b"\x1b]0;my-title\x07";
        let output = process_osc_titles(input, &mut state);
        // Should become: \x1b]0;fcm: my-title\x07
        assert_eq!(output, b"\x1b]0;fcm: my-title\x07");
    }

    #[test]
    fn test_osc_title_with_st_terminator() {
        // Test OSC title with ST terminator: \x1b]0;my-title\x1b\\
        let mut state = OscState::Normal;
        let input = b"\x1b]0;my-title\x1b\\";
        let output = process_osc_titles(input, &mut state);
        // Should become: \x1b]0;fcm: my-title\x07 (we always emit BEL)
        assert_eq!(output, b"\x1b]0;fcm: my-title\x07");
    }

    #[test]
    fn test_osc_title_mixed_with_text() {
        // Test OSC title embedded in normal text
        let mut state = OscState::Normal;
        let input = b"Hello\x1b]0;my-vm: zsh\x07World";
        let output = process_osc_titles(input, &mut state);
        assert_eq!(output, b"Hello\x1b]0;fcm: my-vm: zsh\x07World");
    }

    #[test]
    fn test_osc_title_split_across_chunks() {
        // Test OSC title split across multiple data chunks
        let mut state = OscState::Normal;

        // First chunk: start of title
        let output1 = process_osc_titles(b"\x1b]0;my-ti", &mut state);
        assert_eq!(output1, b""); // Nothing emitted yet, collecting title

        // Second chunk: rest of title
        let output2 = process_osc_titles(b"tle\x07more text", &mut state);
        assert_eq!(output2, b"\x1b]0;fcm: my-title\x07more text");
    }

    #[test]
    fn test_osc_title_code_2() {
        // Test OSC code 2 (also sets window title): \x1b]2;my-title\x07
        let mut state = OscState::Normal;
        let input = b"\x1b]2;my-title\x07";
        let output = process_osc_titles(input, &mut state);
        assert_eq!(output, b"\x1b]0;fcm: my-title\x07");
    }

    #[test]
    fn test_osc_other_codes_passthrough() {
        // Test other OSC codes pass through unchanged (e.g., OSC 8 for hyperlinks)
        let mut state = OscState::Normal;
        let input = b"\x1b]8;;https://example.com\x07link\x1b]8;;\x07";
        let output = process_osc_titles(input, &mut state);
        // Should pass through (starts with \x1b]8, not \x1b]0 or \x1b]2)
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn test_osc_normal_escape_sequences_passthrough() {
        // Test that normal escape sequences (not OSC) pass through
        let mut state = OscState::Normal;
        let input = b"\x1b[32mgreen\x1b[0m";
        let output = process_osc_titles(input, &mut state);
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn test_api_url_default() {
        env::remove_var("FCM_HOST");
        let url = get_api_url_base();
        assert_eq!(url, "http://127.0.0.1:7777");
    }

    #[test]
    fn test_api_url_from_env() {
        env::set_var("FCM_HOST", "192.168.1.100:7777");
        let url = get_api_url_base();
        assert!(url.contains("fcm.192-168-1-100.sslip.io"));
        assert!(url.starts_with("https://"));
        env::remove_var("FCM_HOST");
    }
}
