// fcm-agent: PTY manager for Firecracker VMs
// Listens on TCP :7779, spawns PTY with /bin/sh, proxies I/O via JSON framed messages
// PTY session persists across client disconnects (shell kept alive until VM stops)

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::RawFd;
use std::process;
use std::sync::atomic::{AtomicI32, AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;

// Global shell state - persists across client connections
static MASTER_FD: AtomicI32 = AtomicI32::new(-1);
static CHILD_PID: AtomicI32 = AtomicI32::new(-1);
static SHELL_INITIALIZED: AtomicBool = AtomicBool::new(false);

// Mutex to ensure only one client can connect at a time
static CONNECTION_LOCK: Mutex<()> = Mutex::new(());

fn base64_encode(data: &[u8]) -> String {
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

fn base64_decode(s: &str) -> Vec<u8> {
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

fn set_window_size(fd: RawFd, cols: u16, rows: u16) {
    #[repr(C)]
    struct Winsize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    }
    let ws = Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &ws);
    }
}

fn spawn_shell() -> (RawFd, libc::pid_t) {
    let mut master_fd: RawFd = 0;
    let pid = unsafe {
        let pid = libc::forkpty(&mut master_fd, std::ptr::null_mut(), std::ptr::null(), std::ptr::null());
        if pid == 0 {
            // Child process - exec login shell (sources /etc/profile for PATH)
            let shell = std::ffi::CString::new("/bin/sh").unwrap();
            let login_flag = std::ffi::CString::new("-l").unwrap();
            let args = [shell.as_ptr(), login_flag.as_ptr(), std::ptr::null()];
            libc::execvp(shell.as_ptr(), args.as_ptr());
            libc::_exit(1);
        }
        pid
    };
    if pid < 0 {
        eprintln!("forkpty failed");
        process::exit(1);
    }
    // Set non-blocking on master
    unsafe {
        let flags = libc::fcntl(master_fd, libc::F_GETFL);
        libc::fcntl(master_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    (master_fd, pid)
}

fn check_child_exit(pid: libc::pid_t) -> Option<i32> {
    let mut status: i32 = 0;
    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    if result > 0 {
        if libc::WIFEXITED(status) {
            Some(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            Some(128 + libc::WTERMSIG(status))
        } else {
            Some(1)
        }
    } else {
        None
    }
}

fn send_message(stream: &mut TcpStream, msg: &str) {
    let _ = stream.write_all(msg.as_bytes());
    let _ = stream.write_all(b"\n");
    let _ = stream.flush();
}

/// Returns (master_fd, child_pid, is_reconnect)
/// is_reconnect is true if we're attaching to an existing shell
fn ensure_shell_running() -> (RawFd, libc::pid_t, bool) {
    // Check if we need to spawn or respawn shell
    let master_fd = MASTER_FD.load(Ordering::SeqCst);
    let child_pid = CHILD_PID.load(Ordering::SeqCst);

    // Check if shell was initialized and is still running
    if SHELL_INITIALIZED.load(Ordering::SeqCst) && child_pid > 0 {
        // Check if child is still alive (non-blocking wait)
        let mut status: i32 = 0;
        let result = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
        if result == 0 {
            // Child still running - this is a reconnect
            return (master_fd, child_pid, true);
        }
        // Child exited, need to respawn
        eprintln!("Shell (pid {}) exited, will respawn on check", child_pid);
        unsafe { libc::close(master_fd) };
    }

    // Spawn new shell
    let (new_fd, new_pid) = spawn_shell();
    MASTER_FD.store(new_fd, Ordering::SeqCst);
    CHILD_PID.store(new_pid, Ordering::SeqCst);
    SHELL_INITIALIZED.store(true, Ordering::SeqCst);
    eprintln!("Spawned shell (pid {})", new_pid);

    (new_fd, new_pid, false)
}

fn handle_connection(mut stream: TcpStream) {
    // Only allow one client at a time - others wait
    let _lock = CONNECTION_LOCK.lock().unwrap();

    eprintln!("Client connected from {:?}", stream.peer_addr());

    // Get or create shell (persists across connections)
    let (master_fd, child_pid, is_reconnect) = ensure_shell_running();

    // Set socket to non-blocking for polling
    stream.set_nonblocking(true).ok();

    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line_buf = String::new();
    let mut pty_buf = [0u8; 4096];

    // Track if we need to trigger a prompt (on reconnect, after connection is established)
    let mut needs_prompt_trigger = is_reconnect;

    loop {
        // Check if child exited (user typed 'exit')
        if let Some(exit_code) = check_child_exit(child_pid) {
            eprintln!("Shell exited with code {}", exit_code);
            send_message(&mut stream, &format!("{{\"exit\":{}}}", exit_code));

            // Close the master fd and mark shell as not initialized
            // Shell will respawn on next client connection (not immediately)
            unsafe { libc::close(master_fd) };
            MASTER_FD.store(-1, Ordering::SeqCst);
            CHILD_PID.store(-1, Ordering::SeqCst);
            SHELL_INITIALIZED.store(false, Ordering::SeqCst);
            eprintln!("Shell exited, will respawn on next connection");

            // End this connection - client will disconnect
            break;
        }

        // Read from PTY and send to client
        let pty_read = unsafe {
            libc::read(master_fd, pty_buf.as_mut_ptr() as *mut libc::c_void, pty_buf.len())
        };
        if pty_read > 0 {
            let data = &pty_buf[..pty_read as usize];
            let encoded = base64_encode(data);
            send_message(&mut stream, &format!("{{\"stdout\":\"{}\"}}", encoded));
        }

        // Read from client
        line_buf.clear();
        match reader.read_line(&mut line_buf) {
            Ok(0) => {
                // Client disconnected - BUT keep shell running!
                eprintln!("Client disconnected (shell preserved for reconnect)");
                break;
            }
            Ok(_) => {
                let line = line_buf.trim();
                if line.is_empty() {
                    continue;
                }

                // Parse JSON manually (minimal deps)
                if let Some(stdin_data) = extract_json_string(line, "stdin") {
                    let decoded = base64_decode(&stdin_data);
                    unsafe {
                        libc::write(master_fd, decoded.as_ptr() as *const libc::c_void, decoded.len());
                    }
                } else if let Some((cols, rows)) = extract_resize(line) {
                    set_window_size(master_fd, cols, rows);
                    // Send SIGWINCH to child
                    unsafe { libc::kill(child_pid, libc::SIGWINCH) };

                    // On reconnect, just let SIGWINCH trigger the redraw naturally
                    // Don't inject any characters - minimal interference with the data stream
                    if needs_prompt_trigger {
                        needs_prompt_trigger = false;
                        eprintln!("Reconnect: SIGWINCH sent, no character injection");
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, sleep briefly
                thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("Read error: {}", e);
                break;
            }
        }
    }

    // DO NOT kill shell on disconnect - it persists for next client
    // Shell is only killed when VM stops or user types 'exit'
    eprintln!("Connection handler exited (shell still running)");
}

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

fn extract_resize(json: &str) -> Option<(u16, u16)> {
    // Parse {"resize":{"cols":80,"rows":24}}
    if !json.contains("\"resize\"") {
        return None;
    }
    let cols = extract_json_number(json, "cols")?;
    let rows = extract_json_number(json, "rows")?;
    Some((cols as u16, rows as u16))
}

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

fn main() {
    eprintln!("fcm-agent starting on port 7779");

    let listener = TcpListener::bind("0.0.0.0:7779").expect("Failed to bind to port 7779");
    eprintln!("Listening on 0.0.0.0:7779");

    // Accept one connection at a time (one session per VM)
    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle_connection(s),
            Err(e) => eprintln!("Accept error: {}", e),
        }
    }
}
