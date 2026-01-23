// Daemon HTTP server module

use crate::caddy;
use crate::network;
use crate::session::{attach_to_session, SessionError, SessionInfo, SessionManager};
use crate::vm::{self, VmConfig, VmError, VmState, BASE_DIR};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tiny_http::{Header, Method, Request, Response, Server};

/// Request to create a VM
#[derive(Debug, Deserialize, Default)]
struct CreateVmRequest {
    ssh_public_key: Option<String>,
}

const BIND_ADDR: &str = "0.0.0.0:7777";

/// Terminal server bind address
const TERMINAL_BIND_ADDR: &str = "0.0.0.0:7778";

/// Default port to expose for all VMs
const DEFAULT_EXPOSE_PORT: u16 = 8000;

/// Status page HTTP port (internal, proxied by Caddy)
const STATUS_PAGE_PORT: u16 = 7780;

/// Daemon statistics for status page
#[derive(Clone)]
struct DaemonStats {
    start_time: Instant,
    server_ip: String,
}

impl DaemonStats {
    fn new(server_ip: String) -> Self {
        Self {
            start_time: Instant::now(),
            server_ip,
        }
    }

    fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    fn format_uptime(&self) -> String {
        let secs = self.uptime_secs();
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;

        if days > 0 {
            format!("{}d {}h {}m", days, hours, mins)
        } else if hours > 0 {
            format!("{}h {}m", hours, mins)
        } else {
            format!("{}m", mins)
        }
    }
}

/// Generate the status page HTML
fn generate_status_html(stats: &DaemonStats) -> String {
    // Get VM list
    let vms = vm::list_vms().unwrap_or_default();
    let running_count = vms.iter().filter(|v| v.state == VmState::Running).count();
    let stopped_count = vms.len() - running_count;

    // Build VM table rows
    let vm_rows: String = if vms.is_empty() {
        "<tr><td colspan=\"4\" style=\"text-align:center;color:#666;\">No VMs yet</td></tr>".to_string()
    } else {
        vms.iter()
            .map(|v| {
                let state_color = if v.state == VmState::Running { "#2d5" } else { "#888" };
                let state_text = if v.state == VmState::Running { "running" } else { "stopped" };
                let domain = v.expose.as_ref().map(|e| e.domain.as_str()).unwrap_or("-");
                format!(
                    "<tr><td>{}</td><td style=\"color:{}\">{}</td><td>{}</td><td>{}MB</td></tr>",
                    v.name, state_color, state_text, domain, v.disk_used_mb()
                )
            })
            .collect()
    };

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>fcm</title>
    <style>
        body {{
            font-family: Georgia, serif;
            max-width: 650px;
            margin: 40px auto;
            padding: 0 20px;
            line-height: 1.6;
            color: #333;
            background: #fff;
        }}
        h1 {{
            font-size: 1.5em;
            border-bottom: 1px solid #ccc;
            padding-bottom: 10px;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            font-size: 0.9em;
        }}
        pre {{
            background: #f4f4f4;
            padding: 15px;
            overflow-x: auto;
            font-size: 0.85em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            font-size: 0.9em;
        }}
        th, td {{
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f9f9f9;
        }}
        .stats {{
            background: #f9f9f9;
            padding: 15px;
            margin: 20px 0;
        }}
        .stats span {{
            margin-right: 30px;
        }}
        a {{
            color: #06c;
        }}
    </style>
</head>
<body>
    <h1>fcm</h1>

    <p>
        fcm is a Firecracker VM manager that gives you Heroku-style deploys on bare metal.
        Create a VM, push your code with git, and it's live with SSL in seconds.
        Each VM gets 1 vCPU, 1GB RAM, and runs your app via Procfile.
    </p>

    <h2>Deploy</h2>
    <pre>$ fcm create
$ git init && echo "web: python3 -m http.server 8000" > Procfile
$ git add . && git commit -m "init"
$ git remote add origin root@{}:vm-name.git
$ git push origin main</pre>

    <h2>Status</h2>
    <div class="stats">
        <span><b>Uptime:</b> {}</span>
        <span><b>VMs:</b> {} running, {} stopped</span>
    </div>

    <table>
        <tr><th>Name</th><th>State</th><th>Domain</th><th>Disk</th></tr>
        {}
    </table>

    <p style="margin-top:40px;font-size:0.85em;color:#666;">
        <a href="https://github.com/anthropics/claude-code">Source</a>
    </p>
</body>
</html>"##,
        stats.server_ip,
        stats.format_uptime(),
        running_count,
        stopped_count,
        vm_rows
    )
}

/// Terminal connect request from client
#[derive(Debug, Deserialize)]
struct TerminalConnectRequest {
    vm: String,
    session: String,
    token: String,
    /// Terminal width (optional for backwards compat)
    #[serde(default = "default_cols")]
    cols: u16,
    /// Terminal height (optional for backwards compat)
    #[serde(default = "default_rows")]
    rows: u16,
}

fn default_cols() -> u16 { 80 }
fn default_rows() -> u16 { 24 }

/// Terminal connect response to client
#[derive(Debug, Serialize)]
struct TerminalConnectResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Response for VM operations
#[derive(Debug, Serialize)]
pub struct VmResponse {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub state: String,
    pub vcpu_count: u8,
    pub mem_size_mib: u32,
    pub disk_used_mb: u64,
    pub disk_max_mb: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expose: Option<ExposeResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExposeResponse {
    pub port: u16,
    pub domain: String,
}

impl From<&VmConfig> for VmResponse {
    fn from(config: &VmConfig) -> Self {
        // Get git URL if repo exists
        let git_url = if crate::git::repo_exists(&config.name) {
            // Try to get server IP for git URL
            crate::caddy::get_server_ip()
                .ok()
                .map(|ip| crate::git::get_clone_url(&config.name, &ip))
        } else {
            None
        };

        VmResponse {
            id: config.id.clone(),
            name: config.name.clone(),
            ip: config.ip.clone(),
            state: match config.state {
                VmState::Running => "running".to_string(),
                VmState::Stopped => "stopped".to_string(),
            },
            vcpu_count: config.vcpu_count,
            mem_size_mib: config.mem_size_mib,
            disk_used_mb: config.disk_used_mb(),
            disk_max_mb: config.disk_max_mb(),
            expose: config.expose.as_ref().map(|e| ExposeResponse {
                port: e.port,
                domain: e.domain.clone(),
            }),
            git_url,
        }
    }
}

/// Session response (for API responses)
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub vm_id: String,
    pub tmux_session: String,
    pub created_at: u64,
    pub is_default: bool,
}

impl From<&SessionInfo> for SessionResponse {
    fn from(info: &SessionInfo) -> Self {
        SessionResponse {
            id: info.id.clone(),
            vm_id: info.vm_id.clone(),
            tmux_session: info.tmux_session.clone(),
            created_at: info.created_at,
            is_default: info.is_default,
        }
    }
}

/// Request to create a session
#[derive(Debug, Deserialize, Default)]
struct CreateSessionRequest {
    /// If true, create or return the default session
    #[serde(default)]
    is_default: bool,
}

/// Error response
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

/// Get the token file path
fn token_path() -> PathBuf {
    PathBuf::from(BASE_DIR).join(".token")
}

/// Generate a random 32-character token
fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            if idx < 10 {
                (b'0' + idx) as char
            } else if idx < 36 {
                (b'a' + idx - 10) as char
            } else {
                (b'A' + idx - 36) as char
            }
        })
        .collect()
}

/// Load or create the auth token
fn load_or_create_token() -> Result<String, Box<dyn Error>> {
    let path = token_path();

    // Ensure base directory exists
    let base_dir = PathBuf::from(BASE_DIR);
    if !base_dir.exists() {
        fs::create_dir_all(&base_dir)?;
    }

    if path.exists() {
        Ok(fs::read_to_string(&path)?.trim().to_string())
    } else {
        let token = generate_token();
        fs::write(&path, &token)?;
        // Set restrictive permissions (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        println!("Generated new auth token: {}", token);
        println!("Copy this token to ~/.fcm-token or set FCM_TOKEN env var");
        Ok(token)
    }
}

/// Validate the Authorization header
fn validate_auth(request: &Request, token: &str) -> bool {
    for header in request.headers() {
        let field_str: &str = header.field.as_str().into();
        if field_str.eq_ignore_ascii_case("authorization") {
            let value: &str = header.value.as_str();
            if let Some(bearer_token) = value.strip_prefix("Bearer ") {
                return bearer_token.trim() == token;
            }
        }
    }
    false
}

/// Send a JSON response
fn send_json_response<T: Serialize>(
    request: Request,
    status_code: u16,
    body: &T,
) -> Result<(), Box<dyn Error>> {
    let json = serde_json::to_string(body)?;
    let response = Response::from_string(json)
        .with_status_code(status_code)
        .with_header(
            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
    request.respond(response)?;
    Ok(())
}

/// Send an error response
fn send_error(request: Request, status_code: u16, message: &str) -> Result<(), Box<dyn Error>> {
    send_json_response(request, status_code, &ErrorResponse { error: message.to_string() })
}

/// Handle POST /vms - create a new VM
fn handle_create_vm(mut request: Request) -> Result<(), Box<dyn Error>> {
    // Parse request body for SSH public key
    let create_request: CreateVmRequest = {
        let mut body = String::new();
        request.as_reader().read_to_string(&mut body)?;
        if body.is_empty() {
            CreateVmRequest::default()
        } else {
            serde_json::from_str(&body).unwrap_or_default()
        }
    };

    // Add SSH key to host's authorized_keys for git push access
    if let Some(ref key) = create_request.ssh_public_key {
        if let Err(e) = crate::git::add_ssh_key_to_host(key) {
            eprintln!("Warning: Failed to add SSH key to host: {}", e);
        }
    }

    // Always use random name and expose port 8000 by default
    match vm::create_vm(None, Some(DEFAULT_EXPOSE_PORT), create_request.ssh_public_key) {
        Ok(config) => {
            let response = VmResponse::from(&config);
            send_json_response(request, 201, &response)
        }
        Err(e) => {
            let status = match &e {
                VmError::ResourceNotAvailable(_) => 503,
                VmError::Network(_) => 500,
                VmError::Firecracker(_) => 500,
                VmError::Process(_) => 500,
                _ => 500,
            };
            send_error(request, status, &e.to_string())
        }
    }
}

/// Handle GET /vms - list all VMs
fn handle_list_vms(request: Request) -> Result<(), Box<dyn Error>> {
    let vms = vm::list_vms()?;
    let response: Vec<VmResponse> = vms.iter().map(VmResponse::from).collect();
    send_json_response(request, 200, &response)
}

/// Handle GET /vms/{id} - get VM details
fn handle_get_vm(request: Request, vm_id: &str) -> Result<(), Box<dyn Error>> {
    match vm::find_vm(vm_id) {
        Ok(config) => {
            let response = VmResponse::from(&config);
            send_json_response(request, 200, &response)
        }
        Err(_) => send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    }
}

/// Handle POST /vms/{id}/stop - stop a VM
fn handle_stop_vm(
    request: Request,
    vm_id: &str,
    session_manager: &SessionManager,
) -> Result<(), Box<dyn Error>> {
    // Get the VM ID before stopping (for session cleanup)
    let vm_config = vm::find_vm(vm_id).ok();

    match vm::stop_vm(vm_id) {
        Ok(config) => {
            // Clean up sessions for this VM
            if let Some(ref vc) = vm_config {
                session_manager.remove_vm_sessions(&vc.id);
            }
            let response = VmResponse::from(&config);
            send_json_response(request, 200, &response)
        }
        Err(e) => {
            let status = match &e {
                VmError::NotFound(_) => 404,
                VmError::InvalidState(_) => 400,
                _ => 500,
            };
            send_error(request, status, &e.to_string())
        }
    }
}

/// Handle POST /vms/{id}/start - start a stopped VM
fn handle_start_vm(request: Request, vm_id: &str) -> Result<(), Box<dyn Error>> {
    match vm::start_vm(vm_id) {
        Ok(config) => {
            let response = VmResponse::from(&config);
            send_json_response(request, 200, &response)
        }
        Err(e) => {
            let status = match &e {
                VmError::NotFound(_) => 404,
                VmError::InvalidState(_) => 400,
                VmError::ResourceNotAvailable(_) => 503,
                _ => 500,
            };
            send_error(request, status, &e.to_string())
        }
    }
}

/// Handle DELETE /vms/{id} - destroy a VM
fn handle_destroy_vm(
    request: Request,
    vm_id: &str,
    session_manager: &SessionManager,
) -> Result<(), Box<dyn Error>> {
    // Get the VM ID before destroying (for session cleanup)
    let vm_config = vm::find_vm(vm_id).ok();

    match vm::destroy_vm(vm_id) {
        Ok(()) => {
            // Clean up sessions for this VM
            if let Some(ref vc) = vm_config {
                session_manager.remove_vm_sessions(&vc.id);
            }
            send_json_response(request, 200, &serde_json::json!({"deleted": true}))
        }
        Err(e) => {
            let status = match &e {
                VmError::NotFound(_) => 404,
                _ => 500,
            };
            send_error(request, status, &e.to_string())
        }
    }
}

/// Handle POST /vms/{id}/sessions - create a new session
fn handle_create_session(
    mut request: Request,
    vm_id: &str,
    session_manager: &SessionManager,
) -> Result<(), Box<dyn Error>> {
    // Find VM and validate it's running
    let config = match vm::find_vm(vm_id) {
        Ok(config) => config,
        Err(_) => return send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    };

    if config.state != VmState::Running {
        return send_error(request, 400, &format!("VM '{}' is not running", vm_id));
    }

    // Parse request body for is_default flag
    let create_request: CreateSessionRequest = {
        let mut body = String::new();
        request.as_reader().read_to_string(&mut body)?;
        if body.is_empty() {
            CreateSessionRequest::default()
        } else {
            serde_json::from_str(&body).unwrap_or_default()
        }
    };

    // Create session
    match session_manager.create_session(&config.id, &config.ip, create_request.is_default) {
        Ok(session) => {
            let response = SessionResponse::from(&session);
            send_json_response(request, 201, &response)
        }
        Err(e) => {
            let status = match &e {
                SessionError::VmNotAvailable(_) => 503,
                SessionError::SshError(_) => 502,
                SessionError::TmuxError(_) => 500,
                _ => 500,
            };
            send_error(request, status, &e.to_string())
        }
    }
}

/// Route and handle a request
fn handle_request(
    request: Request,
    token: &str,
    session_manager: &SessionManager,
) -> Result<(), Box<dyn Error>> {
    let path = request.url().to_string();
    let method = request.method().clone();

    // Log request
    println!("{} {}", method, path);

    // Validate auth
    if !validate_auth(&request, token) {
        return send_error(request, 401, "Unauthorized");
    }

    // Route request
    match (method, path.as_str()) {
        // VM collection routes
        (Method::Post, "/vms") => handle_create_vm(request),
        (Method::Get, "/vms") => handle_list_vms(request),

        // VM instance routes
        (Method::Get, path) if path.starts_with("/vms/") => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            match parts.as_slice() {
                ["vms", vm_id] => handle_get_vm(request, vm_id),
                _ => send_error(request, 404, "Not found"),
            }
        }
        (Method::Post, path) if path.starts_with("/vms/") => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            match parts.as_slice() {
                ["vms", vm_id, "stop"] => handle_stop_vm(request, vm_id, session_manager),
                ["vms", vm_id, "start"] => handle_start_vm(request, vm_id),
                ["vms", vm_id, "sessions"] => {
                    handle_create_session(request, vm_id, session_manager)
                }
                _ => send_error(request, 404, "Not found"),
            }
        }
        (Method::Delete, path) if path.starts_with("/vms/") => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            match parts.as_slice() {
                ["vms", vm_id] => handle_destroy_vm(request, vm_id, session_manager),
                _ => send_error(request, 404, "Not found"),
            }
        }

        // Health check (no auth required - handled before auth check in production)
        (Method::Get, "/health") => {
            send_json_response(request, 200, &serde_json::json!({"status": "ok"}))
        }

        _ => send_error(request, 404, "Not found"),
    }
}

/// Handle a single terminal connection
fn handle_terminal_connection(
    mut stream: TcpStream,
    token: &str,
    session_manager: &SessionManager,
) {
    // Set a read timeout for the initial handshake
    if stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .is_err()
    {
        return;
    }

    // Read the JSON connect request (terminated by newline)
    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => {
            let _ = send_terminal_error(&mut stream, "Failed to clone stream");
            return;
        }
    };
    let mut reader = BufReader::new(read_stream);
    let mut request_line = String::new();

    if reader.read_line(&mut request_line).is_err() {
        let _ = send_terminal_error(&mut stream, "Failed to read request");
        return;
    }

    // Parse the connect request
    let request: TerminalConnectRequest = match serde_json::from_str(&request_line) {
        Ok(req) => req,
        Err(e) => {
            let _ = send_terminal_error(&mut stream, &format!("Invalid request: {}", e));
            return;
        }
    };

    println!("Terminal connection: vm={}, session={}", request.vm, request.session);

    // Validate token
    if request.token != token {
        let _ = send_terminal_error(&mut stream, "Invalid token");
        return;
    }

    // Find VM
    let config = match vm::find_vm(&request.vm) {
        Ok(config) => config,
        Err(_) => {
            let _ = send_terminal_error(&mut stream, &format!("VM '{}' not found", request.vm));
            return;
        }
    };

    // Check VM is running
    if config.state != VmState::Running {
        let _ = send_terminal_error(&mut stream, &format!("VM '{}' is not running", request.vm));
        return;
    }

    // Get or create the session - this ensures session persists across disconnects
    // If the session doesn't exist in memory or on the VM, it will be auto-created
    let session = match session_manager.get_or_create_console(&config.id, &config.ip) {
        Ok(session) => session,
        Err(e) => {
            let _ = send_terminal_error(
                &mut stream,
                &format!("Failed to get/create session: {}", e),
            );
            return;
        }
    };

    // Spawn SSH process attached to tmux session with correct terminal size
    let mut child = match attach_to_session(&config.ip, &session.tmux_session, request.cols, request.rows) {
        Ok(child) => child,
        Err(e) => {
            let _ = send_terminal_error(&mut stream, &format!("Failed to attach to session: {}", e));
            return;
        }
    };

    // Send success response
    let response = TerminalConnectResponse {
        success: true,
        error: None,
    };
    if let Err(e) = send_terminal_response(&mut stream, &response) {
        eprintln!("Failed to send success response: {}", e);
        let _ = child.kill();
        return;
    }

    // Clear read timeout for I/O proxying
    let _ = stream.set_read_timeout(None);

    // Get child stdin/stdout
    let child_stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            eprintln!("Failed to get child stdin");
            let _ = child.kill();
            return;
        }
    };
    let child_stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            eprintln!("Failed to get child stdout");
            let _ = child.kill();
            return;
        }
    };

    // Proxy I/O between client and SSH process
    proxy_terminal_io(stream, child_stdin, child_stdout);

    // Wait for child to exit
    let _ = child.wait();
}

/// Send an error response to the terminal client
fn send_terminal_error(stream: &mut TcpStream, message: &str) -> std::io::Result<()> {
    let response = TerminalConnectResponse {
        success: false,
        error: Some(message.to_string()),
    };
    send_terminal_response(stream, &response)
}

/// Send a JSON response to the terminal client
fn send_terminal_response(stream: &mut TcpStream, response: &TerminalConnectResponse) -> std::io::Result<()> {
    let json = serde_json::to_string(response).unwrap();
    stream.write_all(json.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

/// Proxy I/O between TCP stream and child process stdin/stdout
fn proxy_terminal_io(
    stream: TcpStream,
    mut child_stdin: std::process::ChildStdin,
    mut child_stdout: std::process::ChildStdout,
) {
    // Clone stream for reader thread
    let mut read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut write_stream = stream;

    // Spawn thread to read from child stdout and write to client
    let stdout_handle = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match child_stdout.read(&mut buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if write_stream.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    if write_stream.flush().is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Main thread reads from client and writes to child stdin
    let mut buf = [0u8; 4096];
    loop {
        match read_stream.read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                if child_stdin.write_all(&buf[..n]).is_err() {
                    break;
                }
                if child_stdin.flush().is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Close stdin to signal EOF to child
    drop(child_stdin);

    // Wait for stdout thread to finish
    let _ = stdout_handle.join();
}

/// Run the status page server (port 7780)
fn run_status_server(stats: Arc<DaemonStats>) {
    let bind_addr = format!("0.0.0.0:{}", STATUS_PAGE_PORT);
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind status server to {}: {}", bind_addr, e);
            return;
        }
    };

    println!("Status page server listening on {}", bind_addr);

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let stats = Arc::clone(&stats);
            thread::spawn(move || {
                // Read HTTP request (we don't parse it, just serve the page)
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);

                // Generate and send response
                let html = generate_status_html(&stats);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    html.len(),
                    html
                );
                let _ = stream.write_all(response.as_bytes());
            });
        }
    }
}

/// Run the terminal server (port 7778)
fn run_terminal_server(token: String, session_manager: SessionManager) {
    let listener = match TcpListener::bind(TERMINAL_BIND_ADDR) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind terminal server to {}: {}", TERMINAL_BIND_ADDR, e);
            return;
        }
    };

    println!("Terminal server listening on {}", TERMINAL_BIND_ADDR);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let token = token.clone();
                let session_manager = session_manager.clone();

                // Handle each connection in a new thread
                thread::spawn(move || {
                    handle_terminal_connection(stream, &token, &session_manager);
                });
            }
            Err(e) => {
                eprintln!("Terminal server accept error: {}", e);
            }
        }
    }
}

/// Run the daemon HTTP server
pub fn run() -> Result<(), Box<dyn Error>> {
    // Check if running as root (required for firecracker)
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Warning: daemon should be run as root for firecracker operations");
        }
    }

    // Setup network bridge and masquerading
    println!("Setting up network...");
    if let Err(e) = network::setup_network() {
        eprintln!("Warning: Failed to setup network: {}", e);
        eprintln!("VM networking may not work correctly");
    }

    // Get server IP for status page domain
    let server_ip = caddy::get_server_ip().unwrap_or_else(|_| "127.0.0.1".to_string());

    // Create daemon stats for status page
    let stats = Arc::new(DaemonStats::new(server_ip.clone()));

    // Setup status page domain in Caddy (fcm.{ip}.sslip.io -> localhost:7780)
    let status_domain = caddy::generate_domain("fcm", &server_ip);
    println!("Setting up status page at https://{}", status_domain);
    if let Err(e) = caddy::add_site(&status_domain, "127.0.0.1", STATUS_PAGE_PORT) {
        eprintln!("Warning: Failed to add status page to Caddy: {}", e);
    } else if let Err(e) = caddy::reload() {
        eprintln!("Warning: Failed to reload Caddy: {}", e);
    }

    // Load or create auth token
    let token = load_or_create_token()?;

    // Create session manager for persistent console sessions
    let session_manager = SessionManager::new();

    // Start status page server in a separate thread
    {
        let stats_clone = Arc::clone(&stats);
        thread::spawn(move || {
            run_status_server(stats_clone);
        });
    }

    // Start terminal server in a separate thread
    {
        let terminal_token = token.clone();
        let terminal_session_manager = session_manager.clone();
        thread::spawn(move || {
            run_terminal_server(terminal_token, terminal_session_manager);
        });
    }

    // Create HTTP server
    let server = Server::http(BIND_ADDR).map_err(|e| format!("Failed to bind to {}: {}", BIND_ADDR, e))?;
    println!("Daemon listening on http://{}", BIND_ADDR);

    // Handle requests
    for request in server.incoming_requests() {
        if let Err(e) = handle_request(request, &token, &session_manager) {
            eprintln!("Error handling request: {}", e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_token_length() {
        let token = generate_token();
        assert_eq!(token.len(), 32);
    }

    #[test]
    fn test_generate_token_alphanumeric() {
        let token = generate_token();
        assert!(token.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_token_unique() {
        let token1 = generate_token();
        let token2 = generate_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_session_response_from_info() {
        let info = SessionInfo {
            id: "abc123".to_string(),
            vm_id: "vm456".to_string(),
            tmux_session: "fcm-abc123".to_string(),
            created_at: 1700000000,
            is_default: true,
        };
        let response = SessionResponse::from(&info);
        assert_eq!(response.id, "abc123");
        assert_eq!(response.vm_id, "vm456");
        assert_eq!(response.tmux_session, "fcm-abc123");
        assert_eq!(response.created_at, 1700000000);
        assert!(response.is_default);
    }

    #[test]
    fn test_create_session_request_default() {
        let request: CreateSessionRequest = serde_json::from_str("{}").unwrap();
        assert!(!request.is_default);

        let request: CreateSessionRequest = serde_json::from_str(r#"{"is_default": true}"#).unwrap();
        assert!(request.is_default);
    }

    #[test]
    fn test_vm_response_from_config() {
        let config = VmConfig {
            id: "test123".to_string(),
            name: "test-vm".to_string(),
            ip: "172.16.0.50".to_string(),
            state: VmState::Running,
            vcpu_count: 1,
            mem_size_mib: 512,
            expose: None,
        };
        let response = VmResponse::from(&config);
        assert_eq!(response.id, "test123");
        assert_eq!(response.name, "test-vm");
        assert_eq!(response.state, "running");
        assert_eq!(response.vcpu_count, 1);
        assert_eq!(response.mem_size_mib, 512);
    }

    #[test]
    fn test_default_expose_port() {
        assert_eq!(DEFAULT_EXPOSE_PORT, 8000);
    }

    #[test]
    fn test_terminal_connect_request_deserialization() {
        let json = r#"{"vm": "test-vm", "session": "abc123", "token": "secret"}"#;
        let request: TerminalConnectRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.vm, "test-vm");
        assert_eq!(request.session, "abc123");
        assert_eq!(request.token, "secret");
    }

    #[test]
    fn test_terminal_connect_response_success() {
        let response = TerminalConnectResponse {
            success: true,
            error: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains(r#""success":true"#));
        assert!(!json.contains("error"));
    }

    #[test]
    fn test_terminal_connect_response_error() {
        let response = TerminalConnectResponse {
            success: false,
            error: Some("Session not found".to_string()),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains(r#""success":false"#));
        assert!(json.contains("Session not found"));
    }

    #[test]
    fn test_terminal_bind_addr() {
        assert_eq!(TERMINAL_BIND_ADDR, "0.0.0.0:7778");
    }
}
