// Daemon HTTP server module

use crate::network;
use crate::session::{SessionError, SessionInfo, SessionManager};
use crate::vm::{self, VmConfig, VmError, VmState, BASE_DIR};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use tiny_http::{Header, Method, Request, Response, Server};

/// Request to create a VM
#[derive(Debug, Deserialize, Default)]
struct CreateVmRequest {
    ssh_public_key: Option<String>,
}

const BIND_ADDR: &str = "0.0.0.0:7777";

/// Default port to expose for all VMs
const DEFAULT_EXPOSE_PORT: u16 = 8000;

/// Response for VM operations
#[derive(Debug, Serialize)]
pub struct VmResponse {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expose: Option<ExposeResponse>,
}

#[derive(Debug, Serialize)]
pub struct ExposeResponse {
    pub port: u16,
    pub domain: String,
}

impl From<&VmConfig> for VmResponse {
    fn from(config: &VmConfig) -> Self {
        VmResponse {
            id: config.id.clone(),
            name: config.name.clone(),
            ip: config.ip.clone(),
            state: match config.state {
                VmState::Running => "running".to_string(),
                VmState::Stopped => "stopped".to_string(),
            },
            expose: config.expose.as_ref().map(|e| ExposeResponse {
                port: e.port,
                domain: e.domain.clone(),
            }),
        }
    }
}

/// SSH info response
#[derive(Debug, Serialize)]
pub struct SshInfoResponse {
    pub ip: String,
    pub user: String,
    pub port: u16,
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

/// Handle GET /vms/{id}/ssh - get SSH connection info
fn handle_ssh_info(request: Request, vm_id: &str) -> Result<(), Box<dyn Error>> {
    match vm::find_vm(vm_id) {
        Ok(config) => {
            let response = SshInfoResponse {
                ip: config.ip.clone(),
                user: "root".to_string(),
                port: 22,
            };
            send_json_response(request, 200, &response)
        }
        Err(_) => send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    }
}

/// Handle POST /vms/{id}/stop - stop a VM
fn handle_stop_vm(request: Request, vm_id: &str) -> Result<(), Box<dyn Error>> {
    match vm::stop_vm(vm_id) {
        Ok(config) => {
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
fn handle_destroy_vm(request: Request, vm_id: &str) -> Result<(), Box<dyn Error>> {
    match vm::destroy_vm(vm_id) {
        Ok(()) => {
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

/// Handle GET /vms/{id}/sessions - list active sessions for a VM
fn handle_list_sessions(
    request: Request,
    vm_id: &str,
    session_manager: &SessionManager,
) -> Result<(), Box<dyn Error>> {
    // Find VM to validate it exists
    let config = match vm::find_vm(vm_id) {
        Ok(config) => config,
        Err(_) => return send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    };

    // Sync sessions with actual tmux state if VM is running
    if config.state == VmState::Running {
        session_manager.sync_sessions(&config.id, &config.ip);
    }

    let sessions = session_manager.list_sessions(&config.id);
    let response: Vec<SessionResponse> = sessions.iter().map(SessionResponse::from).collect();
    send_json_response(request, 200, &response)
}

/// Handle DELETE /vms/{id}/sessions/{session-id} - kill a session
fn handle_kill_session(
    request: Request,
    vm_id: &str,
    session_id: &str,
    session_manager: &SessionManager,
) -> Result<(), Box<dyn Error>> {
    // Find VM to get IP
    let config = match vm::find_vm(vm_id) {
        Ok(config) => config,
        Err(_) => return send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    };

    // Kill session
    match session_manager.kill_session(session_id, &config.ip) {
        Ok(()) => send_json_response(request, 200, &serde_json::json!({"deleted": true})),
        Err(e) => {
            let status = match &e {
                SessionError::NotFound(_) => 404,
                SessionError::VmNotAvailable(_) => 503,
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
                ["vms", vm_id, "ssh"] => handle_ssh_info(request, vm_id),
                ["vms", vm_id, "sessions"] => {
                    handle_list_sessions(request, vm_id, session_manager)
                }
                _ => send_error(request, 404, "Not found"),
            }
        }
        (Method::Post, path) if path.starts_with("/vms/") => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            match parts.as_slice() {
                ["vms", vm_id, "stop"] => handle_stop_vm(request, vm_id),
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
                ["vms", vm_id] => handle_destroy_vm(request, vm_id),
                ["vms", vm_id, "sessions", session_id] => {
                    handle_kill_session(request, vm_id, session_id, session_manager)
                }
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

    // Load or create auth token
    let token = load_or_create_token()?;

    // Create session manager for persistent console sessions
    let session_manager = SessionManager::new();

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
            expose: None,
        };
        let response = VmResponse::from(&config);
        assert_eq!(response.id, "test123");
        assert_eq!(response.name, "test-vm");
        assert_eq!(response.state, "running");
    }

    #[test]
    fn test_default_expose_port() {
        assert_eq!(DEFAULT_EXPOSE_PORT, 8000);
    }
}
