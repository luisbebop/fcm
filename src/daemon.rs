// Daemon HTTP server module

use crate::vm::{self, VmConfig, VmState, BASE_DIR};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use tiny_http::{Header, Method, Request, Response, Server};

const BIND_ADDR: &str = "127.0.0.1:7777";

/// Request body for creating a VM
#[derive(Debug, Deserialize)]
pub struct CreateVmRequest {
    pub name: Option<String>,
    pub expose: Option<u16>,
}

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
            let value: &str = header.value.as_str().into();
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

/// Parse JSON body from request
fn parse_json_body<T: for<'de> Deserialize<'de>>(request: &mut Request) -> Result<T, String> {
    let mut body = String::new();
    request
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|e| format!("Failed to read body: {}", e))?;
    serde_json::from_str(&body).map_err(|e| format!("Invalid JSON: {}", e))
}

/// Extract VM identifier from path like /vms/{id}/action or /vms/{id}
fn extract_vm_id(path: &str) -> Option<&str> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() >= 2 && parts[0] == "vms" {
        Some(parts[1])
    } else {
        None
    }
}

/// Handle POST /vms - create a new VM
fn handle_create_vm(mut request: Request) -> Result<(), Box<dyn Error>> {
    let create_req: CreateVmRequest = match parse_json_body(&mut request) {
        Ok(req) => req,
        Err(e) => return send_error(request, 400, &e),
    };

    // For now, we'll use a placeholder IP - network module will allocate real IPs
    let ip = "172.16.0.50".to_string();

    let expose_config = create_req.expose.map(|port| vm::ExposeConfig {
        port,
        domain: format!(
            "{}.64-34-93-45.sslip.io",
            create_req.name.as_deref().unwrap_or("vm")
        ),
    });

    let config = VmConfig::new(create_req.name, ip, expose_config);

    // Create VM directory
    fs::create_dir_all(config.dir())?;

    // Save config
    config.save()?;

    // TODO: Actually create the VM (copy rootfs, setup network, start firecracker)
    // This will be implemented in the vm module

    let response = VmResponse::from(&config);
    send_json_response(request, 201, &response)
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
    match vm::find_vm(vm_id) {
        Ok(mut config) => {
            if config.state == VmState::Stopped {
                return send_error(request, 400, "VM is already stopped");
            }
            config.state = VmState::Stopped;
            config.save()?;
            // TODO: Actually stop the firecracker process
            let response = VmResponse::from(&config);
            send_json_response(request, 200, &response)
        }
        Err(_) => send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    }
}

/// Handle POST /vms/{id}/start - start a stopped VM
fn handle_start_vm(request: Request, vm_id: &str) -> Result<(), Box<dyn Error>> {
    match vm::find_vm(vm_id) {
        Ok(mut config) => {
            if config.state == VmState::Running {
                return send_error(request, 400, "VM is already running");
            }
            config.state = VmState::Running;
            config.save()?;
            // TODO: Actually start the firecracker process
            let response = VmResponse::from(&config);
            send_json_response(request, 200, &response)
        }
        Err(_) => send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    }
}

/// Handle DELETE /vms/{id} - destroy a VM
fn handle_destroy_vm(request: Request, vm_id: &str) -> Result<(), Box<dyn Error>> {
    match vm::find_vm(vm_id) {
        Ok(config) => {
            // TODO: Stop firecracker process if running
            // TODO: Remove tap device
            // TODO: Remove from caddy config

            // Remove VM directory
            fs::remove_dir_all(config.dir())?;

            send_json_response(request, 200, &serde_json::json!({"deleted": true}))
        }
        Err(_) => send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    }
}

/// Route and handle a request
fn handle_request(request: Request, token: &str) -> Result<(), Box<dyn Error>> {
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
                _ => send_error(request, 404, "Not found"),
            }
        }
        (Method::Post, path) if path.starts_with("/vms/") => {
            if let Some(vm_id) = extract_vm_id(path) {
                if path.ends_with("/stop") {
                    handle_stop_vm(request, vm_id)
                } else if path.ends_with("/start") {
                    handle_start_vm(request, vm_id)
                } else {
                    send_error(request, 404, "Not found")
                }
            } else {
                send_error(request, 404, "Not found")
            }
        }
        (Method::Delete, path) if path.starts_with("/vms/") => {
            if let Some(vm_id) = extract_vm_id(path) {
                // Make sure it's just /vms/{id} and not /vms/{id}/something
                let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                if parts.len() == 2 {
                    handle_destroy_vm(request, vm_id)
                } else {
                    send_error(request, 404, "Not found")
                }
            } else {
                send_error(request, 404, "Not found")
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

    // Load or create auth token
    let token = load_or_create_token()?;

    // Create HTTP server
    let server = Server::http(BIND_ADDR).map_err(|e| format!("Failed to bind to {}: {}", BIND_ADDR, e))?;
    println!("Daemon listening on http://{}", BIND_ADDR);

    // Handle requests
    for request in server.incoming_requests() {
        if let Err(e) = handle_request(request, &token) {
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
    fn test_extract_vm_id() {
        assert_eq!(extract_vm_id("/vms/abc123"), Some("abc123"));
        assert_eq!(extract_vm_id("/vms/abc123/stop"), Some("abc123"));
        assert_eq!(extract_vm_id("/vms/abc123/ssh"), Some("abc123"));
        assert_eq!(extract_vm_id("/vms"), None);
        assert_eq!(extract_vm_id("/other"), None);
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
    fn test_create_vm_request_deserialization() {
        let json = r#"{"name": "myvm", "expose": 8000}"#;
        let req: CreateVmRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, Some("myvm".to_string()));
        assert_eq!(req.expose, Some(8000));
    }

    #[test]
    fn test_create_vm_request_minimal() {
        let json = r#"{}"#;
        let req: CreateVmRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_none());
        assert!(req.expose.is_none());
    }
}
