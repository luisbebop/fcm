// HTTP client module for communicating with the daemon

use serde::Deserialize;
use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const DAEMON_URL: &str = "http://127.0.0.1:7777";


/// Response for VM operations
#[derive(Debug, Deserialize)]
struct VmResponse {
    id: String,
    name: String,
    ip: String,
    state: String,
    expose: Option<ExposeResponse>,
}

#[derive(Debug, Deserialize)]
struct ExposeResponse {
    port: u16,
    domain: String,
}

/// SSH info response
#[derive(Debug, Deserialize)]
struct SshInfoResponse {
    ip: String,
    user: String,
    port: u16,
}

/// Error response from daemon
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

/// Get the client token file path (~/.fcm-token)
fn token_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".fcm-token")
}

/// Load auth token from environment or file
fn load_token() -> Result<String, Box<dyn Error>> {
    // First try FCM_TOKEN env var
    if let Ok(token) = env::var("FCM_TOKEN") {
        if !token.is_empty() {
            return Ok(token);
        }
    }

    // Then try ~/.fcm-token file
    let path = token_path();
    if path.exists() {
        let token = fs::read_to_string(&path)?.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }

    Err("No auth token found. Set FCM_TOKEN env var or create ~/.fcm-token".into())
}

/// Make an authenticated request to the daemon
fn make_request(
    method: &str,
    path: &str,
    body: Option<String>,
) -> Result<ureq::Response, Box<dyn Error>> {
    let token = load_token()?;
    let url = format!("{}{}", DAEMON_URL, path);

    let request = match method {
        "GET" => ureq::get(&url),
        "POST" => ureq::post(&url),
        "DELETE" => ureq::delete(&url),
        _ => return Err(format!("Unsupported method: {}", method).into()),
    }
    .set("Authorization", &format!("Bearer {}", token))
    .set("Content-Type", "application/json");

    let response = if let Some(body) = body {
        request.send_string(&body)
    } else {
        request.call()
    };

    match response {
        Ok(resp) => Ok(resp),
        Err(ureq::Error::Status(code, resp)) => {
            // Try to parse error message from response
            let error_msg = if let Ok(err) = resp.into_json::<ErrorResponse>() {
                err.error
            } else {
                format!("HTTP error {}", code)
            };
            Err(error_msg.into())
        }
        Err(ureq::Error::Transport(e)) => {
            if e.kind() == ureq::ErrorKind::ConnectionFailed {
                Err("Cannot connect to daemon. Is 'fcm daemon' running?".into())
            } else {
                Err(format!("Connection error: {}", e).into())
            }
        }
    }
}

/// Create a new VM
pub fn create_vm() -> Result<(), Box<dyn Error>> {
    let response = make_request("POST", "/vms", None)?;
    let vm: VmResponse = response.into_json()?;

    println!("Created VM:");
    print_vm(&vm);

    Ok(())
}

/// List all VMs
pub fn list_vms() -> Result<(), Box<dyn Error>> {
    let response = make_request("GET", "/vms", None)?;
    let vms: Vec<VmResponse> = response.into_json()?;

    if vms.is_empty() {
        println!("No VMs found");
        return Ok(());
    }

    // Print header
    println!(
        "{:<12} {:<20} {:<16} {:<10} {}",
        "ID", "NAME", "IP", "STATE", "DOMAIN"
    );
    println!("{}", "-".repeat(80));

    // Print each VM
    for vm in vms {
        let domain = vm
            .expose
            .as_ref()
            .map(|e| e.domain.as_str())
            .unwrap_or("-");
        println!(
            "{:<12} {:<20} {:<16} {:<10} {}",
            vm.id, vm.name, vm.ip, vm.state, domain
        );
    }

    Ok(())
}

/// SSH into a VM
pub fn ssh_vm(vm: &str) -> Result<(), Box<dyn Error>> {
    let response = make_request("GET", &format!("/vms/{}/ssh", vm), None)?;
    let ssh_info: SshInfoResponse = response.into_json()?;

    println!("Connecting to {}@{}...", ssh_info.user, ssh_info.ip);

    // Execute ssh command
    let status = Command::new("ssh")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-p")
        .arg(ssh_info.port.to_string())
        .arg(format!("{}@{}", ssh_info.user, ssh_info.ip))
        .status()?;

    if !status.success() {
        return Err("SSH connection failed".into());
    }

    Ok(())
}

/// Stop a running VM
pub fn stop_vm(vm: &str) -> Result<(), Box<dyn Error>> {
    let response = make_request("POST", &format!("/vms/{}/stop", vm), None)?;
    let vm_resp: VmResponse = response.into_json()?;

    println!("Stopped VM:");
    print_vm(&vm_resp);

    Ok(())
}

/// Start a stopped VM
pub fn start_vm(vm: &str) -> Result<(), Box<dyn Error>> {
    let response = make_request("POST", &format!("/vms/{}/start", vm), None)?;
    let vm_resp: VmResponse = response.into_json()?;

    println!("Started VM:");
    print_vm(&vm_resp);

    Ok(())
}

/// Destroy a VM
pub fn destroy_vm(vm: &str) -> Result<(), Box<dyn Error>> {
    make_request("DELETE", &format!("/vms/{}", vm), None)?;
    println!("Destroyed VM '{}'", vm);
    Ok(())
}

/// Print VM details
fn print_vm(vm: &VmResponse) {
    println!("  ID:    {}", vm.id);
    println!("  Name:  {}", vm.name);
    println!("  IP:    {}", vm.ip);
    println!("  State: {}", vm.state);
    if let Some(expose) = &vm.expose {
        println!("  Port:  {}", expose.port);
        println!("  URL:   https://{}", expose.domain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_path() {
        let path = token_path();
        assert!(path.ends_with(".fcm-token"));
    }

    #[test]
    fn test_vm_response_deserialization() {
        let json = r#"{
            "id": "abc123",
            "name": "test-vm",
            "ip": "172.16.0.50",
            "state": "running",
            "expose": null
        }"#;
        let vm: VmResponse = serde_json::from_str(json).unwrap();
        assert_eq!(vm.id, "abc123");
        assert_eq!(vm.name, "test-vm");
        assert_eq!(vm.ip, "172.16.0.50");
        assert_eq!(vm.state, "running");
        assert!(vm.expose.is_none());
    }

    #[test]
    fn test_vm_response_with_expose_deserialization() {
        let json = r#"{
            "id": "abc123",
            "name": "test-vm",
            "ip": "172.16.0.50",
            "state": "running",
            "expose": {
                "port": 8000,
                "domain": "test-vm.64-34-93-45.sslip.io"
            }
        }"#;
        let vm: VmResponse = serde_json::from_str(json).unwrap();
        assert!(vm.expose.is_some());
        let expose = vm.expose.unwrap();
        assert_eq!(expose.port, 8000);
        assert_eq!(expose.domain, "test-vm.64-34-93-45.sslip.io");
    }

    #[test]
    fn test_ssh_info_deserialization() {
        let json = r#"{
            "ip": "172.16.0.50",
            "user": "root",
            "port": 22
        }"#;
        let info: SshInfoResponse = serde_json::from_str(json).unwrap();
        assert_eq!(info.ip, "172.16.0.50");
        assert_eq!(info.user, "root");
        assert_eq!(info.port, 22);
    }

    #[test]
    fn test_error_response_deserialization() {
        let json = r#"{"error": "VM not found"}"#;
        let err: ErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(err.error, "VM not found");
    }

    #[test]
    fn test_load_token_from_env() {
        // Set the env var
        env::set_var("FCM_TOKEN", "test_token_12345");
        let token = load_token().unwrap();
        assert_eq!(token, "test_token_12345");
        // Clean up
        env::remove_var("FCM_TOKEN");
    }
}
