// HTTP client module for communicating with the daemon

use crate::console;
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

const DEFAULT_DAEMON_URL: &str = "http://127.0.0.1:7777";

/// Get the daemon URL from FCM_HOST env var or use default
fn daemon_url() -> String {
    if let Ok(host) = env::var("FCM_HOST") {
        if host.starts_with("http://") || host.starts_with("https://") {
            host
        } else {
            format!("http://{}", host)
        }
    } else {
        DEFAULT_DAEMON_URL.to_string()
    }
}

/// Request to create a VM with SSH public key
#[derive(Debug, Serialize)]
struct CreateVmRequest {
    ssh_public_key: Option<String>,
}


/// Response for VM operations
#[derive(Debug, Deserialize)]
struct VmResponse {
    #[allow(dead_code)]
    id: String,
    name: String,
    #[allow(dead_code)]
    ip: String,
    state: String,
    vcpu_count: u8,
    mem_size_mib: u32,
    expose: Option<ExposeResponse>,
    git_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExposeResponse {
    #[allow(dead_code)]
    port: u16,
    domain: String,
}

/// Error response from daemon
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

/// Session info response
#[derive(Debug, Deserialize)]
struct SessionResponse {
    id: String,
    #[allow(dead_code)]
    vm_id: String,
    #[allow(dead_code)]
    tmux_session: String,
    #[allow(dead_code)]
    created_at: u64,
    #[allow(dead_code)]
    is_default: bool,
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
    let url = format!("{}{}", daemon_url(), path);

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

/// Find and read the user's SSH public key
fn find_ssh_public_key() -> Option<String> {
    let home = dirs::home_dir()?;
    let ssh_dir = home.join(".ssh");

    // Try common public key files in order of preference
    let key_files = ["id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"];

    for key_file in &key_files {
        let path = ssh_dir.join(key_file);
        if path.exists() {
            if let Ok(key) = fs::read_to_string(&path) {
                let key = key.trim().to_string();
                if !key.is_empty() {
                    return Some(key);
                }
            }
        }
    }

    None
}

/// ANSI color codes
const WHITE: &str = "\x1b[97m";
const GRAY: &str = "\x1b[90m";
const BLUE: &str = "\x1b[94m";
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

/// Zen koans for the create output
const KOANS: &[&str] = &[
    "The code that is not written has no bugs.",
    "First, solve the problem. Then, write the code.",
    "Simplicity is the ultimate sophistication.",
    "Before enlightenment: write code. After enlightenment: write code.",
    "The best code is no code at all.",
    "A journey of a thousand deploys begins with git push.",
    "In the beginner's mind there are many possibilities.",
    "Move fast and fix things.",
    "Make it work, make it right, make it fast.",
    "Code is like humor. When you have to explain it, it's bad.",
    "The obstacle is the path.",
    "What is the sound of one container crashing?",
];

/// Get a random koan
fn random_koan() -> &'static str {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as usize;
    KOANS[seed % KOANS.len()]
}

/// Print the logo ASCII art
fn print_logo() {
    println!(
        r#"
{d}            ░░▒▒▓▓{w}██{d}▓▓▒▒░░{reset}
{d}         ░▒▓{w}██▀▀      ▀▀██{d}▓▒░{reset}
{d}       ░▓{w}█▀                ▀█{d}▓░{reset}
{d}      ▒{w}█▀                    ▀█{d}▒{reset}
{d}     ▒{w}█▌                      ▐█{d}▒{reset}
{d}     ▓{w}█                        █{d}▓{reset}
{d}     ▓{w}█                        █{d}▓{reset}
{d}     ▒{w}█▌                      ▐█{d}▒{reset}
{d}      ▒{w}█▄                    ▄█{d}▒{reset}
{d}       ░▓{w}█▄                ▄█{d}▓░{reset}
{d}         ░▒▓{w}██▄▄      ▄▄██{d}▓▒░{reset}
{d}            ░░▒▒▓▓{w}██{d}▓▓▒▒░░{reset}
"#,
        d = GRAY,
        w = WHITE,
        reset = RESET
    );
}

/// Create a new VM
pub fn create_vm() -> Result<(), Box<dyn Error>> {
    let ssh_public_key = find_ssh_public_key();
    if ssh_public_key.is_none() {
        eprintln!("Warning: No SSH public key found in ~/.ssh/, password auth will be required");
    }

    let request = CreateVmRequest { ssh_public_key };
    let body = serde_json::to_string(&request)?;

    let response = make_request("POST", "/vms", Some(body))?;
    let vm: VmResponse = response.into_json()?;

    // Print logo ASCII art
    print_logo();

    // Print VM info
    println!(
        "{bold}{w}  VM created: {b}{}{reset}",
        vm.name,
        bold = BOLD,
        w = WHITE,
        b = BLUE,
        reset = RESET
    );
    println!();

    if let Some(expose) = &vm.expose {
        println!(
            "{d}  URL:{reset}  {b}https://{}{reset}",
            expose.domain,
            d = GRAY,
            b = BLUE,
            reset = RESET
        );
    }

    if let Some(git_url) = &vm.git_url {
        println!(
            "{d}  Git:{reset}  {b}{}{reset}",
            git_url,
            d = GRAY,
            b = BLUE,
            reset = RESET
        );
    }

    let koan = random_koan();
    println!();
    println!("{bold}{w}  Quick Start:{reset}", bold = BOLD, w = WHITE, reset = RESET);
    println!();
    println!("{d}  # Initialize and deploy{reset}", d = GRAY, reset = RESET);
    println!("  {w}git init{reset}", w = WHITE, reset = RESET);
    println!("  {w}echo '<h1>{}</h1>' > index.html{reset}", koan, w = WHITE, reset = RESET);
    println!("  {w}echo 'web: python3 -m http.server $PORT' > Procfile{reset}", w = WHITE, reset = RESET);
    if let Some(git_url) = &vm.git_url {
        println!("  {w}git remote add fcm {}{reset}", git_url, w = WHITE, reset = RESET);
    }
    println!("  {w}git add -A && git commit -m 'init' && git push fcm main{reset}", w = WHITE, reset = RESET);
    println!();

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
        "{:<20} {:<10} {:<6} {:<8} {:<40} GIT",
        "NAME", "STATE", "VCPU", "MEMORY", "DOMAIN"
    );
    println!("{}", "-".repeat(130));

    // Print each VM
    for vm in vms {
        let domain = vm
            .expose
            .as_ref()
            .map(|e| e.domain.as_str())
            .unwrap_or("-");
        let git_url = vm.git_url.as_deref().unwrap_or("-");
        let memory = format!("{}MB", vm.mem_size_mib);
        println!(
            "{:<20} {:<10} {:<6} {:<8} {:<40} {}",
            vm.name, vm.state, vm.vcpu_count, memory, domain, git_url
        );
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

/// Open a persistent console session on a VM
pub fn console_vm(vm: &str) -> Result<(), Box<dyn Error>> {
    // Get or create the console session via the HTTP API
    let body = r#"{"is_default": true}"#;
    let response = make_request("POST", &format!("/vms/{}/sessions", vm), Some(body.to_string()))?;
    let session: SessionResponse = response.into_json()?;

    // Connect to the session via the terminal streaming protocol
    // Session ID is hidden from user - they just see the VM name
    console::connect(vm, &session.id).map_err(|e| e.to_string())?;

    Ok(())
}

/// Print VM details
fn print_vm(vm: &VmResponse) {
    println!("  Name:   {}", vm.name);
    println!("  State:  {}", vm.state);
    println!("  vCPU:   {}", vm.vcpu_count);
    println!("  Memory: {}MB", vm.mem_size_mib);
    if let Some(expose) = &vm.expose {
        println!("  URL:    https://{}", expose.domain);
    }
    if let Some(git_url) = &vm.git_url {
        println!("  Git:    {}", git_url);
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
            "vcpu_count": 1,
            "mem_size_mib": 512,
            "expose": null,
            "git_url": null
        }"#;
        let vm: VmResponse = serde_json::from_str(json).unwrap();
        assert_eq!(vm.id, "abc123");
        assert_eq!(vm.name, "test-vm");
        assert_eq!(vm.ip, "172.16.0.50");
        assert_eq!(vm.state, "running");
        assert_eq!(vm.vcpu_count, 1);
        assert_eq!(vm.mem_size_mib, 512);
        assert!(vm.expose.is_none());
        assert!(vm.git_url.is_none());
    }

    #[test]
    fn test_vm_response_with_expose_deserialization() {
        let json = r#"{
            "id": "abc123",
            "name": "test-vm",
            "ip": "172.16.0.50",
            "state": "running",
            "vcpu_count": 2,
            "mem_size_mib": 1024,
            "expose": {
                "port": 8000,
                "domain": "test-vm.64-34-93-45.sslip.io"
            },
            "git_url": "root@myserver.com:test-vm.git"
        }"#;
        let vm: VmResponse = serde_json::from_str(json).unwrap();
        assert_eq!(vm.vcpu_count, 2);
        assert_eq!(vm.mem_size_mib, 1024);
        assert!(vm.expose.is_some());
        let expose = vm.expose.unwrap();
        assert_eq!(expose.port, 8000);
        assert_eq!(expose.domain, "test-vm.64-34-93-45.sslip.io");
        assert_eq!(vm.git_url, Some("root@myserver.com:test-vm.git".to_string()));
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

    #[test]
    fn test_create_vm_request_serialization() {
        let request = CreateVmRequest {
            ssh_public_key: Some("ssh-ed25519 AAAAC3NzaC1... user@host".to_string()),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("ssh_public_key"));
        assert!(json.contains("ssh-ed25519"));
    }

    #[test]
    fn test_create_vm_request_without_key() {
        let request = CreateVmRequest {
            ssh_public_key: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("null"));
    }

    #[test]
    fn test_daemon_url_default() {
        env::remove_var("FCM_HOST");
        assert_eq!(daemon_url(), "http://127.0.0.1:7777");
    }

    #[test]
    fn test_daemon_url_from_env() {
        env::set_var("FCM_HOST", "192.168.1.100:7777");
        assert_eq!(daemon_url(), "http://192.168.1.100:7777");
        env::remove_var("FCM_HOST");
    }

    #[test]
    fn test_daemon_url_with_scheme() {
        env::set_var("FCM_HOST", "https://myserver.example.com:7777");
        assert_eq!(daemon_url(), "https://myserver.example.com:7777");
        env::remove_var("FCM_HOST");
    }
}
