// HTTP client module for communicating with the daemon

use crate::console;
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;

/// Default production URL (tryforge.sh domain)
const DEFAULT_DAEMON_URL: &str = "https://fcm.tryforge.sh";
/// Port for local CLI login callback server
const CLI_LOGIN_PORT: u16 = 9876;
const LOCAL_CONFIG_FILE: &str = ".fcm";

/// Local project config that links a directory to a VM
#[derive(Debug, Serialize, Deserialize)]
struct LocalConfig {
    name: String,
    url: Option<String>,
    git: Option<String>,
}

/// Get the daemon URL from FCM_HOST env var or use default (tryforge.sh)
///
/// FCM_HOST can be used to override for local development or custom servers.
/// Examples:
///   - Not set: uses https://fcm.tryforge.sh (default)
///   - FCM_HOST=127.0.0.1:7777: uses http://127.0.0.1:7777 (local dev)
///   - FCM_HOST=https://custom.example.com: uses as-is
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

/// Get the status page URL (used for sessions API)
/// Defaults to tryforge.sh, can be overridden with FCM_HOST for local dev
fn status_url() -> String {
    if let Ok(host) = env::var("FCM_HOST") {
        // Local development or custom server
        if host.contains("127.0.0.1") || host.contains("localhost") {
            "http://127.0.0.1:7780".to_string()
        } else if host.starts_with("http://") || host.starts_with("https://") {
            host
        } else {
            format!("https://{}", host)
        }
    } else {
        // Default to production
        "https://fcm.tryforge.sh".to_string()
    }
}

/// Get the path to the local config file (.fcm in current directory)
fn local_config_path() -> PathBuf {
    PathBuf::from(LOCAL_CONFIG_FILE)
}

/// Save local config to .fcm file in current directory
fn save_local_config(config: &LocalConfig) -> Result<(), Box<dyn Error>> {
    let path = local_config_path();
    let json = serde_json::to_string_pretty(config)?;
    fs::write(&path, json)?;
    Ok(())
}

/// Load local config from .fcm file in current directory
fn load_local_config() -> Result<LocalConfig, Box<dyn Error>> {
    let path = local_config_path();
    if !path.exists() {
        return Err("No .fcm file found in current directory".into());
    }
    let content = fs::read_to_string(&path)?;
    let config: LocalConfig = serde_json::from_str(&content)?;
    Ok(config)
}

/// Get VM name from argument or .fcm config file
pub fn resolve_vm_name(vm: Option<String>) -> Result<String, Box<dyn Error>> {
    match vm {
        Some(name) => Ok(name),
        None => {
            let config = load_local_config()?;
            Ok(config.name)
        }
    }
}

/// Show VM info from local .fcm config file
pub fn show_local_vm() -> Result<(), Box<dyn Error>> {
    let config = load_local_config()?;

    // Try to get live VM info from daemon
    let vm_info = match make_request("GET", &format!("/vms/{}", config.name), None) {
        Ok(response) => response.into_json::<VmResponse>().ok(),
        Err(_) => None,
    };

    println!();
    println!(
        "{bold}{w}  {}{reset}",
        config.name,
        bold = BOLD,
        w = WHITE,
        reset = RESET
    );
    println!();

    // Show state if we have live info
    if let Some(ref vm) = vm_info {
        let state_color = if vm.state == "running" { "\x1b[92m" } else { "\x1b[93m" };
        println!(
            "{d}  State:{reset} {}{}{reset}",
            state_color,
            vm.state,
            d = GRAY,
            reset = RESET
        );
    }

    if let Some(url) = &config.url {
        println!(
            "{d}  URL:{reset}   {b}{}{reset}",
            url,
            d = GRAY,
            b = BLUE,
            reset = RESET
        );
    }

    if let Some(git) = &config.git {
        println!(
            "{d}  Git:{reset}   {b}{}{reset}",
            git,
            d = GRAY,
            b = BLUE,
            reset = RESET
        );
    }

    // Show resources if we have live info
    if let Some(ref vm) = vm_info {
        println!(
            "{d}  vCPU:{reset}  {}",
            vm.vcpu_count,
            d = GRAY,
            reset = RESET
        );
        println!(
            "{d}  Mem:{reset}   {}MB",
            vm.mem_size_mib,
            d = GRAY,
            reset = RESET
        );
        println!(
            "{d}  Disk:{reset}  {}MB/{}MB",
            vm.disk_used_mb, vm.disk_max_mb,
            d = GRAY,
            reset = RESET
        );
    }

    println!();
    println!("{d}  Commands:{reset}", d = GRAY, reset = RESET);
    println!("    {w}fcm console {}{reset}  {d}# open terminal{reset}", config.name, w = WHITE, d = GRAY, reset = RESET);
    println!("    {w}git push{reset}             {d}# deploy{reset}", w = WHITE, d = GRAY, reset = RESET);

    let koan = random_koan();
    println!();
    println!("{bold}{w}  Quick Start:{reset}", bold = BOLD, w = WHITE, reset = RESET);
    println!();
    println!("{d}  # Initialize and deploy{reset}", d = GRAY, reset = RESET);
    println!("  {w}git init{reset}", w = WHITE, reset = RESET);
    println!("  {w}echo '<h1>{}</h1>' > index.html{reset}", koan, w = WHITE, reset = RESET);
    println!("  {w}echo 'web: python3 -m http.server $PORT' > Procfile{reset}", w = WHITE, reset = RESET);
    if let Some(git_url) = &config.git {
        println!("  {w}git remote add origin {}{reset}", git_url, w = WHITE, reset = RESET);
    }
    println!("  {w}git add -A && git commit -m 'init' && git push origin main{reset}", w = WHITE, reset = RESET);
    println!();

    Ok(())
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
    disk_used_mb: u64,
    disk_max_mb: u64,
    #[allow(dead_code)]
    created_at: u64,
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
    // Check if .fcm already exists - show existing VM info instead of creating new
    if local_config_path().exists() {
        return show_local_vm();
    }

    // SSH key is required for git push deployment
    let ssh_public_key = match find_ssh_public_key() {
        Some(key) => key,
        None => {
            eprintln!();
            eprintln!("{bold}{w}  No SSH key found{reset}", bold = BOLD, w = WHITE, reset = RESET);
            eprintln!();
            eprintln!("{d}  An SSH key is required for git push deployment.{reset}", d = GRAY, reset = RESET);
            eprintln!("{d}  Generate one with:{reset}", d = GRAY, reset = RESET);
            eprintln!();
            eprintln!("  {w}ssh-keygen -t ed25519{reset}", w = WHITE, reset = RESET);
            eprintln!();
            eprintln!("{d}  Then run {w}fcm create{d} again.{reset}", d = GRAY, w = WHITE, reset = RESET);
            eprintln!();
            return Err("SSH key required".into());
        }
    };

    let request = CreateVmRequest { ssh_public_key: Some(ssh_public_key) };
    let body = serde_json::to_string(&request)?;

    let response = make_request("POST", "/vms", Some(body))?;
    let vm: VmResponse = response.into_json()?;

    // Save local .fcm config file
    let local_config = LocalConfig {
        name: vm.name.clone(),
        url: vm.expose.as_ref().map(|e| format!("https://{}", e.domain)),
        git: vm.git_url.clone(),
    };
    if let Err(e) = save_local_config(&local_config) {
        eprintln!("Warning: Could not save .fcm config: {}", e);
    }

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
        println!("  {w}git remote add origin {}{reset}", git_url, w = WHITE, reset = RESET);
    }
    println!("  {w}git add -A && git commit -m 'init' && git push origin main{reset}", w = WHITE, reset = RESET);
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
        "{:<20} {:<10} {:<6} {:<8} {:<14} {:<40} GIT",
        "NAME", "STATE", "VCPU", "MEMORY", "DISK", "DOMAIN"
    );
    println!("{}", "-".repeat(150));

    // Print each VM
    for vm in vms {
        let domain = vm
            .expose
            .as_ref()
            .map(|e| e.domain.as_str())
            .unwrap_or("-");
        let git_url = vm.git_url.as_deref().unwrap_or("-");
        let memory = format!("{}MB", vm.mem_size_mib);
        let disk = format!("{}MB/{}MB", vm.disk_used_mb, vm.disk_max_mb);
        println!(
            "{:<20} {:<10} {:<6} {:<8} {:<14} {:<40} {}",
            vm.name, vm.state, vm.vcpu_count, memory, disk, domain, git_url
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

/// Set git remote to FCM deployment target
pub fn set_remote(remote_name: &str) -> Result<(), Box<dyn Error>> {
    let config = load_local_config()?;

    let git_url = config
        .git
        .ok_or("No git URL in .fcm config. Run 'fcm create' first.")?;

    // Check if we're in a git repo
    let status = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()?;

    if !status.status.success() {
        return Err("Not a git repository. Run 'git init' first.".into());
    }

    // Check if remote already exists
    let existing = std::process::Command::new("git")
        .args(["remote", "get-url", remote_name])
        .output()?;

    if existing.status.success() {
        // Update existing remote
        let result = std::process::Command::new("git")
            .args(["remote", "set-url", remote_name, &git_url])
            .status()?;
        if !result.success() {
            return Err("Failed to update git remote".into());
        }
        println!(
            "{d}Updated remote '{w}{}{d}':{reset} {b}{}{reset}",
            remote_name,
            git_url,
            d = GRAY,
            w = WHITE,
            b = BLUE,
            reset = RESET
        );
    } else {
        // Add new remote
        let result = std::process::Command::new("git")
            .args(["remote", "add", remote_name, &git_url])
            .status()?;
        if !result.success() {
            return Err("Failed to add git remote".into());
        }
        println!(
            "{d}Added remote '{w}{}{d}':{reset} {b}{}{reset}",
            remote_name,
            git_url,
            d = GRAY,
            w = WHITE,
            b = BLUE,
            reset = RESET
        );
    }

    Ok(())
}

/// Response from /auth/me endpoint
#[derive(Debug, Deserialize)]
struct AuthMeResponse {
    email: String,
    name: String,
    #[allow(dead_code)]
    is_admin: bool,
}

/// Get FCM status page URL from FCM_HOST
/// Get the status page URL for OAuth login
/// Defaults to tryforge.sh, can be overridden with FCM_HOST for local dev
fn status_page_url() -> String {
    if let Ok(host) = env::var("FCM_HOST") {
        // Local development or custom server
        if host.contains("127.0.0.1") || host.contains("localhost") {
            "http://127.0.0.1:7780".to_string()
        } else {
            "https://fcm.tryforge.sh".to_string()
        }
    } else {
        // Default to production
        "https://fcm.tryforge.sh".to_string()
    }
}

/// Open a URL in the default browser
fn open_browser(url: &str) -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        // Try xdg-open first, then sensible-browser
        if std::process::Command::new("xdg-open").arg(url).spawn().is_err() {
            std::process::Command::new("sensible-browser").arg(url).spawn()?;
        }
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd").args(["/C", "start", url]).spawn()?;
    }
    Ok(())
}

/// Parse query string from URL path
fn parse_query_params(query: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            // URL decode the value
            let decoded = value
                .replace('+', " ")
                .replace("%40", "@")
                .replace("%2B", "+")
                .replace("%20", " ")
                .replace("%3D", "=")
                .replace("%26", "&")
                .replace("%3F", "?");
            params.insert(key.to_string(), decoded);
        }
    }
    params
}

/// Authenticate with Google via OAuth flow
pub fn login() -> Result<(), Box<dyn Error>> {
    // Check if already logged in
    if let Ok(token) = load_token() {
        if token.starts_with("fcm_") {
            println!("Already logged in. Run 'fcm logout' first to login as a different user.");
            return Ok(());
        }
    }

    let base_url = status_page_url();

    // Start local server to receive callback
    let listener = TcpListener::bind(format!("127.0.0.1:{}", CLI_LOGIN_PORT))
        .map_err(|e| format!("Failed to start local server on port {}: {}", CLI_LOGIN_PORT, e))?;

    // Build login URL
    let login_url = format!("{}/cli-login?port={}", base_url, CLI_LOGIN_PORT);

    println!("Opening browser for login...");
    println!("If browser doesn't open, visit: {}", login_url);

    // Open browser
    let _ = open_browser(&login_url);

    // Wait for callback with token
    println!("Waiting for authentication...");

    // Set a timeout on the listener
    listener.set_nonblocking(false)?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // Read HTTP request
                let mut reader = BufReader::new(&stream);
                let mut request_line = String::new();
                reader.read_line(&mut request_line)?;

                // Parse the request path
                let parts: Vec<&str> = request_line.split_whitespace().collect();
                if parts.len() < 2 {
                    continue;
                }
                let path = parts[1];

                // Check if this is the callback
                if path.starts_with("/callback") {
                    // Parse query parameters
                    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
                    let params = parse_query_params(query);

                    if let Some(token) = params.get("token") {
                        // Save token to file
                        let token_file = token_path();
                        fs::write(&token_file, token)?;

                        // Set restrictive permissions
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600))?;
                        }

                        // Get user info (name, email) from params
                        let name = params.get("name").cloned().unwrap_or_else(|| "User".to_string());
                        let email = params.get("email").cloned().unwrap_or_else(|| "unknown".to_string());

                        // Send success response to browser
                        let success_html = format!(r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Login Successful</title>
</head>
<body style="font-family: -apple-system, sans-serif; max-width: 400px; margin: 60px auto; text-align: center;">
<img src="{}/calopsita.jpg" alt="calopsita" style="width: 200px; border-radius: 50%;">
<h1 style="margin-top: 20px;">Login Successful</h1>
<p style="color: #666;">You can close this tab and return to the terminal.</p>
</body>
</html>"#, status_page_url());
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            success_html.len(),
                            success_html
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();

                        println!();
                        println!("Logged in as {} ({})", name, email);
                        return Ok(());
                    } else if let Some(error) = params.get("error") {
                        // Send error response to browser
                        let error_html = format!(r#"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Login Failed</title>
</head>
<body style="font-family: -apple-system, sans-serif; max-width: 400px; margin: 60px auto; text-align: center;">
<img src="{}/calopsita.jpg" alt="calopsita" style="width: 200px; border-radius: 50%;">
<h1 style="color: #c00; margin-top: 20px;">Login Failed</h1>
<p style="color: #666;">{}</p>
</body>
</html>"#, status_page_url(), error);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            error_html.len(),
                            error_html
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();

                        return Err(format!("Login failed: {}", error).into());
                    }
                }

                // Send a simple response for any other request
                let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes());
            }
            Err(e) => {
                return Err(format!("Connection error: {}", e).into());
            }
        }
    }

    Err("Login callback not received".into())
}

/// Remove authentication token
pub fn logout() -> Result<(), Box<dyn Error>> {
    let path = token_path();
    if path.exists() {
        fs::remove_file(&path)?;
        println!("Logged out successfully");
    } else {
        println!("Not logged in");
    }
    Ok(())
}

/// Show current user info
pub fn whoami() -> Result<(), Box<dyn Error>> {
    let token = load_token()?;

    // Check if using legacy daemon token vs user token
    if !token.starts_with("fcm_") {
        println!("Using legacy daemon token (admin access)");
        return Ok(());
    }

    // Get user info from daemon
    let response = make_request("GET", "/auth/me", None)?;
    let user: AuthMeResponse = response.into_json()?;

    println!("{}", user.name);
    println!("{}", user.email);
    if user.is_admin {
        println!("(admin)");
    }

    Ok(())
}

/// Open a persistent console session on a VM
pub fn console_vm(vm: &str, session: Option<&str>) -> Result<(), Box<dyn Error>> {
    // Connect directly via the terminal streaming protocol
    // If session is provided, reconnect to that session
    console::connect(vm, session).map_err(|e| e.to_string())?;
    Ok(())
}

/// List active console sessions
pub fn list_sessions(vm_filter: Option<&str>) -> Result<(), Box<dyn Error>> {
    let url = if let Some(vm) = vm_filter {
        format!("{}/sessions?vm={}", status_url(), vm)
    } else {
        format!("{}/sessions", status_url())
    };

    let token = load_token()?;
    let response = ureq::get(&url)
        .set("Authorization", &format!("Bearer {}", token))
        .call()
        .map_err(|e| format!("Failed to list sessions: {}", e))?;

    let sessions: Vec<serde_json::Value> = response
        .into_json()
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if sessions.is_empty() {
        println!("No active sessions");
        return Ok(());
    }

    println!("{:<8} {:<20} {:<15} {:<20}", "ID", "VM", "IP", "CREATED");
    println!("{}", "-".repeat(65));

    for session in sessions {
        let id = session["id"].as_str().unwrap_or("-");
        let vm_name = session["vm_name"].as_str().unwrap_or("-");
        let vm_ip = session["vm_ip"].as_str().unwrap_or("-");
        let created_at = session["created_at"].as_u64().unwrap_or(0);

        // Format timestamp
        let created_str = if created_at > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let ago = now.saturating_sub(created_at);
            if ago < 60 {
                format!("{}s ago", ago)
            } else if ago < 3600 {
                format!("{}m ago", ago / 60)
            } else if ago < 86400 {
                format!("{}h ago", ago / 3600)
            } else {
                format!("{}d ago", ago / 86400)
            }
        } else {
            "-".to_string()
        };

        println!("{:<8} {:<20} {:<15} {:<20}", id, vm_name, vm_ip, created_str);
    }

    println!();
    println!("Reconnect with: fcm console <vm> -s <id>");

    Ok(())
}

/// Print VM details
fn print_vm(vm: &VmResponse) {
    println!("  Name:   {}", vm.name);
    println!("  State:  {}", vm.state);
    println!("  vCPU:   {}", vm.vcpu_count);
    println!("  Memory: {}MB", vm.mem_size_mib);
    println!("  Disk:   {}MB/{}MB", vm.disk_used_mb, vm.disk_max_mb);
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
    use serial_test::serial;

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
            "disk_used_mb": 145,
            "disk_max_mb": 1024,
            "created_at": 1700000000,
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
        assert_eq!(vm.disk_used_mb, 145);
        assert_eq!(vm.disk_max_mb, 1024);
        assert_eq!(vm.created_at, 1700000000);
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
            "disk_used_mb": 200,
            "disk_max_mb": 2048,
            "created_at": 1700000000,
            "expose": {
                "port": 3000,
                "domain": "test-vm.tryforge.sh"
            },
            "git_url": "root@myserver.com:test-vm.git"
        }"#;
        let vm: VmResponse = serde_json::from_str(json).unwrap();
        assert_eq!(vm.vcpu_count, 2);
        assert_eq!(vm.mem_size_mib, 1024);
        assert_eq!(vm.disk_used_mb, 200);
        assert_eq!(vm.disk_max_mb, 2048);
        assert_eq!(vm.created_at, 1700000000);
        assert!(vm.expose.is_some());
        let expose = vm.expose.unwrap();
        assert_eq!(expose.port, 3000);
        assert_eq!(expose.domain, "test-vm.tryforge.sh");
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
    #[serial]
    fn test_daemon_url_default() {
        env::remove_var("FCM_HOST");
        // Default is now tryforge.sh production URL
        assert_eq!(daemon_url(), "https://fcm.tryforge.sh");
    }

    #[test]
    #[serial]
    fn test_daemon_url_local_dev() {
        // FCM_HOST can override for local development
        env::set_var("FCM_HOST", "127.0.0.1:7777");
        assert_eq!(daemon_url(), "http://127.0.0.1:7777");
        env::remove_var("FCM_HOST");
    }

    #[test]
    #[serial]
    fn test_daemon_url_with_scheme() {
        env::set_var("FCM_HOST", "https://myserver.example.com:7777");
        assert_eq!(daemon_url(), "https://myserver.example.com:7777");
        env::remove_var("FCM_HOST");
    }

    #[test]
    fn test_local_config_serialization() {
        let config = LocalConfig {
            name: "cosmic-nova".to_string(),
            url: Some("https://cosmic-nova.tryforge.sh".to_string()),
            git: Some("root@git.tryforge.sh:cosmic-nova.git".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("cosmic-nova"));
        assert!(json.contains("tryforge.sh"));
    }

    #[test]
    fn test_local_config_deserialization() {
        let json = r#"{
            "name": "test-vm",
            "url": "https://test-vm.example.com",
            "git": "root@example.com:test-vm.git"
        }"#;
        let config: LocalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, "test-vm");
        assert_eq!(config.url, Some("https://test-vm.example.com".to_string()));
        assert_eq!(config.git, Some("root@example.com:test-vm.git".to_string()));
    }

    #[test]
    fn test_local_config_path() {
        let path = local_config_path();
        assert_eq!(path.to_str().unwrap(), ".fcm");
    }
}
