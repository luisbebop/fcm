// Daemon HTTP server module

use crate::caddy;
use crate::network;
use crate::vm::{self, VmConfig, VmError, VmState, BASE_DIR};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use tiny_http::{Header, Method, Request, Response, Server};
use tungstenite::handshake::server::{Request as WsRequest, Response as WsResponse};
use tungstenite::protocol::Message;

/// PTY master file descriptors for console access (VM ID -> master FD)
type ConsoleFds = Arc<Mutex<HashMap<String, RawFd>>>;

/// Ring buffer size for console output (64KB should hold several screens)
const CONSOLE_BUFFER_SIZE: usize = 64 * 1024;

/// Persistent console session - keeps SSH connection alive across WebSocket reconnects
struct ConsoleSession {
    id: String,
    vm_id: String,
    vm_name: String,
    vm_ip: String,
    created_at: u64,
    /// Send bytes to SSH stdin
    input_tx: std::sync::mpsc::Sender<Vec<u8>>,
    /// Subscribers for SSH stdout (each connected WebSocket gets one)
    output_subscribers: Arc<Mutex<Vec<std::sync::mpsc::Sender<Vec<u8>>>>>,
    /// Ring buffer of recent output for screen restoration on reconnect
    output_buffer: Arc<Mutex<VecDeque<u8>>>,
    /// SSH process (kept alive for session duration)
    _ssh_child: std::process::Child,
}

/// Console session storage (session ID -> session)
type ConsoleSessionStore = Arc<Mutex<HashMap<String, ConsoleSession>>>;

/// Global console session store
static CONSOLE_SESSIONS: once_cell::sync::Lazy<ConsoleSessionStore> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Nature-related words for session IDs
const SESSION_WORDS: &[&str] = &[
    "brook", "cloud", "creek", "dawn", "dew", "dusk", "fern", "fjord", "fog",
    "frost", "glade", "grove", "haze", "hill", "lake", "leaf", "marsh", "mist",
    "moon", "moss", "oasis", "ocean", "pine", "pond", "rain", "ridge", "sand",
    "shade", "sky", "snow", "spring", "star", "stone", "storm", "stream", "sun",
    "tide", "tree", "vale", "wave", "wind", "wood",
];

/// Generate a single nature-word session ID (e.g., "brook")
fn generate_console_session_id() -> String {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();
    SESSION_WORDS.choose(&mut rng).unwrap().to_string()
}

/// Request to create a VM
#[derive(Debug, Deserialize, Default)]
struct CreateVmRequest {
    ssh_public_key: Option<String>,
}

const BIND_ADDR: &str = "0.0.0.0:7777";

/// Terminal server bind address (localhost only - Caddy proxies external connections)
const TERMINAL_BIND_ADDR: &str = "127.0.0.1:7778";

/// Default port to expose for all VMs
const DEFAULT_EXPOSE_PORT: u16 = 3000;

/// Status page HTTP port (internal, proxied by Caddy)
const STATUS_PAGE_PORT: u16 = 7780;

/// Directory for release binaries
const RELEASES_DIR: &str = "/var/lib/firecracker/releases";

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

/// Represents an available release binary
#[derive(Debug, Clone)]
struct Release {
    #[allow(dead_code)]
    commit: String,
    platform: String,
    filename: String,
    #[allow(dead_code)]
    size_mb: f64,
}

/// Get the current commit hash and build time from the COMMIT file
/// Format: "commit datetime" (e.g., "abc1234 2024-01-23 15:30")
fn get_current_commit() -> Option<(String, String)> {
    let commit_path = format!("{}/COMMIT", RELEASES_DIR);
    let content = fs::read_to_string(&commit_path).ok()?;
    let parts: Vec<&str> = content.trim().splitn(2, ' ').collect();
    if parts.len() >= 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        Some((parts[0].to_string(), String::new()))
    }
}

/// List available releases in the releases directory
fn list_releases() -> Vec<Release> {
    let mut releases = Vec::new();

    let entries = match fs::read_dir(RELEASES_DIR) {
        Ok(entries) => entries,
        Err(_) => return releases,
    };

    // Get current commit from COMMIT file
    let current_commit = get_current_commit()
        .map(|(c, _)| c)
        .unwrap_or_else(|| "unknown".to_string());

    for entry in entries.flatten() {
        let filename = entry.file_name().to_string_lossy().to_string();

        // Skip non-fcm files and metadata files
        if !filename.starts_with("fcm-") || filename == "COMMIT" {
            continue;
        }

        // Get file size
        let size_mb = entry.metadata()
            .map(|m| m.len() as f64 / 1_048_576.0)
            .unwrap_or(0.0);

        // Current format: fcm-<platform>.tar.gz (e.g., fcm-macos-arm64.tar.gz)
        if filename.ends_with(".tar.gz") {
            let name_without_ext = filename.trim_end_matches(".tar.gz");
            let parts: Vec<&str> = name_without_ext.split('-').collect();

            // New format: fcm-<os>-<arch> (3 parts)
            if parts.len() == 3 {
                let platform = format!("{}-{}", parts[1], parts[2]);
                releases.push(Release {
                    commit: current_commit.clone(),
                    platform,
                    filename,
                    size_mb,
                });
                continue;
            }

            // Legacy format: fcm-<commit>-<os>-<arch> (4+ parts)
            if parts.len() >= 4 {
                let commit = parts[1].to_string();
                let platform = format!("{}-{}", parts[2], parts[3]);
                releases.push(Release {
                    commit,
                    platform,
                    filename,
                    size_mb,
                });
            }
        }
    }

    // Sort by platform (macos first, then linux)
    releases.sort_by(|a, b| a.platform.cmp(&b.platform));

    releases
}

/// Google OAuth2 configuration (loaded from environment)
const OAUTH_CALLBACK_PATH: &str = "/oauth2/callback";

/// Load Google OAuth credentials from environment or .env file
fn load_oauth_credentials() -> (String, String) {
    // Try to load from .env file if environment variables not set
    if std::env::var("GOOGLE_CLIENT_ID").is_err() {
        if let Ok(content) = std::fs::read_to_string("/home/ubuntu/fcm/.env") {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    std::env::set_var(key.trim(), value.trim());
                }
            }
        }
    }

    let client_id = std::env::var("GOOGLE_CLIENT_ID")
        .expect("GOOGLE_CLIENT_ID environment variable not set");
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
        .expect("GOOGLE_CLIENT_SECRET environment variable not set");

    (client_id, client_secret)
}

/// User info from Google OAuth
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: String,
    name: String,
    #[allow(dead_code)]
    #[serde(skip_serializing_if = "Option::is_none")]
    picture: Option<String>,
}

/// User database stored in users.json
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UserDatabase {
    users: HashMap<String, UserRecord>,
    tokens: HashMap<String, TokenRecord>,
}

/// A stored user record
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserRecord {
    id: String,
    email: String,
    name: String,
    created_at: u64,
    is_admin: bool,
}

/// A stored token record
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenRecord {
    user_id: String,
    created_at: u64,
}

/// User database file path
fn users_db_path() -> PathBuf {
    PathBuf::from(BASE_DIR).join("users.json")
}

/// Load user database from disk
fn load_user_db() -> UserDatabase {
    let path = users_db_path();
    if path.exists() {
        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(db) = serde_json::from_str(&content) {
                return db;
            }
        }
    }
    UserDatabase::default()
}

/// Save user database to disk
fn save_user_db(db: &UserDatabase) -> Result<(), Box<dyn Error>> {
    let path = users_db_path();
    let json = serde_json::to_string_pretty(db)?;
    fs::write(&path, json)?;
    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Generate a user token (fcm_...)
fn generate_user_token() -> String {
    let mut rng = rand::thread_rng();
    let random: String = (0..32)
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
        .collect();
    format!("fcm_{}", random)
}

/// Create or update user from Google info and return a token
fn create_or_update_user(user_info: &GoogleUserInfo) -> Result<(String, UserRecord), Box<dyn Error>> {
    let mut db = load_user_db();

    // Check if user exists
    let is_first_user = db.users.is_empty();
    let user = if let Some(existing) = db.users.get(&user_info.id) {
        // Update existing user's name/email but keep is_admin
        let mut updated = existing.clone();
        updated.name = user_info.name.clone();
        updated.email = user_info.email.clone();
        db.users.insert(user_info.id.clone(), updated.clone());
        updated
    } else {
        // Create new user
        let user = UserRecord {
            id: user_info.id.clone(),
            email: user_info.email.clone(),
            name: user_info.name.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_admin: is_first_user, // First user becomes admin
        };
        db.users.insert(user_info.id.clone(), user.clone());
        user
    };

    // Generate new token for this login
    let token = generate_user_token();
    let token_record = TokenRecord {
        user_id: user_info.id.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    db.tokens.insert(token.clone(), token_record);

    // Save database
    save_user_db(&db)?;

    Ok((token, user))
}

/// Google OAuth token response
#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    expires_in: u64,
}

/// Session store for OAuth users
type SessionStore = Arc<Mutex<HashMap<String, GoogleUserInfo>>>;

/// Generate a random session ID
fn generate_session_id() -> String {
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

/// URL decode a string
fn url_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

/// Parse query string into key-value pairs
fn parse_query_string(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            params.insert(url_decode(key), url_decode(value));
        }
    }
    params
}

/// Parse cookies from Cookie header
fn parse_cookies(cookie_header: &str) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some((name, value)) = cookie.split_once('=') {
            cookies.insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    cookies
}

/// Exchange OAuth code for access token
fn exchange_code_for_token(code: &str, redirect_uri: &str) -> Result<GoogleTokenResponse, String> {
    let (client_id, client_secret) = load_oauth_credentials();
    let body = format!(
        "code={}&client_id={}&client_secret={}&redirect_uri={}&grant_type=authorization_code",
        url_encode(code),
        url_encode(&client_id),
        url_encode(&client_secret),
        url_encode(redirect_uri)
    );

    let response = ureq::post("https://oauth2.googleapis.com/token")
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body)
        .map_err(|e| format!("Token exchange failed: {}", e))?;

    response
        .into_json::<GoogleTokenResponse>()
        .map_err(|e| format!("Failed to parse token response: {}", e))
}

/// Fetch user info from Google
fn fetch_google_user_info(access_token: &str) -> Result<GoogleUserInfo, String> {
    let response = ureq::get("https://www.googleapis.com/oauth2/v2/userinfo")
        .set("Authorization", &format!("Bearer {}", access_token))
        .call()
        .map_err(|e| format!("Failed to fetch user info: {}", e))?;

    response
        .into_json::<GoogleUserInfo>()
        .map_err(|e| format!("Failed to parse user info: {}", e))
}

/// Build Google OAuth authorization URL with optional state
fn build_google_auth_url(redirect_uri: &str, state: Option<&str>) -> String {
    let (client_id, _) = load_oauth_credentials();
    let base = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=email%20profile",
        url_encode(&client_id),
        url_encode(redirect_uri)
    );
    if let Some(s) = state {
        format!("{}&state={}", base, url_encode(s))
    } else {
        base
    }
}

/// Generate the status page HTML
fn generate_status_html(stats: &DaemonStats, user: Option<&UserRecord>) -> String {
    // Get VM list, filtered by user ownership
    let all_vms = vm::list_vms().unwrap_or_default();

    // Filter VMs based on user access
    let vms: Vec<_> = match &user {
        None => vec![], // Not logged in - show no VMs
        Some(u) if u.is_admin => all_vms, // Admin sees all VMs
        Some(u) => all_vms.into_iter()
            .filter(|v| v.owner.as_ref() == Some(&u.id))
            .collect(), // Regular user sees only their VMs
    };

    let running_count = vms.iter().filter(|v| v.state == VmState::Running).count();
    let stopped_count = vms.len() - running_count;

    // Build VM table rows
    let vm_rows: String = match &user {
        None => {
            "<tr><td colspan=\"5\" style=\"text-align:center;color:#666;\">Login to see your VMs</td></tr>".to_string()
        }
        Some(_) if vms.is_empty() => {
            "<tr><td colspan=\"5\" style=\"text-align:center;color:#666;\">No VMs yet</td></tr>".to_string()
        }
        Some(_) => {
            vms.iter()
                .map(|v| {
                    let state_color = if v.state == VmState::Running { "#2d5" } else { "#888" };
                    let state_text = if v.state == VmState::Running { "running" } else { "stopped" };
                    let domain_html = v.expose.as_ref()
                        .map(|e| format!("<a href=\"https://{}\" target=\"_blank\">{}</a>", e.domain, e.domain))
                        .unwrap_or_else(|| "-".to_string());
                    let console_html = if v.state == VmState::Running {
                        format!(r#"<a href="/web-console/{}" style="color:#06c;">Console</a>"#, v.name)
                    } else {
                        "-".to_string()
                    };
                    format!(
                        "<tr><td>{}</td><td style=\"color:{}\">{}</td><td>{}</td><td>{}MB</td><td>{}</td></tr>",
                        v.name, state_color, state_text, domain_html, v.disk_used_mb(), console_html
                    )
                })
                .collect()
        }
    };

    // Build auth section (login button or welcome message)
    let auth_section = match user {
        Some(u) => format!(
            r#"<div style="float:right;font-size:0.9em;">Welcome, <b>{}</b> | <a href="/logout">Logout</a></div>"#,
            html_escape(&u.name)
        ),
        None => {
            let redirect_uri = format!("https://fcm.tryforge.sh{}", OAUTH_CALLBACK_PATH);
            let auth_url = build_google_auth_url(&redirect_uri, None);
            format!(
                r#"<div style="float:right;"><a href="{}" style="display:inline-block;padding:8px 16px;background:#4285f4;color:#fff;text-decoration:none;border-radius:4px;font-size:0.9em;">Login with Google</a></div>"#,
                auth_url
            )
        }
    };

    // Build create VM button (only shown when logged in)
    let create_vm_button = match user {
        Some(_) => r#"<button onclick="createVm()" style="padding:8px 16px;background:#28a745;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:0.9em;">Create VM</button>
<script>
async function createVm() {
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = 'Creating...';
    try {
        const resp = await fetch('/api/vms', { method: 'POST', credentials: 'include' });
        if (resp.ok) {
            location.reload();
        } else {
            const err = await resp.text();
            alert('Failed to create VM: ' + err);
            btn.disabled = false;
            btn.textContent = 'Create VM';
        }
    } catch (e) {
        alert('Failed to create VM: ' + e);
        btn.disabled = false;
        btn.textContent = 'Create VM';
    }
}
</script>"#.to_string(),
        None => String::new(),
    };

    // Get current commit and releases
    let (current_commit, build_time) = get_current_commit().unwrap_or_else(|| ("unknown".to_string(), String::new()));
    let releases = list_releases();

    // Build download links
    let download_section = if releases.is_empty() {
        String::new()
    } else {
        let download_links: String = releases
            .iter()
            .map(|r| {
                let platform_name = match r.platform.as_str() {
                    "macos-arm64" => "macOS (Apple Silicon)",
                    "macos-x64" => "macOS (Intel)",
                    "linux-x64" => "Linux",
                    "darwin-arm64" => "macOS",  // legacy
                    "linux-x86_64" => "Linux",  // legacy
                    "linux-aarch64" => "Linux (ARM64)",
                    _ => &r.platform,
                };
                format!(
                    r#"<a href="/releases/{}" style="display:inline-block;margin:5px 10px 5px 0;padding:8px 16px;background:#333;color:#fff;text-decoration:none;border-radius:4px;font-size:0.85em;">{}</a>"#,
                    r.filename,
                    platform_name
                )
            })
            .collect();

        let version_info = if build_time.is_empty() {
            format!("<code>{}</code>", &current_commit[..7.min(current_commit.len())])
        } else {
            format!("<code>{}</code> · <code>{}</code>", &current_commit[..7.min(current_commit.len())], build_time)
        };

        format!(
            r#"
    <h2>Download CLI</h2>
    <p style="margin-bottom:10px;">{}</p>
    <p style="font-size:0.85em;color:#666;margin-top:5px;">{}</p>
"#,
            download_links,
            version_info
        )
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
    {}
    <h1 style="clear:both;">fcm</h1>

    <p>
        fcm is a Firecracker VM manager that gives you Heroku-style deploys on bare metal.
        Create a VM, push your code with git, and it's live with SSL in seconds.
        Each VM gets 1 vCPU, 1GB RAM, and runs your app via Procfile.
    </p>

    <p style="margin:15px 0;">
        <span style="display:inline-block;background:#cc342d;color:#fff;padding:4px 10px;border-radius:4px;font-size:0.8em;margin:3px 5px 3px 0;">Ruby 3.4</span>
        <span style="display:inline-block;background:#3776ab;color:#fff;padding:4px 10px;border-radius:4px;font-size:0.8em;margin:3px 5px 3px 0;">Python 3.12</span>
        <span style="display:inline-block;background:#339933;color:#fff;padding:4px 10px;border-radius:4px;font-size:0.8em;margin:3px 5px 3px 0;">Node.js 24</span>
        <span style="display:inline-block;background:#fbf0df;color:#000;padding:4px 10px;border-radius:4px;font-size:0.8em;margin:3px 5px 3px 0;">Bun 1.3</span>
        <span style="display:inline-block;background:#D97706;color:#fff;padding:4px 10px;border-radius:4px;font-size:0.8em;margin:3px 5px 3px 0;">Claude Code</span>
    </p>
{}
    <h2>Deploy</h2>
    <pre>$ fcm login
$ fcm create
$ git init && echo "web: python3 -m http.server 3000" > Procfile
$ git add . && git commit -m "init"
$ git remote add origin root@tryforge.sh:vm-name.git
$ git push origin main</pre>

    <h2>Status</h2>
    <div class="stats">
        <span><b>Uptime:</b> {}</span>
        <span><b>VMs:</b> {} running, {} stopped</span>
    </div>

    {}

    <table>
        <tr><th>Name</th><th>State</th><th>Domain</th><th>Disk</th><th>Actions</th></tr>
        {}
    </table>

    <p style="margin-top:40px;font-size:0.85em;color:#666;">
        <a href="https://github.com/luisbebop/fcm">Source</a>
    </p>
</body>
</html>"##,
        auth_section,
        download_section,
        stats.format_uptime(),
        running_count,
        stopped_count,
        create_vm_button,
        vm_rows
    )
}

/// HTML escape a string to prevent XSS
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Generate the web console HTML page with xterm.js
fn generate_web_console_html(vm_name: &str, _server_ip: &str) -> String {
    let ws_host = "fcm.tryforge.sh";
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Console: {vm_name}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background: #1e1e1e;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }}
        .header {{
            background: #2d2d2d;
            padding: 8px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #404040;
        }}
        .header h1 {{
            color: #fff;
            font-size: 14px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            font-weight: 500;
        }}
        .header a {{
            color: #888;
            text-decoration: none;
            font-size: 13px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }}
        .header a:hover {{ color: #fff; }}
        #terminal {{
            flex: 1;
            padding: 8px;
        }}
        .status {{
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: rgba(0,0,0,0.8);
            color: #fff;
            padding: 20px 40px;
            border-radius: 8px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: none;
            z-index: 100;
        }}
        .status.show {{ display: block; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{vm_name}</h1>
        <a href="/">← Back to Dashboard</a>
    </div>
    <div id="terminal"></div>
    <div id="status" class="status">Connecting...</div>

    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-web-links@0.9.0/lib/xterm-addon-web-links.min.js"></script>
    <script>
        const vmName = '{vm_name}';
        const wsHost = '{ws_host}';
        const statusEl = document.getElementById('status');

        // Initialize terminal
        const term = new Terminal({{
            cursorBlink: true,
            fontSize: 14,
            fontFamily: 'Menlo, Monaco, "Courier New", monospace',
            theme: {{
                background: '#1e1e1e',
                foreground: '#d4d4d4',
                cursor: '#d4d4d4',
                selection: 'rgba(255, 255, 255, 0.3)',
                black: '#000000',
                red: '#cd3131',
                green: '#0dbc79',
                yellow: '#e5e510',
                blue: '#2472c8',
                magenta: '#bc3fbc',
                cyan: '#11a8cd',
                white: '#e5e5e5',
                brightBlack: '#666666',
                brightRed: '#f14c4c',
                brightGreen: '#23d18b',
                brightYellow: '#f5f543',
                brightBlue: '#3b8eea',
                brightMagenta: '#d670d6',
                brightCyan: '#29b8db',
                brightWhite: '#ffffff'
            }}
        }});

        const fitAddon = new FitAddon.FitAddon();
        const webLinksAddon = new WebLinksAddon.WebLinksAddon();
        term.loadAddon(fitAddon);
        term.loadAddon(webLinksAddon);
        term.open(document.getElementById('terminal'));
        fitAddon.fit();

        let ws = null;
        let reconnectAttempts = 0;
        const maxReconnectAttempts = 5;

        function showStatus(msg) {{
            statusEl.textContent = msg;
            statusEl.classList.add('show');
        }}

        function hideStatus() {{
            statusEl.classList.remove('show');
        }}

        function connect() {{
            showStatus('Connecting...');

            // Build WebSocket URL with per-VM session ID for web console
            const cols = term.cols;
            const rows = term.rows;
            const sessionId = `web-${{vmName}}`;
            const wsUrl = `wss://${{wsHost}}/console?vm=${{encodeURIComponent(vmName)}}&cols=${{cols}}&rows=${{rows}}&session=${{encodeURIComponent(sessionId)}}&env=TERM=xterm-256color`;

            ws = new WebSocket(wsUrl);
            ws.binaryType = 'arraybuffer';

            ws.onopen = function() {{
                hideStatus();
                reconnectAttempts = 0;
                term.focus();
            }};

            ws.onmessage = function(event) {{
                if (event.data instanceof ArrayBuffer) {{
                    // Binary data - terminal output
                    const text = new TextDecoder().decode(event.data);
                    term.write(text);
                }} else {{
                    // Text data - control messages (session info, etc.)
                    try {{
                        const msg = JSON.parse(event.data);
                        if (msg.session) {{
                            console.log('Session:', msg.session);
                        }}
                    }} catch (e) {{
                        // Not JSON, write as text
                        term.write(event.data);
                    }}
                }}
            }};

            ws.onclose = function(event) {{
                if (reconnectAttempts < maxReconnectAttempts) {{
                    reconnectAttempts++;
                    showStatus(`Disconnected. Reconnecting (${{reconnectAttempts}}/${{maxReconnectAttempts}})...`);
                    setTimeout(connect, 1000 * reconnectAttempts);
                }} else {{
                    showStatus('Connection lost. Refresh to reconnect.');
                }}
            }};

            ws.onerror = function(error) {{
                console.error('WebSocket error:', error);
            }};
        }}

        // Send terminal input to WebSocket
        term.onData(function(data) {{
            if (ws && ws.readyState === WebSocket.OPEN) {{
                // Send as binary
                const encoder = new TextEncoder();
                ws.send(encoder.encode(data));
            }}
        }});

        // Handle terminal resize
        window.addEventListener('resize', function() {{
            fitAddon.fit();
            if (ws && ws.readyState === WebSocket.OPEN) {{
                const resizeMsg = JSON.stringify({{
                    type: 'resize',
                    cols: term.cols,
                    rows: term.rows
                }});
                ws.send(resizeMsg);
            }}
        }});

        // Start connection
        connect();
    </script>
</body>
</html>"##,
        vm_name = html_escape(vm_name),
        ws_host = ws_host
    )
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
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expose: Option<ExposeResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExposeResponse {
    pub port: u16,
    pub domain: String,
}

impl From<&VmConfig> for VmResponse {
    fn from(config: &VmConfig) -> Self {
        // Get git URL if repo exists (using git.tryforge.sh for SSH access)
        // Note: git.tryforge.sh is a DNS-only record (not proxied through Cloudflare)
        let git_url = if crate::git::repo_exists(&config.name) {
            Some(crate::git::get_clone_url(&config.name, "git.tryforge.sh"))
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
            created_at: config.created_at,
            expose: config.expose.as_ref().map(|e| ExposeResponse {
                port: e.port,
                domain: e.domain.clone(),
            }),
            git_url,
            owner: config.owner.clone(),
        }
    }
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

/// Extract the bearer token from request
fn extract_bearer_token(request: &Request) -> Option<String> {
    for header in request.headers() {
        let field_str: &str = header.field.as_str().into();
        if field_str.eq_ignore_ascii_case("authorization") {
            let value: &str = header.value.as_str();
            if let Some(bearer_token) = value.strip_prefix("Bearer ") {
                return Some(bearer_token.trim().to_string());
            }
        }
    }
    None
}

/// Get user from token
fn get_user_from_token(token: &str) -> Option<UserRecord> {
    if !token.starts_with("fcm_") {
        return None;
    }
    let db = load_user_db();
    let token_record = db.tokens.get(token)?;
    db.users.get(&token_record.user_id).cloned()
}

/// Represents the access level for a request
#[derive(Debug, Clone)]
enum AccessLevel {
    /// Legacy daemon token - full access to all VMs
    Admin,
    /// User token - can only access their own VMs (or all if is_admin)
    User { id: String, is_admin: bool },
}

impl AccessLevel {
    /// Check if this access level can access a VM
    fn can_access_vm(&self, vm: &VmConfig) -> bool {
        match self {
            AccessLevel::Admin => true,
            AccessLevel::User { id, is_admin } => {
                if *is_admin {
                    return true;
                }
                // User can access VMs they own, or VMs with no owner (legacy)
                match &vm.owner {
                    Some(owner) => owner == id,
                    None => true, // Allow access to legacy VMs without owner
                }
            }
        }
    }

    /// Get the user ID for setting VM ownership (None for admin/legacy)
    fn owner_id(&self) -> Option<String> {
        match self {
            AccessLevel::Admin => None,
            AccessLevel::User { id, .. } => Some(id.clone()),
        }
    }
}

/// Determine access level from request
fn get_access_level(request: &Request, daemon_token: &str) -> Option<AccessLevel> {
    let token = extract_bearer_token(request)?;

    // Check legacy daemon token
    if token == daemon_token {
        return Some(AccessLevel::Admin);
    }

    // Check user token
    if let Some(user) = get_user_from_token(&token) {
        return Some(AccessLevel::User {
            id: user.id,
            is_admin: user.is_admin,
        });
    }

    None
}

/// Response for /auth/me endpoint
#[derive(Debug, Serialize)]
struct AuthMeResponse {
    email: String,
    name: String,
    is_admin: bool,
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
fn handle_create_vm(mut request: Request, access_level: &AccessLevel, console_fds: &ConsoleFds) -> Result<(), Box<dyn Error>> {
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

    // Get owner ID from access level
    let owner = access_level.owner_id();

    // Always use random name and expose port 3000 by default
    match vm::create_vm(None, Some(DEFAULT_EXPOSE_PORT), create_request.ssh_public_key, owner) {
        Ok((config, master_fd)) => {
            // Store the PTY master FD for console access
            console_fds.lock().unwrap().insert(config.id.clone(), master_fd);
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

/// Handle GET /vms - list all VMs (filtered by access level)
fn handle_list_vms(request: Request, access_level: &AccessLevel) -> Result<(), Box<dyn Error>> {
    let vms = vm::list_vms()?;
    // Filter VMs by access level
    let filtered_vms: Vec<_> = vms
        .into_iter()
        .filter(|vm| access_level.can_access_vm(vm))
        .collect();
    let response: Vec<VmResponse> = filtered_vms.iter().map(VmResponse::from).collect();
    send_json_response(request, 200, &response)
}

/// Handle GET /vms/{id} - get VM details
fn handle_get_vm(request: Request, vm_id: &str, access_level: &AccessLevel) -> Result<(), Box<dyn Error>> {
    match vm::find_vm(vm_id) {
        Ok(config) => {
            if !access_level.can_access_vm(&config) {
                return send_error(request, 403, "Access denied");
            }
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
    access_level: &AccessLevel,
    console_fds: &ConsoleFds,
) -> Result<(), Box<dyn Error>> {
    // Get the VM config for access check
    let vm_config = match vm::find_vm(vm_id) {
        Ok(config) => config,
        Err(_) => return send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    };

    // Check access
    if !access_level.can_access_vm(&vm_config) {
        return send_error(request, 403, "Access denied");
    }

    match vm::stop_vm(vm_id) {
        Ok(config) => {
            // Close and remove the PTY master FD
            if let Some(fd) = console_fds.lock().unwrap().remove(&vm_config.id) {
                unsafe { libc::close(fd); }
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
fn handle_start_vm(request: Request, vm_id: &str, access_level: &AccessLevel, console_fds: &ConsoleFds) -> Result<(), Box<dyn Error>> {
    // Get the VM config for access check
    let vm_config = match vm::find_vm(vm_id) {
        Ok(config) => config,
        Err(_) => return send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    };

    // Check access
    if !access_level.can_access_vm(&vm_config) {
        return send_error(request, 403, "Access denied");
    }

    match vm::start_vm(vm_id) {
        Ok((config, master_fd)) => {
            // Store the PTY master FD for console access
            eprintln!("Storing PTY FD {} for VM {} (id={})", master_fd, config.name, config.id);
            console_fds.lock().unwrap().insert(config.id.clone(), master_fd);
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
    access_level: &AccessLevel,
    console_fds: &ConsoleFds,
) -> Result<(), Box<dyn Error>> {
    // Get the VM config for access check
    let vm_config = match vm::find_vm(vm_id) {
        Ok(config) => config,
        Err(_) => return send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    };

    // Check access
    if !access_level.can_access_vm(&vm_config) {
        return send_error(request, 403, "Access denied");
    }

    match vm::destroy_vm(vm_id) {
        Ok(()) => {
            // Close and remove the PTY master FD
            if let Some(fd) = console_fds.lock().unwrap().remove(&vm_config.id) {
                unsafe { libc::close(fd); }
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

/// Handle GET /auth/me - get current user info
fn handle_auth_me(request: Request) -> Result<(), Box<dyn Error>> {
    let token = match extract_bearer_token(&request) {
        Some(t) => t,
        None => return send_error(request, 401, "No token provided"),
    };

    // Check if using legacy daemon token
    if !token.starts_with("fcm_") {
        return send_json_response(request, 200, &AuthMeResponse {
            email: "admin@local".to_string(),
            name: "Admin (legacy token)".to_string(),
            is_admin: true,
        });
    }

    // Look up user from token
    match get_user_from_token(&token) {
        Some(user) => {
            send_json_response(request, 200, &AuthMeResponse {
                email: user.email,
                name: user.name,
                is_admin: user.is_admin,
            })
        }
        None => send_error(request, 401, "Invalid token"),
    }
}

/// Handle PUT /vms/{vm}/fs?path=/path/to/file - upload file to VM
///
/// Uses SSH to write file content to VM. This is used for:
/// - Terminfo uploads (e.g., /usr/share/terminfo/x/xterm-256color)
/// - Other small file transfers
fn handle_upload_file(
    mut request: Request,
    vm_id: &str,
    access_level: &AccessLevel,
) -> Result<(), Box<dyn Error>> {
    // Get the VM config for access check and IP
    let vm_config = match vm::find_vm(vm_id) {
        Ok(config) => config,
        Err(_) => return send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    };

    // Check access
    if !access_level.can_access_vm(&vm_config) {
        return send_error(request, 403, "Access denied");
    }

    // Check VM is running
    if vm_config.state != VmState::Running {
        return send_error(request, 503, "VM is not running");
    }

    // Parse query string to get path
    let url = request.url().to_string();
    let query = url.split('?').nth(1).unwrap_or("");
    let params = parse_query_string(query);

    let dest_path = match params.get("path") {
        Some(p) if !p.is_empty() => p.clone(),
        _ => return send_error(request, 400, "Missing 'path' query parameter"),
    };

    // Validate path - must be absolute and within allowed directories
    if !dest_path.starts_with('/') {
        return send_error(request, 400, "Path must be absolute");
    }

    // Security: only allow specific directories for uploads
    let allowed_prefixes = [
        "/usr/share/terminfo/",
        "/tmp/",
    ];
    if !allowed_prefixes.iter().any(|prefix| dest_path.starts_with(prefix)) {
        return send_error(request, 403, "Path not in allowed upload directories");
    }

    // Read file content from request body
    let mut body = Vec::new();
    if let Err(e) = request.as_reader().read_to_end(&mut body) {
        return send_error(request, 400, &format!("Failed to read request body: {}", e));
    }

    // Upload file to VM via SSH
    // Use sshpass to handle password auth (root:root in base image)
    match upload_file_to_vm(&vm_config.ip, &dest_path, &body) {
        Ok(()) => send_json_response(request, 200, &serde_json::json!({
            "uploaded": true,
            "path": dest_path,
            "size": body.len()
        })),
        Err(e) => send_error(request, 500, &format!("Failed to upload file: {}", e)),
    }
}

/// Upload file content to VM via SSH
fn upload_file_to_vm(vm_ip: &str, dest_path: &str, content: &[u8]) -> Result<(), String> {
    use std::process::{Command, Stdio};

    // Ensure parent directory exists, then write file via stdin
    // Using cat to write binary data safely
    let mkdir_cmd = format!(
        "mkdir -p \"$(dirname '{}')\" && cat > '{}'",
        dest_path.replace('\'', "'\\''"),
        dest_path.replace('\'', "'\\''")
    );

    let mut child = Command::new("sshpass")
        .args([
            "-p", "root",
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            &format!("root@{}", vm_ip),
            &mkdir_cmd,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn sshpass: {}", e))?;

    // Write content to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(content).map_err(|e| format!("Failed to write to stdin: {}", e))?;
    }

    let output = child.wait_with_output()
        .map_err(|e| format!("Failed to wait for sshpass: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("SSH command failed: {}", stderr.trim()))
    }
}

/// Route and handle a request
fn handle_request(
    request: Request,
    token: &str,
    console_fds: &ConsoleFds,
) -> Result<(), Box<dyn Error>> {
    let path = request.url().to_string();
    let method = request.method().clone();

    // Log request
    println!("{} {}", method, path);

    // Get access level (also validates auth)
    let access_level = match get_access_level(&request, token) {
        Some(level) => level,
        None => return send_error(request, 401, "Unauthorized"),
    };

    // Route request
    match (method, path.as_str()) {
        // Auth routes
        (Method::Get, "/auth/me") => handle_auth_me(request),

        // VM collection routes
        (Method::Post, "/vms") => handle_create_vm(request, &access_level, console_fds),
        (Method::Get, "/vms") => handle_list_vms(request, &access_level),

        // VM instance routes
        (Method::Get, path) if path.starts_with("/vms/") => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            match parts.as_slice() {
                ["vms", vm_id] => handle_get_vm(request, vm_id, &access_level),
                _ => send_error(request, 404, "Not found"),
            }
        }
        (Method::Post, path) if path.starts_with("/vms/") => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            match parts.as_slice() {
                ["vms", vm_id, "stop"] => handle_stop_vm(request, vm_id, &access_level, console_fds),
                ["vms", vm_id, "start"] => handle_start_vm(request, vm_id, &access_level, console_fds),
                _ => send_error(request, 404, "Not found"),
            }
        }
        (Method::Delete, path) if path.starts_with("/vms/") => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            match parts.as_slice() {
                ["vms", vm_id] => handle_destroy_vm(request, vm_id, &access_level, console_fds),
                _ => send_error(request, 404, "Not found"),
            }
        }
        (Method::Put, path) if path.starts_with("/vms/") => {
            // Strip query string for routing, but keep full path for handler
            let path_only = path.split('?').next().unwrap_or(path);
            let parts: Vec<&str> = path_only.trim_start_matches('/').split('/').collect();
            match parts.as_slice() {
                ["vms", vm_id, "fs"] => handle_upload_file(request, vm_id, &access_level),
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

/// WebSocket console request parsed from HTTP upgrade
struct WsConsoleRequest {
    vm: String,
    token: String,
    #[allow(dead_code)]
    cols: u16,
    #[allow(dead_code)]
    rows: u16,
    env: HashMap<String, String>,
    /// Optional session ID to reconnect to existing session
    session: Option<String>,
}

/// Parse query string into params, handling repeated keys for env vars
fn parse_ws_query_params(query: &str) -> (HashMap<String, String>, Vec<(String, String)>) {
    let mut params = HashMap::new();
    let mut env_vars = Vec::new();

    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            let key = url_decode(key);
            let value = url_decode(value);

            if key == "env" {
                // Parse env var: "KEY=value"
                if let Some((env_key, env_val)) = value.split_once('=') {
                    env_vars.push((env_key.to_string(), env_val.to_string()));
                }
            } else {
                params.insert(key, value);
            }
        }
    }

    (params, env_vars)
}

/// HTTP response type for WebSocket callback errors
type WsErrorResponse = tungstenite::http::Response<Option<String>>;

/// Handle a single terminal connection via WebSocket -> SSH
fn handle_terminal_connection(
    stream: TcpStream,
    token: &str,
    _console_fds: &ConsoleFds,
    sessions: &SessionStore,
) {
    // Use RefCell for interior mutability to share with closure
    use std::cell::RefCell;

    // Variables to store parsed request info from callback
    let parsed_request: RefCell<Option<WsConsoleRequest>> = RefCell::new(None);
    let token_copy = token.to_string();
    let sessions_clone = Arc::clone(sessions);

    // Use accept_hdr to inspect HTTP headers during WebSocket handshake
    let callback = |req: &WsRequest, response: WsResponse| -> Result<WsResponse, WsErrorResponse> {
        // Extract Authorization header (for CLI clients)
        let auth_header = req.headers()
            .iter()
            .find(|(name, _)| name.as_str().eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.to_str().unwrap_or_default().to_string());

        let bearer_token = auth_header
            .as_ref()
            .and_then(|h| h.strip_prefix("Bearer "))
            .map(|t| t.trim().to_string());

        // Extract Cookie header (for web clients)
        let cookie_header = req.headers()
            .iter()
            .find(|(name, _)| name.as_str().eq_ignore_ascii_case("cookie"))
            .map(|(_, value)| value.to_str().unwrap_or_default().to_string());

        // Try to get user from cookie session
        let cookie_user = cookie_header.as_ref().and_then(|cookies| {
            // Parse fcm_session cookie
            for part in cookies.split(';') {
                let part = part.trim();
                if let Some(session_id) = part.strip_prefix("fcm_session=") {
                    // Look up session in the store
                    if let Ok(store) = sessions_clone.lock() {
                        if let Some(google_user) = store.get(session_id) {
                            // Look up UserRecord from database
                            let db = load_user_db();
                            return db.users.get(&google_user.id).cloned();
                        }
                    }
                }
            }
            None
        });

        // Parse query params from URI
        let uri = req.uri().to_string();
        let query = uri.split_once('?').map(|(_, q)| q).unwrap_or("");
        let (params, env_vars) = parse_ws_query_params(query);

        // Extract VM name (required)
        let vm_name = params.get("vm").cloned().unwrap_or_default();
        if vm_name.is_empty() {
            return Err(tungstenite::http::Response::builder()
                .status(400)
                .body(Some("Missing vm parameter".to_string()))
                .unwrap());
        }

        // Extract terminal size
        let cols: u16 = params.get("cols").and_then(|c| c.parse().ok()).unwrap_or(80);
        let rows: u16 = params.get("rows").and_then(|r| r.parse().ok()).unwrap_or(24);

        // Build env map
        let mut env = HashMap::new();
        for (k, v) in env_vars {
            env.insert(k, v);
        }

        // Extract optional session ID for reconnection
        let session = params.get("session").cloned().filter(|s| !s.is_empty());

        // Determine auth token - prefer Bearer token, fall back to cookie auth
        // For cookie auth, we use a special marker that will be handled later
        let request_token = if let Some(token) = bearer_token {
            token
        } else if let Some(user) = &cookie_user {
            // Use special format to indicate cookie-based auth: "cookie:{user_id}:{is_admin}"
            format!("cookie:{}:{}", user.id, user.is_admin)
        } else {
            return Err(tungstenite::http::Response::builder()
                .status(401)
                .body(Some("Missing Authorization header or session cookie".to_string()))
                .unwrap());
        };

        // Store parsed request for later use
        *parsed_request.borrow_mut() = Some(WsConsoleRequest {
            vm: vm_name,
            token: request_token,
            cols,
            rows,
            env,
            session,
        });

        Ok(response)
    };

    // Accept WebSocket connection with callback for header inspection
    let websocket = match tungstenite::accept_hdr(stream, callback) {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("WebSocket handshake failed: {:?}", e);
            return;
        }
    };

    // Get the parsed request
    let request = match parsed_request.into_inner() {
        Some(req) => req,
        None => {
            eprintln!("No request parsed from WebSocket handshake");
            return;
        }
    };

    println!("WebSocket console connection: vm={}, session={:?}", request.vm, request.session);

    // Validate token and get access level
    let access_level = if request.token == token_copy {
        AccessLevel::Admin
    } else if request.token.starts_with("fcm_") {
        match get_user_from_token(&request.token) {
            Some(user) => AccessLevel::User { id: user.id, is_admin: user.is_admin },
            None => {
                eprintln!("Invalid user token for WebSocket console");
                return;
            }
        }
    } else if request.token.starts_with("cookie:") {
        // Cookie-based auth: "cookie:{user_id}:{is_admin}"
        let parts: Vec<&str> = request.token.splitn(3, ':').collect();
        if parts.len() == 3 {
            let user_id = parts[1].to_string();
            let is_admin = parts[2] == "true";
            AccessLevel::User { id: user_id, is_admin }
        } else {
            eprintln!("Invalid cookie auth format for WebSocket console");
            return;
        }
    } else {
        eprintln!("Invalid token for WebSocket console");
        return;
    };

    // Find VM
    let config = match vm::find_vm(&request.vm) {
        Ok(config) => config,
        Err(_) => {
            eprintln!("VM '{}' not found for WebSocket console", request.vm);
            return;
        }
    };

    // Check access
    if !access_level.can_access_vm(&config) {
        eprintln!("Access denied to VM '{}' for WebSocket console", request.vm);
        return;
    }

    // Check VM is running
    if config.state != VmState::Running {
        eprintln!("VM '{}' is not running for WebSocket console", request.vm);
        return;
    }

    // Get VM IP address
    let vm_ip = config.ip.clone();
    if vm_ip.is_empty() {
        eprintln!("VM '{}' has no IP address", request.vm);
        return;
    }

    // Get or create session
    // First, check if we can reconnect to an existing session
    let existing_session = if let Some(ref sid) = request.session {
        let sessions = CONSOLE_SESSIONS.lock().unwrap();
        if let Some(session) = sessions.get(sid) {
            if session.vm_id != config.id {
                eprintln!("Session {} belongs to different VM", sid);
                return;
            }
            eprintln!("Reconnecting to session {} for VM {}", sid, request.vm);
            Some((sid.clone(), session.input_tx.clone(), Arc::clone(&session.output_subscribers), Arc::clone(&session.output_buffer)))
        } else {
            None // Session ID provided but doesn't exist - will create new
        }
    } else {
        None // No session ID provided - will create new
    };

    let (session_id, input_tx, output_subscribers, output_buffer, is_reconnect) = if let Some((sid, tx, subs, buf)) = existing_session {
        (sid, tx, subs, buf, true)
    } else {
        // Create new session - use provided ID or generate one
        let session_id = request.session.clone().unwrap_or_else(generate_console_session_id);
        eprintln!("Creating new session {} for VM {} at {}", session_id, request.vm, vm_ip);

        // Build environment variables for SSH
        let mut env_args = Vec::new();
        for (key, value) in &request.env {
            if key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !key.is_empty() {
                env_args.push(format!("{}={}", key, value));
            }
        }

        // Spawn SSH to VM with PTY allocation
        let mut ssh_cmd = std::process::Command::new("sshpass");
        ssh_cmd
            .arg("-p").arg("root")
            .arg("ssh")
            .arg("-tt")
            .arg("-o").arg("StrictHostKeyChecking=no")
            .arg("-o").arg("UserKnownHostsFile=/dev/null")
            .arg("-o").arg("LogLevel=ERROR")
            .arg(format!("root@{}", vm_ip));

        let shell_cmd = if env_args.is_empty() {
            "exec zsh --login".to_string()
        } else {
            format!("export {}; exec zsh --login", env_args.join(" "))
        };
        ssh_cmd.arg(shell_cmd);

        ssh_cmd.stdin(std::process::Stdio::piped());
        ssh_cmd.stdout(std::process::Stdio::piped());
        ssh_cmd.stderr(std::process::Stdio::piped());

        let mut child = match ssh_cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to spawn SSH: {}", e);
                return;
            }
        };

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        // Create channels for input (to SSH stdin)
        let (input_tx, input_rx) = std::sync::mpsc::channel::<Vec<u8>>();

        // Create output subscribers list
        let output_subscribers: Arc<Mutex<Vec<std::sync::mpsc::Sender<Vec<u8>>>>> =
            Arc::new(Mutex::new(Vec::new()));

        // Create ring buffer for output (for screen restoration on reconnect)
        let output_buffer: Arc<Mutex<VecDeque<u8>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(CONSOLE_BUFFER_SIZE)));

        // Start SSH stdin writer thread
        let input_rx_for_writer = input_rx;
        let mut stdin_writer = stdin;
        thread::spawn(move || {
            use std::io::Write;
            while let Ok(data) = input_rx_for_writer.recv() {
                if stdin_writer.write_all(&data).is_err() {
                    break;
                }
                let _ = stdin_writer.flush();
            }
        });

        // Start SSH stdout reader thread that broadcasts to subscribers and buffers output
        let output_subs_for_reader = Arc::clone(&output_subscribers);
        let output_buffer_for_reader = Arc::clone(&output_buffer);
        let mut stdout_reader = stdout;
        let session_id_for_reader = session_id.clone();
        thread::spawn(move || {
            use std::io::Read;
            let mut buf = [0u8; 4096];
            loop {
                match stdout_reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = buf[..n].to_vec();

                        // Store in ring buffer for reconnection replay
                        {
                            let mut buffer = output_buffer_for_reader.lock().unwrap();
                            for &byte in &data {
                                if buffer.len() >= CONSOLE_BUFFER_SIZE {
                                    buffer.pop_front();
                                }
                                buffer.push_back(byte);
                            }
                        }

                        // Send to all subscribers, remove dead ones
                        let subs = output_subs_for_reader.lock().unwrap();
                        let mut to_remove = Vec::new();
                        for (i, tx) in subs.iter().enumerate() {
                            if tx.send(data.clone()).is_err() {
                                to_remove.push(i);
                            }
                        }
                        drop(subs);
                        // Clean up dead subscribers
                        if !to_remove.is_empty() {
                            let mut subs = output_subs_for_reader.lock().unwrap();
                            for i in to_remove.into_iter().rev() {
                                if i < subs.len() {
                                    subs.remove(i);
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            // SSH exited - clean up session from global store
            eprintln!("SSH exited for session {}, cleaning up", session_id_for_reader);
            CONSOLE_SESSIONS.lock().unwrap().remove(&session_id_for_reader);
        });

        // Store session
        let session = ConsoleSession {
            id: session_id.clone(),
            vm_id: config.id.clone(),
            vm_name: config.name.clone(),
            vm_ip: vm_ip.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            input_tx: input_tx.clone(),
            output_subscribers: Arc::clone(&output_subscribers),
            output_buffer: Arc::clone(&output_buffer),
            _ssh_child: child,
        };

        CONSOLE_SESSIONS.lock().unwrap().insert(session_id.clone(), session);
        (session_id, input_tx, output_subscribers, output_buffer, false)
    };

    // Attach WebSocket to session
    eprintln!("Attaching WebSocket to session {}", session_id);
    proxy_websocket_session(websocket, &session_id, &config.name, input_tx, output_subscribers, output_buffer, is_reconnect);
    eprintln!("WebSocket disconnected from session {}", session_id);
}


/// Proxy WebSocket to a persistent console session
/// Uses channels to communicate with the session's SSH process
fn proxy_websocket_session(
    mut websocket: tungstenite::WebSocket<TcpStream>,
    session_id: &str,
    vm_name: &str,
    input_tx: std::sync::mpsc::Sender<Vec<u8>>,
    output_subscribers: Arc<Mutex<Vec<std::sync::mpsc::Sender<Vec<u8>>>>>,
    output_buffer: Arc<Mutex<VecDeque<u8>>>,
    is_reconnect: bool,
) {
    use std::sync::mpsc;

    // Send session ID and OSC title to client
    let session_msg = format!("\x1b]0;fcm: {} [{}]\x07", vm_name, session_id);
    let _ = websocket.send(Message::Binary(session_msg.into_bytes()));

    // Send session ID as text message so client can save it
    let session_info = format!("{{\"session\":\"{}\"}}", session_id);
    let _ = websocket.send(Message::Text(session_info));
    let _ = websocket.flush();

    // On reconnect, replay the output buffer to restore screen state
    if is_reconnect {
        let buffer = output_buffer.lock().unwrap();
        if !buffer.is_empty() {
            // Send clear screen first, then buffer contents
            // Clear screen: ESC[2J (clear entire screen) + ESC[H (cursor home)
            let clear_screen = b"\x1b[2J\x1b[H";
            let _ = websocket.send(Message::Binary(clear_screen.to_vec()));

            // Send buffered output
            let data: Vec<u8> = buffer.iter().copied().collect();
            let _ = websocket.send(Message::Binary(data));
            let _ = websocket.flush();
        }
        drop(buffer);

        // Send Ctrl+L to trigger TUI apps to redraw
        let _ = input_tx.send(vec![0x0c]); // Ctrl+L = 0x0c
    }

    // Create output channel for this WebSocket
    let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>();

    // Subscribe to session output
    output_subscribers.lock().unwrap().push(output_tx);

    // Set WebSocket to non-blocking for polling
    let ws_fd = websocket.get_ref().as_raw_fd();
    unsafe {
        let flags = libc::fcntl(ws_fd, libc::F_GETFL);
        libc::fcntl(ws_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // Main loop: proxy between WebSocket and session channels
    loop {
        // Check for data from session (SSH stdout via broadcast)
        match output_rx.try_recv() {
            Ok(data) => {
                if websocket.send(Message::Binary(data)).is_err() {
                    break;
                }
                let _ = websocket.flush();
            }
            Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {}
        }

        // Check for data from WebSocket (user input)
        match websocket.read() {
            Ok(Message::Binary(data)) => {
                if input_tx.send(data).is_err() {
                    break;
                }
            }
            Ok(Message::Text(_text)) => {
                // Resize messages ignored - SSH handles terminal size via PTY
            }
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(data)) => {
                let _ = websocket.send(Message::Pong(data));
            }
            Ok(_) => {}
            Err(tungstenite::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }

    // Note: We don't remove ourselves from output_subscribers here
    // The reader thread will clean up dead subscribers automatically
}

/// Parse HTTP request and extract method, path, headers
fn parse_http_request(buf: &[u8]) -> Option<(String, String, HashMap<String, String>)> {
    let request_str = String::from_utf8_lossy(buf);
    let mut lines = request_str.lines();

    // Parse request line (e.g., "GET /path HTTP/1.1")
    let request_line = lines.next()?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    // Parse headers
    let mut headers = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }

    Some((method, path, headers))
}

/// Send HTTP redirect response
fn send_redirect(stream: &mut TcpStream, location: &str, set_cookie: Option<&str>) {
    let cookie_header = set_cookie
        .map(|c| format!("Set-Cookie: {}\r\n", c))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: {}\r\n{}Connection: close\r\n\r\n",
        location, cookie_header
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Send HTTP HTML response
fn send_html_response(stream: &mut TcpStream, status: u16, html: &str, set_cookie: Option<&str>) {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let cookie_header = set_cookie
        .map(|c| format!("Set-Cookie: {}\r\n", c))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{}",
        status, status_text, html.len(), cookie_header, html
    );
    let _ = stream.write_all(response.as_bytes());
}

/// Run the status page server (port 7780)
fn run_status_server(stats: Arc<DaemonStats>, sessions: SessionStore, console_fds: ConsoleFds) {
    let bind_addr = format!("0.0.0.0:{}", STATUS_PAGE_PORT);
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind status server to {}: {}", bind_addr, e);
            return;
        }
    };

    println!("Status page server listening on {}", bind_addr);

    for mut stream in listener.incoming().flatten() {
        let stats = Arc::clone(&stats);
        let sessions = Arc::clone(&sessions);
        let console_fds = Arc::clone(&console_fds);
        thread::spawn(move || {
            // Read HTTP request
            let mut buf = [0u8; 4096];
            let n = match stream.read(&mut buf) {
                Ok(n) => n,
                Err(_) => return,
            };

            // Parse request
            let (method, path, headers) = match parse_http_request(&buf[..n]) {
                Some(parsed) => parsed,
                None => return,
            };

            // Get cookies
            let cookies = headers
                .get("cookie")
                .map(|c| parse_cookies(c))
                .unwrap_or_default();

            // Get session from cookie (GoogleUserInfo)
            let session_id = cookies.get("fcm_session").cloned();
            let google_user = session_id
                .as_ref()
                .and_then(|sid| sessions.lock().ok()?.get(sid).cloned());

            // Look up UserRecord from database to get is_admin status
            let user_record = google_user.as_ref().and_then(|gu| {
                let db = load_user_db();
                db.users.get(&gu.id).cloned()
            });

            // Route request
            let base_url = "https://fcm.tryforge.sh".to_string();

            if method == "GET" {
                // Handle CLI login initiation
                if path.starts_with("/cli-login") {
                    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
                    let params = parse_query_string(query);

                    if let Some(port) = params.get("port") {
                        // Build OAuth URL with state containing CLI port
                        let redirect_uri = format!("{}{}", base_url, OAUTH_CALLBACK_PATH);
                        let state = format!("cli:{}", port);
                        let auth_url = build_google_auth_url(&redirect_uri, Some(&state));
                        send_redirect(&mut stream, &auth_url, None);
                        return;
                    } else {
                        let html = "<html><body><h1>Error</h1><p>Missing port parameter</p></body></html>";
                        send_html_response(&mut stream, 400, html, None);
                        return;
                    }
                }

                // Handle OAuth callback
                if path.starts_with(OAUTH_CALLBACK_PATH) {
                    let query = path
                        .split_once('?')
                        .map(|(_, q)| q)
                        .unwrap_or("");
                    let params = parse_query_string(query);

                    if let Some(code) = params.get("code") {
                        let redirect_uri = format!("{}{}", base_url, OAUTH_CALLBACK_PATH);

                        // Check if this is a CLI login (state starts with "cli:")
                        let cli_port = params.get("state")
                            .filter(|s| s.starts_with("cli:"))
                            .and_then(|s| s.strip_prefix("cli:"))
                            .and_then(|p| p.parse::<u16>().ok());

                        // Exchange code for token
                        match exchange_code_for_token(code, &redirect_uri) {
                            Ok(token_response) => {
                                // Fetch user info
                                match fetch_google_user_info(&token_response.access_token) {
                                    Ok(user_info) => {
                                        if let Some(port) = cli_port {
                                            // CLI login flow - create user token and redirect to local server
                                            match create_or_update_user(&user_info) {
                                                Ok((user_token, _user)) => {
                                                    let callback_url = format!(
                                                        "http://127.0.0.1:{}/callback?token={}&name={}&email={}",
                                                        port,
                                                        url_encode(&user_token),
                                                        url_encode(&user_info.name),
                                                        url_encode(&user_info.email)
                                                    );
                                                    send_redirect(&mut stream, &callback_url, None);
                                                }
                                                Err(e) => {
                                                    let callback_url = format!(
                                                        "http://127.0.0.1:{}/callback?error={}",
                                                        port,
                                                        url_encode(&e.to_string())
                                                    );
                                                    send_redirect(&mut stream, &callback_url, None);
                                                }
                                            }
                                        } else {
                                            // Web login flow - create session cookie
                                            let new_session_id = generate_session_id();
                                            if let Ok(mut sessions) = sessions.lock() {
                                                sessions.insert(new_session_id.clone(), user_info);
                                            }

                                            // Redirect to home with session cookie
                                            let cookie = format!(
                                                "fcm_session={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800",
                                                new_session_id
                                            );
                                            send_redirect(&mut stream, &base_url, Some(&cookie));
                                        }
                                        return;
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to fetch user info: {}", e);
                                        if let Some(port) = cli_port {
                                            let callback_url = format!(
                                                "http://127.0.0.1:{}/callback?error={}",
                                                port,
                                                url_encode(&e)
                                            );
                                            send_redirect(&mut stream, &callback_url, None);
                                        } else {
                                            let html = format!("<html><body><h1>Login Failed</h1><p>{}</p><a href=\"{}\">Try again</a></body></html>", html_escape(&e), base_url);
                                            send_html_response(&mut stream, 500, &html, None);
                                        }
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Token exchange failed: {}", e);
                                if let Some(port) = cli_port {
                                    let callback_url = format!(
                                        "http://127.0.0.1:{}/callback?error={}",
                                        port,
                                        url_encode(&e)
                                    );
                                    send_redirect(&mut stream, &callback_url, None);
                                } else {
                                    let html = format!("<html><body><h1>Login Failed</h1><p>{}</p><a href=\"{}\">Try again</a></body></html>", html_escape(&e), base_url);
                                    send_html_response(&mut stream, 500, &html, None);
                                }
                                return;
                            }
                        }
                    } else if let Some(error) = params.get("error") {
                        // Check if this is a CLI login error
                        let cli_port = params.get("state")
                            .filter(|s| s.starts_with("cli:"))
                            .and_then(|s| s.strip_prefix("cli:"))
                            .and_then(|p| p.parse::<u16>().ok());

                        if let Some(port) = cli_port {
                            let callback_url = format!(
                                "http://127.0.0.1:{}/callback?error={}",
                                port,
                                url_encode(error)
                            );
                            send_redirect(&mut stream, &callback_url, None);
                        } else {
                            let html = format!("<html><body><h1>Login Failed</h1><p>Error: {}</p><a href=\"{}\">Go back</a></body></html>", html_escape(error), base_url);
                            send_html_response(&mut stream, 400, &html, None);
                        }
                        return;
                    }
                }

                // Handle logout
                if path == "/logout" {
                    // Remove session
                    if let Some(sid) = session_id {
                        if let Ok(mut sessions) = sessions.lock() {
                            sessions.remove(&sid);
                        }
                    }

                    // Clear cookie and redirect
                    let cookie = "fcm_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
                    send_redirect(&mut stream, &base_url, Some(cookie));
                    return;
                }

                // List console sessions (JSON API)
                if path == "/sessions" || path.starts_with("/sessions?") {
                    // Parse query params for optional VM filter
                    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
                    let params = parse_query_string(query);
                    let vm_filter = params.get("vm");

                    let sessions = CONSOLE_SESSIONS.lock().unwrap();
                    let session_list: Vec<serde_json::Value> = sessions
                        .values()
                        .filter(|s| vm_filter.is_none() || vm_filter == Some(&s.vm_name) || vm_filter == Some(&s.vm_id))
                        .map(|s| {
                            serde_json::json!({
                                "id": s.id,
                                "vm_id": s.vm_id,
                                "vm_name": s.vm_name,
                                "vm_ip": s.vm_ip,
                                "created_at": s.created_at,
                            })
                        })
                        .collect();

                    let json = serde_json::to_string(&session_list).unwrap_or_else(|_| "[]".to_string());
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(),
                        json
                    );
                    let _ = stream.write_all(response.as_bytes());
                    return;
                }

                // Delete a console session
                if let Some(session_id) = path.strip_prefix("/sessions/") {
                    if method == "DELETE" {
                        let mut sessions = CONSOLE_SESSIONS.lock().unwrap();
                        if sessions.remove(session_id).is_some() {
                            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes());
                        } else {
                            let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(response.as_bytes());
                        }
                        return;
                    }
                }

                // Serve release files
                if let Some(filename) = path.strip_prefix("/releases/") {
                    // Sanitize: only allow alphanumeric, dash, dot, underscore
                    if filename.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') {
                        let file_path = format!("{}/{}", RELEASES_DIR, filename);
                        if let Ok(file_data) = std::fs::read(&file_path) {
                            let content_type = if filename.ends_with(".tar.gz") {
                                "application/gzip"
                            } else {
                                "application/octet-stream"
                            };
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nContent-Disposition: attachment; filename=\"{}\"\r\nCache-Control: public, max-age=86400\r\nConnection: close\r\n\r\n",
                                content_type,
                                file_data.len(),
                                filename
                            );
                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.write_all(&file_data);
                            let _ = stream.flush();
                            return;
                        }
                    }
                    // File not found or invalid filename
                    let html = "<html><body><h1>404 Not Found</h1></body></html>";
                    send_html_response(&mut stream, 404, html, None);
                    return;
                }

                // Serve calopsita image
                if path == "/calopsita.jpg" {
                    let image_path = format!("{}/calopsita.jpg", BASE_DIR);
                    if let Ok(image_data) = std::fs::read(&image_path) {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\nCache-Control: public, max-age=86400\r\nConnection: close\r\n\r\n",
                            image_data.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.write_all(&image_data);
                        let _ = stream.flush();
                        return;
                    }
                }

                // Web console page
                if let Some(vm_name) = path.strip_prefix("/web-console/") {
                    // Check if user is logged in
                    if user_record.is_none() {
                        send_redirect(&mut stream, &base_url, None);
                        return;
                    }

                    // Verify VM exists and user has access
                    let vm_name = vm_name.trim_end_matches('/');
                    match vm::find_vm(vm_name) {
                        Ok(config) => {
                            // Check access
                            let user = user_record.as_ref().unwrap();
                            let has_access = user.is_admin || config.owner.as_ref() == Some(&user.id);
                            if !has_access {
                                let html = "<html><body><h1>403 Forbidden</h1><p>You don't have access to this VM.</p></body></html>";
                                send_html_response(&mut stream, 403, html, None);
                                return;
                            }

                            if config.state != VmState::Running {
                                let html = "<html><body><h1>VM Not Running</h1><p>This VM is not running. Start it first to access the console.</p></body></html>";
                                send_html_response(&mut stream, 503, html, None);
                                return;
                            }

                            // Serve web console page
                            let console_html = generate_web_console_html(vm_name, &stats.server_ip);
                            send_html_response(&mut stream, 200, &console_html, None);
                            return;
                        }
                        Err(_) => {
                            let html = "<html><body><h1>404 Not Found</h1><p>VM not found.</p></body></html>";
                            send_html_response(&mut stream, 404, html, None);
                            return;
                        }
                    }
                }
            }

            // Handle POST /api/vms - create VM via web interface
            if method == "POST" && path == "/api/vms" {
                // Check if user is logged in
                if user_record.is_none() {
                    let response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nUnauthorized";
                    let _ = stream.write_all(response.as_bytes());
                    return;
                }

                let user = user_record.as_ref().unwrap();

                // Create VM with default settings (expose port 3000)
                match vm::create_vm(None, Some(3000), None, Some(user.id.clone())) {
                    Ok((config, pty_fd)) => {
                        // Store PTY FD for console access
                        {
                            let mut fds = console_fds.lock().unwrap();
                            fds.insert(config.id.clone(), pty_fd);
                        }

                        // Setup git repo for the VM
                        let domain = caddy::generate_domain(&config.name, &stats.server_ip);
                        if let Err(e) = crate::git::create_repo(&config.name, &config.ip, &domain) {
                            eprintln!("Failed to setup git repo for {}: {}", config.name, e);
                        }

                        // Add to Caddy for SSL
                        if let Err(e) = caddy::add_site(&domain, &config.ip, 3000) {
                            eprintln!("Failed to add Caddy site for {}: {}", config.name, e);
                        }

                        // Update config with expose info
                        let mut updated_config = config.clone();
                        updated_config.expose = Some(crate::vm::ExposeConfig {
                            port: 3000,
                            domain: domain.clone(),
                        });
                        let _ = updated_config.save();

                        // Return success JSON
                        let json = serde_json::json!({
                            "id": config.id,
                            "name": config.name,
                            "domain": domain,
                        });
                        let json_str = serde_json::to_string(&json).unwrap_or_default();
                        let response = format!(
                            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            json_str.len(),
                            json_str
                        );
                        let _ = stream.write_all(response.as_bytes());
                        return;
                    }
                    Err(e) => {
                        let error_msg = format!("Failed to create VM: {}", e);
                        let response = format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            error_msg.len(),
                            error_msg
                        );
                        let _ = stream.write_all(response.as_bytes());
                        return;
                    }
                }
            }

            // Generate and send status page
            let html = generate_status_html(&stats, user_record.as_ref());
            send_html_response(&mut stream, 200, &html, None);
        });
    }
}

/// Run the terminal server (port 7778)
fn run_terminal_server(token: String, console_fds: ConsoleFds, sessions: SessionStore) {
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
                let console_fds = Arc::clone(&console_fds);
                let sessions = Arc::clone(&sessions);

                // Handle each connection in a new thread
                thread::spawn(move || {
                    handle_terminal_connection(stream, &token, &console_fds, &sessions);
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

    // Create OAuth session store
    let oauth_sessions: SessionStore = Arc::new(Mutex::new(HashMap::new()));

    // Setup status page domain in Caddy with WebSocket console support
    // fcm.tryforge.sh -> /console proxies to 7778, /* to 7780
    let status_domain = caddy::generate_domain("fcm", &server_ip);
    println!("Setting up status page at https://{}", status_domain);
    println!("WebSocket console available at wss://{}/console", status_domain);
    if let Err(e) = caddy::add_fcm_domain(&status_domain, 7777, STATUS_PAGE_PORT, 7778) {
        eprintln!("Warning: Failed to add status page to Caddy: {}", e);
    } else if let Err(e) = caddy::reload() {
        eprintln!("Warning: Failed to reload Caddy: {}", e);
    }

    // Load or create auth token
    let token = load_or_create_token()?;

    // Create PTY FD storage for serial console
    let console_fds: ConsoleFds = Arc::new(Mutex::new(HashMap::new()));

    // Start status page server in a separate thread
    {
        let stats_clone = Arc::clone(&stats);
        let sessions_clone = Arc::clone(&oauth_sessions);
        let console_fds_clone = Arc::clone(&console_fds);
        thread::spawn(move || {
            run_status_server(stats_clone, sessions_clone, console_fds_clone);
        });
    }

    // Start terminal server in a separate thread
    {
        let terminal_token = token.clone();
        let terminal_console_fds = Arc::clone(&console_fds);
        let terminal_sessions = Arc::clone(&oauth_sessions);
        thread::spawn(move || {
            run_terminal_server(terminal_token, terminal_console_fds, terminal_sessions);
        });
    }

    // Create HTTP server
    let server = Server::http(BIND_ADDR).map_err(|e| format!("Failed to bind to {}: {}", BIND_ADDR, e))?;
    println!("Daemon listening on http://{}", BIND_ADDR);

    // Handle requests
    for request in server.incoming_requests() {
        if let Err(e) = handle_request(request, &token, &console_fds) {
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
    fn test_vm_response_from_config() {
        let config = VmConfig {
            id: "test123".to_string(),
            name: "test-vm".to_string(),
            ip: "172.16.0.50".to_string(),
            state: VmState::Running,
            vcpu_count: 1,
            mem_size_mib: 512,
            created_at: 1700000000,
            expose: None,
            owner: Some("user456".to_string()),
        };
        let response = VmResponse::from(&config);
        assert_eq!(response.id, "test123");
        assert_eq!(response.name, "test-vm");
        assert_eq!(response.state, "running");
        assert_eq!(response.vcpu_count, 1);
        assert_eq!(response.mem_size_mib, 512);
        assert_eq!(response.created_at, 1700000000);
        assert_eq!(response.owner, Some("user456".to_string()));
    }

    #[test]
    fn test_access_level_admin_can_access_all() {
        let vm = VmConfig {
            id: "test".to_string(),
            name: "test-vm".to_string(),
            ip: "172.16.0.50".to_string(),
            state: VmState::Running,
            vcpu_count: 1,
            mem_size_mib: 512,
            created_at: 0,
            expose: None,
            owner: Some("other-user".to_string()),
        };
        let admin = AccessLevel::Admin;
        assert!(admin.can_access_vm(&vm));
    }

    #[test]
    fn test_access_level_user_can_access_own() {
        let vm = VmConfig {
            id: "test".to_string(),
            name: "test-vm".to_string(),
            ip: "172.16.0.50".to_string(),
            state: VmState::Running,
            vcpu_count: 1,
            mem_size_mib: 512,
            created_at: 0,
            expose: None,
            owner: Some("user123".to_string()),
        };
        let user = AccessLevel::User { id: "user123".to_string(), is_admin: false };
        assert!(user.can_access_vm(&vm));
    }

    #[test]
    fn test_access_level_user_cannot_access_other() {
        let vm = VmConfig {
            id: "test".to_string(),
            name: "test-vm".to_string(),
            ip: "172.16.0.50".to_string(),
            state: VmState::Running,
            vcpu_count: 1,
            mem_size_mib: 512,
            created_at: 0,
            expose: None,
            owner: Some("other-user".to_string()),
        };
        let user = AccessLevel::User { id: "user123".to_string(), is_admin: false };
        assert!(!user.can_access_vm(&vm));
    }

    #[test]
    fn test_access_level_admin_user_can_access_all() {
        let vm = VmConfig {
            id: "test".to_string(),
            name: "test-vm".to_string(),
            ip: "172.16.0.50".to_string(),
            state: VmState::Running,
            vcpu_count: 1,
            mem_size_mib: 512,
            created_at: 0,
            expose: None,
            owner: Some("other-user".to_string()),
        };
        let admin_user = AccessLevel::User { id: "admin123".to_string(), is_admin: true };
        assert!(admin_user.can_access_vm(&vm));
    }

    #[test]
    fn test_access_level_user_can_access_legacy_vm() {
        // VMs without owner (legacy) are accessible to all authenticated users
        let vm = VmConfig {
            id: "test".to_string(),
            name: "test-vm".to_string(),
            ip: "172.16.0.50".to_string(),
            state: VmState::Running,
            vcpu_count: 1,
            mem_size_mib: 512,
            created_at: 0,
            expose: None,
            owner: None,
        };
        let user = AccessLevel::User { id: "user123".to_string(), is_admin: false };
        assert!(user.can_access_vm(&vm));
    }

    #[test]
    fn test_default_expose_port() {
        assert_eq!(DEFAULT_EXPOSE_PORT, 3000);
    }

    #[test]
    fn test_terminal_bind_addr() {
        // Terminal server binds to localhost only - Caddy proxies external connections
        assert_eq!(TERMINAL_BIND_ADDR, "127.0.0.1:7778");
    }

    #[test]
    fn test_parse_ws_query_params() {
        let query = "vm=cosmic-nova&cols=120&rows=40&env=TERM%3Dxterm&env=SHELL%3D%2Fbin%2Fzsh";
        let (params, envs) = parse_ws_query_params(query);
        assert_eq!(params.get("vm"), Some(&"cosmic-nova".to_string()));
        assert_eq!(params.get("cols"), Some(&"120".to_string()));
        assert_eq!(params.get("rows"), Some(&"40".to_string()));
        assert_eq!(envs.len(), 2);
        assert_eq!(envs[0], ("TERM".to_string(), "xterm".to_string()));
        assert_eq!(envs[1], ("SHELL".to_string(), "/bin/zsh".to_string()));
    }

    #[test]
    fn test_upload_path_validation() {
        // Test allowed upload path prefixes
        let allowed_prefixes = [
            "/usr/share/terminfo/",
            "/tmp/",
        ];

        // Valid paths
        assert!(allowed_prefixes.iter().any(|p| "/usr/share/terminfo/x/xterm-256color".starts_with(p)));
        assert!(allowed_prefixes.iter().any(|p| "/tmp/test.txt".starts_with(p)));

        // Invalid paths
        assert!(!allowed_prefixes.iter().any(|p| "/etc/passwd".starts_with(p)));
        assert!(!allowed_prefixes.iter().any(|p| "/root/.ssh/authorized_keys".starts_with(p)));
        assert!(!allowed_prefixes.iter().any(|p| "/app/code.py".starts_with(p)));
    }
}
