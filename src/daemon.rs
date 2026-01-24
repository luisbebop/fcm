// Daemon HTTP server module

use crate::caddy;
use crate::network;
use crate::session::{connect_to_agent, send_resize, base64_decode, extract_stdout, make_stdin_message, SessionError, SessionInfo, SessionManager};
use crate::vm::{self, VmConfig, VmError, VmState, BASE_DIR};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
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

    for entry in entries.flatten() {
        let filename = entry.file_name().to_string_lossy().to_string();

        // Expected format: fcm-<commit>-<platform>.tar.gz
        // e.g., fcm-abc1234-linux-x86_64.tar.gz, fcm-abc1234-darwin-arm64.tar.gz
        if !filename.starts_with("fcm-") || !filename.ends_with(".tar.gz") {
            continue;
        }

        // Parse the filename
        let name_without_ext = filename.trim_end_matches(".tar.gz");
        let parts: Vec<&str> = name_without_ext.split('-').collect();

        // Format: fcm-<commit>-<os>-<arch>
        if parts.len() >= 4 {
            let commit = parts[1].to_string();
            let platform = format!("{}-{}", parts[2], parts[3]);

            // Get file size
            let size_mb = entry.metadata()
                .map(|m| m.len() as f64 / 1_048_576.0)
                .unwrap_or(0.0);

            releases.push(Release {
                commit,
                platform,
                filename,
                size_mb,
            });
        }
    }

    // Sort by platform (darwin first, then linux)
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
            "<tr><td colspan=\"4\" style=\"text-align:center;color:#666;\">Login to see your VMs</td></tr>".to_string()
        }
        Some(_) if vms.is_empty() => {
            "<tr><td colspan=\"4\" style=\"text-align:center;color:#666;\">No VMs yet</td></tr>".to_string()
        }
        Some(_) => {
            vms.iter()
                .map(|v| {
                    let state_color = if v.state == VmState::Running { "#2d5" } else { "#888" };
                    let state_text = if v.state == VmState::Running { "running" } else { "stopped" };
                    let domain_html = v.expose.as_ref()
                        .map(|e| format!("<a href=\"https://{}\" target=\"_blank\">{}</a>", e.domain, e.domain))
                        .unwrap_or_else(|| "-".to_string());
                    format!(
                        "<tr><td>{}</td><td style=\"color:{}\">{}</td><td>{}</td><td>{}MB</td></tr>",
                        v.name, state_color, state_text, domain_html, v.disk_used_mb()
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
            let redirect_uri = format!("https://fcm.{}.sslip.io{}", stats.server_ip.replace('.', "-"), OAUTH_CALLBACK_PATH);
            let auth_url = build_google_auth_url(&redirect_uri, None);
            format!(
                r#"<div style="float:right;"><a href="{}" style="display:inline-block;padding:8px 16px;background:#4285f4;color:#fff;text-decoration:none;border-radius:4px;font-size:0.9em;">Login with Google</a></div>"#,
                auth_url
            )
        }
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
                    "darwin-arm64" => "macOS",
                    "linux-x86_64" => "Linux",
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
    </p>
{}
    <h2>Deploy</h2>
    <pre>$ fcm login
$ fcm create
$ git init && echo "web: python3 -m http.server 3000" > Procfile
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
        <a href="https://github.com/luisbebop/fcm">Source</a>
    </p>
</body>
</html>"##,
        auth_section,
        download_section,
        stats.server_ip,
        stats.format_uptime(),
        running_count,
        stopped_count,
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

/// Session response (for API responses)
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub vm_id: String,
    pub session_name: String,
    pub created_at: u64,
    pub is_default: bool,
}

impl From<&SessionInfo> for SessionResponse {
    fn from(info: &SessionInfo) -> Self {
        SessionResponse {
            id: info.id.clone(),
            vm_id: info.vm_id.clone(),
            session_name: info.session_name.clone(),
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
fn handle_create_vm(mut request: Request, access_level: &AccessLevel) -> Result<(), Box<dyn Error>> {
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
    session_manager: &SessionManager,
    access_level: &AccessLevel,
) -> Result<(), Box<dyn Error>> {
    // Get the VM config for access check and session cleanup
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
            // Clean up sessions for this VM
            session_manager.remove_vm_sessions(&vm_config.id);
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
fn handle_start_vm(request: Request, vm_id: &str, access_level: &AccessLevel) -> Result<(), Box<dyn Error>> {
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
    access_level: &AccessLevel,
) -> Result<(), Box<dyn Error>> {
    // Get the VM config for access check and session cleanup
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
            // Clean up sessions for this VM
            session_manager.remove_vm_sessions(&vm_config.id);
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
    access_level: &AccessLevel,
) -> Result<(), Box<dyn Error>> {
    // Find VM and validate it's running
    let config = match vm::find_vm(vm_id) {
        Ok(config) => config,
        Err(_) => return send_error(request, 404, &format!("VM '{}' not found", vm_id)),
    };

    // Check access
    if !access_level.can_access_vm(&config) {
        return send_error(request, 403, "Access denied");
    }

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
                SessionError::ConnectionFailed(_) => 502,
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
        (Method::Post, "/vms") => handle_create_vm(request, &access_level),
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
                ["vms", vm_id, "stop"] => handle_stop_vm(request, vm_id, session_manager, &access_level),
                ["vms", vm_id, "start"] => handle_start_vm(request, vm_id, &access_level),
                ["vms", vm_id, "sessions"] => {
                    handle_create_session(request, vm_id, session_manager, &access_level)
                }
                _ => send_error(request, 404, "Not found"),
            }
        }
        (Method::Delete, path) if path.starts_with("/vms/") => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            match parts.as_slice() {
                ["vms", vm_id] => handle_destroy_vm(request, vm_id, session_manager, &access_level),
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

    // Validate token and get access level
    let access_level = if request.token == token {
        AccessLevel::Admin
    } else if request.token.starts_with("fcm_") {
        match get_user_from_token(&request.token) {
            Some(user) => AccessLevel::User { id: user.id, is_admin: user.is_admin },
            None => {
                let _ = send_terminal_error(&mut stream, "Invalid token");
                return;
            }
        }
    } else {
        let _ = send_terminal_error(&mut stream, "Invalid token");
        return;
    };

    // Find VM
    let config = match vm::find_vm(&request.vm) {
        Ok(config) => config,
        Err(_) => {
            let _ = send_terminal_error(&mut stream, &format!("VM '{}' not found", request.vm));
            return;
        }
    };

    // Check access
    if !access_level.can_access_vm(&config) {
        let _ = send_terminal_error(&mut stream, "Access denied");
        return;
    }

    // Check VM is running
    if config.state != VmState::Running {
        let _ = send_terminal_error(&mut stream, &format!("VM '{}' is not running", request.vm));
        return;
    }

    // Register session in memory (for tracking)
    let _ = session_manager.get_or_create_console(&config.id, &config.ip);

    // Connect to fcm-agent on VM
    let mut agent_stream = match connect_to_agent(&config.ip) {
        Ok(s) => s,
        Err(e) => {
            let _ = send_terminal_error(&mut stream, &format!("Failed to connect to fcm-agent: {}", e));
            return;
        }
    };

    // Send initial terminal size to agent
    if let Err(e) = send_resize(&mut agent_stream, request.cols, request.rows) {
        let _ = send_terminal_error(&mut stream, &format!("Failed to send resize: {}", e));
        return;
    }

    // Send success response to client
    let response = TerminalConnectResponse {
        success: true,
        error: None,
    };
    if let Err(e) = send_terminal_response(&mut stream, &response) {
        eprintln!("Failed to send success response: {}", e);
        return;
    }

    // Clear read timeout for I/O proxying
    let _ = stream.set_read_timeout(None);

    // Proxy JSON-framed messages between client and fcm-agent
    proxy_agent_io(stream, agent_stream);
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

/// Proxy I/O between client TCP stream and fcm-agent
///
/// Protocol:
/// - Client sends raw bytes, we convert to JSON: {"stdin":"base64data"}
/// - Agent sends JSON: {"stdout":"base64data"}, we decode and send raw bytes to client
/// - Agent sends {"exit":N} when shell exits (shell respawns automatically)
fn proxy_agent_io(client_stream: TcpStream, agent_stream: TcpStream) {
    // Clone streams for threads
    let client_read = match client_stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut client_write = client_stream;

    let agent_read = match agent_stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut agent_write = agent_stream;

    // Thread to read from fcm-agent and write to client
    // Agent sends JSON messages, we decode and send raw bytes
    let agent_reader_handle = thread::spawn(move || {
        let mut reader = BufReader::new(agent_read);
        let mut line = String::new();

        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let trimmed = line.trim();
                    if let Some(encoded) = extract_stdout(trimmed) {
                        // Decode base64 and write raw bytes to client
                        let decoded = base64_decode(&encoded);
                        if client_write.write_all(&decoded).is_err() {
                            break;
                        }
                        if client_write.flush().is_err() {
                            break;
                        }
                    }
                    // Ignore {"exit":N} - shell respawns automatically
                }
                Err(_) => break,
            }
        }
    });

    // Main thread reads from client and writes to fcm-agent
    // Client sends raw bytes (encoded to stdin) or JSON resize messages (forwarded directly)
    let mut buf = [0u8; 4096];
    let mut client_read_stream = client_read;

    loop {
        match client_read_stream.read(&mut buf) {
            Ok(0) => break, // EOF
            Ok(n) => {
                let data = &buf[..n];

                // Check if this is a resize message from client
                // Resize messages start with {"resize": and are JSON
                if data.starts_with(b"{\"resize\"") {
                    // Forward resize message directly to agent (add newline if missing)
                    if agent_write.write_all(data).is_err() {
                        break;
                    }
                    if !data.ends_with(b"\n") && agent_write.write_all(b"\n").is_err() {
                        break;
                    }
                } else {
                    // Encode as JSON stdin message
                    let msg = make_stdin_message(data);
                    if agent_write.write_all(msg.as_bytes()).is_err() {
                        break;
                    }
                }
                if agent_write.flush().is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Wait for agent reader thread to finish
    let _ = agent_reader_handle.join();
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
fn run_status_server(stats: Arc<DaemonStats>, sessions: SessionStore) {
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
            let base_url = format!("https://fcm.{}.sslip.io", stats.server_ip.replace('.', "-"));

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
            }

            // Generate and send status page
            let html = generate_status_html(&stats, user_record.as_ref());
            send_html_response(&mut stream, 200, &html, None);
        });
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

    // Create OAuth session store
    let oauth_sessions: SessionStore = Arc::new(Mutex::new(HashMap::new()));

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
        let sessions_clone = Arc::clone(&oauth_sessions);
        thread::spawn(move || {
            run_status_server(stats_clone, sessions_clone);
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
            session_name: "console-vm456".to_string(),
            created_at: 1700000000,
            is_default: true,
        };
        let response = SessionResponse::from(&info);
        assert_eq!(response.id, "abc123");
        assert_eq!(response.vm_id, "vm456");
        assert_eq!(response.session_name, "console-vm456");
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
