// Caddy configuration management

use std::fs;
use std::io;
use std::process::Command;

/// Default Caddyfile path
pub const CADDYFILE_PATH: &str = "/etc/caddy/Caddyfile";

/// Result type for caddy operations
pub type Result<T> = std::result::Result<T, CaddyError>;

/// Caddy operation errors
#[derive(Debug)]
pub enum CaddyError {
    /// IO error
    Io(io::Error),
    /// Command execution failed
    Command(String),
    /// Failed to get server IP
    NoServerIp,
}

impl std::fmt::Display for CaddyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaddyError::Io(e) => write!(f, "IO error: {}", e),
            CaddyError::Command(msg) => write!(f, "Command failed: {}", msg),
            CaddyError::NoServerIp => write!(f, "Failed to determine server public IP"),
        }
    }
}

impl std::error::Error for CaddyError {}

impl From<io::Error> for CaddyError {
    fn from(err: io::Error) -> Self {
        CaddyError::Io(err)
    }
}

/// Get the server's public IP address
/// Uses external service to determine public IP
pub fn get_server_ip() -> Result<String> {
    // Try multiple methods to get public IP

    // Method 1: curl ifconfig.me
    let output = Command::new("curl")
        .args(["-s", "-4", "--max-time", "5", "ifconfig.me"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if is_valid_ipv4(&ip) {
                return Ok(ip);
            }
        }
    }

    // Method 2: curl icanhazip.com
    let output = Command::new("curl")
        .args(["-s", "-4", "--max-time", "5", "icanhazip.com"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if is_valid_ipv4(&ip) {
                return Ok(ip);
            }
        }
    }

    Err(CaddyError::NoServerIp)
}

/// Check if a string is a valid IPv4 address
fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Generate sslip.io domain for a VM
/// Format: <name>.<ip-with-dashes>.sslip.io
/// Example: myvm.64-34-93-45.sslip.io
pub fn generate_domain(vm_name: &str, server_ip: &str) -> String {
    let ip_dashed = server_ip.replace('.', "-");
    format!("{}.{}.sslip.io", vm_name, ip_dashed)
}

/// Generate Caddy config block for a VM
fn generate_caddy_block(domain: &str, vm_ip: &str, port: u16) -> String {
    format!(
        r#"
# fcm-managed: {}
{} {{
    reverse_proxy {}:{}
}}
"#,
        domain, domain, vm_ip, port
    )
}

/// Add a VM to the Caddyfile and reload
pub fn add_site(domain: &str, vm_ip: &str, port: u16) -> Result<()> {
    add_site_to_file(domain, vm_ip, port, CADDYFILE_PATH)
}

/// Add a VM to a specific Caddyfile (for testing)
pub fn add_site_to_file(domain: &str, vm_ip: &str, port: u16, caddyfile_path: &str) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = std::path::Path::new(caddyfile_path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    // Read existing Caddyfile or create empty
    let existing = fs::read_to_string(caddyfile_path).unwrap_or_default();

    // Check if domain already exists
    if existing.contains(&format!("# fcm-managed: {}", domain)) {
        // Already exists, update it instead
        return update_site_in_file(domain, vm_ip, port, caddyfile_path);
    }

    // Append new block
    let block = generate_caddy_block(domain, vm_ip, port);
    let new_content = format!("{}{}", existing, block);

    fs::write(caddyfile_path, new_content)?;

    Ok(())
}

/// Update an existing site in the Caddyfile
fn update_site_in_file(domain: &str, vm_ip: &str, port: u16, caddyfile_path: &str) -> Result<()> {
    let content = fs::read_to_string(caddyfile_path)?;

    // Remove old block and add new one
    let new_content = remove_site_block(&content, domain);
    let block = generate_caddy_block(domain, vm_ip, port);
    let final_content = format!("{}{}", new_content, block);

    fs::write(caddyfile_path, final_content)?;

    Ok(())
}

/// Remove a site block from Caddyfile content
fn remove_site_block(content: &str, domain: &str) -> String {
    let marker = format!("# fcm-managed: {}", domain);
    let mut result = String::new();
    let mut skip_block = false;
    let mut brace_count = 0;

    for line in content.lines() {
        if line.contains(&marker) {
            skip_block = true;
            continue;
        }

        if skip_block {
            // Count braces to find end of block
            for c in line.chars() {
                match c {
                    '{' => brace_count += 1,
                    '}' => {
                        brace_count -= 1;
                        if brace_count <= 0 {
                            skip_block = false;
                            brace_count = 0;
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }

        result.push_str(line);
        result.push('\n');
    }

    // Remove trailing newlines but keep one
    let trimmed = result.trim_end();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{}\n", trimmed)
    }
}

/// Remove a VM from the Caddyfile and reload
pub fn remove_site(domain: &str) -> Result<()> {
    remove_site_from_file(domain, CADDYFILE_PATH)
}

/// Remove a VM from a specific Caddyfile (for testing)
pub fn remove_site_from_file(domain: &str, caddyfile_path: &str) -> Result<()> {
    let content = fs::read_to_string(caddyfile_path)?;
    let new_content = remove_site_block(&content, domain);
    fs::write(caddyfile_path, new_content)?;
    Ok(())
}

/// Reload Caddy configuration
pub fn reload() -> Result<()> {
    // Try systemctl first (most common)
    let output = Command::new("systemctl")
        .args(["reload", "caddy"])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            return Ok(());
        }
    }

    // Try caddy reload command
    let output = Command::new("caddy")
        .args(["reload", "--config", CADDYFILE_PATH])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CaddyError::Command(format!(
            "Failed to reload Caddy: {}",
            stderr.trim()
        )));
    }

    Err(CaddyError::Command("Failed to reload Caddy".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_is_valid_ipv4() {
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(is_valid_ipv4("64.34.93.45"));
        assert!(is_valid_ipv4("0.0.0.0"));
        assert!(is_valid_ipv4("255.255.255.255"));
    }

    #[test]
    fn test_is_valid_ipv4_invalid() {
        assert!(!is_valid_ipv4(""));
        assert!(!is_valid_ipv4("invalid"));
        assert!(!is_valid_ipv4("192.168.1"));
        assert!(!is_valid_ipv4("192.168.1.256"));
        assert!(!is_valid_ipv4("192.168.1.1.1"));
        assert!(!is_valid_ipv4("192.168.1.abc"));
    }

    #[test]
    fn test_generate_domain() {
        assert_eq!(
            generate_domain("myvm", "64.34.93.45"),
            "myvm.64-34-93-45.sslip.io"
        );
        assert_eq!(
            generate_domain("test", "192.168.1.1"),
            "test.192-168-1-1.sslip.io"
        );
    }

    #[test]
    fn test_generate_caddy_block() {
        let block = generate_caddy_block("myvm.64-34-93-45.sslip.io", "172.16.0.50", 8000);
        assert!(block.contains("# fcm-managed: myvm.64-34-93-45.sslip.io"));
        assert!(block.contains("myvm.64-34-93-45.sslip.io {"));
        assert!(block.contains("reverse_proxy 172.16.0.50:8000"));
    }

    #[test]
    fn test_add_site_to_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        add_site_to_file("test.example.com", "172.16.0.50", 8000, path).unwrap();

        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("# fcm-managed: test.example.com"));
        assert!(content.contains("test.example.com {"));
        assert!(content.contains("reverse_proxy 172.16.0.50:8000"));
    }

    #[test]
    fn test_add_site_to_existing_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        // Write initial content
        fs::write(path, "# Existing Caddyfile\nexample.com {\n    root /var/www\n}\n").unwrap();

        add_site_to_file("test.example.com", "172.16.0.50", 8000, path).unwrap();

        let content = fs::read_to_string(path).unwrap();
        // Should preserve existing content
        assert!(content.contains("# Existing Caddyfile"));
        assert!(content.contains("example.com {"));
        // Should add new block
        assert!(content.contains("# fcm-managed: test.example.com"));
        assert!(content.contains("reverse_proxy 172.16.0.50:8000"));
    }

    #[test]
    fn test_remove_site_block() {
        let content = r#"# Header
example.com {
    root /var/www
}

# fcm-managed: test.example.com
test.example.com {
    reverse_proxy 172.16.0.50:8000
}

other.com {
    root /var/other
}
"#;

        let result = remove_site_block(content, "test.example.com");

        assert!(result.contains("example.com {"));
        assert!(result.contains("other.com {"));
        assert!(!result.contains("# fcm-managed: test.example.com"));
        assert!(!result.contains("reverse_proxy 172.16.0.50:8000"));
    }

    #[test]
    fn test_remove_site_from_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        // Add a site first
        add_site_to_file("test.example.com", "172.16.0.50", 8000, path).unwrap();

        // Verify it was added
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("# fcm-managed: test.example.com"));

        // Remove it
        remove_site_from_file("test.example.com", path).unwrap();

        // Verify it was removed
        let content = fs::read_to_string(path).unwrap();
        assert!(!content.contains("# fcm-managed: test.example.com"));
        assert!(!content.contains("reverse_proxy"));
    }

    #[test]
    fn test_add_multiple_sites() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        add_site_to_file("site1.example.com", "172.16.0.50", 8000, path).unwrap();
        add_site_to_file("site2.example.com", "172.16.0.51", 8001, path).unwrap();

        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("# fcm-managed: site1.example.com"));
        assert!(content.contains("# fcm-managed: site2.example.com"));
        assert!(content.contains("reverse_proxy 172.16.0.50:8000"));
        assert!(content.contains("reverse_proxy 172.16.0.51:8001"));
    }

    #[test]
    fn test_update_existing_site() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        // Add site
        add_site_to_file("test.example.com", "172.16.0.50", 8000, path).unwrap();

        // Update with different port
        add_site_to_file("test.example.com", "172.16.0.50", 9000, path).unwrap();

        let content = fs::read_to_string(path).unwrap();
        // Should have only one entry
        assert_eq!(content.matches("# fcm-managed: test.example.com").count(), 1);
        // Should have new port
        assert!(content.contains("reverse_proxy 172.16.0.50:9000"));
        assert!(!content.contains("reverse_proxy 172.16.0.50:8000"));
    }

    #[test]
    fn test_caddy_error_display() {
        let err = CaddyError::NoServerIp;
        assert!(err.to_string().contains("Failed to determine server public IP"));

        let err = CaddyError::Command("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_caddyfile_path_constant() {
        assert_eq!(CADDYFILE_PATH, "/etc/caddy/Caddyfile");
    }
}
