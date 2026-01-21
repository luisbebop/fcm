// Firecracker API over unix socket

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Firecracker API client over unix socket
pub struct FirecrackerClient {
    socket_path: String,
}

/// Boot source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
}

/// Drive configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

/// Machine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineConfig {
    pub vcpu_count: u8,
    pub mem_size_mib: u32,
}

/// Network interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub iface_id: String,
    pub guest_mac: String,
    pub host_dev_name: String,
}

/// Action type for VM control
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ActionType {
    InstanceStart,
    SendCtrlAltDel,
}

/// Action request for VM control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action_type: ActionType,
}

/// API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub fault_message: String,
}

/// Result type for Firecracker API operations
pub type Result<T> = std::result::Result<T, FirecrackerError>;

/// Firecracker API errors
#[derive(Debug)]
pub enum FirecrackerError {
    /// Socket connection error
    Connection(std::io::Error),
    /// HTTP protocol error
    Protocol(String),
    /// API error response from Firecracker
    Api(u16, String),
    /// JSON serialization/deserialization error
    Json(serde_json::Error),
}

impl std::fmt::Display for FirecrackerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirecrackerError::Connection(e) => write!(f, "Socket connection error: {}", e),
            FirecrackerError::Protocol(msg) => write!(f, "HTTP protocol error: {}", msg),
            FirecrackerError::Api(status, msg) => write!(f, "API error ({}): {}", status, msg),
            FirecrackerError::Json(e) => write!(f, "JSON error: {}", e),
        }
    }
}

impl std::error::Error for FirecrackerError {}

impl From<std::io::Error> for FirecrackerError {
    fn from(err: std::io::Error) -> Self {
        FirecrackerError::Connection(err)
    }
}

impl From<serde_json::Error> for FirecrackerError {
    fn from(err: serde_json::Error) -> Self {
        FirecrackerError::Json(err)
    }
}

impl FirecrackerClient {
    /// Create a new Firecracker API client
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_string_lossy().into_owned(),
        }
    }

    /// Connect to the unix socket
    fn connect(&self) -> Result<UnixStream> {
        let stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(stream)
    }

    /// Make an HTTP request over the unix socket
    fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
        let mut stream = self.connect()?;

        // Build HTTP request
        let content_length = body.map(|b| b.len()).unwrap_or(0);
        let request = if let Some(body) = body {
            format!(
                "{} {} HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Accept: application/json\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 \r\n\
                 {}",
                method, path, content_length, body
            )
        } else {
            format!(
                "{} {} HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Accept: application/json\r\n\
                 \r\n",
                method, path
            )
        };

        // Send request
        stream.write_all(request.as_bytes())?;
        stream.flush()?;

        // Read response
        let mut reader = BufReader::new(stream);

        // Parse status line
        let mut status_line = String::new();
        reader.read_line(&mut status_line)?;
        let status_code = parse_status_line(&status_line)?;

        // Parse headers
        let mut content_length: usize = 0;
        loop {
            let mut header = String::new();
            reader.read_line(&mut header)?;
            if header == "\r\n" || header.is_empty() {
                break;
            }
            if let Some(len) = header.strip_prefix("Content-Length: ") {
                content_length = len.trim().parse().unwrap_or(0);
            }
            // Also check lowercase
            if let Some(len) = header.strip_prefix("content-length: ") {
                content_length = len.trim().parse().unwrap_or(0);
            }
        }

        // Read body
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body)?;
        }
        let body_str = String::from_utf8_lossy(&body).into_owned();

        Ok((status_code, body_str))
    }

    /// PUT request with JSON body
    fn put<T: Serialize>(&self, path: &str, data: &T) -> Result<()> {
        let body = serde_json::to_string(data)?;
        let (status, response_body) = self.request("PUT", path, Some(&body))?;

        if (200..300).contains(&status) {
            Ok(())
        } else {
            let msg = if response_body.is_empty() {
                "Unknown error".to_string()
            } else if let Ok(err) = serde_json::from_str::<ApiError>(&response_body) {
                err.fault_message
            } else {
                response_body
            };
            Err(FirecrackerError::Api(status, msg))
        }
    }

    /// Configure boot source (kernel and boot args)
    pub fn set_boot_source(&self, boot_source: &BootSource) -> Result<()> {
        self.put("/boot-source", boot_source)
    }

    /// Configure a drive
    pub fn set_drive(&self, drive: &Drive) -> Result<()> {
        let path = format!("/drives/{}", drive.drive_id);
        self.put(&path, drive)
    }

    /// Configure machine (vcpu, memory)
    pub fn set_machine_config(&self, config: &MachineConfig) -> Result<()> {
        self.put("/machine-config", config)
    }

    /// Configure a network interface
    pub fn set_network_interface(&self, iface: &NetworkInterface) -> Result<()> {
        let path = format!("/network-interfaces/{}", iface.iface_id);
        self.put(&path, iface)
    }

    /// Start the VM instance
    pub fn start_instance(&self) -> Result<()> {
        let action = Action {
            action_type: ActionType::InstanceStart,
        };
        self.put("/actions", &action)
    }

    /// Send Ctrl+Alt+Del to the VM (graceful shutdown)
    pub fn send_ctrl_alt_del(&self) -> Result<()> {
        let action = Action {
            action_type: ActionType::SendCtrlAltDel,
        };
        self.put("/actions", &action)
    }

    /// Check if the socket is accessible
    pub fn is_available(&self) -> bool {
        self.connect().is_ok()
    }
}

/// Parse HTTP status line and extract status code
fn parse_status_line(line: &str) -> Result<u16> {
    // Format: "HTTP/1.1 200 OK\r\n"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(FirecrackerError::Protocol(format!(
            "Invalid status line: {}",
            line.trim()
        )));
    }
    parts[1]
        .parse()
        .map_err(|_| FirecrackerError::Protocol(format!("Invalid status code: {}", parts[1])))
}

/// Generate a MAC address from VM ID
pub fn generate_mac(vm_id: &str) -> String {
    // Use VM ID to generate a deterministic MAC address
    // Format: AA:FC:00:XX:XX:XX where XX is derived from vm_id
    let bytes: Vec<u8> = vm_id.bytes().take(6).collect();
    let mut mac = [0xAAu8, 0xFC, 0x00, 0x00, 0x00, 0x00];
    for (i, b) in bytes.iter().enumerate().take(3) {
        mac[3 + i] = *b;
    }
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Build kernel boot args for a VM
pub fn build_boot_args(vm_name: &str, vm_ip: &str, gateway: &str) -> String {
    format!(
        "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/init root=/dev/vda rw ip={}::{}:255.255.255.0:{}:eth0:on",
        vm_ip, gateway, vm_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_source_serialization() {
        let boot_source = BootSource {
            kernel_image_path: "/var/lib/firecracker/vmlinux.bin".to_string(),
            boot_args: "console=ttyS0".to_string(),
        };
        let json = serde_json::to_string(&boot_source).unwrap();
        assert!(json.contains("kernel_image_path"));
        assert!(json.contains("boot_args"));
    }

    #[test]
    fn test_drive_serialization() {
        let drive = Drive {
            drive_id: "rootfs".to_string(),
            path_on_host: "/var/lib/firecracker/abc12345/rootfs.img".to_string(),
            is_root_device: true,
            is_read_only: false,
        };
        let json = serde_json::to_string(&drive).unwrap();
        assert!(json.contains("drive_id"));
        assert!(json.contains("is_root_device"));
    }

    #[test]
    fn test_machine_config_serialization() {
        let config = MachineConfig {
            vcpu_count: 2,
            mem_size_mib: 512,
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("vcpu_count"));
        assert!(json.contains("mem_size_mib"));
    }

    #[test]
    fn test_network_interface_serialization() {
        let iface = NetworkInterface {
            iface_id: "eth0".to_string(),
            guest_mac: "AA:FC:00:61:62:63".to_string(),
            host_dev_name: "tap_abc12345".to_string(),
        };
        let json = serde_json::to_string(&iface).unwrap();
        assert!(json.contains("iface_id"));
        assert!(json.contains("guest_mac"));
        assert!(json.contains("host_dev_name"));
    }

    #[test]
    fn test_action_serialization() {
        let action = Action {
            action_type: ActionType::InstanceStart,
        };
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("InstanceStart"));
    }

    #[test]
    fn test_action_ctrl_alt_del_serialization() {
        let action = Action {
            action_type: ActionType::SendCtrlAltDel,
        };
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("SendCtrlAltDel"));
    }

    #[test]
    fn test_parse_status_line_ok() {
        let status = parse_status_line("HTTP/1.1 200 OK\r\n").unwrap();
        assert_eq!(status, 200);
    }

    #[test]
    fn test_parse_status_line_no_content() {
        let status = parse_status_line("HTTP/1.1 204 No Content\r\n").unwrap();
        assert_eq!(status, 204);
    }

    #[test]
    fn test_parse_status_line_bad_request() {
        let status = parse_status_line("HTTP/1.1 400 Bad Request\r\n").unwrap();
        assert_eq!(status, 400);
    }

    #[test]
    fn test_parse_status_line_invalid() {
        let result = parse_status_line("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_mac() {
        let mac = generate_mac("abc12345");
        assert!(mac.starts_with("AA:FC:00:"));
        assert_eq!(mac.len(), 17);
        // MAC should be deterministic
        assert_eq!(mac, generate_mac("abc12345"));
    }

    #[test]
    fn test_generate_mac_different_ids() {
        let mac1 = generate_mac("abc12345");
        let mac2 = generate_mac("xyz98765");
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_build_boot_args() {
        let args = build_boot_args("myvm", "172.16.0.50", "172.16.0.1");
        assert!(args.contains("172.16.0.50"));
        assert!(args.contains("172.16.0.1"));
        assert!(args.contains("myvm"));
        assert!(args.contains("eth0:on"));
    }

    #[test]
    fn test_firecracker_client_new() {
        let client = FirecrackerClient::new("/tmp/test.socket");
        assert_eq!(client.socket_path, "/tmp/test.socket");
    }

    #[test]
    fn test_api_error_deserialization() {
        let json = r#"{"fault_message": "Invalid request"}"#;
        let err: ApiError = serde_json::from_str(json).unwrap();
        assert_eq!(err.fault_message, "Invalid request");
    }

    #[test]
    fn test_firecracker_error_display() {
        let err = FirecrackerError::Api(400, "Bad request".to_string());
        assert!(err.to_string().contains("400"));
        assert!(err.to_string().contains("Bad request"));
    }
}
