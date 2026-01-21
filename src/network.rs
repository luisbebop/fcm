// Network management (tap devices, IP allocation)

use std::collections::HashSet;
use std::fs;
use std::io;
use std::process::Command;

use crate::vm::list_vms;

/// Network gateway IP
pub const GATEWAY: &str = "172.16.0.1";

/// Subnet mask for VMs
pub const SUBNET_MASK: &str = "255.255.255.0";

/// CIDR notation for the subnet
pub const SUBNET_CIDR: &str = "172.16.0.0/24";

/// First IP in the allocation range
const IP_RANGE_START: u8 = 50;

/// Last IP in the allocation range
const IP_RANGE_END: u8 = 254;

/// Result type for network operations
pub type Result<T> = std::result::Result<T, NetworkError>;

/// Network operation errors
#[derive(Debug)]
pub enum NetworkError {
    /// Command execution failed
    Command(String),
    /// IO error
    Io(io::Error),
    /// No IPs available in the pool
    NoAvailableIp,
    /// Invalid IP address
    InvalidIp(String),
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::Command(msg) => write!(f, "Command failed: {}", msg),
            NetworkError::Io(e) => write!(f, "IO error: {}", e),
            NetworkError::NoAvailableIp => write!(f, "No available IP addresses in pool"),
            NetworkError::InvalidIp(ip) => write!(f, "Invalid IP address: {}", ip),
        }
    }
}

impl std::error::Error for NetworkError {}

impl From<io::Error> for NetworkError {
    fn from(err: io::Error) -> Self {
        NetworkError::Io(err)
    }
}

/// Get the tap device name for a VM
pub fn tap_name(vm_id: &str) -> String {
    // Tap device names are limited to 15 chars
    // "tap_" + 8 char id = 12 chars, so we're safe
    format!("tap_{}", vm_id)
}

/// Create a tap device for a VM
pub fn create_tap(vm_id: &str) -> Result<()> {
    let tap = tap_name(vm_id);

    // Create tap device
    let output = Command::new("ip")
        .args(["tuntap", "add", "dev", &tap, "mode", "tap"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore if device already exists
        if !stderr.contains("exists") {
            return Err(NetworkError::Command(format!(
                "Failed to create tap device: {}",
                stderr.trim()
            )));
        }
    }

    // Bring up the tap device
    let output = Command::new("ip")
        .args(["link", "set", &tap, "up"])
        .output()?;

    if !output.status.success() {
        return Err(NetworkError::Command(format!(
            "Failed to bring up tap device: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    // Add to bridge if fcm0 bridge exists, otherwise set IP on tap directly
    if bridge_exists("fcm0") {
        let output = Command::new("ip")
            .args(["link", "set", &tap, "master", "fcm0"])
            .output()?;

        if !output.status.success() {
            return Err(NetworkError::Command(format!(
                "Failed to add tap to bridge: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
    }

    Ok(())
}

/// Delete a tap device
pub fn delete_tap(vm_id: &str) -> Result<()> {
    let tap = tap_name(vm_id);

    let output = Command::new("ip")
        .args(["link", "delete", &tap])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore if device doesn't exist
        if !stderr.contains("Cannot find device") && !stderr.contains("No such device") {
            return Err(NetworkError::Command(format!(
                "Failed to delete tap device: {}",
                stderr.trim()
            )));
        }
    }

    Ok(())
}

/// Check if a bridge exists
fn bridge_exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Setup the network bridge and masquerading (called once on daemon start)
pub fn setup_network() -> Result<()> {
    // Create bridge if it doesn't exist
    if !bridge_exists("fcm0") {
        let output = Command::new("ip")
            .args(["link", "add", "fcm0", "type", "bridge"])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("exists") {
                return Err(NetworkError::Command(format!(
                    "Failed to create bridge: {}",
                    stderr.trim()
                )));
            }
        }
    }

    // Assign gateway IP to bridge
    let output = Command::new("ip")
        .args(["addr", "add", &format!("{}/24", GATEWAY), "dev", "fcm0"])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore if already assigned
        if !stderr.contains("RTNETLINK answers: File exists") {
            return Err(NetworkError::Command(format!(
                "Failed to assign IP to bridge: {}",
                stderr.trim()
            )));
        }
    }

    // Bring up the bridge
    let output = Command::new("ip")
        .args(["link", "set", "fcm0", "up"])
        .output()?;

    if !output.status.success() {
        return Err(NetworkError::Command(format!(
            "Failed to bring up bridge: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    // Enable IP forwarding
    fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;

    // Setup nftables masquerade for outbound traffic
    setup_masquerade()?;

    Ok(())
}

/// Setup nftables masquerade for NAT
fn setup_masquerade() -> Result<()> {
    // Check if fcm table already exists
    let check = Command::new("nft")
        .args(["list", "table", "ip", "fcm"])
        .output()?;

    if check.status.success() {
        // Table exists, skip setup
        return Ok(());
    }

    // Create nftables rules for masquerading
    // This allows VMs to access the internet through the host
    let nft_rules = r#"
table ip fcm {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 172.16.0.0/24 masquerade
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        iifname "fcm0" accept
        oifname "fcm0" accept
    }
}
"#;

    // Use shell to pipe rules to nft
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("echo '{}' | nft -f -", nft_rules.trim()))
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't fail if nft isn't available - might be using iptables
        if !stderr.contains("command not found") {
            return Err(NetworkError::Command(format!(
                "Failed to setup nftables: {}",
                stderr.trim()
            )));
        }
    }

    Ok(())
}

/// Cleanup network (called on daemon shutdown)
pub fn cleanup_network() -> Result<()> {
    // Delete the nftables table
    let _ = Command::new("nft")
        .args(["delete", "table", "ip", "fcm"])
        .output();

    // Delete the bridge
    let _ = Command::new("ip")
        .args(["link", "delete", "fcm0"])
        .output();

    Ok(())
}

/// Allocate an IP address from the pool
pub fn allocate_ip() -> Result<String> {
    let used_ips = get_used_ips()?;

    for last_octet in IP_RANGE_START..=IP_RANGE_END {
        let ip = format!("172.16.0.{}", last_octet);
        if !used_ips.contains(&ip) {
            return Ok(ip);
        }
    }

    Err(NetworkError::NoAvailableIp)
}

/// Get set of IPs currently in use by VMs
fn get_used_ips() -> Result<HashSet<String>> {
    let vms = list_vms().map_err(NetworkError::Io)?;
    Ok(vms.into_iter().map(|vm| vm.ip).collect())
}

/// Parse the last octet from an IP address
pub fn parse_last_octet(ip: &str) -> Result<u8> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return Err(NetworkError::InvalidIp(ip.to_string()));
    }
    parts[3]
        .parse()
        .map_err(|_| NetworkError::InvalidIp(ip.to_string()))
}

/// Check if an IP is in the valid range
pub fn is_valid_vm_ip(ip: &str) -> bool {
    if !ip.starts_with("172.16.0.") {
        return false;
    }
    match parse_last_octet(ip) {
        Ok(octet) => octet >= IP_RANGE_START && octet <= IP_RANGE_END,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tap_name() {
        assert_eq!(tap_name("abc12345"), "tap_abc12345");
        assert_eq!(tap_name("xy9z"), "tap_xy9z");
    }

    #[test]
    fn test_tap_name_length() {
        // Tap device names must be <= 15 chars
        let name = tap_name("12345678");
        assert!(name.len() <= 15);
    }

    #[test]
    fn test_parse_last_octet() {
        assert_eq!(parse_last_octet("172.16.0.50").unwrap(), 50);
        assert_eq!(parse_last_octet("172.16.0.254").unwrap(), 254);
        assert_eq!(parse_last_octet("10.0.0.1").unwrap(), 1);
    }

    #[test]
    fn test_parse_last_octet_invalid() {
        assert!(parse_last_octet("invalid").is_err());
        assert!(parse_last_octet("172.16.0").is_err());
        assert!(parse_last_octet("172.16.0.abc").is_err());
    }

    #[test]
    fn test_is_valid_vm_ip() {
        assert!(is_valid_vm_ip("172.16.0.50"));
        assert!(is_valid_vm_ip("172.16.0.100"));
        assert!(is_valid_vm_ip("172.16.0.254"));
    }

    #[test]
    fn test_is_valid_vm_ip_out_of_range() {
        // Below range
        assert!(!is_valid_vm_ip("172.16.0.49"));
        assert!(!is_valid_vm_ip("172.16.0.1"));
        // Wrong subnet
        assert!(!is_valid_vm_ip("10.0.0.50"));
        assert!(!is_valid_vm_ip("172.16.1.50"));
    }

    #[test]
    fn test_is_valid_vm_ip_invalid() {
        assert!(!is_valid_vm_ip("invalid"));
        assert!(!is_valid_vm_ip("172.16.0"));
    }

    #[test]
    fn test_gateway_constant() {
        assert_eq!(GATEWAY, "172.16.0.1");
    }

    #[test]
    fn test_subnet_mask_constant() {
        assert_eq!(SUBNET_MASK, "255.255.255.0");
    }

    #[test]
    fn test_network_error_display() {
        let err = NetworkError::NoAvailableIp;
        assert!(err.to_string().contains("No available IP"));

        let err = NetworkError::InvalidIp("bad".to_string());
        assert!(err.to_string().contains("bad"));

        let err = NetworkError::Command("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_ip_range_valid() {
        // Verify range constants are valid
        assert!(IP_RANGE_START < IP_RANGE_END);
        assert!(IP_RANGE_START >= 50);
        assert!(IP_RANGE_END <= 254);
    }
}
