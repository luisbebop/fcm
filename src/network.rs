// Network management (tap devices, IP allocation)

use std::collections::HashSet;
use std::fs;
use std::io;
use std::process::Command;

use crate::vm::list_vms;

/// Network gateway IP
pub const GATEWAY: &str = "172.16.0.1";

/// First IP in the allocation range
const IP_RANGE_START: u8 = 50;

/// Last IP in the allocation range
const IP_RANGE_END: u8 = 254;

// Compile-time validation of IP range constants
const _: () = {
    assert!(IP_RANGE_START < IP_RANGE_END);
    assert!(IP_RANGE_START >= 50);
    assert!(IP_RANGE_END <= 254);
};

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
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkError::Command(msg) => write!(f, "Command failed: {}", msg),
            NetworkError::Io(e) => write!(f, "IO error: {}", e),
            NetworkError::NoAvailableIp => write!(f, "No available IP addresses in pool"),
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

    // Create nftables rules for masquerading and VM isolation
    // This allows VMs to access the internet through the host
    // but blocks direct VM-to-VM SSH connections for security
    let nft_rules = r#"
table ip fcm {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 172.16.0.0/24 masquerade
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        # Block VM-to-VM SSH (isolation) - host can still SSH to VMs
        ip saddr 172.16.0.0/24 ip daddr 172.16.0.0/24 tcp dport 22 drop
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
    fn test_gateway_constant() {
        assert_eq!(GATEWAY, "172.16.0.1");
    }

    #[test]
    fn test_network_error_display() {
        let err = NetworkError::NoAvailableIp;
        assert!(err.to_string().contains("No available IP"));

        let err = NetworkError::Command("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }

}
