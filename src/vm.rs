// VM management module

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::caddy;
use crate::firecracker::{
    self, BootSource, Drive, FirecrackerClient, MachineConfig, NetworkInterface,
};
use crate::git;
use crate::network;

pub const BASE_DIR: &str = "/var/lib/firecracker";
const KERNEL_PATH: &str = "/var/lib/firecracker/vmlinux.bin";
const BASE_ROOTFS_PATH: &str = "/var/lib/firecracker/base-rootfs.img";

/// Default VM configuration
const DEFAULT_VCPU_COUNT: u8 = 1;
const DEFAULT_MEM_SIZE_MIB: u32 = 512;

const ADJECTIVES: &[&str] = &[
    "cosmic", "quantum", "stellar", "solar", "lunar", "orbital", "nebula",
    "cyber", "digital", "neural", "binary", "atomic", "photon", "plasma",
    "misty", "crystal", "amber", "coral", "forest", "arctic", "alpine",
];

const NOUNS: &[&str] = &[
    "nova", "comet", "pulsar", "quasar", "aurora", "eclipse", "meteor",
    "circuit", "matrix", "nexus", "vertex", "tensor", "vector", "cipher",
    "river", "canyon", "glacier", "meadow", "reef", "grove", "peak",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum VmState {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposeConfig {
    pub port: u16,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub state: VmState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expose: Option<ExposeConfig>,
}

impl VmConfig {
    /// Create a new VM config with generated ID
    pub fn new(name: Option<String>, ip: String, expose: Option<ExposeConfig>) -> Self {
        let id = generate_id();
        let name = name.unwrap_or_else(random_name);
        Self {
            id,
            name,
            ip,
            state: VmState::Running,
            expose,
        }
    }

    /// Get the VM's directory path
    pub fn dir(&self) -> PathBuf {
        PathBuf::from(BASE_DIR).join(&self.id)
    }

    /// Get the config.json path for this VM
    pub fn config_path(&self) -> PathBuf {
        self.dir().join("config.json")
    }

    /// Get the rootfs.img path for this VM
    pub fn rootfs_path(&self) -> PathBuf {
        self.dir().join("rootfs.img")
    }

    /// Get the firecracker socket path for this VM
    pub fn socket_path(&self) -> PathBuf {
        self.dir().join("firecracker.socket")
    }

    /// Get the firecracker PID file path for this VM
    pub fn pid_path(&self) -> PathBuf {
        self.dir().join("firecracker.pid")
    }

    /// Save config to disk
    pub fn save(&self) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(self.config_path(), json)
    }

    /// Load config from a VM directory
    pub fn load(vm_dir: &Path) -> io::Result<Self> {
        let config_path = vm_dir.join("config.json");
        let json = fs::read_to_string(config_path)?;
        serde_json::from_str(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Generate a random 8-character alphanumeric ID
pub fn generate_id() -> String {
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// Generate a random name from adjective-noun combinations
pub fn random_name() -> String {
    let mut rng = rand::thread_rng();
    let adj = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.gen_range(0..NOUNS.len())];
    format!("{}-{}", adj, noun)
}

/// List all VMs by reading config files from BASE_DIR
pub fn list_vms() -> io::Result<Vec<VmConfig>> {
    let base = PathBuf::from(BASE_DIR);
    if !base.exists() {
        return Ok(Vec::new());
    }

    let mut vms = Vec::new();
    for entry in fs::read_dir(base)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            // Skip hidden directories like .token
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') {
                    continue;
                }
            }
            if let Ok(config) = VmConfig::load(&path) {
                vms.push(config);
            }
        }
    }
    Ok(vms)
}

/// Find a VM by name or ID
pub fn find_vm(name_or_id: &str) -> io::Result<VmConfig> {
    let vms = list_vms()?;
    vms.into_iter()
        .find(|vm| vm.id == name_or_id || vm.name == name_or_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("VM '{}' not found", name_or_id)))
}

/// Result type for VM operations
pub type Result<T> = std::result::Result<T, VmError>;

/// VM operation errors
#[derive(Debug)]
pub enum VmError {
    /// IO error
    Io(io::Error),
    /// Network error
    Network(network::NetworkError),
    /// Firecracker error
    Firecracker(firecracker::FirecrackerError),
    /// Caddy error
    Caddy(caddy::CaddyError),
    /// Git error
    Git(git::GitError),
    /// VM not found
    NotFound(String),
    /// Invalid state for operation
    InvalidState(String),
    /// Resource not available
    ResourceNotAvailable(String),
    /// Process error
    Process(String),
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmError::Io(e) => write!(f, "IO error: {}", e),
            VmError::Network(e) => write!(f, "Network error: {}", e),
            VmError::Firecracker(e) => write!(f, "Firecracker error: {}", e),
            VmError::Caddy(e) => write!(f, "Caddy error: {}", e),
            VmError::Git(e) => write!(f, "Git error: {}", e),
            VmError::NotFound(msg) => write!(f, "Not found: {}", msg),
            VmError::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            VmError::ResourceNotAvailable(msg) => write!(f, "Resource not available: {}", msg),
            VmError::Process(msg) => write!(f, "Process error: {}", msg),
        }
    }
}

impl std::error::Error for VmError {}

impl From<io::Error> for VmError {
    fn from(err: io::Error) -> Self {
        VmError::Io(err)
    }
}

impl From<network::NetworkError> for VmError {
    fn from(err: network::NetworkError) -> Self {
        VmError::Network(err)
    }
}

impl From<firecracker::FirecrackerError> for VmError {
    fn from(err: firecracker::FirecrackerError) -> Self {
        VmError::Firecracker(err)
    }
}

impl From<caddy::CaddyError> for VmError {
    fn from(err: caddy::CaddyError) -> Self {
        VmError::Caddy(err)
    }
}

impl From<git::GitError> for VmError {
    fn from(err: git::GitError) -> Self {
        VmError::Git(err)
    }
}

/// Inject an SSH public key into a rootfs image
fn inject_ssh_key(rootfs_path: &Path, ssh_public_key: &str) -> Result<()> {
    // Create a temporary mount point
    let mount_point = rootfs_path.parent().unwrap().join("mnt");
    fs::create_dir_all(&mount_point)?;

    // Mount the rootfs image
    let mount_output = Command::new("mount")
        .args(["-o", "loop", rootfs_path.to_str().unwrap(), mount_point.to_str().unwrap()])
        .output()?;

    if !mount_output.status.success() {
        let _ = fs::remove_dir(&mount_point);
        return Err(VmError::Process(format!(
            "Failed to mount rootfs: {}",
            String::from_utf8_lossy(&mount_output.stderr)
        )));
    }

    // Create /root/.ssh directory
    let ssh_dir = mount_point.join("root/.ssh");
    let result = (|| -> Result<()> {
        fs::create_dir_all(&ssh_dir)?;

        // Write authorized_keys
        let auth_keys_path = ssh_dir.join("authorized_keys");
        fs::write(&auth_keys_path, format!("{}\n", ssh_public_key))?;

        // Set permissions: directory 700, file 600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&auth_keys_path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    })();

    // Always unmount, even if there was an error
    let unmount_output = Command::new("umount")
        .arg(mount_point.to_str().unwrap())
        .output()?;

    // Remove mount point directory
    let _ = fs::remove_dir(&mount_point);

    // Check unmount success
    if !unmount_output.status.success() {
        return Err(VmError::Process(format!(
            "Failed to unmount rootfs: {}",
            String::from_utf8_lossy(&unmount_output.stderr)
        )));
    }

    result
}

/// Create a new VM
///
/// This function:
/// 1. Allocates an IP from the pool
/// 2. Creates the VM directory
/// 3. Copies the base rootfs (sparse copy)
/// 4. Injects SSH public key if provided
/// 5. Creates the tap device
/// 6. Spawns the firecracker process
/// 7. Configures firecracker via API
/// 8. Starts the VM
/// 9. If expose is set, configures Caddy
pub fn create_vm(name: Option<String>, expose_port: Option<u16>, ssh_public_key: Option<String>) -> Result<VmConfig> {
    // Check that required files exist
    if !Path::new(KERNEL_PATH).exists() {
        return Err(VmError::ResourceNotAvailable(format!(
            "Kernel not found at {}",
            KERNEL_PATH
        )));
    }
    if !Path::new(BASE_ROOTFS_PATH).exists() {
        return Err(VmError::ResourceNotAvailable(format!(
            "Base rootfs not found at {}",
            BASE_ROOTFS_PATH
        )));
    }

    // Allocate IP
    let ip = network::allocate_ip()?;

    // Generate name first (needed for domain)
    let vm_name = name.unwrap_or_else(random_name);

    // Create VM config
    let expose_config = if let Some(port) = expose_port {
        // Get server public IP for sslip.io domain
        let server_ip = caddy::get_server_ip()?;
        let domain = caddy::generate_domain(&vm_name, &server_ip);
        Some(ExposeConfig { port, domain })
    } else {
        None
    };

    let config = VmConfig::new(Some(vm_name), ip.clone(), expose_config);

    // Create VM directory
    fs::create_dir_all(config.dir())?;

    // Copy rootfs with sparse support
    let rootfs_dest = config.rootfs_path();
    let output = Command::new("cp")
        .args(["--sparse=always", BASE_ROOTFS_PATH, rootfs_dest.to_str().unwrap()])
        .output()?;

    if !output.status.success() {
        // Cleanup on failure
        let _ = fs::remove_dir_all(config.dir());
        return Err(VmError::Process(format!(
            "Failed to copy rootfs: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Inject SSH public key if provided
    if let Some(ref key) = ssh_public_key {
        if let Err(e) = inject_ssh_key(&rootfs_dest, key) {
            let _ = fs::remove_dir_all(config.dir());
            return Err(e);
        }
    }

    // Create tap device
    if let Err(e) = network::create_tap(&config.id) {
        // Cleanup on failure
        let _ = fs::remove_dir_all(config.dir());
        return Err(e.into());
    }

    // Spawn firecracker process
    let fc_result = spawn_firecracker(&config);
    if let Err(e) = fc_result {
        // Cleanup on failure
        let _ = network::delete_tap(&config.id);
        let _ = fs::remove_dir_all(config.dir());
        return Err(e);
    }

    // Wait for socket to be available
    let socket_path = config.socket_path();
    if !wait_for_socket(&socket_path, Duration::from_secs(5)) {
        // Cleanup on failure
        kill_firecracker(&config);
        let _ = network::delete_tap(&config.id);
        let _ = fs::remove_dir_all(config.dir());
        return Err(VmError::Process("Firecracker socket not available".to_string()));
    }

    // Configure firecracker
    let fc_client = FirecrackerClient::new(&socket_path);

    // Set boot source
    let boot_args = firecracker::build_boot_args(&config.name, &config.ip, network::GATEWAY);
    let boot_source = BootSource {
        kernel_image_path: KERNEL_PATH.to_string(),
        boot_args,
    };
    if let Err(e) = fc_client.set_boot_source(&boot_source) {
        cleanup_failed_vm(&config);
        return Err(e.into());
    }

    // Set rootfs drive
    let drive = Drive {
        drive_id: "rootfs".to_string(),
        path_on_host: rootfs_dest.to_string_lossy().into_owned(),
        is_root_device: true,
        is_read_only: false,
    };
    if let Err(e) = fc_client.set_drive(&drive) {
        cleanup_failed_vm(&config);
        return Err(e.into());
    }

    // Set machine config
    let machine_config = MachineConfig {
        vcpu_count: DEFAULT_VCPU_COUNT,
        mem_size_mib: DEFAULT_MEM_SIZE_MIB,
    };
    if let Err(e) = fc_client.set_machine_config(&machine_config) {
        cleanup_failed_vm(&config);
        return Err(e.into());
    }

    // Set network interface
    let tap_name = network::tap_name(&config.id);
    let mac = firecracker::generate_mac(&config.id);
    let network_iface = NetworkInterface {
        iface_id: "eth0".to_string(),
        guest_mac: mac,
        host_dev_name: tap_name,
    };
    if let Err(e) = fc_client.set_network_interface(&network_iface) {
        cleanup_failed_vm(&config);
        return Err(e.into());
    }

    // Start the VM
    if let Err(e) = fc_client.start_instance() {
        cleanup_failed_vm(&config);
        return Err(e.into());
    }

    // Save config
    config.save()?;

    // Configure Caddy if exposing a port
    if let Some(ref expose) = config.expose {
        if let Err(e) = caddy::add_site(&expose.domain, &config.ip, expose.port) {
            eprintln!("Warning: Failed to add Caddy site: {}", e);
            // Don't fail the VM creation for this
        } else if let Err(e) = caddy::reload() {
            eprintln!("Warning: Failed to reload Caddy: {}", e);
        }
    }

    // Create git repository for Procfile deployments
    if let Err(e) = git::create_repo(&config.name, &config.ip) {
        eprintln!("Warning: Failed to create git repo: {}", e);
        // Don't fail the VM creation for this
    }

    Ok(config)
}

/// Stop a running VM
pub fn stop_vm(name_or_id: &str) -> Result<VmConfig> {
    let mut config = find_vm(name_or_id)
        .map_err(|_| VmError::NotFound(format!("VM '{}' not found", name_or_id)))?;

    if config.state == VmState::Stopped {
        return Err(VmError::InvalidState("VM is already stopped".to_string()));
    }

    // Try graceful shutdown first via Firecracker API
    let socket_path = config.socket_path();
    if socket_path.exists() {
        let fc_client = FirecrackerClient::new(&socket_path);
        if fc_client.is_available() {
            // Send Ctrl+Alt+Del for graceful shutdown
            let _ = fc_client.send_ctrl_alt_del();
            // Wait a bit for graceful shutdown
            thread::sleep(Duration::from_secs(2));
        }
    }

    // Kill firecracker process
    kill_firecracker(&config);

    // Delete tap device
    let _ = network::delete_tap(&config.id);

    // Remove socket file
    let _ = fs::remove_file(config.socket_path());

    // Update state
    config.state = VmState::Stopped;
    config.save()?;

    Ok(config)
}

/// Start a stopped VM
pub fn start_vm(name_or_id: &str) -> Result<VmConfig> {
    let mut config = find_vm(name_or_id)
        .map_err(|_| VmError::NotFound(format!("VM '{}' not found", name_or_id)))?;

    if config.state == VmState::Running {
        return Err(VmError::InvalidState("VM is already running".to_string()));
    }

    // Check that rootfs exists
    if !config.rootfs_path().exists() {
        return Err(VmError::ResourceNotAvailable("VM rootfs not found".to_string()));
    }

    // Create tap device
    network::create_tap(&config.id)?;

    // Spawn firecracker process
    spawn_firecracker(&config)?;

    // Wait for socket to be available
    let socket_path = config.socket_path();
    if !wait_for_socket(&socket_path, Duration::from_secs(5)) {
        kill_firecracker(&config);
        let _ = network::delete_tap(&config.id);
        return Err(VmError::Process("Firecracker socket not available".to_string()));
    }

    // Configure firecracker
    let fc_client = FirecrackerClient::new(&socket_path);

    // Set boot source
    let boot_args = firecracker::build_boot_args(&config.name, &config.ip, network::GATEWAY);
    let boot_source = BootSource {
        kernel_image_path: KERNEL_PATH.to_string(),
        boot_args,
    };
    fc_client.set_boot_source(&boot_source)?;

    // Set rootfs drive
    let drive = Drive {
        drive_id: "rootfs".to_string(),
        path_on_host: config.rootfs_path().to_string_lossy().into_owned(),
        is_root_device: true,
        is_read_only: false,
    };
    fc_client.set_drive(&drive)?;

    // Set machine config
    let machine_config = MachineConfig {
        vcpu_count: DEFAULT_VCPU_COUNT,
        mem_size_mib: DEFAULT_MEM_SIZE_MIB,
    };
    fc_client.set_machine_config(&machine_config)?;

    // Set network interface
    let tap_name = network::tap_name(&config.id);
    let mac = firecracker::generate_mac(&config.id);
    let network_iface = NetworkInterface {
        iface_id: "eth0".to_string(),
        guest_mac: mac,
        host_dev_name: tap_name,
    };
    fc_client.set_network_interface(&network_iface)?;

    // Start the VM
    fc_client.start_instance()?;

    // Update state
    config.state = VmState::Running;
    config.save()?;

    Ok(config)
}

/// Destroy a VM completely
pub fn destroy_vm(name_or_id: &str) -> Result<()> {
    let config = find_vm(name_or_id)
        .map_err(|_| VmError::NotFound(format!("VM '{}' not found", name_or_id)))?;

    // Stop the VM if running
    if config.state == VmState::Running {
        // Try graceful shutdown
        let socket_path = config.socket_path();
        if socket_path.exists() {
            let fc_client = FirecrackerClient::new(&socket_path);
            if fc_client.is_available() {
                let _ = fc_client.send_ctrl_alt_del();
                thread::sleep(Duration::from_millis(500));
            }
        }
        kill_firecracker(&config);
    }

    // Delete tap device
    let _ = network::delete_tap(&config.id);

    // Remove from Caddy if exposed
    if let Some(ref expose) = config.expose {
        if let Err(e) = caddy::remove_site(&expose.domain) {
            eprintln!("Warning: Failed to remove Caddy site: {}", e);
        } else if let Err(e) = caddy::reload() {
            eprintln!("Warning: Failed to reload Caddy: {}", e);
        }
    }

    // Remove git repository
    if let Err(e) = git::delete_repo(&config.name) {
        eprintln!("Warning: Failed to delete git repo: {}", e);
    }

    // Remove VM directory
    fs::remove_dir_all(config.dir())?;

    Ok(())
}

/// Spawn the firecracker process
fn spawn_firecracker(config: &VmConfig) -> Result<Child> {
    let socket_path = config.socket_path();
    let pid_path = config.pid_path();

    // Remove old socket if exists
    let _ = fs::remove_file(&socket_path);

    // Spawn firecracker process
    let child = Command::new("firecracker")
        .args([
            "--api-sock",
            socket_path.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| VmError::Process(format!("Failed to spawn firecracker: {}", e)))?;

    // Save PID
    fs::write(&pid_path, child.id().to_string())?;

    Ok(child)
}

/// Kill the firecracker process for a VM
fn kill_firecracker(config: &VmConfig) {
    let pid_path = config.pid_path();

    if let Ok(pid_str) = fs::read_to_string(&pid_path) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            // Send SIGTERM first for graceful shutdown
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            thread::sleep(Duration::from_millis(500));

            // Check if still running and send SIGKILL
            unsafe {
                if libc::kill(pid, 0) == 0 {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
    }

    // Remove PID file
    let _ = fs::remove_file(&pid_path);
}

/// Wait for the firecracker socket to become available
fn wait_for_socket(socket_path: &Path, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if socket_path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Clean up a failed VM creation
fn cleanup_failed_vm(config: &VmConfig) {
    kill_firecracker(config);
    let _ = network::delete_tap(&config.id);
    let _ = fs::remove_dir_all(config.dir());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id_length() {
        let id = generate_id();
        assert_eq!(id.len(), 8);
    }

    #[test]
    fn test_generate_id_alphanumeric() {
        let id = generate_id();
        assert!(id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_id_unique() {
        let id1 = generate_id();
        let id2 = generate_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_random_name_format() {
        let name = random_name();
        assert!(name.contains('-'));
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert!(ADJECTIVES.contains(&parts[0]));
        assert!(NOUNS.contains(&parts[1]));
    }

    #[test]
    fn test_vm_config_new() {
        let config = VmConfig::new(None, "172.16.0.50".to_string(), None);
        assert_eq!(config.id.len(), 8);
        assert!(config.name.contains('-'));
        assert_eq!(config.ip, "172.16.0.50");
        assert_eq!(config.state, VmState::Running);
        assert!(config.expose.is_none());
    }

    #[test]
    fn test_vm_config_with_name() {
        let config = VmConfig::new(Some("myvm".to_string()), "172.16.0.50".to_string(), None);
        assert_eq!(config.name, "myvm");
    }

    #[test]
    fn test_vm_config_with_expose() {
        let expose = ExposeConfig {
            port: 8000,
            domain: "myvm.64-34-93-45.sslip.io".to_string(),
        };
        let config = VmConfig::new(Some("myvm".to_string()), "172.16.0.50".to_string(), Some(expose));
        assert!(config.expose.is_some());
        assert_eq!(config.expose.as_ref().unwrap().port, 8000);
    }

    #[test]
    fn test_vm_config_serialization() {
        let config = VmConfig::new(Some("test".to_string()), "172.16.0.50".to_string(), None);
        let json = serde_json::to_string(&config).unwrap();
        let parsed: VmConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.ip, "172.16.0.50");
    }

    #[test]
    fn test_vm_paths() {
        let mut config = VmConfig::new(Some("test".to_string()), "172.16.0.50".to_string(), None);
        config.id = "abc12345".to_string();

        assert_eq!(config.dir(), PathBuf::from("/var/lib/firecracker/abc12345"));
        assert_eq!(config.config_path(), PathBuf::from("/var/lib/firecracker/abc12345/config.json"));
        assert_eq!(config.rootfs_path(), PathBuf::from("/var/lib/firecracker/abc12345/rootfs.img"));
        assert_eq!(config.socket_path(), PathBuf::from("/var/lib/firecracker/abc12345/firecracker.socket"));
    }

    #[test]
    fn test_vm_error_display() {
        let err = VmError::NotFound("test-vm".to_string());
        assert!(err.to_string().contains("test-vm"));

        let err = VmError::InvalidState("already running".to_string());
        assert!(err.to_string().contains("already running"));

        let err = VmError::ResourceNotAvailable("kernel".to_string());
        assert!(err.to_string().contains("kernel"));

        let err = VmError::Process("spawn failed".to_string());
        assert!(err.to_string().contains("spawn failed"));
    }

    #[test]
    fn test_vm_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let vm_err: VmError = io_err.into();
        assert!(matches!(vm_err, VmError::Io(_)));
    }

    #[test]
    fn test_kernel_path_constant() {
        assert_eq!(KERNEL_PATH, "/var/lib/firecracker/vmlinux.bin");
    }

    #[test]
    fn test_base_rootfs_path_constant() {
        assert_eq!(BASE_ROOTFS_PATH, "/var/lib/firecracker/base-rootfs.img");
    }

    #[test]
    fn test_default_vm_config() {
        assert_eq!(DEFAULT_VCPU_COUNT, 1);
        assert_eq!(DEFAULT_MEM_SIZE_MIB, 512);
    }
}
