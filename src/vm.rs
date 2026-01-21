// VM management module

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const BASE_DIR: &str = "/var/lib/firecracker";

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

    /// Load config by VM ID
    pub fn load_by_id(id: &str) -> io::Result<Self> {
        let vm_dir = PathBuf::from(BASE_DIR).join(id);
        Self::load(&vm_dir)
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
}
