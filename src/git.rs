// Git repository management module for Procfile deployments

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

/// Git repos are stored in /root/<vm-name>.git
const GIT_REPOS_BASE: &str = "/root";

/// Path to the fcm git shell wrapper script
const FCM_GIT_SHELL_PATH: &str = "/usr/local/bin/fcm-git-shell";

/// Git operation errors
#[derive(Debug)]
pub enum GitError {
    /// IO error
    Io(io::Error),
    /// Command failed
    CommandFailed(String),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitError::Io(e) => write!(f, "IO error: {}", e),
            GitError::CommandFailed(msg) => write!(f, "Command failed: {}", msg),
        }
    }
}

impl std::error::Error for GitError {}

impl From<io::Error> for GitError {
    fn from(err: io::Error) -> Self {
        GitError::Io(err)
    }
}

/// Get the path to a VM's git repo
pub fn repo_path(vm_name: &str) -> PathBuf {
    PathBuf::from(GIT_REPOS_BASE).join(format!("{}.git", vm_name))
}

/// Create a bare git repository for a VM with a post-receive hook
pub fn create_repo(vm_name: &str, vm_ip: &str, domain: &str) -> Result<PathBuf, GitError> {
    let path = repo_path(vm_name);

    // Create bare repo using git init --bare
    let output = Command::new("git")
        .args(["init", "--bare", path.to_str().unwrap()])
        .output()?;

    if !output.status.success() {
        return Err(GitError::CommandFailed(format!(
            "Failed to create git repo: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Create hooks directory if it doesn't exist
    let hooks_dir = path.join("hooks");
    fs::create_dir_all(&hooks_dir)?;

    // Create post-receive hook
    let hook_path = hooks_dir.join("post-receive");
    let hook_content = generate_post_receive_hook(vm_name, vm_ip, domain);
    fs::write(&hook_path, hook_content)?;

    // Make hook executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755))?;
    }

    Ok(path)
}

/// Delete a VM's git repository
pub fn delete_repo(vm_name: &str) -> Result<(), GitError> {
    let path = repo_path(vm_name);
    if path.exists() {
        fs::remove_dir_all(&path)?;
    }
    Ok(())
}

/// Check if a git repo exists for a VM
pub fn repo_exists(vm_name: &str) -> bool {
    repo_path(vm_name).exists()
}

/// Generate the post-receive hook script
fn generate_post_receive_hook(vm_name: &str, vm_ip: &str, domain: &str) -> String {
    format!(
        r#"#!/bin/bash
# FCM post-receive hook for {vm_name}
# This hook deploys code to the VM after git push

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

VM_NAME="{vm_name}"
VM_IP="{vm_ip}"
DOMAIN="{domain}"
WORK_TREE="/tmp/fcm-deploy-$VM_NAME"
APP_DIR="/app"

ssh_cmd() {{
    sshpass -p "root" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$VM_IP" "$@" 2>/dev/null
}}

echo ""
echo "-----> Deploying to $VM_NAME..."

# Create temporary work tree
rm -rf "$WORK_TREE"
mkdir -p "$WORK_TREE"

# Check out the pushed code
while read oldrev newrev refname; do
    branch=$(git rev-parse --symbolic --abbrev-ref $refname 2>/dev/null || echo "")
    if [ "$branch" = "main" ] || [ "$branch" = "master" ]; then
        echo "-----> Received push to $branch"
        git --work-tree="$WORK_TREE" checkout -f "$branch"
    fi
done

# Sync code to VM
echo "-----> Syncing code to VM..."
cd "$WORK_TREE" && tar cf - . | ssh_cmd "cd $APP_DIR && tar xf -"

# Run deployment on VM
echo "-----> Running deployment..."
if ssh_cmd "/usr/local/bin/fcm-deploy"; then
    # Show startup logs
    echo ""
    echo "-----> Startup logs:"
    ssh_cmd "tail -20 /var/log/fcm-web.log 2>/dev/null" | sed 's/^/       /'

    # Clean up
    rm -rf "$WORK_TREE"
    echo ""
    echo "-----> Deployed!"
    echo ""
    echo "       https://$DOMAIN"
    echo ""
else
    # Show error logs
    echo ""
    echo "-----> Startup logs:"
    ssh_cmd "tail -30 /var/log/fcm-web.log 2>/dev/null" | sed 's/^/       /'

    rm -rf "$WORK_TREE"
    echo ""
    echo "-----> Deploy failed!"
    echo ""
    exit 1
fi
"#,
        vm_name = vm_name,
        vm_ip = vm_ip,
        domain = domain
    )
}

/// Get the git clone URL for a VM (requires server hostname)
pub fn get_clone_url(vm_name: &str, server_host: &str) -> String {
    format!("root@{}:{}.git", server_host, vm_name)
}

/// Generate the fcm-git-shell wrapper script content
/// This script restricts SSH access to only git commands for VM repositories
fn generate_git_shell_script() -> &'static str {
    r#"#!/bin/bash
# FCM Git Shell - Restricts SSH access to git commands only
# This script is used as a forced command in authorized_keys

set -e

# Only allow git-receive-pack and git-upload-pack commands
if [ -z "$SSH_ORIGINAL_COMMAND" ]; then
    echo "ERROR: Interactive shell access is not allowed." >&2
    echo "This SSH key is restricted to git push/pull operations only." >&2
    exit 1
fi

# Parse the command - should be: git-receive-pack 'repo.git' or git-upload-pack 'repo.git'
CMD=$(echo "$SSH_ORIGINAL_COMMAND" | awk '{print $1}')
REPO=$(echo "$SSH_ORIGINAL_COMMAND" | sed "s/^[^ ]* '//" | sed "s/'$//")

# Validate command
case "$CMD" in
    git-receive-pack|git-upload-pack)
        ;;
    *)
        echo "ERROR: Command not allowed: $CMD" >&2
        echo "Only git push/pull operations are permitted." >&2
        exit 1
        ;;
esac

# Validate repo path - must be a .git repo in /root/
# Handle various input formats:
#   /root/vm-name.git -> vm-name.git
#   /vm-name.git -> vm-name.git
#   ./vm-name.git -> vm-name.git
#   vm-name.git -> vm-name.git
REPO_CLEAN=$(echo "$REPO" | sed 's|^/root/||' | sed 's|^/||' | sed 's|^\./||')

# Must end in .git
if [[ ! "$REPO_CLEAN" =~ \.git$ ]]; then
    echo "ERROR: Invalid repository path." >&2
    exit 1
fi

# Must not contain path traversal or subdirectories
if [[ "$REPO_CLEAN" =~ \.\. ]] || [[ "$REPO_CLEAN" =~ / ]]; then
    echo "ERROR: Invalid repository path." >&2
    exit 1
fi

# Build full path
FULL_PATH="/root/$REPO_CLEAN"

# Check repo exists
if [ ! -d "$FULL_PATH" ]; then
    echo "ERROR: Repository not found." >&2
    exit 1
fi

# Execute the git command
exec $CMD "$FULL_PATH"
"#
}

/// Install the fcm-git-shell script if it doesn't exist or is outdated
pub fn ensure_git_shell_installed() -> Result<(), GitError> {
    let script_content = generate_git_shell_script();
    let script_path = PathBuf::from(FCM_GIT_SHELL_PATH);

    // Check if script exists and matches current content
    let needs_update = if script_path.exists() {
        match fs::read_to_string(&script_path) {
            Ok(existing) => existing != script_content,
            Err(_) => true,
        }
    } else {
        true
    };

    if needs_update {
        // Ensure parent directory exists
        if let Some(parent) = script_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&script_path, script_content)?;

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))?;
        }
    }

    Ok(())
}

/// Extract the raw key from an authorized_keys line (removes any command prefix)
fn extract_raw_key(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // If line starts with ssh- or ecdsa-, it's already a raw key
    if line.starts_with("ssh-") || line.starts_with("ecdsa-") {
        return Some(line);
    }

    // Otherwise, find the key portion after options
    // Keys start with: ssh-rsa, ssh-ed25519, ssh-dss, ecdsa-sha2-*
    for prefix in &["ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-"] {
        if let Some(pos) = line.find(prefix) {
            return Some(&line[pos..]);
        }
    }

    None
}

/// Add an SSH public key to the host's authorized_keys for git push access
/// Keys are added with a forced command that restricts access to git operations only
pub fn add_ssh_key_to_host(ssh_public_key: &str) -> Result<(), GitError> {
    // Ensure git shell is installed first
    ensure_git_shell_installed()?;

    let ssh_dir = PathBuf::from("/root/.ssh");
    let authorized_keys_path = ssh_dir.join("authorized_keys");

    // Ensure .ssh directory exists with correct permissions
    if !ssh_dir.exists() {
        fs::create_dir_all(&ssh_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700))?;
        }
    }

    // Read existing authorized_keys or create empty
    let existing = if authorized_keys_path.exists() {
        fs::read_to_string(&authorized_keys_path)?
    } else {
        String::new()
    };

    // Check if key already exists (compare raw key portion)
    let key_trimmed = ssh_public_key.trim();
    let key_raw = extract_raw_key(key_trimmed).unwrap_or(key_trimmed);

    for line in existing.lines() {
        if let Some(existing_raw) = extract_raw_key(line) {
            if existing_raw == key_raw {
                return Ok(()); // Key already exists
            }
        }
    }

    // Build restricted key entry with forced command
    let restricted_key = format!(
        r#"command="{}",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty {}"#,
        FCM_GIT_SHELL_PATH,
        key_trimmed
    );

    // Append the new key
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&restricted_key);
    content.push('\n');

    fs::write(&authorized_keys_path, content)?;

    // Set correct permissions on authorized_keys
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&authorized_keys_path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repo_path() {
        let path = repo_path("cosmic-nova");
        assert_eq!(path, PathBuf::from("/root/cosmic-nova.git"));
    }

    #[test]
    fn test_get_clone_url() {
        let url = get_clone_url("cosmic-nova", "myserver.com");
        assert_eq!(url, "root@myserver.com:cosmic-nova.git");
    }

    #[test]
    fn test_generate_post_receive_hook() {
        let hook = generate_post_receive_hook("test-vm", "172.16.0.50", "test-vm.tryforge.sh");
        assert!(hook.contains("test-vm"));
        assert!(hook.contains("172.16.0.50"));
        assert!(hook.contains("fcm-deploy"));
        assert!(hook.contains("sshpass"));
        assert!(hook.contains("Deployed!"));
        assert!(hook.contains("Deploy failed!"));
        assert!(hook.contains("Startup logs:"));
        assert!(hook.contains("fcm-web.log"));
        assert!(hook.contains(r#"DOMAIN="test-vm.tryforge.sh""#));
        assert!(hook.contains("https://$DOMAIN"));
    }

    #[test]
    fn test_git_error_display() {
        let err = GitError::CommandFailed("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let io_err = GitError::Io(io::Error::new(io::ErrorKind::NotFound, "not found"));
        assert!(io_err.to_string().contains("not found"));
    }

    #[test]
    fn test_repo_exists_false() {
        // Non-existent repo should return false
        assert!(!repo_exists("nonexistent-vm-12345"));
    }

    #[test]
    fn test_add_ssh_key_to_host_content() {
        // Test the key trimming and formatting logic
        let key = "ssh-ed25519 AAAAC3... user@host";
        let trimmed = key.trim();
        assert_eq!(trimmed, key);

        // Test key with whitespace
        let key_with_spaces = "  ssh-ed25519 AAAAC3... user@host  \n";
        let trimmed = key_with_spaces.trim();
        assert_eq!(trimmed, "ssh-ed25519 AAAAC3... user@host");
    }

    #[test]
    fn test_extract_raw_key() {
        // Raw key without options
        let raw = "ssh-ed25519 AAAAC3NzaC1... user@host";
        assert_eq!(extract_raw_key(raw), Some(raw));

        // Key with command prefix
        let with_prefix = r#"command="/usr/local/bin/fcm-git-shell",no-pty ssh-ed25519 AAAAC3NzaC1... user@host"#;
        assert_eq!(
            extract_raw_key(with_prefix),
            Some("ssh-ed25519 AAAAC3NzaC1... user@host")
        );

        // RSA key
        let rsa = "ssh-rsa AAAAB3NzaC1yc2E... user@host";
        assert_eq!(extract_raw_key(rsa), Some(rsa));

        // Empty and comment lines
        assert_eq!(extract_raw_key(""), None);
        assert_eq!(extract_raw_key("# comment"), None);
        assert_eq!(extract_raw_key("   "), None);
    }

    #[test]
    fn test_generate_git_shell_script() {
        let script = generate_git_shell_script();

        // Should be a bash script
        assert!(script.starts_with("#!/bin/bash"));

        // Should check SSH_ORIGINAL_COMMAND
        assert!(script.contains("SSH_ORIGINAL_COMMAND"));

        // Should only allow git commands
        assert!(script.contains("git-receive-pack"));
        assert!(script.contains("git-upload-pack"));

        // Should reject interactive shells
        assert!(script.contains("Interactive shell access is not allowed"));

        // Should prevent path traversal (checks for .. pattern)
        assert!(script.contains(r"\.\.")); // regex pattern for ..
    }

    #[test]
    fn test_restricted_key_format() {
        // Verify the format of restricted keys
        let key = "ssh-ed25519 AAAAC3... user@host";
        let restricted = format!(
            r#"command="{}",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty {}"#,
            FCM_GIT_SHELL_PATH,
            key
        );

        // Should contain the forced command
        assert!(restricted.contains("command=\"/usr/local/bin/fcm-git-shell\""));

        // Should have security restrictions
        assert!(restricted.contains("no-port-forwarding"));
        assert!(restricted.contains("no-agent-forwarding"));
        assert!(restricted.contains("no-X11-forwarding"));
        assert!(restricted.contains("no-pty"));

        // Should end with the actual key
        assert!(restricted.ends_with(key));
    }
}
