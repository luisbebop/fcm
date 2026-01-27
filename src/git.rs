// Git repository management module for Procfile deployments

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

/// Git repos are stored in /root/<vm-name>.git
const GIT_REPOS_BASE: &str = "/root";

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

/// Add an SSH public key to the host's authorized_keys for git push access
pub fn add_ssh_key_to_host(ssh_public_key: &str) -> Result<(), GitError> {
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

    // Check if key already exists (avoid duplicates)
    let key_trimmed = ssh_public_key.trim();
    if existing.lines().any(|line| line.trim() == key_trimmed) {
        return Ok(()); // Key already exists
    }

    // Append the new key
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(key_trimmed);
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
}
