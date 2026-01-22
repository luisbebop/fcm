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
pub fn create_repo(vm_name: &str, vm_ip: &str) -> Result<PathBuf, GitError> {
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
    let hook_content = generate_post_receive_hook(vm_name, vm_ip);
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
fn generate_post_receive_hook(vm_name: &str, vm_ip: &str) -> String {
    format!(
        r#"#!/bin/bash
# FCM post-receive hook for {vm_name}
# This hook deploys code to the VM after git push

set -e
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

VM_NAME="{vm_name}"
VM_IP="{vm_ip}"
WORK_TREE="/tmp/fcm-deploy-$VM_NAME"
APP_DIR="/app"

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
cd "$WORK_TREE" && tar cf - . | sshpass -p "root" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$VM_IP" "cd $APP_DIR && tar xf -"

# Run deployment on VM
echo "-----> Running deployment..."
sshpass -p "root" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$VM_IP" "/usr/local/bin/fcm-deploy"

# Clean up
rm -rf "$WORK_TREE"

echo "-----> Deployment complete!"
"#,
        vm_name = vm_name,
        vm_ip = vm_ip
    )
}

/// Get the git clone URL for a VM (requires server hostname)
pub fn get_clone_url(vm_name: &str, server_host: &str) -> String {
    format!("root@{}:{}.git", server_host, vm_name)
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
        let hook = generate_post_receive_hook("test-vm", "172.16.0.50");
        assert!(hook.contains("test-vm"));
        assert!(hook.contains("172.16.0.50"));
        assert!(hook.contains("fcm-deploy"));
        assert!(hook.contains("sshpass"));
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
}
