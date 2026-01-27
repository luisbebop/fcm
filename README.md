# fcm

![fcm create](image.png)

A dead-simple CLI for running microVMs on bare metal. Create a VM, push your code, get a URL. That's it.

```
$ fcm create
VM created: cosmic-nova
URL: https://cosmic-nova.tryforge.sh

$ git push origin main
-----> Deploying to cosmic-nova...
-----> Detected Python (requirements.txt)
-----> Running pip install...
-----> Starting: gunicorn app:app
-----> Deploy successful!
       https://cosmic-nova.tryforge.sh
```

## What is this?

fcm is a Firecracker VM manager that gives you Heroku-style deploys on your own hardware. Each "app" runs in its own microVM with:

- **Instant boot** (~125ms) - Firecracker VMs are fast
- **Full isolation** - Real VMs, not containers
- **Git push deploy** - Just like Heroku
- **Auto SSL** - Free certs via Let's Encrypt
- **Persistent console** - SSH-like access that survives disconnects
- **Web console** - Browser-based terminal via xterm.js
- **Multi-user auth** - Google OAuth with per-user VM isolation

No Kubernetes. No Docker. No YAML files. Just VMs.

## Quick Start

```bash
# Start the daemon (requires root)
sudo fcm daemon &

# Create a VM
fcm create

# Push your code
git init
echo "web: python3 -m http.server 3000" > Procfile
echo "<h1>Hello World</h1>" > index.html
git add . && git commit -m "init"
git remote add origin root@yourserver.com:cosmic-nova.git
git push origin main

# Access your VM's console
fcm console cosmic-nova
```

## Commands

```
fcm create              Create a new VM (random name, port 3000 exposed)
fcm ls                  List all VMs
fcm console <vm>        Open persistent console session
fcm console ls          List active console sessions
fcm console <vm> -s ID  Reconnect to existing session
fcm stop <vm>           Stop a VM
fcm start <vm>          Start a stopped VM
fcm destroy <vm>        Delete a VM and its data
fcm login               Authenticate with Google OAuth
fcm logout              Remove authentication token
fcm whoami              Show current user info
fcm daemon              Run the daemon (requires root)
```

When you run `fcm create` in a directory, it saves a `.fcm` file. After that, you can just run `fcm console`, `fcm stop`, etc. without specifying the VM name.

## Console Sessions

fcm provides persistent console sessions that survive network disconnects:

```bash
# Open a new console session
fcm console cosmic-nova
# Session: brook
# Reconnect with: fcm console cosmic-nova -s brook

# List active sessions
fcm console ls
# ID       VM             CREATED
# brook    cosmic-nova    2 minutes ago
# fern     nebula-vertex  1 hour ago

# Reconnect to an existing session
fcm console cosmic-nova -s brook
```

**Features:**
- Sessions persist on the server even when you disconnect
- TUI apps (vim, htop, claude) restore their screen on reconnect
- Server-side 64KB ring buffer captures recent output
- Auto-cleanup when you type `exit` in the shell

**Keyboard shortcuts:**
- `Ctrl+]` - Disconnect from console (session stays alive)
- `Ctrl+D` or `exit` - End session and disconnect

## Web Console

Access your VMs from any browser at `https://fcm.tryforge.sh`:

1. Visit the status page URL shown when daemon starts
2. Login with Google OAuth
3. Click "Console" next to any running VM
4. Full terminal emulation with xterm.js

The web console uses the same persistent sessions as the CLI, with session ID `web-<vm-name>`.

## Authentication

fcm supports two authentication methods:

### Google OAuth (for users)

```bash
# Login with your Google account
fcm login

# Check your current user
fcm whoami

# Logout when done
fcm logout
```

The login flow opens a browser for Google authentication. Your credentials are stored locally in `~/.fcm-token`.

### Admin Token (for server operators)

The daemon generates an admin token at `/var/lib/firecracker/.token` on first run. This token has full access to all VMs.

```bash
# Copy the admin token from the server
scp root@yourserver:/var/lib/firecracker/.token ~/.fcm-token

# Test it
fcm ls
```

## Installation (Bare Metal)

This guide assumes a fresh Ubuntu 22.04+ server with a public IP.

### 1. Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install build tools
sudo apt install -y build-essential curl git

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 2. Install Firecracker

```bash
# Download Firecracker
FIRECRACKER_VERSION="v1.7.0"
curl -L "https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-x86_64.tgz" | tar -xz

# Install binaries
sudo mv release-${FIRECRACKER_VERSION}-x86_64/firecracker-${FIRECRACKER_VERSION}-x86_64 /usr/local/bin/firecracker
sudo mv release-${FIRECRACKER_VERSION}-x86_64/jailer-${FIRECRACKER_VERSION}-x86_64 /usr/local/bin/jailer
rm -rf release-${FIRECRACKER_VERSION}-x86_64

# Verify
firecracker --version
```

### 3. Install Caddy (for SSL)

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy

# Start Caddy
sudo systemctl enable caddy
sudo systemctl start caddy
```

### 4. Install Additional Tools

```bash
# sshpass (for VM communication)
sudo apt install -y sshpass

# Docker (for building base image)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

### 5. Build and Install fcm

```bash
# Clone the repo
git clone https://github.com/luisbebop/fcm.git
cd fcm

# Build
cargo build --release

# Install
sudo cp target/release/fcm /usr/local/bin/
```

### 6. Download the Kernel

```bash
sudo mkdir -p /var/lib/firecracker

# Download a pre-built kernel (or build your own)
curl -L "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin" \
  -o /tmp/vmlinux.bin
sudo mv /tmp/vmlinux.bin /var/lib/firecracker/vmlinux.bin
```

### 7. Build the Base Image

```bash
cd fcm/rootfs

# Build the rootfs (requires Docker)
sudo ./build.sh

# This creates /var/lib/firecracker/base-rootfs.img
```

### 8. Configure Networking

```bash
# Enable IP forwarding
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# The daemon will create the bridge and NAT rules automatically
```

### 9. Configure SSH for Git Push

```bash
# Enable SSH environment variables (needed for git-receive-pack)
echo "PermitUserEnvironment yes" | sudo tee -a /etc/ssh/sshd_config
sudo mkdir -p /root/.ssh
echo "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" | sudo tee /root/.ssh/environment
sudo chmod 600 /root/.ssh/environment
sudo systemctl restart sshd
```

### 10. Configure Google OAuth

To enable multi-user authentication with Google OAuth:

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the "Google+ API" or "Google Identity" API
4. Go to **APIs & Services > Credentials**
5. Click **Create Credentials > OAuth client ID**
6. Select **Web application**
7. Add authorized redirect URI: `https://fcm.tryforge.sh/oauth2/callback`
8. Copy the Client ID and Client Secret

Set the environment variables before starting the daemon:

```bash
export GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="your-client-secret"
```

> **Note:** Without Google OAuth configured, the daemon will still work but only with the admin token. Users won't be able to use `fcm login`.

### 11. Start the Daemon

```bash
# Set required environment variables
export GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="your-client-secret"

# Run as root (required for network setup)
sudo -E fcm daemon

# Or create a systemd service (recommended for production)
```

### 12. Create Systemd Service (Recommended)

Create `/etc/systemd/system/fcm.service`:

```ini
[Unit]
Description=fcm Firecracker VM Manager
After=network.target caddy.service

[Service]
Type=simple
ExecStart=/usr/local/bin/fcm daemon
Restart=always
RestartSec=5
Environment="GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com"
Environment="GOOGLE_CLIENT_SECRET=your-client-secret"

[Install]
WantedBy=multi-user.target
```

Then enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable fcm
sudo systemctl start fcm
```

### 13. Configure Client

On your local machine:

```bash
# Download the client binary
curl -sL https://fcm.tryforge.sh/releases/fcm-macos-arm64.tar.gz | tar xz
sudo mv fcm /usr/local/bin/

# Login with Google
fcm login
```

The CLI automatically connects to `fcm.tryforge.sh`. No configuration needed.

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              Your Server                                    │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐                               │
│  │   VM 1   │   │   VM 2   │   │   VM 3   │  Firecracker microVMs         │
│  │  :3000   │   │  :3000   │   │  :3000   │  (172.16.0.50+)               │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘                               │
│       │              │              │                                      │
│       └──────────────┼──────────────┘                                      │
│                      │                                                     │
│                ┌─────┴─────┐                                               │
│                │   fcm0    │  Bridge (172.16.0.1)                          │
│                └─────┬─────┘                                               │
│                      │                                                     │
│                     NAT                                                    │
│                      │                                                     │
│  ┌───────────────────┴───────────────────┐                                 │
│  │                Caddy                  │  Reverse Proxy + Auto SSL       │
│  │  vm1.tryforge.sh → 172.16.0.50       │                                 │
│  │  vm2.tryforge.sh → 172.16.0.51       │  Port 443 (HTTPS)               │
│  │  fcm.tryforge.sh/console → :7778     │  WebSocket console              │
│  │  fcm.tryforge.sh/* → :7780           │  Status page                    │
│  └───────────────────┬───────────────────┘                                 │
│                      │                                                     │
│  ┌───────────────────┴───────────────────┐                                 │
│  │            fcm daemon                 │                                 │
│  │  :7777  - HTTP API                    │                                 │
│  │  :7778  - WebSocket terminal (local)  │                                 │
│  │  :7780  - Status page (local)         │                                 │
│  └───────────────────────────────────────┘                                 │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
                       │
                    :443 (HTTPS)
                       │
                   Internet
```

### Ports

| Port | Binding | Description |
|------|---------|-------------|
| 7777 | 0.0.0.0 | HTTP API (daemon commands) |
| 7778 | 127.0.0.1 | WebSocket terminal server (via Caddy) |
| 7780 | 127.0.0.1 | Status page server (via Caddy) |
| 443 | Caddy | HTTPS (proxies to VMs, console, status page) |
| 80 | Caddy | HTTP (redirects to HTTPS) |

## Procfile

Your app needs a `Procfile` that tells fcm how to start it:

```
web: python3 app.py
```

fcm auto-detects and installs dependencies:

| File | Action |
|------|--------|
| `requirements.txt` | `pip install -r requirements.txt` |
| `Gemfile` | `bundle install` |
| `package.json` | `npm install` |
| `bun.lockb` | `bun install` |

The web process runs with `PORT=3000`.

## VM Specs

Each VM gets:
- 1 vCPU
- 1024 MB RAM
- 2 GB disk (sparse)
- 512 MB swap

### Base Image Contents

| Component | Size | Version |
|-----------|------|---------|
| **Runtimes** | | |
| Ruby | 34 MB | 3.4 |
| Python | 55 MB | 3.12 |
| Node.js | 64 MB | 24.x |
| Bun | 90 MB | 1.3 |
| Claude Code | 206 MB | latest |
| **Build Tools** | | |
| GCC | 21 MB | |
| Headers | 30 MB | |
| Libexec | 130 MB | |
| **Other** | | |
| Shared libs | 15 MB | |
| Swap file | 512 MB | |
| **Total** | ~1.1 GB | |

## Environment Variables

### Server-side (daemon)

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLIENT_ID` | For OAuth | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | For OAuth | Google OAuth client secret |

### Client-side

| Variable | Required | Description |
|----------|----------|-------------|
| `FCM_TOKEN` | No | Auth token (alternative to `~/.fcm-token`) |
| `FCM_HOST` | No | Override server address (default: `fcm.tryforge.sh`, use `127.0.0.1:7777` for local dev) |

## Files and Directories

### Server

```
/var/lib/firecracker/
├── .token                  # Admin auth token
├── vmlinux.bin             # Linux kernel
├── base-rootfs.img         # Base VM image (~1.1GB sparse)
├── users.json              # User database and tokens
├── <vm-id>/
│   ├── config.json         # VM metadata
│   ├── rootfs.img          # VM's disk (copy-on-write)
│   ├── firecracker.socket  # Firecracker API socket
│   └── firecracker.pid     # Process ID

/etc/caddy/Caddyfile        # Caddy reverse proxy config
/root/<vm-name>.git/        # Git repos for each VM
```

### Client

```
~/.fcm-token                # Auth token (from fcm login)
.fcm                        # VM name for current directory
```

## Troubleshooting

### Connection Issues

**"Connection refused" when running fcm commands**
```bash
# Check if daemon is running on the server
pgrep -a fcm

# Test API connectivity (default: fcm.tryforge.sh)
curl -v https://fcm.tryforge.sh/health
```

**"Cannot connect to terminal server"**
- Old client version - download latest from status page
- WebSocket connection goes through Caddy on port 443, not direct to 7778

### Authentication Issues

**"No auth token found"**
```bash
# Login with Google OAuth
fcm login

# Or set token manually
export FCM_TOKEN="your-token"
```

**"GOOGLE_CLIENT_ID environment variable not set"**
- Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` before starting daemon
- Use `sudo -E` to preserve environment variables

**OAuth callback fails**
- Verify redirect URI in Google Console matches: `https://fcm.tryforge.sh/oauth2/callback`
- Check Caddy is running and SSL certificate was issued

### VM Issues

**VM won't start**
```bash
# Check Firecracker
firecracker --version

# Check kernel
ls -la /var/lib/firecracker/vmlinux.bin

# Check base image
ls -la /var/lib/firecracker/base-rootfs.img

# Check daemon logs
journalctl -u fcm -f
```

**VM starts but app doesn't work**
```bash
# Connect to console
fcm console <vm-name>

# Check if process is running
ps aux | grep web

# Check logs
cat /var/log/app.log

# Test locally
curl localhost:3000
```

**"No IP addresses available"**
- Maximum 205 VMs (172.16.0.50-254)
- Destroy unused VMs: `fcm destroy <vm-name>`

### Console Issues

**Console shows garbled output**
```bash
# Reset terminal
reset

# Or disconnect and reconnect
# Press Ctrl+] then reconnect
fcm console <vm-name>
```

**Session not found on reconnect**
- Sessions are cleaned up when shell exits (`exit` command)
- Sessions are lost if daemon restarts
- Use `fcm console ls` to see active sessions

**Web console won't connect**
- Check browser console for WebSocket errors
- Verify you're logged in (cookie-based auth)
- Try CLI console to verify VM is accessible

### SSL Issues

**SSL certificate not working**
```bash
# Check Caddy status
sudo systemctl status caddy

# View Caddy logs
sudo journalctl -u caddy -f

# Verify ports 80 and 443 are open
sudo ufw status
sudo iptables -L -n | grep -E "80|443"
```

**Domain not resolving**
- Ensure DNS is properly configured for tryforge.sh
- Try: `nslookup vm-name.tryforge.sh`

### Git Push Issues

**"Permission denied" on git push**
```bash
# Add your SSH key to the server
ssh-copy-id root@yourserver

# Or check authorized_keys
cat /root/.ssh/authorized_keys
```

**"git-receive-pack: command not found"**
```bash
# Enable SSH environment on server
echo "PermitUserEnvironment yes" | sudo tee -a /etc/ssh/sshd_config
echo "PATH=/usr/local/bin:/usr/bin:/bin" | sudo tee /root/.ssh/environment
sudo chmod 600 /root/.ssh/environment
sudo systemctl restart sshd
```

### Network Issues

**VMs can't reach internet**
```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Should be 1

# Check NAT rules
sudo iptables -t nat -L POSTROUTING -n | grep 172.16

# Check bridge
ip addr show fcm0
```

**Can't reach VM from outside**
- VMs are only accessible via Caddy reverse proxy
- Direct access to 172.16.0.x requires being on the host

### Logs

```bash
# Daemon logs (if using systemd)
sudo journalctl -u fcm -f

# Daemon logs (if running manually)
tail -f /var/log/fcm.log

# Caddy logs
sudo journalctl -u caddy -f

# VM console output (from host)
cat /var/lib/firecracker/<vm-id>/firecracker.log
```

## Updating

### Update fcm binary

```bash
cd fcm
git pull
cargo build --release
sudo systemctl stop fcm
sudo cp target/release/fcm /usr/local/bin/
sudo systemctl start fcm
```

### Update base image

```bash
cd fcm/rootfs
sudo ./build.sh
# New VMs will use updated image
# Existing VMs keep their current rootfs
```

### Update client

```bash
# Download latest from status page
curl -sL https://fcm.tryforge.sh/releases/fcm-macos-arm64.tar.gz | tar xz
sudo mv fcm /usr/local/bin/
```

## License

MIT
