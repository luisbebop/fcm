# fcm - firecracker vm manager

simple rust cli for managing firecracker vms on baremetal.

## overview

single binary with two modes:
- `fcm daemon` - runs http server on localhost:7777 (requires root)
- `fcm <cmd>` - cli client that talks to daemon via http

## authentication

simple token-based auth:
- daemon generates token on first run, saves to `/var/lib/firecracker/.token`
- client reads token from `~/.fcm-token` or `FCM_TOKEN` env var
- all requests include `Authorization: Bearer <token>` header
- daemon validates token on each request

## commands

```
fcm create                    # create vm with random name, expose port 3000
fcm ls                        # list vms
fcm console <vm>              # open persistent console session
fcm stop <vm>                 # stop vm
fcm start <vm>                # start stopped vm
fcm destroy <vm>              # destroy vm
fcm daemon                    # run daemon (root)
```

## vm names

auto-generated from word lists (space + tech + nature):

```rust
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

// generates: "cosmic-nova", "quantum-reef", "misty-comet", etc.
fn random_name() -> String {
    format!("{}-{}", random_choice(ADJECTIVES), random_choice(NOUNS))
}
```

## project structure

```
fcm/
├── Cargo.toml
└── src/
    ├── main.rs          # cli parsing, entry point
    ├── daemon.rs        # http server on :7777, terminal server on :7778
    ├── client.rs        # http client to daemon (with token auth)
    ├── console.rs       # terminal streaming client for console/attach
    ├── vm.rs            # vm create/start/stop/destroy, PTY management
    ├── firecracker.rs   # firecracker api over unix socket
    ├── network.rs       # tap device, ip allocation
    └── caddy.rs         # caddy config management
```

## dependencies (minimal)

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rand = "0.8"
tiny_http = "0.12"    # simple sync http server for daemon
ureq = "2"            # simple sync http client for cli
```

no async runtime - sync http only.

## vm creation flow

1. generate 8-char id (e.g. "8i5agfx2")
2. create dir `/var/lib/firecracker/<id>/`
3. copy rootfs with `cp --sparse=always`
4. allocate ip from 172.16.0.50-254
5. create tap device `tap_<id>`
6. spawn firecracker process
7. configure via api (boot-source, drives, machine-config, network)
8. start vm
9. if --expose: add to caddy, reload

## network

- tap device per vm: `tap_<id>`
- gateway: 172.16.0.1
- vm ips: 172.16.0.50+
- boot args: `ip=<vm-ip>::172.16.0.1:255.255.255.0:<name>:eth0:on`
- nftables masquerade for outbound

## ssl/domain

- sslip.io: `<name>.64-34-93-45.sslip.io`
- caddy auto-ssl via let's encrypt
- append block to `/etc/caddy/Caddyfile`, reload

## serial console (no agent)

Uses Firecracker's built-in serial console - no agent process needed inside the VM.

### architecture

```
┌─────────────┐         ┌─────────────┐         ┌───────────────────────────────┐
│  fcm CLI    │ ──TCP── │   Daemon    │ ──PTY── │ Firecracker stdin/stdout      │
│ (any host)  │  :7778  │  (proxies)  │  master │ ↔ /dev/ttyS0 ↔ getty ↔ shell  │
└─────────────┘         └─────────────┘         └───────────────────────────────┘
```

### how it works

1. Firecracker's stdin/stdout is connected to a PTY (not /dev/null)
2. Guest kernel has `console=ttyS0` in boot args (already configured)
3. Guest runs `getty` on `/dev/ttyS0` which provides login shell
4. Daemon stores PTY master FD per VM
5. CLI connects to daemon on port 7778
6. Daemon proxies raw bytes between CLI and PTY master (no encoding!)
7. Terminal resize uses ioctl(TIOCSWINSZ) on PTY master

### key benefits

| Aspect | Before (fcm-agent) | After (serial console) |
|--------|-------------------|------------------------|
| Processes in VM | init, fcm-agent, shell | init, getty, shell |
| Protocol overhead | JSON + base64 (~40 bytes/char) | None (raw bytes) |
| Latency | 10ms polling + 50ms reconnect | Instant (select-based) |
| Code complexity | ~800 lines (agent + session + protocol) | ~100 lines (PTY proxy) |
| Dependencies | fcm-agent binary in rootfs | Standard getty |

### terminal protocol (port 7778)

```json
// client -> daemon: initial connect (JSON, newline-delimited)
{"vm": "vm-id", "token": "auth-token", "cols": 80, "rows": 24}

// daemon -> client: connect response (JSON, newline-delimited)
{"success": true}
{"success": false, "error": "VM not found"}

// after success: raw bytes bidirectionally (no JSON, no base64!)
// resize messages: {"resize": {"cols": 120, "rows": 40}}
```

### vm requirements

- getty/agetty running on /dev/ttyS0 (started by init)
- no fcm-agent needed
- SSH still used for git push deployment

## procfile deployment

heroku-style git push deployment for VMs.

### how it works

1. each VM gets a git repo on the fcm host at `/root/<vm-name>.git`
2. `fcm create` output shows git URL: `root@<host>:<vm-name>.git`
3. user pushes code: `git push fcm main`
4. post-receive hook syncs code to VM's `/app` directory
5. auto-detects dependencies (Gemfile, requirements.txt, package.json)
6. runs install commands (bundle install, pip install, npm install)
7. parses Procfile and starts web process with `PORT=3000`

### procfile format

```
web: <command>
```

examples:
- `web: python3 app.py`
- `web: bundle exec rails server -p $PORT -b 0.0.0.0`
- `web: node index.js`

### architecture

```
User's Machine              FCM Host                          VM (172.16.0.x)
+------------+             +-------------------------+        +---------------+
|            | git push    | /root/<vm-name>.git     |        |               |
| local repo |------------>| (bare repo)             |  scp   | /app          |
|            | SSH:22      |         |               |------->| (code)        |
+------------+             |  post-receive hook      |  ssh   |               |
                           |  (syncs + deploys)      |------->| fcm-deploy    |
                           +-------------------------+        +---------------+
```

### vm scripts

- `fcm-deploy`: runs on VM after code sync, installs deps, restarts web
- `fcm-runner`: process manager for web process (start/stop/restart)

### usage

```bash
$ fcm create
VM created: cosmic-nova
  Git: root@myserver.com:cosmic-nova.git

$ git remote add fcm root@myserver.com:cosmic-nova.git
$ git push fcm main
remote: -----> Deploying to cosmic-nova...
remote: -----> Detected Python (requirements.txt)
remote: -----> Running pip install...
remote: -----> Starting: python app.py
remote: -----> Live at https://cosmic-nova.64-34-93-45.sslip.io
```

## base image

create new alpine-based rootfs with:
- dropbear (lightweight ssh server for git push deployment)
- agetty (for serial console login via /dev/ttyS0)
- ruby 4.0 + bundler (latest stable: 4.0.1) for heroku-style deployments
- python 3.14 + pip (latest stable: 3.14.2) for heroku-style deployments
- nodejs + bun for javascript deployments
- rng-tools (for entropy initialization in firecracker)
- minimal init script

dockerfile:
```dockerfile
FROM alpine:edge

RUN apk add --no-cache \
    dropbear dropbear-scp ruby ruby-bundler python3 py3-pip \
    nodejs npm curl bash iproute2 rng-tools agetty

# Configure dropbear SSH and set root password (for git push)
RUN mkdir -p /etc/dropbear && \
    dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key && \
    dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key && \
    dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key && \
    echo "root:root" | chpasswd

# Copy init script
COPY init /tmp/init
RUN chmod +x /tmp/init && mv /tmp/init /sbin/init
```

init script starts dropbear ssh (for git push) and agetty on ttyS0 (for serial console).

build: `docker build + docker export + dd + mkfs.ext4 + tar extract`

## files

```
/var/lib/firecracker/
├── .token                   # daemon auth token
├── vmlinux.bin              # kernel (shared)
├── base-rootfs.img          # rootfs with ssh, ruby, python (~400MB)
├── <vm-id>/
│   ├── config.json          # vm metadata
│   ├── firecracker.socket   # firecracker api socket
│   ├── firecracker.pid
│   └── rootfs.img           # vm's copy
~/.fcm-token                 # client copies token here
/etc/caddy/Caddyfile         # caddy config
```

## config.json format

```json
{
  "id": "8i5agfx2",
  "name": "myvm",
  "ip": "172.16.0.50",
  "state": "running",
  "expose": {"port": 3000, "domain": "myvm.64-34-93-45.sslip.io"}
}
```

## verification

1. `sudo fcm daemon &` - start daemon
2. `fcm create` - create vm (auto-generates name like "cosmic-nova")
3. `fcm ls` - see vm running
4. `fcm console cosmic-nova` - open persistent console, verify ruby/python available
5. disconnect (Ctrl+] or close terminal)
6. `fcm console cosmic-nova` - reconnect to same session, verify state preserved
7. `curl https://cosmic-nova.64-34-93-45.sslip.io` - verify ssl works
8. `fcm destroy cosmic-nova` - cleanup

## multi-user authentication

per-user tokens so each user can only see/manage their own VMs.

### login flow

```
1. user runs: fcm login
2. cli starts local server on 127.0.0.1:9876
3. cli opens browser to: https://fcm.{ip}.sslip.io/cli-login?port=9876
4. status page redirects to google oauth
5. after oauth success, status page generates token
6. status page redirects to: http://127.0.0.1:9876/callback?token=fcm_abc123...
7. local cli server receives token, saves to ~/.fcm-token
8. cli shows "Logged in as user@example.com" and exits
9. browser shows "Login successful! You can close this tab."
```

### commands

```
fcm login                     # authenticate with google (automatic token save)
fcm logout                    # remove token from ~/.fcm-token
fcm whoami                    # show current user info
```

### vm ownership

- each vm has an `owner` field (user id of creator)
- users can only see/manage their own vms
- legacy daemon token (`/var/lib/firecracker/.token`) has full access
- first user to login becomes admin (can see all vms)

### user database

stored in `/var/lib/firecracker/users.json`:

```json
{
  "users": {
    "google_user_id": {
      "id": "google_user_id",
      "email": "user@example.com",
      "name": "User Name",
      "created_at": 1700000000,
      "is_admin": false
    }
  },
  "tokens": {
    "fcm_abc123...": {
      "user_id": "google_user_id",
      "created_at": 1700000000
    }
  }
}
```

### api endpoints

```
GET /auth/me                  # get current user info (validates token)
GET /cli-login?port=9876      # initiate cli login flow (redirects to oauth)
```

### access control

1. **legacy daemon token** (`/var/lib/firecracker/.token`): full access to all VMs
2. **user token** (`fcm_...`): access only to VMs with matching `owner` field
3. **admin users**: can see/manage all VMs

### files

```
/var/lib/firecracker/users.json   # user database and tokens
~/.fcm-token                       # client token (fcm_... format)
```

## console redesign implementation plan

### step 1: update VM spawn to use PTY (`src/vm.rs`)

Create PTY when spawning Firecracker, store the master FD:

```rust
use std::os::unix::io::{FromRawFd, RawFd};

fn spawn_firecracker(config: &VmConfig) -> Result<(Child, RawFd)> {
    // Create a PTY for the serial console
    let mut master_fd: RawFd = 0;
    let slave_fd = unsafe {
        let mut slave_fd: RawFd = 0;
        if libc::openpty(&mut master_fd, &mut slave_fd,
                         std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) != 0 {
            return Err(VmError::Process("Failed to create PTY".into()));
        }
        slave_fd
    };

    // Connect Firecracker stdin/stdout to PTY slave
    let child = Command::new("firecracker")
        .args(["--api-sock", socket_path.to_str().unwrap()])
        .stdin(unsafe { Stdio::from_raw_fd(slave_fd) })
        .stdout(unsafe { Stdio::from_raw_fd(slave_fd) })
        .stderr(Stdio::piped())
        .spawn()?;

    // Close slave FD in parent (child has it now)
    unsafe { libc::close(slave_fd) };

    // Return master FD for console access
    Ok((child, master_fd))
}
```

### step 2: store PTY master FD in daemon

Store in a runtime map (not VmConfig since FDs don't serialize):

```rust
// src/daemon.rs
use once_cell::sync::Lazy;
static CONSOLE_FDS: Lazy<Mutex<HashMap<String, RawFd>>> = Lazy::new(|| Mutex::new(HashMap::new()));
```

### step 3: update rootfs init to run getty

Update `rootfs/init` to spawn getty on ttyS0:

```bash
# Start getty on serial console for interactive login
# Auto-login as root (no password prompt)
setsid agetty --autologin root --noclear ttyS0 115200 vt100 &
```

### step 4: simplify daemon terminal handler

Replace complex proxy with direct PTY I/O:

```rust
fn handle_terminal_connection(stream: TcpStream, console_fds: &Mutex<HashMap<String, RawFd>>) {
    // 1. Read connect request (vm, token, cols, rows)
    // 2. Validate token and VM
    // 3. Get PTY master FD for this VM
    let master_fd = console_fds.lock().unwrap().get(&vm_id).copied();

    if let Some(fd) = master_fd {
        // 4. Set terminal size on PTY
        set_window_size(fd, cols, rows);

        // 5. Send success response
        // 6. Proxy raw bytes: stream ↔ PTY (no encoding!)
        proxy_raw_io(stream, fd);
    }
}

fn proxy_raw_io(mut stream: TcpStream, pty_fd: RawFd) {
    // Simple bidirectional copy using select()
    // No JSON, no base64, just raw bytes
}
```

### step 5: remove fcm-agent

- Delete `fcm-agent/` directory entirely
- Remove fcm-agent from `rootfs/Dockerfile`
- Remove fcm-agent startup from `rootfs/init`

### step 6: clean up unused code

Remove from codebase:
- `src/session.rs` - no longer needed (no sessions to manage)
- Terminal JSON protocol code in `src/daemon.rs`
- Base64 encode/decode helpers

### files to modify

| File | Action | Description |
|------|--------|-------------|
| `src/vm.rs` | Modify | Create PTY in spawn_firecracker, return master FD |
| `src/daemon.rs` | Simplify | Direct PTY proxy instead of fcm-agent connection |
| `src/console.rs` | Simplify | Remove JSON message handling (already sends raw bytes!) |
| `rootfs/init` | Modify | Add getty on ttyS0 instead of fcm-agent |
| `rootfs/Dockerfile` | Modify | Remove fcm-agent, add agetty if needed |
| `fcm-agent/` | **DELETE** | No longer needed |
| `src/session.rs` | **DELETE** | No longer needed |

### challenges & solutions

**Challenge 1: PTY FD persistence across daemon restart**

Solution: Accept that daemon restart = console disconnect (user just reconnects). The PTY FDs are stored in memory and lost on restart.

**Challenge 2: Multiple clients to same console**

Solution: Allow only one console client at a time (like SSH). First connection wins, subsequent connections get "console in use" error.

**Challenge 3: Terminal resize**

Solution: Use ioctl(TIOCSWINSZ) on master FD when client sends resize message.

### verification

1. Build and test:
   ```bash
   cargo test
   cargo build --release
   ```

2. Rebuild rootfs (no fcm-agent):
   ```bash
   cd rootfs && sudo ./build.sh
   ```

3. Test console:
   ```bash
   fcm create
   fcm console <vm-name>
   # Should see getty login prompt or auto-login shell
   # Test: typing, colors, cursor, resize
   # Test: disconnect, reconnect
   ```

4. Verify no agent:
   ```bash
   # In console
   ps aux
   # Should NOT see fcm-agent, only: init, getty/agetty, shell
   ```
