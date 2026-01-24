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

## Task 99: WebSocket Console Protocol (Sprite-style)

### Summary

Migrate fcm console from raw TCP (port 7778) to WebSocket over TLS (port 443), following Sprite's complete protocol design including:
- Auth in WebSocket upgrade headers
- Environment passthrough (TERM, SHELL, etc.)
- Terminfo sync (upload terminfo before connect)
- OSC title sequences (terminal title updates)
- Pure binary frames for terminal I/O
- TLS via Caddy (one less port to manage)

**Note:** zsh is already in the base image (Task 98). This task focuses on the complete WebSocket terminal protocol.

### Current State

- **Server** (`daemon.rs:1180-1416`): TCP on port 7778, JSON handshake + raw bytes
- **Client** (`console.rs:234-419`): TcpStream, SIGWINCH handler, two-thread I/O
- **Protocol flaw**: Resize messages detected by `starts_with(b"{\"resize\"")` - fragile
- **Extra port**: Port 7778 must be exposed separately from HTTPS

### Target State (Sprite-style)

- **Transport**: WebSocket over TLS (wss://) via Caddy on port 443
- **Auth**: Bearer token in HTTP header during WebSocket upgrade
- **Connection params**: VM name, terminal size, env vars in URL query string
- **Terminal I/O**: Pure binary WebSocket frames after handshake
- **Resize**: Text frame with JSON
- **Terminfo**: Upload before connect (optional)
- **OSC title**: Server sends title updates to client

### Architecture

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐         ┌───────────────┐
│  fcm CLI    │ ──wss── │   Caddy     │ ──ws─── │   Daemon    │ ──PTY── │  Firecracker  │
│ (any host)  │  :443   │  (TLS+proxy)│ :7778   │  (internal) │  master │  serial ttyS0 │
└─────────────┘         └─────────────┘         └─────────────┘         └───────────────┘
```

- Caddy handles TLS termination and certificate management
- Daemon listens on `127.0.0.1:7778` (localhost only, not exposed)
- Single external port (443) for both HTTP API and WebSocket console
- Firewall-friendly (port 443 almost always allowed)

### Protocol Specification

#### Pre-Connection: Terminfo Upload (Optional)

Before WebSocket connect, client uploads terminfo to VM:

```
PUT /vms/{vm-name}/fs?path=/usr/share/terminfo/{first-char}/{term-type}
Authorization: Bearer {token}
Content-Type: application/octet-stream

<binary terminfo data>
```

This ensures the VM has proper terminfo for the client's terminal type.

#### WebSocket Connection

```
WebSocket URL:
  wss://fcm.{ip}.sslip.io/console?vm={vm-name}&cols={cols}&rows={rows}&env=TERM=xterm-256color&env=SHELL=/bin/zsh

Query Parameters:
  vm        - VM name (required)
  cols      - Terminal width (default: 80)
  rows      - Terminal height (default: 24)
  env       - Environment variable (repeatable), format: KEY=value
              Common: TERM, SHELL, COLORTERM, LANG, LC_ALL

HTTP Headers (during WebSocket upgrade):
  Authorization: Bearer {token}
  Upgrade: websocket
  Connection: Upgrade
  Sec-WebSocket-Version: 13

Response:
  101 Switching Protocols (success)
  401 Unauthorized (bad token)
  404 Not Found (VM not found)
  403 Forbidden (access denied)
```

#### After 101: Message Flow

```
Client → Server:
  - Binary frames: keyboard input (raw bytes)
  - Text frames: control messages (resize)

Server → Client:
  - Binary frames: terminal output (raw bytes)
    - Includes shell prompt, command output
    - Includes OSC sequences for title updates
  - Text frames: (reserved for future control messages)

Resize message (Text frame, Client → Server):
  {"type":"resize","cols":120,"rows":40}
```

#### OSC Title Sequences

Server sends OSC escape sequences embedded in terminal output:

```
Set title:     \x1b]0;{vm-name}: {process}\x07
               \x1b]0;cosmic-nova: zsh --login\x07

Client should:
  1. Detect OSC sequences in binary output
  2. Extract title from sequence
  3. Update terminal title (optional prefix: "fcm: ")
```

#### Environment Variables

Common env vars to pass:

| Variable | Example | Description |
|----------|---------|-------------|
| `TERM` | `xterm-256color` | Terminal type |
| `SHELL` | `/bin/zsh` | User's shell |
| `COLORTERM` | `truecolor` | Color support |
| `LANG` | `en_US.UTF-8` | Locale |
| `LC_ALL` | `en_US.UTF-8` | Locale override |

### Benefits Over Current Protocol

| Current TCP | Sprite-style WebSocket |
|-------------|------------------------|
| Separate port 7778 | Single port 443 (via Caddy) |
| No TLS | TLS with auto-renewed certs |
| JSON auth message after connect | Auth in HTTP headers (standard) |
| Fragile resize detection | WebSocket frame types separate control |
| Custom protocol | Standard WebSocket (browser-compatible) |
| No ping/pong | Built-in keepalive |
| No env passthrough | Full environment passthrough |
| No terminfo sync | Client can upload terminfo |
| No title updates | OSC title sequences |

### Implementation Steps

#### Step 1: Add dependencies

**File: `Cargo.toml`**

```toml
tungstenite = { version = "0.24", features = ["native-tls"] }  # WebSocket with TLS
url = "2"  # For URL parsing
native-tls = "0.2"  # TLS for wss:// client connections
```

#### Step 2: Configure Caddy to proxy WebSocket

Add WebSocket proxy to Caddyfile for the `/console` path:

```caddyfile
fcm.{ip}.sslip.io {
    # Existing routes...

    # WebSocket console - proxy to daemon
    handle /console {
        reverse_proxy 127.0.0.1:7778
    }
}
```

Caddy automatically handles:
- TLS termination (Let's Encrypt)
- WebSocket upgrade detection
- Connection keep-alive

#### Step 3: Update daemon.rs - WebSocket server (localhost only)

Daemon listens on `127.0.0.1:7778` (not exposed externally - Caddy proxies to it).

**New structs:**
```rust
/// Parsed WebSocket console request
struct WsConsoleRequest {
    vm: String,
    token: String,
    cols: u16,
    rows: u16,
    env: HashMap<String, String>,  // Environment variables
}
```

**New functions:**
```rust
/// Parse HTTP upgrade request before WebSocket handshake
fn parse_ws_upgrade_request(buf: &[u8]) -> Result<WsConsoleRequest, (u16, &'static str)>

/// Parse query string into key-value pairs (handles repeated keys for env)
fn parse_query_params(query: &str) -> (HashMap<String, String>, Vec<(String, String)>)

/// Send HTTP error response (before WebSocket)
fn send_http_error(stream: &mut TcpStream, status: u16, message: &str)
```

**Bind to localhost only:**
```rust
// In run_terminal_server()
let listener = TcpListener::bind("127.0.0.1:7778")?;  // localhost only, Caddy proxies
```

**Updated handle_terminal_connection():**
```rust
fn handle_terminal_connection(stream: TcpStream, daemon_token: &str, console_fds: &ConsoleFds) {
    // 1. Read HTTP request (peek or buffer)
    let mut buf = [0u8; 4096];
    let n = stream.peek(&mut buf)?;

    // 2. Parse request to get auth and params
    let request = match parse_ws_upgrade_request(&buf[..n]) {
        Ok(r) => r,
        Err((status, msg)) => {
            send_http_error(&mut stream, status, msg);
            return;
        }
    };

    // 3. Validate token
    let access_level = validate_token(&request.token, daemon_token)?;

    // 4. Find VM and check access
    let config = vm::find_vm(&request.vm)?;
    if !access_level.can_access_vm(&config) {
        send_http_error(&mut stream, 403, "Access denied");
        return;
    }

    // 5. Check VM running
    if config.state != VmState::Running {
        send_http_error(&mut stream, 503, "VM not running");
        return;
    }

    // 6. Get PTY FD
    let master_fd = match console_fds.lock().unwrap().get(&config.id) {
        Some(&fd) => fd,
        None => {
            send_http_error(&mut stream, 503, "Console not available");
            return;
        }
    };

    // 7. Complete WebSocket handshake
    let websocket = tungstenite::accept(stream)?;

    // 8. Set terminal size
    set_pty_window_size(master_fd, request.cols, request.rows);

    // 9. Set environment variables in VM (write to PTY)
    for (key, value) in &request.env {
        let export_cmd = format!("export {}={}\n", key, shell_escape(value));
        unsafe { libc::write(master_fd, export_cmd.as_ptr() as *const _, export_cmd.len()) };
    }

    // 10. Proxy WebSocket <-> PTY
    proxy_websocket_pty(websocket, master_fd, &config.name);
}
```

**Updated proxy_websocket_pty() with OSC title:**
```rust
fn proxy_websocket_pty(
    websocket: WebSocket<TcpStream>,
    master_fd: RawFd,
    vm_name: &str,  // For OSC title prefix
) {
    // Send initial OSC title: "\x1b]0;{vm_name}: zsh\x07"
    let initial_title = format!("\x1b]0;{}: zsh\x07", vm_name);
    websocket.send(Message::Binary(initial_title.into_bytes()))?;

    // Reader thread: PTY -> Binary WebSocket frames
    //   (OSC sequences from shell pass through naturally)

    // Main thread: WebSocket frames -> PTY
    //   Binary -> write to PTY
    //   Text with resize -> TIOCSWINSZ
}
```

#### Step 4: Add terminfo upload endpoint to daemon HTTP server

**New endpoint in daemon's HTTP server (port 7777):**

```
PUT /vms/{vm}/fs
Query params:
  path - file path in VM (e.g., /usr/share/terminfo/x/xterm-256color)
Body: binary file content

Implementation:
  1. Validate token and VM access
  2. Get VM's IP address
  3. SCP file content to VM (via SSH)
```

This is optional but improves terminal compatibility.

#### Step 5: Update console.rs - WebSocket client

**New connect() flow:**
```rust
pub fn connect(vm: &str) -> Result<(), ConsoleError> {
    let host = api_host();  // e.g., "fcm.64-34-93-45.sslip.io"
    let token = load_token()?;
    let (cols, rows) = get_terminal_size();

    // Gather environment variables
    let term = env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/zsh".to_string());
    let colorterm = env::var("COLORTERM").ok();
    let lang = env::var("LANG").ok();

    // Optional: Upload terminfo before connect
    // upload_terminfo(vm, &term)?;

    // Build WebSocket URL with query params (wss:// via Caddy)
    let mut url = format!(
        "wss://{}/console?vm={}&cols={}&rows={}&env=TERM={}&env=SHELL={}",
        host,
        url_encode(vm), cols, rows,
        url_encode(&term), url_encode(&shell)
    );
    if let Some(ct) = colorterm {
        url.push_str(&format!("&env=COLORTERM={}", url_encode(&ct)));
    }
    if let Some(l) = lang {
        url.push_str(&format!("&env=LANG={}", url_encode(&l)));
    }

    // Connect with auth header (TLS handled by tungstenite)
    let request = tungstenite::http::Request::builder()
        .uri(&url)
        .header("Authorization", format!("Bearer {}", token))
        .body(())?;

    print!("Connecting to {}...", vm);
    io::stdout().flush()?;

    let (websocket, response) = tungstenite::connect(request)
        .map_err(|e| ConsoleError::ConnectionFailed(e.to_string()))?;

    if response.status() != 101 {
        println!(" failed");
        return Err(ConsoleError::AuthFailed(format!("HTTP {}", response.status())));
    }

    println!(" connected\r\n");

    // Enter raw terminal mode
    if !is_tty() {
        return Err(ConsoleError::TerminalError("stdin is not a terminal".into()));
    }
    let _raw_terminal = RawTerminal::enable()?;

    // Install SIGWINCH handler
    install_sigwinch_handler();

    // Proxy WebSocket <-> terminal
    proxy_websocket_terminal(websocket, vm)?;

    Ok(())
}
```

**OSC title handling in client:**
```rust
fn handle_osc_title(data: &[u8], vm_name: &str) {
    // Detect OSC sequence: \x1b]0;{title}\x07 or \x1b]0;{title}\x1b\\
    // Extract title and set terminal title with prefix
    // set_terminal_title(&format!("fcm: {}", title));
}

fn set_terminal_title(title: &str) {
    // Write OSC sequence to stdout
    print!("\x1b]0;{}\x07", title);
    io::stdout().flush().ok();
}
```

**Resize handling:**
```rust
// When SIGWINCH received:
let resize_msg = format!(r#"{{"type":"resize","cols":{},"rows":{}}}"#, cols, rows);
websocket.send(Message::Text(resize_msg))?;
```

#### Step 6: Optional - Terminfo upload helper

```rust
/// Upload local terminfo to VM before connecting
fn upload_terminfo(host: &str, vm: &str, term: &str) -> Result<(), ConsoleError> {
    let token = load_token()?;

    // Find local terminfo file
    let terminfo_path = format!("/usr/share/terminfo/{}/{}",
        term.chars().next().unwrap(), term);

    let terminfo_data = std::fs::read(&terminfo_path)
        .map_err(|_| ConsoleError::TerminalError("Cannot read terminfo".into()))?;

    // Upload to VM (via HTTPS)
    let url = format!("https://{}/vms/{}/fs?path={}",
        host, vm, url_encode(&terminfo_path));

    ureq::put(&url)
        .set("Authorization", &format!("Bearer {}", token))
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&terminfo_data)?;

    Ok(())
}
```

#### Step 7: Cleanup old code

**Remove from daemon.rs:**
- `TerminalConnectRequest` struct
- `TerminalConnectResponse` struct
- `send_terminal_error()` function
- `send_terminal_response()` function
- `parse_resize_message()` function (replaced by JSON parsing)
- `proxy_pty_io()` function (replaced by `proxy_websocket_pty`)

**Remove from console.rs:**
- `ConnectRequest` struct
- `ConnectResponse` struct
- `make_resize_message()` function

#### Step 8: Add tests

```rust
#[test]
fn test_parse_ws_query_params() {
    let query = "vm=cosmic-nova&cols=120&rows=40&env=TERM=xterm&env=SHELL=/bin/zsh";
    let (params, envs) = parse_query_params(query);
    assert_eq!(params.get("vm"), Some(&"cosmic-nova".to_string()));
    assert_eq!(params.get("cols"), Some(&"120".to_string()));
    assert_eq!(envs.len(), 2);
}

#[test]
fn test_osc_title_detection() {
    let data = b"Hello\x1b]0;my-vm: zsh\x07World";
    // Test OSC extraction
}

#[test]
fn test_resize_message_format() {
    let msg = r#"{"type":"resize","cols":120,"rows":40}"#;
    // verify parsing
}
```

### Files to Modify

| File | Changes |
|------|---------|
| `Cargo.toml` | Add `tungstenite = "0.24"`, `url = "2"`, TLS deps |
| `src/daemon.rs` | WebSocket server on 127.0.0.1:7778, env passthrough, OSC support (~200 lines) |
| `src/console.rs` | WebSocket client with wss://, env passthrough, terminfo upload (~150 lines) |
| `src/caddy.rs` | Add `/console` WebSocket proxy route to Caddyfile generation |

### Verification

1. **Build and test:**
   ```bash
   cargo build
   cargo test
   cargo clippy
   ```

2. **Start daemon:**
   ```bash
   sudo ./target/debug/fcm daemon
   ```

3. **Verify Caddy config includes WebSocket proxy:**
   ```bash
   grep -A2 "/console" /etc/caddy/Caddyfile
   # Should show: handle /console { reverse_proxy 127.0.0.1:7778 }
   ```

4. **Create test VM:**
   ```bash
   fcm create
   ```

5. **Test console with environment:**
   ```bash
   fcm console <vm-name>
   # Verify shell prompt (zsh)
   # Check environment:
   echo $TERM      # Should show xterm-256color
   echo $SHELL     # Should show /bin/zsh
   # Check terminal title updates (if terminal supports)
   ```

6. **Test colors and terminal features:**
   ```bash
   # In console:
   ls --color=auto
   vim  # Should have proper terminfo
   htop # Should work with colors
   ```

7. **Test resize:**
   ```bash
   # Resize terminal window
   # Run: stty size
   # Should show new dimensions
   ```

8. **Test reconnect:**
   ```bash
   # Ctrl+] to disconnect
   fcm console <vm-name>
   # Should reconnect, shell state preserved
   ```

9. **Test TLS is working:**
   ```bash
   # Connection should use wss:// (TLS)
   # No certificate warnings
   # Works through corporate firewalls (port 443)
   ```

10. **Test error cases:**
    ```bash
    FCM_TOKEN=invalid fcm console <vm-name>  # 401
    fcm console nonexistent-vm               # 404
    ```

11. **Cleanup:**
    ```bash
    fcm destroy <vm-name>
    ```

### Technical Notes

#### Environment Variable Injection

Two approaches for passing env vars to shell:

1. **Query params** (chosen): Pass in URL, daemon writes `export` commands to PTY
   - Pro: Works with any shell
   - Con: Commands visible in shell history

2. **PTY environment**: Set env vars on PTY before shell starts
   - Pro: Cleaner
   - Con: Requires PTY to be set up before shell (not possible with serial console)

For serial console (our architecture), option 1 is the only choice.

#### OSC Title Flow

```
Shell in VM               Daemon                    Client Terminal
     |                       |                           |
     |-- OSC: "zsh" -------->|                           |
     |                       |-- Binary frame: OSC ----->|
     |                       |                           |-- Set title: "fcm: zsh"
```

The shell (zsh) naturally sends OSC sequences. The daemon passes them through in binary frames. The client detects and processes them.

#### Threading Model

Same as current implementation:
- Server: Thread per connection
- Client: Reader thread + main thread for stdin
- Use `Arc<Mutex<WebSocket>>` for shared write access

#### Caddy WebSocket Proxy

Caddy handles:
- TLS termination (Let's Encrypt certificates)
- WebSocket upgrade detection (automatic)
- Proxying to daemon on localhost:7778
- Connection timeouts and keep-alive

The daemon receives plain WebSocket (ws://) from Caddy, not TLS. This simplifies daemon code.

#### tungstenite Usage

**Server (daemon):** Use `tungstenite::accept_hdr()` to inspect headers during handshake:

```rust
let callback = |req: &Request, response: Response| {
    // Extract Authorization header
    // Extract query params
    // Validate here, return error to reject
    Ok(response)
};
let websocket = accept_hdr(stream, callback)?;
```

**Client:** Use `tungstenite::connect()` with TLS connector:

```rust
use native_tls::TlsConnector;
use tungstenite::client::IntoClientRequest;

let request = url.into_client_request()?;
let connector = TlsConnector::new()?;
let (websocket, _) = tungstenite::connect(request)?;  // TLS handled automatically for wss://
```
