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
    ├── session.rs       # session management (connect to fcm-agent in VM)
    ├── vm.rs            # vm create/start/stop/destroy
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

## persistent console sessions

cli-based interactive console with persistent, detachable sessions (similar to sprites.dev):

### architecture

```
┌─────────────┐         ┌─────────────┐         ┌───────────┐
│  fcm CLI    │ ──TCP── │   Daemon    │ ──TCP── │ fcm-agent │
│ (any host)  │  :7778  │  (proxies)  │  :7779  │   (PTY)   │
└─────────────┘         └─────────────┘         └───────────┘
                                                      │
                                                    [PTY]
                                                      │
                                                   /bin/sh
```

### how it works

1. each VM runs `fcm-agent` on port 7779 (started by init)
2. fcm-agent manages PTY sessions directly (no SSH/tmux needed)
3. CLI connects to daemon on port 7778
4. daemon proxies messages to fcm-agent on VM's internal IP
5. if client disconnects, PTY session keeps running on fcm-agent
6. client can reconnect anytime with `fcm console`

### session management

- `fcm console <vm>` - connects to VM's persistent console session
- one session per VM (simple, no session IDs to manage)
- session persists until VM is stopped
- if shell exits (user types `exit`), new shell spawns automatically

### terminal protocol (port 7778)

JSON framed messages (newline-delimited):

```json
// client -> daemon: initial connect
{"vm": "vm-id", "token": "auth-token", "cols": 80, "rows": 24}

// daemon -> client: connect response
{"success": true}
{"success": false, "error": "VM not found"}

// bidirectional: terminal I/O
{"stdin": "base64-encoded-input"}      // client -> daemon -> agent
{"stdout": "base64-encoded-output"}    // agent -> daemon -> client

// client -> daemon -> agent: resize terminal
{"resize": {"cols": 120, "rows": 40}}

// agent -> daemon -> client: shell exited (new shell spawns)
{"exit": 0}
```

### fcm-agent

small daemon running on each VM that manages PTY sessions:

```
fcm-agent
├── listens on TCP :7779 (internal network only)
├── accepts connection from daemon (172.16.0.1)
├── spawns PTY with /bin/sh
├── proxies stdin/stdout between TCP and PTY
├── handles resize (SIGWINCH to PTY)
└── respawns shell if user exits
```

protocol (TCP :7779, JSON newline-delimited):
```json
{"stdin": "base64data"}                // write to PTY
{"stdout": "base64data"}               // read from PTY
{"resize": {"cols": 80, "rows": 24}}   // resize PTY
{"exit": 0}                            // shell exited
```

implementation: ~200 lines of Rust, ~50KB binary, no dependencies

### vm requirements

- fcm-agent binary at /usr/local/bin/fcm-agent
- fcm-agent started by init, listens on port 7779
- no SSH/tmux required for console (SSH still used for git push)

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
- fcm-agent (PTY manager for console sessions)
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
    nodejs npm curl bash iproute2 rng-tools

# Configure dropbear SSH and set root password (for git push)
RUN mkdir -p /etc/dropbear && \
    dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key && \
    dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key && \
    dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key && \
    echo "root:root" | chpasswd

# Copy fcm-agent binary (for console sessions)
COPY fcm-agent /usr/local/bin/fcm-agent
RUN chmod +x /usr/local/bin/fcm-agent

# Copy init script
COPY init /tmp/init
RUN chmod +x /tmp/init && mv /tmp/init /sbin/init
```

init script starts dropbear ssh (for git push) and fcm-agent (for console).

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
