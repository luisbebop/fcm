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
fcm create                    # create vm with random name, expose port 8000
fcm ls                        # list vms
fcm console <vm>              # open persistent console session
fcm sessions <vm>             # list active sessions for a vm
fcm attach <vm> <session-id>  # reattach to existing session
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
    ├── session.rs       # session management (create/list/attach tmux sessions)
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
┌─────────────┐         ┌─────────────┐         ┌─────────┐
│  fcm CLI    │ ──TCP── │   Daemon    │ ──SSH── │   VM    │
│ (any host)  │  :7778  │  (manages   │         │ (tmux)  │
└─────────────┘         │  sessions)  │         └─────────┘
                        └─────────────┘
```

### how it works

1. each vm runs `tmux` by default
2. daemon manages sessions internally (creates/attaches tmux sessions via ssh to vm)
3. cli connects to daemon on streaming port (7778)
4. daemon proxies terminal i/o between cli and vm's tmux session
5. if client disconnects (network drop, close terminal), tmux session keeps running
6. client can reconnect anytime with `fcm attach`

### session management

- `fcm console <vm>` - creates new session or attaches to existing default session
- `fcm sessions <vm>` - lists all active sessions for a vm
- `fcm attach <vm> <session-id>` - reattaches to a specific session
- sessions persist until explicitly killed or vm is stopped
- supports multiple concurrent sessions per vm (multi-user ready)

### daemon endpoints

```
POST   /vms/{id}/sessions              # create new session, returns session-id
GET    /vms/{id}/sessions              # list active sessions
DELETE /vms/{id}/sessions/{session-id} # kill a session
```

### terminal streaming (port 7778)

- daemon listens on tcp port 7778 for terminal connections
- client connects, sends: `{"vm": "vm-id", "session": "session-id", "token": "auth-token"}`
- daemon authenticates, then spawns `ssh root@vm-ip tmux attach -t session-id`
- daemon proxies raw terminal i/o between client and ssh process
- client handles raw terminal mode for proper tty experience

### vm requirements

- tmux installed in base rootfs
- ssh access from daemon to vm (already works via internal network)

## base image

create new alpine-based rootfs with:
- openssh-server (with root login enabled)
- tmux (for persistent console sessions)
- ruby 4.0 + bundler (latest stable: 4.0.1)
- python 3.14 + pip (latest stable: 3.14.2)
- minimal init script (same pattern as existing alpine image)

dockerfile:
```dockerfile
FROM alpine:edge
RUN apk add --no-cache \
    openssh ruby ruby-bundler python3 py3-pip \
    tmux curl bash iproute2
# configure ssh
RUN ssh-keygen -A && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "root:root" | chpasswd
# copy init script (configures network from cmdline, starts sshd)
COPY init /sbin/init
```

init script starts sshd and listens on port 8000 placeholder.

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
  "expose": {"port": 8000, "domain": "myvm.64-34-93-45.sslip.io"}
}
```

## verification

1. `sudo fcm daemon &` - start daemon
2. `fcm create` - create vm (auto-generates name like "cosmic-nova")
3. `fcm ls` - see vm running
4. `fcm console cosmic-nova` - open persistent console, verify ruby/python available
5. disconnect (close terminal or network drop)
6. `fcm sessions cosmic-nova` - see session still running
7. `fcm attach cosmic-nova <session-id>` - reattach, verify state preserved
8. `curl https://cosmic-nova.64-34-93-45.sslip.io` - verify ssl works
9. `fcm destroy cosmic-nova` - cleanup
