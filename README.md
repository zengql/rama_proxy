# rama-proxy

`rama-proxy` is a client/server SOCKS5 proxy for Clash-style rule engines.

The current target is:

- `client` runs locally and exposes SOCKS5 TCP/UDP to Clash
- `server` runs remotely and performs outbound access
- client-to-server traffic uses pre-established TCP tunnels instead of direct per-request SOCKS5 from Clash to the remote host

## Scope

- SOCKS5 `CONNECT`
- SOCKS5 `UDP ASSOCIATE`
- long-lived client/server tunnel pool
- local SOCKS5 endpoint for Clash Party
- remote outbound TCP/UDP access

Out of scope:

- HTTP / HTTPS CONNECT proxy
- browser-specific logic
- complex routing logic inside `rama-proxy` itself

## Commands

```powershell
rama-proxy server init
rama-proxy server check
rama-proxy server --config config/server.toml

rama-proxy client init
rama-proxy client check
rama-proxy client --config config/client.toml
```

Command notes:

- `server` starts the remote tunnel server when no nested command is provided
- `client` starts the local Clash-facing SOCKS5 service when no nested command is provided
- `init` writes a default config file for that mode
- `check` validates the config file and exits
- `--daemon` can be used with either `server` or `client`

## Architecture

```text
Clash Party -> local rama-proxy client -> tunnel pool -> remote rama-proxy server -> target
```

Responsibilities:

- Clash Party handles rules, groups, and policy
- `rama-proxy client` exposes a local SOCKS5 TCP/UDP endpoint
- `rama-proxy server` accepts tunnel connections and performs the final outbound connect / udp relay

## Server Config

Default file: `config/server.toml`

```toml
[server]
bind = "0.0.0.0"
port = 19090
outbound_ip_mode = "ipv4"
workers = 0

[auth]
shared_secret = "change-me"

[log]
level = "info"
format = "text"
```

Notes:

- `server.bind` is the remote listen IP
- `server.port` is the tunnel port used by clients
- `outbound_ip_mode` controls how the remote server connects to target addresses
- `auth.shared_secret` must match the client config

## Client Config

Default file: `config/client.toml`

```toml
[client]
server_addr = "127.0.0.1:19090"
shared_secret = "change-me"
pool_size = 8
connect_timeout_secs = 10

[socks5]
bind = "127.0.0.1"
port = 1080

[udp]
enabled = true
idle_timeout_secs = 60

[auth]
mode = "none"
users = []

[log]
level = "info"
format = "text"
```

Notes:

- `client.server_addr` points to the remote `rama-proxy server`
- `client.pool_size` controls how many idle tunnels the client keeps ready
- `socks5.bind` and `socks5.port` define the local endpoint for Clash Party
- `udp.enabled` enables local SOCKS5 `UDP ASSOCIATE`
- `auth` controls local SOCKS5 authentication between Clash Party and the local client

## Clash Party

Point Clash Party to the local `client` listener instead of the remote server:

```yaml
proxies:
  - name: rama-proxy
    type: socks5
    server: 127.0.0.1
    port: 1080
    udp: true
```

If local SOCKS5 auth is enabled:

```yaml
proxies:
  - name: rama-proxy
    type: socks5
    server: 127.0.0.1
    port: 1080
    udp: true
    username: your-user
    password: your-pass
```

## Deployment Order

1. Initialize and edit `config/server.toml` on the remote host.
2. Start `rama-proxy server`.
3. Initialize and edit `config/client.toml` on the local host.
4. Set `client.server_addr` and `auth.shared_secret`.
5. Start `rama-proxy client`.
6. Point Clash Party to the local SOCKS5 endpoint.

## Current Behavior

This version is focused on a stable first cut:

- TCP requests use a tunnel connection that is opened by the local client and switched into raw relay mode after the server confirms the target
- UDP associate uses one tunnel TCP control connection plus one local UDP socket per SOCKS5 association
- the client maintains a pool of pre-authenticated idle tunnel connections

This is not a full multi-stream multiplexing transport yet. It is intentionally simpler so the TCP/UDP proxy path stays easier to reason about and debug.

## Logging

The program writes logs for:

- client/server startup
- tunnel authentication and request handling
- TCP tunnel lifecycle
- UDP associate lifecycle
- SOCKS5 handshake failures
