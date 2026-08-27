# rama-proxy

`rama-proxy` is a client/server SOCKS5 proxy for Clash-style rule engines.

## Planned Release 1.2.3 (not released)

This section records changes intended for the future 1.2.3 release. The current
package version remains unchanged until that release is prepared.

- Add top-level `rama-proxy stop` to stop any running server, client, and UI daemon.
- Add `server --ui` to start and manage the UI child process together with the server.
- Add `ui stop` and `ui --daemon` for managing the built-in web UI process.
- Add `ui init` to generate `config/ui.toml` with bind address, port, PID files,
  stats socket, and sampling interval settings.
- Make UI settings load from `config/ui.toml` by default, with command-line
  options overriding the config file.
- Keep the last successful stats snapshot when the UI stats socket temporarily
  fails, so client names and tunnel data do not fall back to `/proc` data.
- Fix heartbeat tunnel reporting so active tunnels are not incorrectly removed
  because of the previous 600-second age filter.

## Release 1.2.1

This release hardens the server against slow or malformed tunnel clients and
adds the protection counters to the built-in UI.

Server-side changes:

- TLS accept and the private tunnel handshake time out after 10 seconds by default.
- At most 1024 tunnel handshakes run concurrently by default; rejected handshakes are logged and counted.
- UDP tunnel payloads are limited to 65535 bytes before allocation.
- UDP tunnels close after 300 seconds without traffic or heartbeat activity by default.
- Server tunnel sockets use TCP keepalive by default to detect half-open client connections without limiting long-lived tunnels.
- The stats Unix socket has a 5-second timeout for connect, request write, request read, and response read/write.
- The server records current total, handshake, TCP, and UDP connections, plus cumulative handshake timeouts, handshake rejections, and EMFILE events.
- The UI displays the connection and protection counters in a separate server protection section.

The new server settings are configurable in `[server]`:

```toml
handshake_timeout_secs = 10
max_handshakes = 1024
udp_idle_timeout_secs = 300
tcp_keepalive_secs = 60
```

Existing server configuration files remain compatible. Missing settings use the
defaults above. Rama remains on the vendored `0.3.0-alpha.4` API in this
release. Rama `0.4.0` was evaluated separately and is not included because it
contains breaking API changes across the TLS, connector, proxy-layer, and I/O
forwarding APIs used by this project.

The current target is:

- `client` runs locally and exposes SOCKS5 TCP/UDP to Clash
- `server` runs remotely and performs outbound access
- client-to-server traffic uses pre-established TCP tunnels instead of direct per-request SOCKS5 from Clash to the remote host
- optional Rama rustls-based TLS can be enabled for the client-to-server tunnel

## Scope

- SOCKS5 `CONNECT`
- SOCKS5 `UDP ASSOCIATE`
- optional local HTTP proxy adapter over the local SOCKS5 endpoint
- long-lived client/server tunnel pool
- local SOCKS5 endpoint for Clash Party
- remote outbound TCP/UDP access

Out of scope:

- HTTPS proxy listener (`https://proxy-host:port`)
- browser-specific logic
- complex routing logic inside `rama-proxy` itself

## Commands

```powershell
rama-proxy server init
rama-proxy server check
rama-proxy server stats
rama-proxy server --config config/server.toml
rama-proxy server --config config/server.toml --ui

rama-proxy client init
rama-proxy client check
rama-proxy client --config config/client.toml

rama-proxy ui
rama-proxy ui stop
rama-proxy ui init
rama-proxy ui --config config/ui.toml --daemon
rama-proxy stop
rama-proxy ui --port 19091
rama-proxy ui --pid-file config/rama-proxy-server.pid
```

Command notes:

- `server` starts the remote tunnel server when no nested command is provided
- `server --ui` starts the built-in UI as a child process and manages it with the server lifecycle
- `server stats` prints the latest server connection snapshot JSON
- `client` starts the local Clash-facing SOCKS5 service when no nested command is provided
- `ui` starts a built-in web UI for observing a running `server` process on Linux
- `ui stop` stops the UI process recorded in `config/rama-proxy-ui.pid`
- `ui init` writes a default `config/ui.toml` file
- `stop` stops the background `server`, `client`, and `ui` processes when present
- `init` writes a default config file for that mode
- `check` validates the config file and exits
- `--daemon` can be used with either `server` or `client`
- `server --ui --daemon` starts both server and UI in the background
- `--daemon` can also be used with `ui` to detach the web UI as a background process

## Web UI

The built-in UI is a separate process inside the same binary.

Default behavior:

- bind: `127.0.0.1`
- port: `19091`
- pid file: `config/rama-proxy-server.pid`

Example:

```powershell
rama-proxy server --config config/server.toml --daemon
rama-proxy server stats
rama-proxy ui --daemon
```

Then open:

- `http://127.0.0.1:19091/`

Supported flags:

The UI now reads defaults from `config/ui.toml` (or `--config <path>`). CLI flags override the config file values. Run `rama-proxy ui init` to generate a default config:

```toml
bind = "127.0.0.1"
port = 19091
pid_file = "config/rama-proxy-server.pid"
ui_pid_file = "config/rama-proxy-ui.pid"
stats_socket = "config/rama-proxy-server.stats.sock"
interval_ms = 2000
```

- `--bind <ip>`
- `--port <port>`
- `--pid-file <path>`
- `--stats-socket <path>`
- `--interval-ms <millis>`
- `--daemon`

Current UI data comes from polling `/proc/<pid>` on Linux, so:

- it is intended to observe a running remote `server` process
- it does not require changing the `server` runtime path
- fd and socket "observed duration" means "how long the UI has seen this item", not the exact kernel creation timestamp

Current pages and APIs:

- `/`: HTML dashboard
- `/api/snapshot`: JSON snapshot
- `/healthz`: health check

## Server Stats Snapshot

When `server` runs, it serves a protocol-level connection snapshot over a local admin socket.

Default behavior:

- stats socket: `config/rama-proxy-server.stats.sock`

Example:

```powershell
rama-proxy server --config config/server.toml --stats-socket config/rama-proxy-server.stats.sock
rama-proxy server stats --stats-socket config/rama-proxy-server.stats.sock
```

The snapshot includes:

- current tunnel count
- `handshake` / `idle` / `active-tcp` / `active-udp` counts
- whether each tunnel is currently in use
- client address
- target address
- upstream address
- accepted time
- last active time
- age / idle seconds
- bytes from client / bytes from target

This data comes from the `server` protocol path itself, not from `/proc` inference. The running server exposes it on a local admin socket, and `server stats` prints the current snapshot to stdout for external tooling to collect.

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
handshake_timeout_secs = 10
max_handshakes = 1024
udp_idle_timeout_secs = 300

[auth]
shared_secret = "change-me"

[tls]
enabled = false
cert_path = ""
key_path = ""
require_client_auth = false
client_ca_cert_path = ""

[log]
level = "info"
format = "text"
```

Notes:

- `server.bind` is the remote listen IP
- `server.port` is the tunnel port used by clients
- `--stats-socket` controls where the local admin stats socket is created
- `outbound_ip_mode` controls how the remote server connects to target addresses
- `auth.shared_secret` must match the client config
- enable `[tls]` to protect the tunnel with server certificate based TLS
- `tls.require_client_auth = true` enables mTLS-style client certificate verification

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

[http_connect]
bind = "127.0.0.1"
port = 18080

[udp]
enabled = true
idle_timeout_secs = 60

[auth]
mode = "none"
users = []

[tls]
enabled = false
server_name = ""
ca_cert_path = ""
insecure_skip_verify = false
client_cert_path = ""
client_key_path = ""

[log]
level = "info"
format = "text"
```

Notes:

- `client.server_addr` points to the remote `rama-proxy server`
- `client.pool_size` is the target idle prebuilt tunnel count; startup and every tunnel checkout immediately trigger async refill back to that target, and `idle + maintenance-hold + connecting` never exceeds this limit
- idle tunnel connections are health-checked in the background; stale connections are discarded and replenished immediately
- `tls.client_cert_path` and `tls.client_key_path` are optional; when both are empty the client only verifies the server certificate and does not perform mutual TLS
- `socks5.bind` and `socks5.port` define the local endpoint for Clash Party
- `socks5.tcp_keepalive_secs` enables TCP keepalive on accepted local connections; it detects half-open mobile/VPN connections without limiting normal long-lived connections
- configuring `http_connect.port` starts a local child process that accepts HTTP proxy requests and forwards through the local SOCKS5 listener
- the adapter supports HTTP `CONNECT` plus plain `http://...` forward-proxy requests over HTTP/1.x
- `udp.enabled` enables local SOCKS5 `UDP ASSOCIATE`
- `auth` controls local SOCKS5 authentication between Clash Party and the local client
- `tls.server_name` and `tls.ca_cert_path` are required when `tls.enabled = true`
- `tls.client_cert_path` and `tls.client_key_path` are optional and used only when the server requires client auth
- `tls.insecure_skip_verify` is reserved and currently rejected by config validation

## HTTP Proxy Usage

Use this mode when an app or browser does not support SOCKS5 but does support an HTTP proxy.

Example client config:

```toml
[socks5]
bind = "127.0.0.1"
port = 1080

[http_connect]
bind = "127.0.0.1"
port = 18080
```

Behavior:

- starting `rama-proxy client --config config/client.toml` also starts a local HTTP proxy child process when `http_connect.port` is configured
- if `http_connect.port` is omitted, the HTTP proxy adapter is not started
- the HTTP child process does not connect to the remote server directly
- it forwards accepted `CONNECT host:port` requests plus plain HTTP proxy requests such as `GET http://example.com/path HTTP/1.1` through the local SOCKS5 listener defined by `[socks5]`
- if `[socks5].bind` uses a wildcard listener such as `0.0.0.0` or `::`, the HTTP child process automatically connects to the loopback form (`127.0.0.1` or `::1`) instead of the wildcard address
- this keeps the existing tunnel, TLS, auth, and pool behavior in the original client/server path

Point the app to:

- proxy type: `HTTP`
- proxy host: `127.0.0.1`
- proxy port: `18080`

Current limitation:

- HTTPS target traffic works through the tunnel after `CONNECT` succeeds
- plain HTTP proxy requests are forwarded as one upstream request per connection with `Connection: close`
- request bodies using `Transfer-Encoding` are not supported yet
- HTTP request pipelining is not supported

If you need to run the adapter separately for debugging, the internal command is:

```powershell
rama-proxy http-connect-proxy --config config/client.toml
```

## TLS Overview

TLS in `rama-proxy` applies only to the `client <-> server` tunnel.

It does not change:

- the local SOCKS5 endpoint exposed by `client`
- the private tunnel opcode semantics
- the shared-secret check after the TLS handshake

Current TLS behavior:

- `server.tls.enabled = true` means all connecting clients must use TLS
- `server.tls.enabled = false` means all connecting clients must use plaintext
- mixed TLS and non-TLS clients are not supported on the same listener
- mTLS is optional and enabled only when `server.tls.require_client_auth = true`

## TLS Certificate Generation

The examples below use `openssl`.

### 1. Generate a CA

```powershell
openssl genrsa -out ca.key 2048
openssl req -x509 -new -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=rama-proxy-ca"
```

### 2. Generate the server certificate

Use a CN / SAN value that the client will use as `tls.server_name`.

Create `server.ext`:

```text
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = rama-proxy-server
IP.1 = 127.0.0.1
```

Generate and sign the server certificate:

```powershell
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=rama-proxy-server"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650 -sha256 -extfile server.ext
```

### 3. Optional: generate a client certificate for mTLS

Create `client.ext`:

```text
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
```

Generate and sign the client certificate:

```powershell
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=rama-proxy-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 3650 -sha256 -extfile client.ext
```

Generated files:

- `ca.crt`: CA certificate used by the client to verify the server
- `server.crt` / `server.key`: server certificate and private key
- `client.crt` / `client.key`: optional client certificate and private key for mTLS

## TLS Configuration Examples

### 1. One-way TLS

Server:

```toml
[tls]
enabled = true
cert_path = "certs/server.crt"
key_path = "certs/server.key"
require_client_auth = false
client_ca_cert_path = ""
```

Client:

```toml
[tls]
enabled = true
server_name = "rama-proxy-server"
ca_cert_path = "certs/ca.crt"
insecure_skip_verify = false
client_cert_path = ""
client_key_path = ""
```

Notes:

- `client.tls.server_name` must match the server certificate CN or SAN
- if the server certificate only contains an IP SAN, use that IP as `server_name`
- the client must trust the CA that signed `server.crt`

### 2. mTLS

Server:

```toml
[tls]
enabled = true
cert_path = "certs/server.crt"
key_path = "certs/server.key"
require_client_auth = true
client_ca_cert_path = "certs/ca.crt"
```

Client:

```toml
[tls]
enabled = true
server_name = "rama-proxy-server"
ca_cert_path = "certs/ca.crt"
insecure_skip_verify = false
client_cert_path = "certs/client.crt"
client_key_path = "certs/client.key"
```

Notes:

- when `require_client_auth = true`, the client certificate must be signed by the CA trusted by `client_ca_cert_path`
- `client_cert_path` and `client_key_path` must be configured together

## TLS Usage

Recommended order:

1. Generate the CA and server certificate.
2. Copy `server.crt` and `server.key` to the remote server host.
3. Copy `ca.crt` to the client host.
4. If mTLS is enabled, also copy `client.crt` and `client.key` to the client host.
5. Update `[tls]` in both `config/server.toml` and `config/client.toml`.
6. Run `rama-proxy server check --config config/server.toml`.
7. Run `rama-proxy client check --config config/client.toml`.
8. Start the server, then start the client.

Expected result:

- the client connects to the server over TLS first
- after TLS succeeds, the existing private tunnel handshake still runs
- SOCKS5 users continue to connect only to the local `client`

Common mistakes:

- `client.tls.server_name` does not match the server certificate
- `client.tls.ca_cert_path` does not trust the issuing CA
- enabling TLS on only one side
- setting `require_client_auth = true` on the server without configuring client certs
- trying to use `tls.insecure_skip_verify`, which is currently rejected

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
5. If needed, generate certificates and enable `[tls]` on both sides.
6. If needed, enable `[http_connect]` and choose a local HTTP proxy port.
7. Start `rama-proxy client`.
8. Point Clash Party to the local SOCKS5 endpoint, or point an HTTP-proxy-only app to the local `[http_connect]` endpoint.

## Current Behavior

This version is focused on a stable first cut:

- TCP requests use a tunnel connection that is opened by the local client and switched into raw relay mode after the server confirms the target
- UDP associate uses one tunnel TCP control connection plus one local UDP socket per SOCKS5 association
- the client maintains a warm pool of pre-authenticated idle tunnel connections up to `client.pool_size` and creates extra tunnels on demand
- the pool now performs background idle health checks and removes stale tunnels proactively
- warm-pool refill immediately schedules the full missing tunnel count and backs off exponentially after repeated TLS or handshake failures
- when acquire sees a small number of stale idle tunnels, it discards them and quickly falls back to creating a fresh tunnel instead of spending the full request timeout probing many dead entries
- when TLS is enabled, the tunnel transport is wrapped by Rama rustls before the private tunnel handshake starts

This is not a full multi-stream multiplexing transport yet. It is intentionally simpler so the TCP/UDP proxy path stays easier to reason about and debug.

## Logging

The program writes logs for:

- client/server startup
- tunnel authentication and request handling
- TCP tunnel lifecycle
- UDP associate lifecycle
- SOCKS5 handshake failures
