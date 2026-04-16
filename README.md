# rama-proxy

`rama-proxy` is a client/server SOCKS5 proxy for Clash-style rule engines.

The current target is:

- `client` runs locally and exposes SOCKS5 TCP/UDP to Clash
- `server` runs remotely and performs outbound access
- client-to-server traffic uses pre-established TCP tunnels instead of direct per-request SOCKS5 from Clash to the remote host
- optional Rama rustls-based TLS can be enabled for the client-to-server tunnel

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
- `client.pool_size` controls how many idle tunnels the client keeps ready
- `socks5.bind` and `socks5.port` define the local endpoint for Clash Party
- `udp.enabled` enables local SOCKS5 `UDP ASSOCIATE`
- `auth` controls local SOCKS5 authentication between Clash Party and the local client
- `tls.server_name` and `tls.ca_cert_path` are required when `tls.enabled = true`
- `tls.client_cert_path` and `tls.client_key_path` are optional and used only when the server requires client auth
- `tls.insecure_skip_verify` is reserved and currently rejected by config validation

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
6. Start `rama-proxy client`.
7. Point Clash Party to the local SOCKS5 endpoint.

## Current Behavior

This version is focused on a stable first cut:

- TCP requests use a tunnel connection that is opened by the local client and switched into raw relay mode after the server confirms the target
- UDP associate uses one tunnel TCP control connection plus one local UDP socket per SOCKS5 association
- the client maintains a pool of pre-authenticated idle tunnel connections
- when TLS is enabled, the tunnel transport is wrapped by Rama rustls before the private tunnel handshake starts

This is not a full multi-stream multiplexing transport yet. It is intentionally simpler so the TCP/UDP proxy path stays easier to reason about and debug.

## Logging

The program writes logs for:

- client/server startup
- tunnel authentication and request handling
- TCP tunnel lifecycle
- UDP associate lifecycle
- SOCKS5 handshake failures
