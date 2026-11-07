use std::net::{IpAddr, SocketAddr};
use std::str;

use rama::net::address::{Host, HostWithPort};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpSocket, TcpStream},
};
use tracing::{info, warn};

use crate::{
    config::{ClientConfigFile, LocalAuthConfig},
    error::AppError,
};

const MAX_HTTP_HEADER_SIZE: usize = 16 * 1024;

pub async fn run(config: ClientConfigFile) -> Result<(), AppError> {
    let Some(http_port) = config.http_connect.port else {
        return Err(AppError::InvalidConfig(
            "http_connect.port must be configured to run the HTTP CONNECT adapter".to_string(),
        ));
    };

    let bind_ip = parse_bind_ip(&config.http_connect.bind)?;
    let listen_addr = SocketAddr::new(bind_ip, http_port);
    let listener = bind_listener(listen_addr).await?;
    let socks5_addr = resolve_local_socks5_upstream_addr(&config.socks5.bind, config.socks5.port)?;

    info!(
        bind = %listen_addr,
        upstream_socks5 = %socks5_addr,
        "http connect proxy started"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let auth = config.auth.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_session(stream, peer, socks5_addr, auth).await {
                warn!(client = %peer, error = %err, "http connect session ended with error");
            }
        });
    }
}

async fn bind_listener(addr: SocketAddr) -> Result<TcpListener, AppError> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    Ok(socket.listen(4096)?)
}

async fn handle_session(
    mut stream: TcpStream,
    peer: SocketAddr,
    socks5_addr: SocketAddr,
    auth: LocalAuthConfig,
) -> Result<(), AppError> {
    stream.set_nodelay(true)?;
    let mut forward_upstream = None::<ForwardUpstream>;

    loop {
        let Some(raw_request) = read_http_request(&mut stream).await? else {
            return Ok(());
        };
        let request = match parse_http_request(&raw_request.header_bytes) {
            Ok(request) => request,
            Err(HttpRequestError::BadRequest(message)) => {
                write_http_error(&mut stream, "400 Bad Request", &message).await?;
                return Ok(());
            }
        };

        match request {
            HttpRequest::Connect(connect_request) => {
                drop(forward_upstream.take());
                let target = &connect_request.target;
                let mut upstream = match connect_via_socks5(socks5_addr, target, &auth).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        warn!(
                            client = %peer,
                            target = %target,
                            error = %err,
                            "http proxy upstream establish failed"
                        );
                        write_http_error(
                            &mut stream,
                            "502 Bad Gateway",
                            "upstream socks5 connect failed",
                        )
                        .await?;
                        return Ok(());
                    }
                };

                write_connect_established(&mut stream).await?;
                if !raw_request.tail_bytes.is_empty() {
                    upstream.write_all(&raw_request.tail_bytes).await?;
                }

                let result = copy_bidirectional(&mut stream, &mut upstream).await;
                return match result {
                    Ok((up_bytes, down_bytes)) => {
                        info!(
                            client = %peer,
                            target = %connect_request.target,
                            up_bytes,
                            down_bytes,
                            "http connect session finished"
                        );
                        Ok(())
                    }
                    Err(err) => Err(AppError::Io(err)),
                };
            }
            HttpRequest::Forward(forward_request) => {
                let target = forward_request.target.to_string();
                if forward_upstream
                    .as_ref()
                    .map(|upstream| upstream.target.as_str())
                    != Some(target.as_str())
                {
                    drop(forward_upstream.take());
                    let upstream =
                        match connect_via_socks5(socks5_addr, &forward_request.target, &auth).await
                        {
                            Ok(stream) => stream,
                            Err(err) => {
                                warn!(
                                    client = %peer,
                                    target = %forward_request.target,
                                    error = %err,
                                    "http proxy upstream establish failed"
                                );
                                write_http_error(
                                    &mut stream,
                                    "502 Bad Gateway",
                                    "upstream socks5 connect failed",
                                )
                                .await?;
                                return Ok(());
                            }
                        };
                    forward_upstream = Some(ForwardUpstream {
                        target,
                        stream: upstream,
                    });
                }

                let upstream = &mut forward_upstream
                    .as_mut()
                    .expect("forward upstream must exist")
                    .stream;
                relay_forward_request(
                    &mut stream,
                    upstream,
                    &raw_request.tail_bytes,
                    &forward_request,
                )
                .await?;

                let response_keep_alive =
                    relay_forward_response(upstream, &mut stream, &forward_request.method).await?;
                info!(
                    client = %peer,
                    method = %forward_request.method,
                    target = %forward_request.target,
                    reused_upstream = response_keep_alive,
                    "http forward session finished"
                );

                if !response_keep_alive {
                    drop(forward_upstream.take());
                }
                if !forward_request.client_keep_alive || !response_keep_alive {
                    return Ok(());
                }
            }
        }
    }
}

async fn read_http_request(stream: &mut TcpStream) -> Result<Option<RawHttpMessage>, AppError> {
    read_http_message(
        stream,
        "client closed connection before sending a full HTTP request",
        true,
    )
    .await
}

async fn read_http_response(stream: &mut TcpStream) -> Result<RawHttpMessage, AppError> {
    read_http_message(
        stream,
        "upstream closed connection before sending a full HTTP response",
        false,
    )
    .await?
    .ok_or_else(|| {
        AppError::InvalidConfig(
            "upstream closed connection before sending a full HTTP response".to_string(),
        )
    })
}

async fn read_http_message(
    stream: &mut TcpStream,
    eof_message: &str,
    allow_empty_eof: bool,
) -> Result<Option<RawHttpMessage>, AppError> {
    let mut buf = Vec::with_capacity(1024);
    let mut read_buf = [0u8; 2048];

    loop {
        let n = stream.read(&mut read_buf).await?;
        if n == 0 {
            if allow_empty_eof && buf.is_empty() {
                return Ok(None);
            }
            return Err(AppError::InvalidConfig(eof_message.to_string()));
        }
        buf.extend_from_slice(&read_buf[..n]);
        if let Some(header_end) = find_header_end(&buf) {
            let tail_start = header_end + 4;
            return Ok(Some(RawHttpMessage {
                header_bytes: buf[..tail_start].to_vec(),
                tail_bytes: buf[tail_start..].to_vec(),
            }));
        }
        if buf.len() > MAX_HTTP_HEADER_SIZE {
            return Err(AppError::InvalidConfig(
                "http request header is too large".to_string(),
            ));
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_http_request(header_bytes: &[u8]) -> Result<HttpRequest, HttpRequestError> {
    let header = str::from_utf8(header_bytes).map_err(|_| {
        HttpRequestError::BadRequest("request header is not valid utf-8".to_string())
    })?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| HttpRequestError::BadRequest("request line is missing".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();

    if method.is_empty() || target.is_empty() || version.is_empty() {
        return Err(HttpRequestError::BadRequest(
            "request line must be METHOD target HTTP/1.x".to_string(),
        ));
    }
    if !version.starts_with("HTTP/1.") {
        return Err(HttpRequestError::BadRequest(format!(
            "unsupported http version: {version}"
        )));
    }

    let headers = parse_headers(lines)?;

    if method == "CONNECT" {
        let target = target.parse::<HostWithPort>().map_err(|err| {
            HttpRequestError::BadRequest(format!("invalid CONNECT authority: {err}"))
        })?;
        return Ok(HttpRequest::Connect(ConnectRequest { target }));
    }

    Ok(HttpRequest::Forward(parse_forward_request(
        method, target, version, &headers,
    )?))
}

async fn connect_via_socks5(
    socks5_addr: SocketAddr,
    target: &HostWithPort,
    auth: &LocalAuthConfig,
) -> Result<TcpStream, AppError> {
    let mut stream = TcpStream::connect(socks5_addr).await?;
    stream.set_nodelay(true)?;

    if auth.mode == "password" {
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply).await?;
    if method_reply[0] != 0x05 {
        return Err(AppError::InvalidConfig(format!(
            "invalid socks5 greeting version: {}",
            method_reply[0]
        )));
    }
    if method_reply[1] == 0xFF {
        return Err(AppError::InvalidConfig(
            "local socks5 rejected all authentication methods".to_string(),
        ));
    }

    if method_reply[1] == 0x02 {
        authenticate_socks5_user(&mut stream, auth).await?;
    } else if method_reply[1] != 0x00 {
        return Err(AppError::InvalidConfig(format!(
            "unsupported socks5 auth method selected by local proxy: {}",
            method_reply[1]
        )));
    }

    let request = build_socks5_connect_request(target)?;
    stream.write_all(&request).await?;

    let mut response_head = [0u8; 4];
    stream.read_exact(&mut response_head).await?;
    if response_head[0] != 0x05 {
        return Err(AppError::InvalidConfig(format!(
            "invalid socks5 response version: {}",
            response_head[0]
        )));
    }
    if response_head[1] != 0x00 {
        return Err(AppError::InvalidConfig(format!(
            "local socks5 connect failed with reply code {}",
            response_head[1]
        )));
    }
    if response_head[2] != 0x00 {
        return Err(AppError::InvalidConfig(
            "local socks5 response used a non-zero reserved byte".to_string(),
        ));
    }

    consume_socks5_address(&mut stream, response_head[3]).await?;
    Ok(stream)
}

async fn authenticate_socks5_user(
    stream: &mut TcpStream,
    auth: &LocalAuthConfig,
) -> Result<(), AppError> {
    let user = auth.users.first().ok_or_else(|| {
        AppError::InvalidConfig(
            "auth.users must not be empty when local socks5 auth.mode is password".to_string(),
        )
    })?;
    let username = user.username.as_bytes();
    let password = user.password.as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(AppError::InvalidConfig(
            "local socks5 username/password is too long for RFC1929".to_string(),
        ));
    }

    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;

    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x00 {
        return Err(AppError::InvalidConfig(
            "local socks5 username/password authentication failed".to_string(),
        ));
    }
    Ok(())
}

fn build_socks5_connect_request(target: &HostWithPort) -> Result<Vec<u8>, AppError> {
    let mut request = Vec::with_capacity(6 + target.to_string().len());
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    match &target.host {
        Host::Address(addr) => match addr {
            IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        },
        Host::Name(name) => {
            let name = name.as_ref().as_bytes();
            if name.len() > u8::MAX as usize {
                return Err(AppError::InvalidConfig(
                    "CONNECT host name is too long for socks5 domain mode".to_string(),
                ));
            }
            request.push(0x03);
            request.push(name.len() as u8);
            request.extend_from_slice(name);
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    Ok(request)
}

async fn consume_socks5_address(stream: &mut TcpStream, atyp: u8) -> Result<(), AppError> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0u8; len + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        other => {
            return Err(AppError::InvalidConfig(format!(
                "unsupported socks5 address type in response: {other}"
            )));
        }
    }
    Ok(())
}

async fn write_connect_established(stream: &mut TcpStream) -> Result<(), AppError> {
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: rama-proxy\r\n\r\n")
        .await?;
    Ok(())
}

async fn write_http_error(
    stream: &mut TcpStream,
    status: &str,
    message: &str,
) -> Result<(), AppError> {
    let body = format!("{message}\n");
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

fn parse_bind_ip(bind: &str) -> Result<IpAddr, AppError> {
    bind.parse()
        .map_err(|_| AppError::InvalidConfig("bind must be a valid IP address".to_string()))
}

fn resolve_local_socks5_upstream_addr(bind: &str, port: u16) -> Result<SocketAddr, AppError> {
    let ip = parse_bind_ip(bind)?;
    let resolved_ip = match ip {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        other => other,
    };
    Ok(SocketAddr::new(resolved_ip, port))
}

struct RawHttpMessage {
    header_bytes: Vec<u8>,
    tail_bytes: Vec<u8>,
}

struct ForwardUpstream {
    target: String,
    stream: TcpStream,
}

struct ConnectRequest {
    target: HostWithPort,
}

struct ForwardRequest {
    method: String,
    target: HostWithPort,
    upstream_header_bytes: Vec<u8>,
    body_kind: HttpRequestBodyKind,
    client_keep_alive: bool,
}

enum HttpRequest {
    Connect(ConnectRequest),
    Forward(ForwardRequest),
}

enum HttpRequestBodyKind {
    None,
    ContentLength(usize),
}

enum HttpResponseBodyKind {
    None,
    ContentLength(usize),
    Chunked,
    UntilClose,
}

struct HttpResponseHead {
    keep_alive: bool,
    body_kind: HttpResponseBodyKind,
}

#[derive(Debug)]
enum HttpRequestError {
    BadRequest(String),
}

fn parse_headers<'a, I>(lines: I) -> Result<Vec<(String, String)>, HttpRequestError>
where
    I: Iterator<Item = &'a str>,
{
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HttpRequestError::BadRequest(format!(
                "invalid http header line: {line}"
            )));
        };
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Ok(headers)
}

fn parse_forward_request(
    method: &str,
    raw_target: &str,
    version: &str,
    headers: &[(String, String)],
) -> Result<ForwardRequest, HttpRequestError> {
    let client_keep_alive = should_keep_alive(version, headers, true);
    let mut host_header = None::<String>;
    let mut content_length = None::<usize>;
    let mut transfer_encoding = None::<String>;
    let mut has_expect = false;
    let mut filtered_headers = Vec::new();

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "host" => {
                host_header = Some(value.clone());
                filtered_headers.push((name.clone(), value.clone()));
            }
            "content-length" => {
                let parsed = value.parse::<usize>().map_err(|_| {
                    HttpRequestError::BadRequest(format!("invalid Content-Length header: {value}"))
                })?;
                content_length = Some(parsed);
                filtered_headers.push((name.clone(), value.clone()));
            }
            "transfer-encoding" => {
                transfer_encoding = Some(value.clone());
            }
            "expect" => {
                has_expect = true;
            }
            "keep-alive" | "proxy-connection" | "proxy-authorization" | "connection" => {}
            _ => filtered_headers.push((name.clone(), value.clone())),
        }
    }

    if has_expect {
        return Err(HttpRequestError::BadRequest(
            "Expect request headers are not supported yet".to_string(),
        ));
    }

    if let Some(encoding) = transfer_encoding {
        return Err(HttpRequestError::BadRequest(format!(
            "unsupported request Transfer-Encoding: {encoding}"
        )));
    }

    let body_kind = match content_length {
        Some(length) => HttpRequestBodyKind::ContentLength(length),
        None => HttpRequestBodyKind::None,
    };

    let (target, path_and_query) = parse_forward_target(raw_target, host_header.as_deref())?;
    let mut upstream_header = format!("{method} {path_and_query} {version}\r\n");

    if host_header.is_none() {
        upstream_header.push_str(&format!("Host: {}\r\n", target));
    }
    for (name, value) in filtered_headers {
        upstream_header.push_str(&format!("{name}: {value}\r\n"));
    }
    if client_keep_alive {
        upstream_header.push_str("Connection: keep-alive\r\n\r\n");
    } else {
        upstream_header.push_str("Connection: close\r\n\r\n");
    }

    Ok(ForwardRequest {
        method: method.to_string(),
        target,
        upstream_header_bytes: upstream_header.into_bytes(),
        body_kind,
        client_keep_alive,
    })
}

fn parse_forward_target(
    raw_target: &str,
    host_header: Option<&str>,
) -> Result<(HostWithPort, String), HttpRequestError> {
    let lower_target = raw_target.to_ascii_lowercase();
    if lower_target.starts_with("http://") {
        let rest = &raw_target[7..];
        let path_start = rest.find('/').unwrap_or(rest.len());
        let (authority, suffix) = rest.split_at(path_start);
        if authority.is_empty() {
            return Err(HttpRequestError::BadRequest(
                "absolute-form http target is missing authority".to_string(),
            ));
        }
        if authority.contains('@') {
            return Err(HttpRequestError::BadRequest(
                "userinfo in proxy request targets is not supported".to_string(),
            ));
        }
        let target = parse_host_with_default_port(authority, 80)?;
        let path = if suffix.is_empty() { "/" } else { suffix };
        return Ok((target, path.to_string()));
    }

    if lower_target.starts_with("https://") {
        return Err(HttpRequestError::BadRequest(
            "https absolute-form requests must use CONNECT".to_string(),
        ));
    }

    if raw_target.starts_with('/') || raw_target == "*" {
        let host = host_header.ok_or_else(|| {
            HttpRequestError::BadRequest(
                "Host header is required for origin-form proxy requests".to_string(),
            )
        })?;
        let target = parse_host_with_default_port(host, 80)?;
        return Ok((target, raw_target.to_string()));
    }

    Err(HttpRequestError::BadRequest(format!(
        "unsupported request target form: {raw_target}"
    )))
}

fn parse_host_with_default_port(
    authority: &str,
    default_port: u16,
) -> Result<HostWithPort, HttpRequestError> {
    if authority.starts_with('[') {
        if authority.contains("]:") {
            return authority.parse::<HostWithPort>().map_err(|err| {
                HttpRequestError::BadRequest(format!("invalid authority {authority}: {err}"))
            });
        }
        return format!("{authority}:{default_port}")
            .parse::<HostWithPort>()
            .map_err(|err| {
                HttpRequestError::BadRequest(format!("invalid authority {authority}: {err}"))
            });
    }

    if authority.rsplit_once(':').is_some_and(|(_, port)| {
        !port.is_empty() && port.as_bytes().iter().all(|byte| byte.is_ascii_digit())
    }) {
        return authority.parse::<HostWithPort>().map_err(|err| {
            HttpRequestError::BadRequest(format!("invalid authority {authority}: {err}"))
        });
    }

    format!("{authority}:{default_port}")
        .parse::<HostWithPort>()
        .map_err(|err| {
            HttpRequestError::BadRequest(format!("invalid authority {authority}: {err}"))
        })
}

async fn relay_forward_response(
    upstream: &mut TcpStream,
    client: &mut TcpStream,
    request_method: &str,
) -> Result<bool, AppError> {
    let raw_response = read_http_response(upstream).await?;
    let response = parse_http_response(&raw_response.header_bytes, request_method)
        .map_err(|HttpRequestError::BadRequest(message)| AppError::InvalidConfig(message))?;

    client.write_all(&raw_response.header_bytes).await?;
    match response.body_kind {
        HttpResponseBodyKind::None => {
            if !raw_response.tail_bytes.is_empty() {
                return Err(AppError::InvalidConfig(
                    "unexpected bytes after response headers without body".to_string(),
                ));
            }
        }
        HttpResponseBodyKind::ContentLength(length) => {
            relay_prefetched_body(upstream, client, &raw_response.tail_bytes, length).await?;
        }
        HttpResponseBodyKind::Chunked => {
            relay_chunked_body(upstream, client, raw_response.tail_bytes).await?;
        }
        HttpResponseBodyKind::UntilClose => {
            if !raw_response.tail_bytes.is_empty() {
                client.write_all(&raw_response.tail_bytes).await?;
            }
            let mut read_buf = [0u8; 8192];
            loop {
                let n = upstream.read(&mut read_buf).await?;
                if n == 0 {
                    break;
                }
                client.write_all(&read_buf[..n]).await?;
            }
            return Ok(false);
        }
    }
    client.flush().await?;
    Ok(response.keep_alive)
}

fn parse_http_response(
    header_bytes: &[u8],
    request_method: &str,
) -> Result<HttpResponseHead, HttpRequestError> {
    let header = str::from_utf8(header_bytes).map_err(|_| {
        HttpRequestError::BadRequest("response header is not valid utf-8".to_string())
    })?;
    let mut lines = header.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        HttpRequestError::BadRequest("response status line is missing".to_string())
    })?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status_code = parts
        .next()
        .ok_or_else(|| HttpRequestError::BadRequest("response status code is missing".to_string()))?
        .parse::<u16>()
        .map_err(|_| HttpRequestError::BadRequest("invalid response status code".to_string()))?;

    if !version.starts_with("HTTP/1.") {
        return Err(HttpRequestError::BadRequest(format!(
            "unsupported upstream http version: {version}"
        )));
    }

    let headers = parse_headers(lines)?;
    let keep_alive = should_keep_alive(version, &headers, false);
    let body_kind = response_body_kind(status_code, request_method, &headers)?;

    Ok(HttpResponseHead {
        keep_alive,
        body_kind,
    })
}

fn response_body_kind(
    status_code: u16,
    request_method: &str,
    headers: &[(String, String)],
) -> Result<HttpResponseBodyKind, HttpRequestError> {
    if request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || status_code == 204
        || status_code == 304
    {
        return Ok(HttpResponseBodyKind::None);
    }

    if header_contains_token(headers, &["transfer-encoding"], "chunked") {
        return Ok(HttpResponseBodyKind::Chunked);
    }

    if let Some(value) = header_value(headers, "content-length") {
        let length = value.parse::<usize>().map_err(|_| {
            HttpRequestError::BadRequest(format!("invalid response Content-Length header: {value}"))
        })?;
        return Ok(HttpResponseBodyKind::ContentLength(length));
    }

    Ok(HttpResponseBodyKind::UntilClose)
}

fn should_keep_alive(
    version: &str,
    headers: &[(String, String)],
    include_proxy_connection: bool,
) -> bool {
    let names = if include_proxy_connection {
        &["connection", "proxy-connection"][..]
    } else {
        &["connection"][..]
    };
    if header_contains_token(headers, names, "close") {
        return false;
    }
    if header_contains_token(headers, names, "keep-alive") {
        return true;
    }
    version == "HTTP/1.1"
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn header_contains_token(headers: &[(String, String)], names: &[&str], token: &str) -> bool {
    headers.iter().any(|(name, value)| {
        names
            .iter()
            .any(|candidate| name.eq_ignore_ascii_case(candidate))
            && value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
}

async fn relay_prefetched_body(
    upstream: &mut TcpStream,
    client: &mut TcpStream,
    tail_bytes: &[u8],
    length: usize,
) -> Result<(), AppError> {
    if tail_bytes.len() > length {
        return Err(AppError::InvalidConfig(
            "unexpected bytes after fixed-length response body".to_string(),
        ));
    }

    if !tail_bytes.is_empty() {
        client.write_all(tail_bytes).await?;
    }

    let mut remaining = length.saturating_sub(tail_bytes.len());
    let mut read_buf = [0u8; 8192];
    while remaining > 0 {
        let next = remaining.min(read_buf.len());
        let n = upstream.read(&mut read_buf[..next]).await?;
        if n == 0 {
            return Err(AppError::InvalidConfig(
                "upstream closed connection before sending the full response body".to_string(),
            ));
        }
        client.write_all(&read_buf[..n]).await?;
        remaining -= n;
    }

    Ok(())
}

async fn relay_chunked_body(
    upstream: &mut TcpStream,
    client: &mut TcpStream,
    mut buf: Vec<u8>,
) -> Result<(), AppError> {
    loop {
        let line_end = read_until_crlf(upstream, &mut buf).await?;
        let chunk_header_len = line_end + 2;
        let chunk_size = parse_chunk_size(&buf[..line_end])?;
        client.write_all(&buf[..chunk_header_len]).await?;
        buf.drain(..chunk_header_len);

        if chunk_size == 0 {
            relay_chunk_trailers(upstream, client, buf).await?;
            return Ok(());
        }

        relay_chunk_data(upstream, client, &mut buf, chunk_size).await?;
    }
}

async fn relay_chunk_data(
    upstream: &mut TcpStream,
    client: &mut TcpStream,
    buf: &mut Vec<u8>,
    chunk_size: usize,
) -> Result<(), AppError> {
    let required = chunk_size
        .checked_add(2)
        .ok_or_else(|| AppError::InvalidConfig("chunk size is too large".to_string()))?;
    read_at_least(upstream, buf, required).await?;
    if &buf[chunk_size..required] != b"\r\n" {
        return Err(AppError::InvalidConfig(
            "chunk data is missing trailing CRLF".to_string(),
        ));
    }
    client.write_all(&buf[..required]).await?;
    buf.drain(..required);
    Ok(())
}

async fn relay_chunk_trailers(
    upstream: &mut TcpStream,
    client: &mut TcpStream,
    mut buf: Vec<u8>,
) -> Result<(), AppError> {
    loop {
        let line_end = read_until_crlf(upstream, &mut buf).await?;
        let trailer_line_len = line_end + 2;
        client.write_all(&buf[..trailer_line_len]).await?;
        buf.drain(..trailer_line_len);
        if line_end == 0 {
            if !buf.is_empty() {
                return Err(AppError::InvalidConfig(
                    "unexpected bytes after chunked response trailers".to_string(),
                ));
            }
            return Ok(());
        }
    }
}

async fn read_until_crlf(upstream: &mut TcpStream, buf: &mut Vec<u8>) -> Result<usize, AppError> {
    loop {
        if let Some(line_end) = find_crlf(buf) {
            return Ok(line_end);
        }
        let mut read_buf = [0u8; 2048];
        let n = upstream.read(&mut read_buf).await?;
        if n == 0 {
            return Err(AppError::InvalidConfig(
                "upstream closed connection before completing chunked response".to_string(),
            ));
        }
        buf.extend_from_slice(&read_buf[..n]);
    }
}

async fn read_at_least(
    upstream: &mut TcpStream,
    buf: &mut Vec<u8>,
    required: usize,
) -> Result<(), AppError> {
    while buf.len() < required {
        let mut read_buf = [0u8; 8192];
        let n = upstream.read(&mut read_buf).await?;
        if n == 0 {
            return Err(AppError::InvalidConfig(
                "upstream closed connection before completing chunked response".to_string(),
            ));
        }
        buf.extend_from_slice(&read_buf[..n]);
    }
    Ok(())
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|window| window == b"\r\n")
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, AppError> {
    let line = str::from_utf8(line)
        .map_err(|_| AppError::InvalidConfig("chunk size line is not valid utf-8".to_string()))?;
    let size = line.split(';').next().unwrap_or_default().trim();
    usize::from_str_radix(size, 16)
        .map_err(|_| AppError::InvalidConfig(format!("invalid chunk size: {size}")))
}

async fn relay_forward_request(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    tail_bytes: &[u8],
    request: &ForwardRequest,
) -> Result<(), AppError> {
    upstream.write_all(&request.upstream_header_bytes).await?;
    match request.body_kind {
        HttpRequestBodyKind::None => {
            if !tail_bytes.is_empty() {
                return Err(AppError::InvalidConfig(
                    "unexpected bytes after headers for a request without body".to_string(),
                ));
            }
        }
        HttpRequestBodyKind::ContentLength(length) => {
            relay_sized_body(client, upstream, tail_bytes, length).await?;
        }
    }
    upstream.flush().await?;
    Ok(())
}

async fn relay_sized_body(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    tail_bytes: &[u8],
    length: usize,
) -> Result<(), AppError> {
    if tail_bytes.len() > length {
        return Err(AppError::InvalidConfig(
            "http request pipelining is not supported".to_string(),
        ));
    }

    if !tail_bytes.is_empty() {
        upstream.write_all(tail_bytes).await?;
    }

    let mut remaining = length.saturating_sub(tail_bytes.len());
    let mut read_buf = [0u8; 8192];
    while remaining > 0 {
        let next = remaining.min(read_buf.len());
        let n = client.read(&mut read_buf[..next]).await?;
        if n == 0 {
            return Err(AppError::InvalidConfig(
                "client closed connection before sending the full request body".to_string(),
            ));
        }
        upstream.write_all(&read_buf[..n]).await?;
        remaining -= n;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_1_1_forward_keeps_alive_by_default() {
        let request = parse_http_request(
            b"GET http://example.com/data HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .expect("request should parse");

        let HttpRequest::Forward(request) = request else {
            panic!("expected forward request");
        };
        assert!(request.client_keep_alive);
        assert!(
            str::from_utf8(&request.upstream_header_bytes)
                .expect("header should be utf8")
                .contains("Connection: keep-alive\r\n")
        );
    }

    #[test]
    fn http_1_0_forward_closes_by_default() {
        let request = parse_http_request(
            b"GET http://example.com/data HTTP/1.0\r\nHost: example.com\r\n\r\n",
        )
        .expect("request should parse");

        let HttpRequest::Forward(request) = request else {
            panic!("expected forward request");
        };
        assert!(!request.client_keep_alive);
        assert!(
            str::from_utf8(&request.upstream_header_bytes)
                .expect("header should be utf8")
                .contains("Connection: close\r\n")
        );
    }

    #[test]
    fn response_connection_close_disables_reuse() {
        let response = parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n",
            "GET",
        )
        .expect("response should parse");

        assert!(!response.keep_alive);
        assert!(matches!(
            response.body_kind,
            HttpResponseBodyKind::ContentLength(3)
        ));
    }

    #[test]
    fn response_without_body_length_uses_close_boundary() {
        let response = parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
            "GET",
        )
        .expect("response should parse");

        assert!(response.keep_alive);
        assert!(matches!(
            response.body_kind,
            HttpResponseBodyKind::UntilClose
        ));
    }
}
