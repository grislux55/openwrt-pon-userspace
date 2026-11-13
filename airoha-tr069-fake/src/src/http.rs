// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use digest_auth::{
    Algorithm, AuthContext, AuthorizationHeader, Charset, HttpMethod, Qop, WwwAuthenticateHeader,
};
use url::Url;

use crate::audit::AuditLogger;
use crate::crypto_tls::{base64_encode, random_hex_nonce, TlsClientStream};
use crate::net_iso::{connect_isolated_tcp, InterfaceRuntime};

pub const MAX_HTTP_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_CONN_REQ_HEADER_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlParts {
    pub is_https: bool,
    pub host: String,
    pub port: u16,
    pub path_query: String,
}

pub fn parse_url(url_str: &str) -> io::Result<UrlParts> {
    let parsed = Url::parse(url_str).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACS URL must be a valid http:// or https:// URL",
        )
    })?;
    let is_https = match parsed.scheme() {
        "https" => true,
        "http" => false,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ACS URL must start with http:// or https://",
            ))
        }
    };
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty URL host"))?
        .to_owned();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid URL port"))?;
    let mut path_query = if parsed.path().is_empty() {
        "/".to_owned()
    } else {
        parsed.path().to_owned()
    };
    if let Some(q) = parsed.query() {
        path_query.push('?');
        path_query.push_str(q);
    }
    Ok(UrlParts {
        is_https,
        host,
        port,
        path_query,
    })
}

enum TransportStream {
    Plain(TcpStream),
    Tls(TlsClientStream),
}

impl Read for TransportStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TransportStream::Plain(s) => s.read(buf),
            TransportStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for TransportStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TransportStream::Plain(s) => s.write(buf),
            TransportStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TransportStream::Plain(s) => s.flush(),
            TransportStream::Tls(s) => s.flush(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub set_cookies: Vec<String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub qop: Option<String>,
    pub opaque: Option<String>,
    pub algorithm: String,
}

pub struct AcsHttpClient {
    url: UrlParts,
    username: String,
    password: String,
    insecure_tls: bool,
    rt: InterfaceRuntime,
    cookies: BTreeMap<String, String>,
    digest: Option<DigestChallenge>,
    use_basic: bool,
    nonce_count: u32,
    stream: Option<TransportStream>,
}

impl AcsHttpClient {
    pub fn new(
        url_str: &str,
        username: &str,
        password: &str,
        insecure_tls: bool,
        rt: InterfaceRuntime,
    ) -> io::Result<Self> {
        let url = parse_url(url_str)?;
        Ok(Self {
            url,
            username: username.to_owned(),
            password: password.to_owned(),
            insecure_tls,
            rt,
            cookies: BTreeMap::new(),
            digest: None,
            use_basic: false,
            nonce_count: 0,
            stream: None,
        })
    }

    pub fn post_cwmp(&mut self, body: &str, soap_action: Option<&str>) -> io::Result<HttpResponse> {
        let path_query = self.url.path_query.clone();
        let body_bytes = body.as_bytes();
        for attempt in 0..3 {
            let auth_header = self.build_auth_header("POST", &path_query, body_bytes);
            let resp = self.send_once(body_bytes, soap_action, auth_header.as_deref())?;
            if resp.status == 401 && attempt < 2 && !self.username.is_empty() {
                if let Some(chal) = resp.headers.get("www-authenticate") {
                    if chal.trim_start().to_ascii_lowercase().starts_with("digest ") {
                        if let Some(parsed) = parse_digest_challenge(chal) {
                            self.use_basic = false;
                            self.digest = Some(parsed);
                            self.nonce_count = 0;
                            continue;
                        }
                    } else if chal.trim_start().to_ascii_lowercase().starts_with("basic") {
                        self.digest = None;
                        self.use_basic = true;
                        continue;
                    }
                }
            }
            return Ok(resp);
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "ACS authentication failed",
        ))
    }

    fn build_basic_header(&self) -> String {
        let raw = format!("{}:{}", self.username, self.password);
        format!("Basic {}", base64_encode(raw.as_bytes()))
    }

    fn build_auth_header(&mut self, method: &str, uri: &str, body: &[u8]) -> Option<String> {
        if self.username.is_empty() {
            return None;
        }
        if let Some(chal) = self.digest.clone() {
            self.nonce_count += 1;
            let cnonce = random_hex_nonce();
            return Some(build_digest_authorization_with_body(
                &self.username,
                &self.password,
                method,
                uri,
                &chal,
                self.nonce_count,
                &cnonce,
                Some(body),
            ));
        }
        if self.use_basic {
            return Some(self.build_basic_header());
        }
        None
    }

    fn ensure_connected(&mut self) -> io::Result<&mut TransportStream> {
        if self.stream.is_none() {
            let tcp = connect_isolated_tcp(
                &self.url.host,
                self.url.port,
                &self.rt,
                Duration::from_secs(10),
            )?;
            let transport = if self.url.is_https {
                let sni = self.url.host.trim_matches(|c| c == '[' || c == ']');
                TransportStream::Tls(TlsClientStream::connect(tcp, sni, self.insecure_tls)?)
            } else {
                TransportStream::Plain(tcp)
            };
            self.stream = Some(transport);
        }
        Ok(self.stream.as_mut().unwrap())
    }

    fn send_once(
        &mut self,
        body: &[u8],
        soap_action: Option<&str>,
        auth_header: Option<&str>,
    ) -> io::Result<HttpResponse> {
        let req = self.format_request(body, soap_action, auth_header);
        let mut retry_reconnect = true;
        loop {
            let write_res = {
                let s = self.ensure_connected()?;
                s.write_all(&req).and_then(|_| s.flush())
            };
            if write_res.is_err() && retry_reconnect {
                self.stream = None;
                retry_reconnect = false;
                continue;
            }
            write_res?;
            let read_res = {
                let s = self.stream.as_mut().unwrap();
                read_http_response(s)
            };
            match read_res {
                Ok(resp) => {
                    for sc in &resp.set_cookies {
                        if let Some((k, v)) = sc.split(';').next().and_then(|kv| kv.split_once('=')) {
                            self.cookies.insert(k.trim().to_owned(), v.trim().to_owned());
                        }
                    }
                    if resp
                        .headers
                        .get("connection")
                        .map(|v| v.eq_ignore_ascii_case("close"))
                        .unwrap_or(false)
                    {
                        self.stream = None;
                    }
                    return Ok(resp);
                }
                Err(_) if retry_reconnect => {
                    self.stream = None;
                    retry_reconnect = false;
                    continue;
                }
                Err(e) => {
                    self.stream = None;
                    return Err(e);
                }
            }
        }
    }

    fn format_request(
        &self,
        body: &[u8],
        soap_action: Option<&str>,
        auth_header: Option<&str>,
    ) -> Vec<u8> {
        let host_hdr = if (self.url.is_https && self.url.port == 443)
            || (!self.url.is_https && self.url.port == 80)
        {
            self.url.host.clone()
        } else {
            format!("{}:{}", self.url.host, self.url.port)
        };
        let mut hdr = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NNRRWrt-TR069-Fake/0.1\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {}\r\nConnection: keep-alive\r\n",
            self.url.path_query,
            host_hdr,
            body.len()
        );
        if let Some(action) = soap_action {
            hdr.push_str(&format!("SOAPAction: \"{action}\"\r\n"));
        } else {
            hdr.push_str("SOAPAction: \"\"\r\n");
        }
        if let Some(auth) = auth_header {
            hdr.push_str(&format!("Authorization: {auth}\r\n"));
        }
        if !self.cookies.is_empty() {
            let cookie_str = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            hdr.push_str(&format!("Cookie: {cookie_str}\r\n"));
        }
        hdr.push_str("\r\n");
        let mut bytes = hdr.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }
}

pub fn read_http_response<R: Read>(stream: &mut R) -> io::Result<HttpResponse> {
    let mut raw = Vec::with_capacity(512);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if raw.len() >= MAX_HTTP_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response headers exceed 64 KiB limit",
            ));
        }
        let max_read = chunk.len().min(MAX_HTTP_HEADER_BYTES - raw.len());
        let n = stream.read(&mut chunk[..max_read])?;
        if n == 0 {
            if raw.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "empty HTTP response",
                ));
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed HTTP headers",
            ));
        }
        raw.extend_from_slice(&chunk[..n]);
        let mut hdr_slots = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut hdr_slots);
        match resp.parse(&raw) {
            Ok(httparse::Status::Complete(offset)) => break offset,
            Ok(httparse::Status::Partial) => continue,
            Err(err) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid HTTP response headers: {err}"),
                ))
            }
        }
    };

    let (status, headers, set_cookies) = {
        let mut hdr_slots = [httparse::EMPTY_HEADER; 64];
        let mut parsed = httparse::Response::new(&mut hdr_slots);
        let _ = parsed.parse(&raw[..header_end]).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("HTTP parse error: {e}"))
        })?;
        let status = parsed
            .code
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status code"))?;
        let mut headers = BTreeMap::new();
        let mut set_cookies = Vec::new();
        for h in parsed.headers.iter() {
            let key_lower = h.name.trim().to_ascii_lowercase();
            let val = std::str::from_utf8(h.value)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 HTTP header"))?
                .trim()
                .to_owned();
            if key_lower == "set-cookie" {
                set_cookies.push(val.clone());
            }
            headers.insert(key_lower, val);
        }
        (status, headers, set_cookies)
    };

    let leftover = &raw[header_end..];
    let mut body_stream = Cursor::new(leftover).chain(stream);

    let is_chunked = headers
        .get("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    let body = if is_chunked {
        read_chunked_body(&mut body_stream)?
    } else if let Some(cl_raw) = headers.get("content-length") {
        let cl = cl_raw.parse::<usize>().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP Content-Length")
        })?;
        if cl > MAX_HTTP_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP Content-Length exceeds 2 MiB limit",
            ));
        }
        let mut buf = vec![0u8; cl];
        body_stream.read_exact(&mut buf)?;
        buf
    } else if status == 204 || (100..200).contains(&status) || status == 304 {
        Vec::new()
    } else {
        let mut buf = Vec::new();
        let _ = body_stream
            .take((MAX_HTTP_BODY_BYTES + 1) as u64)
            .read_to_end(&mut buf)?;
        if buf.len() > MAX_HTTP_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response body exceeds 2 MiB limit",
            ));
        }
        buf
    };
    Ok(HttpResponse {
        status,
        headers,
        set_cookies,
        body,
    })
}

fn read_chunked_body<R: Read>(stream: &mut R) -> io::Result<Vec<u8>> {
    let mut reader = BufReader::new(stream);
    let mut out = Vec::new();
    loop {
        let mut line = Vec::new();
        let n_hdr = (&mut reader).take(8192).read_until(b'\n', &mut line)?;
        if n_hdr == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated HTTP chunk header",
            ));
        }
        let size = match httparse::parse_chunk_size(&line) {
            Ok(httparse::Status::Complete((_, sz))) => usize::try_from(sz).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "HTTP chunk size overflow")
            })?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HTTP chunk size",
                ))
            }
        };
        if size == 0 {
            let mut trailer = String::new();
            loop {
                trailer.clear();
                let n = (&mut reader).take(8192).read_line(&mut trailer)?;
                if n == 0 || trailer == "\r\n" || trailer == "\n" {
                    break;
                }
            }
            break;
        }
        if size > MAX_HTTP_BODY_BYTES || out.len().saturating_add(size) > MAX_HTTP_BODY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP chunked body exceeds 2 MiB limit",
            ));
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        out.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
        if &crlf != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing CRLF after HTTP chunk",
            ));
        }
    }
    Ok(out)
}

fn canonicalize_algorithm_name(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "MD5" => Some("MD5"),
        "MD5-SESS" => Some("MD5-sess"),
        "SHA-256" => Some("SHA-256"),
        "SHA-256-SESS" => Some("SHA-256-sess"),
        "SHA-512-256" => Some("SHA-512-256"),
        "SHA-512-256-SESS" => Some("SHA-512-256-sess"),
        _ => None,
    }
}

fn normalize_digest_header(header: &str) -> Option<String> {
    let trimmed = header.trim();
    if trimmed.len() < 7 || !trimmed[..6].eq_ignore_ascii_case("digest") {
        return None;
    }
    let rest = &trimmed[6..];
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let mut normalized = format!("Digest {}", rest.trim_start());
    for (bad, good) in [
        ("algorithm=md5-sess", "algorithm=MD5-sess"),
        ("algorithm=MD5-SESS", "algorithm=MD5-sess"),
        ("algorithm=md5", "algorithm=MD5"),
        ("algorithm=sha-256-sess", "algorithm=SHA-256-sess"),
        ("algorithm=SHA-256-SESS", "algorithm=SHA-256-sess"),
        ("algorithm=sha-256", "algorithm=SHA-256"),
        ("algorithm=sha-512-256-sess", "algorithm=SHA-512-256-sess"),
        ("algorithm=SHA-512-256-SESS", "algorithm=SHA-512-256-sess"),
        ("algorithm=sha-512-256", "algorithm=SHA-512-256"),
    ] {
        normalized = normalized.replace(bad, good);
    }
    Some(normalized)
}

pub fn parse_digest_challenge(header: &str) -> Option<DigestChallenge> {
    let norm = normalize_digest_header(header)?;
    let prompt = WwwAuthenticateHeader::parse(&norm).ok()?;
    let qop = prompt.qop.as_ref().and_then(|qops| {
        if qops.contains(&Qop::AUTH) {
            Some("auth".to_owned())
        } else {
            qops.first().map(ToString::to_string)
        }
    });
    Some(DigestChallenge {
        realm: prompt.realm,
        nonce: prompt.nonce,
        qop,
        opaque: prompt.opaque,
        algorithm: prompt.algorithm.to_string(),
    })
}

pub fn build_digest_authorization(
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    chal: &DigestChallenge,
    nc: u32,
    cnonce: &str,
) -> String {
    build_digest_authorization_with_body(
        username,
        password,
        method,
        uri,
        chal,
        nc,
        cnonce,
        Some(&[]),
    )
}

pub fn build_digest_authorization_with_body(
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    chal: &DigestChallenge,
    nc: u32,
    cnonce: &str,
    body: Option<&[u8]>,
) -> String {
    let algo = canonicalize_algorithm_name(&chal.algorithm)
        .and_then(|s| Algorithm::from_str(s).ok())
        .unwrap_or_default();
    let qop = chal
        .qop
        .as_deref()
        .and_then(|q| Qop::from_str(&q.trim().to_ascii_lowercase()).ok())
        .map(|q| vec![q]);
    let mut prompt = WwwAuthenticateHeader {
        domain: None,
        realm: chal.realm.clone(),
        nonce: chal.nonce.clone(),
        opaque: chal.opaque.clone(),
        stale: false,
        algorithm: algo,
        qop,
        userhash: false,
        charset: Charset::ASCII,
        nc: nc.saturating_sub(1),
    };
    let mut ctx = AuthContext::new_with_method(
        username,
        password,
        uri,
        body,
        HttpMethod::from(method),
    );
    if !cnonce.is_empty() {
        ctx.set_custom_cnonce(cnonce);
    }
    match prompt.respond(&ctx) {
        Ok(hdr) => hdr.to_header_string(),
        Err(_) => String::new(),
    }
}

#[derive(Clone, Debug)]
struct IssuedNonce {
    issued_at: std::time::Instant,
    last_nc: u32,
    consumed_without_qop: bool,
}

#[derive(Default)]
pub struct NonceTracker {
    entries: BTreeMap<String, IssuedNonce>,
}

impl NonceTracker {
    pub fn issue(&mut self) -> String {
        self.prune_expired();
        if self.entries.len() >= 128 {
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.issued_at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
        let nonce = random_hex_nonce();
        self.entries.insert(
            nonce.clone(),
            IssuedNonce {
                issued_at: std::time::Instant::now(),
                last_nc: 0,
                consumed_without_qop: false,
            },
        );
        nonce
    }

    fn prune_expired(&mut self) {
        let ttl = Duration::from_secs(120);
        self.entries.retain(|_, v| v.issued_at.elapsed() < ttl);
    }

    pub fn validate_and_advance(
        &mut self,
        nonce: &str,
        qop: Option<&str>,
        nc_hex: Option<&str>,
    ) -> bool {
        self.prune_expired();
        let Some(state) = self.entries.get_mut(nonce) else {
            return false;
        };
        if let Some(q) = qop {
            if !q.eq_ignore_ascii_case("auth") && !q.eq_ignore_ascii_case("auth-int") {
                return false;
            }
            let Some(nc_str) = nc_hex else {
                return false;
            };
            let Ok(nc_val) = u32::from_str_radix(nc_str, 16) else {
                return false;
            };
            if nc_val == 0 || nc_val <= state.last_nc {
                return false;
            }
            state.last_nc = nc_val;
            true
        } else {
            if state.consumed_without_qop {
                return false;
            }
            state.consumed_without_qop = true;
            true
        }
    }
}

fn header_contains_nc_param(norm_header: &str) -> bool {
    let lower = norm_header.to_ascii_lowercase();
    lower.contains(" nc=") || lower.contains(",nc=") || lower.contains("\tnc=")
}

pub fn verify_digest_authorization(
    auth_header: &str,
    method: &str,
    expected_user: &str,
    expected_pass: &str,
    expected_realm: &str,
    nonce_tracker: Option<&Mutex<NonceTracker>>,
) -> bool {
    verify_digest_authorization_with_body(
        auth_header,
        method,
        Some(&[]),
        expected_user,
        expected_pass,
        expected_realm,
        nonce_tracker,
    )
}

pub fn verify_digest_authorization_with_body(
    auth_header: &str,
    method: &str,
    body: Option<&[u8]>,
    expected_user: &str,
    expected_pass: &str,
    expected_realm: &str,
    nonce_tracker: Option<&Mutex<NonceTracker>>,
) -> bool {
    if expected_user.is_empty() {
        return true;
    }
    let Some(norm) = normalize_digest_header(auth_header) else {
        return false;
    };
    let Ok(parsed) = AuthorizationHeader::parse(&norm) else {
        return false;
    };
    if parsed.realm != expected_realm {
        return false;
    }
    let user_ok = if parsed.userhash {
        let expected_hash = parsed
            .algorithm
            .hash(format!("{expected_user}:{expected_realm}").as_bytes());
        expected_hash.eq_ignore_ascii_case(&parsed.username)
    } else {
        parsed.username == expected_user
    };
    if !user_ok {
        return false;
    }
    if parsed.qop.is_some() && !header_contains_nc_param(&norm) {
        return false;
    }
    let received_response = parsed.response.clone();
    let mut check = parsed.clone();
    let mut ctx = AuthContext::new_with_method(
        expected_user,
        expected_pass,
        parsed.uri.as_str(),
        body,
        HttpMethod::from(method),
    );
    if let Some(cn) = &parsed.cnonce {
        ctx.set_custom_cnonce(cn.as_str());
    }
    check.digest(&ctx);
    if !check.response.eq_ignore_ascii_case(&received_response) {
        return false;
    }
    if let Some(tracker) = nonce_tracker {
        let qop_str = parsed.qop.map(|q| q.to_string());
        let nc_hex = parsed.qop.map(|_| format!("{:08x}", parsed.nc));
        let mut guard = tracker.lock().expect("nonce tracker mutex poisoned");
        return guard.validate_and_advance(
            &parsed.nonce,
            qop_str.as_deref(),
            nc_hex.as_deref(),
        );
    }
    true
}

#[derive(Clone, Debug)]
pub struct ConnReqCreds {
    pub path: String,
    pub username: String,
    pub password: String,
}

pub struct ConnectionRequestServer {
    pub bound_addrs: Vec<SocketAddr>,
    stop: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl ConnectionRequestServer {
    pub fn start(
        bind_addrs: &[SocketAddr],
        creds: Arc<Mutex<ConnReqCreds>>,
        trigger_flag: Arc<AtomicBool>,
        audit: AuditLogger,
    ) -> io::Result<Self> {
        for addr in bind_addrs {
            if addr.ip().is_unspecified() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ConnectionRequest must bind strictly to tr069 interface IP, never 0.0.0.0 or ::",
                ));
            }
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut bound_addrs = Vec::new();
        let mut handles = Vec::new();
        let realm = "NNRRWrt-TR069".to_owned();
        let nonce_tracker = Arc::new(Mutex::new(NonceTracker::default()));
        for addr in bind_addrs {
            let listener = TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            let local = listener.local_addr()?;
            bound_addrs.push(local);
            let stop_c = Arc::clone(&stop);
            let creds_c = Arc::clone(&creds);
            let trig_c = Arc::clone(&trigger_flag);
            let audit_c = audit.clone();
            let realm_c = realm.clone();
            let tracker_c = Arc::clone(&nonce_tracker);
            let handle = std::thread::spawn(move || {
                while !stop_c.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, peer)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                            handle_conn_req(
                                &mut stream,
                                peer,
                                &creds_c,
                                &realm_c,
                                &tracker_c,
                                &trig_c,
                                &audit_c,
                            );
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(_) => break,
                    }
                }
            });
            handles.push(handle);
        }
        Ok(Self {
            bound_addrs,
            stop,
            handles,
        })
    }

    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.handles {
            let _ = h.join();
        }
    }
}

fn read_conn_req_request<R: Read>(
    stream: &mut R,
) -> Option<(String, String, Option<String>, Vec<u8>)> {
    let mut raw = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if raw.len() >= MAX_CONN_REQ_HEADER_BYTES {
            return None;
        }
        let max_read = chunk.len().min(MAX_CONN_REQ_HEADER_BYTES - raw.len());
        let n = stream.read(&mut chunk[..max_read]).ok()?;
        if n == 0 {
            return None;
        }
        raw.extend_from_slice(&chunk[..n]);
        let mut hdr_slots = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut hdr_slots);
        match req.parse(&raw) {
            Ok(httparse::Status::Complete(offset)) => break offset,
            Ok(httparse::Status::Partial) => continue,
            Err(_) => return None,
        }
    };

    let (method, req_path, auth_hdr, content_len) = {
        let mut hdr_slots = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut hdr_slots);
        req.parse(&raw[..header_end]).ok()?;
        let method = req.method.unwrap_or("GET").to_owned();
        let req_path = req.path.unwrap_or("/").to_owned();
        let mut auth_hdr = None;
        let mut content_len = 0usize;
        for h in req.headers.iter() {
            if h.name.eq_ignore_ascii_case("authorization") {
                if let Ok(v) = std::str::from_utf8(h.value) {
                    auth_hdr = Some(v.trim().to_owned());
                }
            } else if h.name.eq_ignore_ascii_case("content-length") {
                if let Ok(v) = std::str::from_utf8(h.value) {
                    content_len = v.trim().parse::<usize>().ok().filter(|&n| n <= 65_536)?;
                }
            }
        }
        (method, req_path, auth_hdr, content_len)
    };

    let mut body = Vec::new();
    if content_len > 0 {
        let mut body_stream = Cursor::new(&raw[header_end..]).chain(stream);
        body.resize(content_len, 0);
        body_stream.read_exact(&mut body).ok()?;
    }
    Some((method, req_path, auth_hdr, body))
}

fn handle_conn_req(
    stream: &mut TcpStream,
    peer: SocketAddr,
    creds: &Arc<Mutex<ConnReqCreds>>,
    realm: &str,
    nonce_tracker: &Arc<Mutex<NonceTracker>>,
    trigger_flag: &Arc<AtomicBool>,
    audit: &AuditLogger,
) {
    let Some((method, req_path, auth_hdr, body)) = read_conn_req_request(stream) else {
        return;
    };
    let cfg = creds.lock().expect("creds mutex poisoned").clone();
    let path_match = req_path.split('?').next().unwrap_or(&req_path) == cfg.path;
    if !path_match {
        let _ = stream.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    let authorized = if cfg.username.is_empty() {
        true
    } else if let Some(auth) = auth_hdr.as_deref() {
        verify_digest_authorization_with_body(
            auth,
            &method,
            Some(&body),
            &cfg.username,
            &cfg.password,
            realm,
            Some(nonce_tracker),
        )
    } else {
        false
    };
    if !authorized {
        let nonce = nonce_tracker
            .lock()
            .expect("nonce tracker mutex poisoned")
            .issue();
        let resp = format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"{realm}\", qop=\"auth\", nonce=\"{nonce}\", algorithm=MD5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        audit.record(
            "WARN",
            "conn_req",
            &format!("Unauthorized ConnectionRequest from {peer} path={req_path}"),
        );
        let _ = stream.write_all(resp.as_bytes());
        return;
    }
    trigger_flag.store(true, Ordering::SeqCst);
    audit.record(
        "INFO",
        "conn_req",
        &format!("Accepted ConnectionRequest from {peer} path={req_path}"),
    );
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}
