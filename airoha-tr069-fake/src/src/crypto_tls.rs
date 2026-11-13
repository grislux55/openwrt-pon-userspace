// SPDX-License-Identifier: GPL-2.0-only

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use md5::{Digest as _, Md5};
use openssl::ssl::{ConnectConfiguration, SslConnector, SslMethod, SslStream, SslVerifyMode};
use sha2::Sha256;

pub fn md5_hex(data: &[u8]) -> String {
    format!("{:x}", Md5::digest(data))
}

pub fn sha256_hex(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

pub fn base64_encode(input: &[u8]) -> String {
    BASE64_STANDARD.encode(input)
}

pub fn random_hex_nonce() -> String {
    let mut urandom_bytes = [0u8; 16];
    if getrandom::fill(&mut urandom_bytes).is_ok() {
        let mut hex = String::with_capacity(32);
        for b in urandom_bytes {
            hex.push_str(&format!("{b:02x}"));
        }
        return hex;
    }
    static FALLBACK_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let seq = FALLBACK_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let input = format!("{ns}:{pid}:{seq}:tr069fake");
    sha256_hex(input.as_bytes())[..32].to_owned()
}

fn build_tls_connect_config(
    sni_host: &str,
    insecure_tls: bool,
) -> io::Result<(ConnectConfiguration, String)> {
    if sni_host.is_empty() || sni_host.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS host"));
    }
    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| io::Error::other(format!("SslConnector::builder failed: {e}")))?;
    if insecure_tls {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        builder
            .set_default_verify_paths()
            .map_err(|e| io::Error::other(format!("set_default_verify_paths failed: {e}")))?;
        builder.set_verify(SslVerifyMode::PEER);
    }
    let connector = builder.build();
    let mut cfg = connector
        .configure()
        .map_err(|e| io::Error::other(format!("SslConnector::configure failed: {e}")))?;
    if insecure_tls {
        cfg.set_verify_hostname(false);
    }
    Ok((cfg, sni_host.to_owned()))
}

pub struct TlsClientStream {
    inner: SslStream<TcpStream>,
}

impl TlsClientStream {
    pub fn connect(tcp: TcpStream, sni_host: &str, insecure_tls: bool) -> io::Result<Self> {
        let (cfg, domain) = build_tls_connect_config(sni_host, insecure_tls)?;
        let ssl = cfg.into_ssl(&domain).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("TLS peer setup failed: {e}"),
            )
        })?;
        let inner = ssl.connect(tcp).map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("TLS handshake failed: {e}"),
            )
        })?;
        Ok(Self { inner })
    }
}

impl Read for TlsClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Drop for TlsClientStream {
    fn drop(&mut self) {
        let _ = self.inner.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_peer_identity_accepts_hostname_and_ip_literals() {
        for host in ["acs.example.com", "192.0.2.10", "2001:db8::10"] {
            let (cfg, domain) = build_tls_connect_config(host, false).expect("tls config");
            cfg.into_ssl(&domain)
                .unwrap_or_else(|err| panic!("host {host} failed: {err}"));
        }
    }
}
