use std::env;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};
use sha2::{Digest, Sha256};

use crate::config::{Config, TlsVersion};
use crate::error::{OpenfortivpnError, Result};

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct TlsConnection {
    stream: StreamOwned<ClientConnection, TcpStream>,
    peer_cert_sha256: String,
    verification: CertificateVerification,
    tcp_peer_addr: SocketAddr,
}

impl TlsConnection {
    pub fn connect(config: &Config) -> Result<Self> {
        let tcp = connect_tcp(config)?;
        Self::connect_stream(config, tcp)
    }

    pub fn connect_stream(config: &Config, tcp: TcpStream) -> Result<Self> {
        reject_unsupported_rustls_options(config)?;
        let tcp_peer_addr = tcp.peer_addr()?;
        let server_name = server_name(config)?;
        let verifier = Arc::new(RecordingVerifier::new(root_verifier()?, config));
        let mut client_config = if config.user_cert.is_some() || config.user_key.is_some() {
            ClientConfig::builder_with_provider(crypto_provider())
                .with_safe_default_protocol_versions()
                .map_err(|err| OpenfortivpnError::TlsHandshake(err.to_string()))?
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone())
                .with_client_auth_cert(
                    load_client_cert_chain(config)
                        .map_err(|err| OpenfortivpnError::TlsHandshake(err.to_string()))?,
                    load_client_private_key(config)
                        .map_err(|err| OpenfortivpnError::TlsHandshake(err.to_string()))?,
                )
                .map_err(|err| OpenfortivpnError::TlsHandshake(err.to_string()))?
        } else {
            ClientConfig::builder_with_provider(crypto_provider())
                .with_safe_default_protocol_versions()
                .map_err(|err| OpenfortivpnError::TlsHandshake(err.to_string()))?
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone())
                .with_no_client_auth()
        };
        client_config.key_log = Arc::new(rustls::KeyLogFile::new());

        let connection = ClientConnection::new(Arc::new(client_config), server_name)
            .map_err(|err| OpenfortivpnError::TlsHandshake(err.to_string()))?;
        let mut stream = StreamOwned::new(connection, tcp);
        while stream.conn.is_handshaking() {
            stream
                .conn
                .complete_io(&mut stream.sock)
                .map_err(|err| OpenfortivpnError::TlsHandshake(err.to_string()))?;
        }

        let peer_cert = stream
            .conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or(OpenfortivpnError::MissingPeerCertificate)?;
        let peer_cert_sha256 = cert_sha256_hex(peer_cert.as_ref());
        let verification = verifier.verification_for(config, &peer_cert_sha256)?;

        Ok(Self {
            stream,
            peer_cert_sha256,
            verification,
            tcp_peer_addr,
        })
    }

    pub fn peer_cert_sha256(&self) -> &str {
        &self.peer_cert_sha256
    }

    pub fn verification(&self) -> CertificateVerification {
        self.verification
    }

    pub fn tcp_peer_addr(&self) -> SocketAddr {
        self.tcp_peer_addr
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.stream.sock.set_nonblocking(nonblocking)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.sock.set_read_timeout(timeout)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.sock.set_write_timeout(timeout)
    }

    pub fn into_inner(self) -> StreamOwned<ClientConnection, TcpStream> {
        self.stream
    }
}

#[cfg(unix)]
impl AsRawFd for TlsConnection {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.sock.as_raw_fd()
    }
}

impl Read for TlsConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for TlsConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateVerification {
    VerifiedByPki,
    VerifiedByPinnedDigest,
    Disabled,
}

#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    insecure: bool,
    trusted_certs: Vec<String>,
    last_pki_result: std::sync::Mutex<Option<std::result::Result<(), String>>>,
}

impl RecordingVerifier {
    fn new(inner: Arc<WebPkiServerVerifier>, config: &Config) -> Self {
        Self {
            inner,
            insecure: config.insecure_ssl,
            trusted_certs: config.trusted_certs.clone(),
            last_pki_result: std::sync::Mutex::new(None),
        }
    }

    fn verification_for(
        &self,
        config: &Config,
        peer_cert_sha256: &str,
    ) -> Result<CertificateVerification> {
        if config.insecure_ssl {
            return Ok(CertificateVerification::Disabled);
        }
        if self
            .trusted_certs
            .iter()
            .any(|digest| digest.eq_ignore_ascii_case(peer_cert_sha256))
        {
            return Ok(CertificateVerification::VerifiedByPinnedDigest);
        }
        match self.last_pki_result.lock().expect("verifier mutex poisoned").clone() {
            Some(Ok(())) => Ok(CertificateVerification::VerifiedByPki),
            Some(Err(err)) => Err(OpenfortivpnError::CertificateVerification(format!(
                "{err}; add '--trusted-cert {peer_cert_sha256}' if this gateway certificate is expected"
            ))),
            None => Err(OpenfortivpnError::CertificateVerification(format!(
                "certificate was not verified; add '--trusted-cert {peer_cert_sha256}' if this gateway certificate is expected"
            ))),
        }
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let pki = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        *self
            .last_pki_result
            .lock()
            .expect("verifier mutex poisoned") = Some(match &pki {
            Ok(_) => Ok(()),
            Err(err) => Err(err.to_string()),
        });
        if pki.is_ok()
            || self.insecure
            || self
                .trusted_certs
                .iter()
                .any(|digest| digest.eq_ignore_ascii_case(&cert_sha256_hex(end_entity.as_ref())))
        {
            Ok(ServerCertVerified::assertion())
        } else {
            pki
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls_rustcrypto::provider())
}

fn root_verifier() -> Result<Arc<WebPkiServerVerifier>> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        roots.add(cert).map_err(|err| {
            OpenfortivpnError::TlsHandshake(format!("failed to add native root certificate: {err}"))
        })?;
    }
    if roots.is_empty() {
        return Err(OpenfortivpnError::TlsHandshake(
            "no native root certificates found".to_owned(),
        ));
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), crypto_provider())
        .build()
        .map_err(|err| OpenfortivpnError::TlsHandshake(err.to_string()))
}

fn server_name(config: &Config) -> Result<ServerName<'static>> {
    let sni_host = config.sni.as_deref().unwrap_or(&config.gateway_host);
    ServerName::try_from(sni_host.to_owned())
        .map_err(|_| OpenfortivpnError::TlsHandshake(format!("bad SNI host: {sni_host}")))
}

fn reject_unsupported_rustls_options(config: &Config) -> Result<()> {
    if config.cipher_list.is_some() {
        return Err(OpenfortivpnError::TlsHandshake(
            "--cipher-list is not supported with rustls".to_owned(),
        ));
    }
    if config.seclevel_1 {
        return Err(OpenfortivpnError::TlsHandshake(
            "--seclevel-1 is not supported with rustls".to_owned(),
        ));
    }
    if matches!(config.min_tls, Some(TlsVersion::Tls10 | TlsVersion::Tls11)) {
        return Err(OpenfortivpnError::TlsHandshake(
            "rustls supports TLS 1.2 and newer only".to_owned(),
        ));
    }
    if config
        .user_cert
        .as_deref()
        .is_some_and(|cert| cert.starts_with("pkcs11:"))
        || config
            .user_key
            .as_deref()
            .is_some_and(|key| key.starts_with("pkcs11:"))
    {
        return Err(OpenfortivpnError::TlsHandshake(
            "PKCS#11 client certificates are not supported with rustls".to_owned(),
        ));
    }
    Ok(())
}

fn load_client_cert_chain(
    config: &Config,
) -> std::result::Result<Vec<CertificateDer<'static>>, rustls::Error> {
    let Some(cert_path) = &config.user_cert else {
        return Err(rustls::Error::General(
            "no client certificate configured".to_owned(),
        ));
    };
    let file = File::open(cert_path).map_err(|err| {
        rustls::Error::General(format!(
            "failed to open client certificate {cert_path}: {err}"
        ))
    })?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| {
            rustls::Error::General(format!(
                "failed to read client certificate {cert_path}: {err}"
            ))
        })
}

fn load_client_private_key(
    config: &Config,
) -> std::result::Result<PrivateKeyDer<'static>, rustls::Error> {
    let Some(key_path) = config.user_key.as_ref().or(config.user_cert.as_ref()) else {
        return Err(rustls::Error::General(
            "no client key configured".to_owned(),
        ));
    };
    let file = File::open(key_path).map_err(|err| {
        rustls::Error::General(format!("failed to open client key {key_path}: {err}"))
    })?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .map_err(|err| {
            rustls::Error::General(format!("failed to read client key {key_path}: {err}"))
        })?
        .ok_or_else(|| rustls::Error::General(format!("no private key found in {key_path}")))
}

fn connect_tcp(config: &Config) -> Result<TcpStream> {
    if let Some(proxy) = proxy_from_environment()? {
        let mut stream = connect_tcp_direct(&proxy.host, proxy.port)?;
        establish_http_connect_proxy(&mut stream, &config.gateway_host, config.gateway_port)?;
        return Ok(stream);
    }

    connect_tcp_direct(&config.gateway_host, config.gateway_port)
}

fn connect_tcp_direct(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = (host, port).to_socket_addrs()?;
    let mut last_error = None;

    for addr in addrs {
        match TcpStream::connect_timeout(&addr, TCP_CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error
        .unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("could not resolve {host}:{port}"),
            )
        })
        .into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyConfig {
    host: String,
    port: u16,
}

fn proxy_from_environment() -> Result<Option<ProxyConfig>> {
    for key in ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"] {
        if let Ok(value) = env::var(key) {
            if !value.trim().is_empty() {
                return parse_proxy_url(&value).map(Some);
            }
        }
    }
    Ok(None)
}

fn parse_proxy_url(value: &str) -> Result<ProxyConfig> {
    let mut proxy = value.trim().trim_end_matches('/');
    if let Some((scheme, rest)) = proxy.split_once("://") {
        if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
            return Err(OpenfortivpnError::Network(format!(
                "unsupported proxy scheme in {value:?}; only HTTP CONNECT proxies are supported"
            )));
        }
        proxy = rest.trim_end_matches('/');
    }

    let proxy = proxy.rsplit('@').next().unwrap_or(proxy);
    let (host, port) = if let Some((host, port)) = proxy.rsplit_once(':') {
        if host.is_empty() || port.is_empty() {
            return Err(OpenfortivpnError::Network(format!(
                "bad proxy address: {value}"
            )));
        }
        let port = port.parse::<u16>().map_err(|_| {
            OpenfortivpnError::Network(format!("bad proxy port in proxy address: {value}"))
        })?;
        (host, port)
    } else {
        (proxy, 8080)
    };

    if host.is_empty() || port == 0 {
        return Err(OpenfortivpnError::Network(format!(
            "bad proxy address: {value}"
        )));
    }

    Ok(ProxyConfig {
        host: host.to_owned(),
        port,
    })
}

fn establish_http_connect_proxy(stream: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    let target = format!("{host}:{port}");
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut response = Vec::with_capacity(4096);
    let mut byte = [0_u8; 1];
    while response.len() < 4096 {
        let read = stream.read(&mut byte)?;
        if read == 0 {
            break;
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") || response.ends_with(b"\n\n") {
            break;
        }
    }

    let response_text = String::from_utf8_lossy(&response);
    let status_line = response_text.lines().next().unwrap_or_default();
    if status_line.contains(" 200 ")
        || status_line.ends_with(" 200")
        || status_line.contains(" 200 OK")
    {
        Ok(())
    } else {
        Err(OpenfortivpnError::Network(format!(
            "proxy CONNECT failed: {status_line}"
        )))
    }
}

fn cert_sha256_hex(cert: &[u8]) -> String {
    bytes_to_lower_hex(&Sha256::digest(cert))
}

fn bytes_to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_lower_hex() {
        assert_eq!(bytes_to_lower_hex(&[0x00, 0xab, 0xcd, 0xff]), "00abcdff");
    }

    #[test]
    fn rejects_unsupported_rustls_options() {
        let mut cfg = Config::default();
        cfg.cipher_list = Some("DEFAULT".to_owned());
        assert!(reject_unsupported_rustls_options(&cfg).is_err());

        let mut cfg = Config::default();
        cfg.seclevel_1 = true;
        assert!(reject_unsupported_rustls_options(&cfg).is_err());

        let mut cfg = Config::default();
        cfg.min_tls = Some(TlsVersion::Tls10);
        assert!(reject_unsupported_rustls_options(&cfg).is_err());
    }

    #[test]
    fn parses_proxy_urls_like_c() {
        assert_eq!(
            parse_proxy_url("http://proxy.example:3128/").unwrap(),
            ProxyConfig {
                host: "proxy.example".to_owned(),
                port: 3128,
            }
        );
        assert_eq!(
            parse_proxy_url("proxy.example").unwrap(),
            ProxyConfig {
                host: "proxy.example".to_owned(),
                port: 8080,
            }
        );
        assert!(parse_proxy_url("socks5://proxy.example:1080").is_err());
    }

    #[test]
    fn sends_http_connect_to_proxy() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 256];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("CONNECT vpn.example:443 HTTP/1.1\r\n"));
            assert!(request.contains("Host: vpn.example:443\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nProxy-Agent: test\r\n\r\n")
                .unwrap();
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        establish_http_connect_proxy(&mut stream, "vpn.example", 443).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn hashes_certificate_bytes() {
        assert_eq!(
            cert_sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
