use std::env;
use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use foreign_types::ForeignType;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{HandshakeError, SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion};
use openssl::x509::{X509VerifyResult, X509};

use crate::config::{Config, TlsVersion};
use crate::error::{OpenfortivpnError, Result};

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_STRICT_CIPHER_LIST: &str = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
const DEFAULT_STRICT_CIPHER_LIST_SECLEVEL_1: &str =
    "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4:@SECLEVEL=1";
const DEFAULT_INSECURE_CIPHER_LIST_SECLEVEL_1: &str = "DEFAULT@SECLEVEL=1";

pub struct TlsConnection {
    stream: SslStream<TcpStream>,
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
        let tcp_peer_addr = tcp.peer_addr()?;
        let sni_host = config.sni.as_deref().unwrap_or(&config.gateway_host);
        let mut connector_builder = SslConnector::builder(SslMethod::tls())?;

        connector_builder.set_default_verify_paths()?;
        if let Some(ca_file) = &config.ca_file {
            connector_builder.set_ca_file(ca_file)?;
        }

        if let Some(cipher_list) = effective_cipher_list(config) {
            connector_builder.set_cipher_list(cipher_list)?;
        }

        if let Some(version) = &config.min_tls {
            connector_builder.set_min_proto_version(Some(to_ssl_version(version)))?;
        }

        configure_client_certificate(&mut connector_builder, config)?;

        // Keep the handshake alive even on verification errors. This mirrors the C
        // implementation's ability to accept a certificate via --trusted-cert after
        // ordinary PKI/hostname verification failed.
        connector_builder.set_verify_callback(SslVerifyMode::PEER, |_preverify_ok, _ctx| true);

        let connector = connector_builder.build();
        let mut ssl = connector.configure()?.into_ssl(sni_host)?;
        ssl.param_mut().set_host(&config.gateway_host)?;

        let stream = match ssl.connect(tcp) {
            Ok(stream) => stream,
            Err(HandshakeError::SetupFailure(err)) => return Err(err.into()),
            Err(HandshakeError::Failure(err)) => {
                return Err(OpenfortivpnError::TlsHandshake(err.error().to_string()))
            }
            Err(HandshakeError::WouldBlock(_)) => {
                return Err(OpenfortivpnError::TlsHandshake(
                    "non-blocking handshake unexpectedly returned WouldBlock".to_owned(),
                ))
            }
        };

        let peer_cert = stream
            .ssl()
            .peer_certificate()
            .ok_or(OpenfortivpnError::MissingPeerCertificate)?;
        let peer_cert_sha256 = cert_sha256_hex(&peer_cert)?;
        let verify_result = stream.ssl().verify_result();
        let verification = verify_certificate(config, verify_result, &peer_cert_sha256)?;

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
        self.stream.get_ref().set_nonblocking(nonblocking)
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.get_ref().set_read_timeout(timeout)
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.get_ref().set_write_timeout(timeout)
    }

    pub fn into_inner(self) -> SslStream<TcpStream> {
        self.stream
    }
}

#[cfg(unix)]
impl AsRawFd for TlsConnection {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.get_ref().as_raw_fd()
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

fn configure_client_certificate(
    connector_builder: &mut openssl::ssl::SslConnectorBuilder,
    config: &Config,
) -> Result<()> {
    if let Some(cert) = &config.user_cert {
        if cert.starts_with("pkcs11:") {
            return configure_pkcs11_client_certificate(connector_builder, config, cert);
        }
    }

    if config
        .user_key
        .as_deref()
        .is_some_and(|key| key.starts_with("pkcs11:"))
    {
        return Err(OpenfortivpnError::TlsHandshake(
            "PKCS#11 private keys require --user-cert=pkcs11:<uri> so the certificate can be loaded from the token too".to_owned(),
        ));
    }

    if let Some(cert) = &config.user_cert {
        connector_builder.set_certificate_chain_file(cert)?;
    }
    if let Some(key) = &config.user_key {
        connector_builder.set_private_key_file(key, openssl::ssl::SslFiletype::PEM)?;
        connector_builder.check_private_key()?;
    }

    Ok(())
}

fn configure_pkcs11_client_certificate(
    connector_builder: &mut openssl::ssl::SslConnectorBuilder,
    _config: &Config,
    uri: &str,
) -> Result<()> {
    let (cert, pkey) = load_pkcs11_certificate_and_key(uri)?;
    connector_builder.set_certificate(&cert)?;
    connector_builder.set_private_key(&pkey)?;
    connector_builder.check_private_key()?;
    Ok(())
}

fn load_pkcs11_certificate_and_key(uri: &str) -> Result<(X509, PKey<Private>)> {
    let ossl_store = OsslStoreFns::load()?;
    let uri = CString::new(uri).map_err(|_| {
        OpenfortivpnError::TlsHandshake("PKCS#11 URI contains an embedded NUL byte".to_owned())
    })?;
    let mut store = StoreCtx::open(&ossl_store, &uri)?;
    let mut cert = None;
    let mut pkey = None;

    loop {
        let info = unsafe { (ossl_store.load)(store.as_ptr()) };
        if info.is_null() {
            break;
        }
        let info = StoreInfo(info, ossl_store.info_free);
        let info_type = unsafe { (ossl_store.info_get_type)(info.0) };
        match info_type {
            ossl_store::OSSL_STORE_INFO_CERT => {
                if cert.is_some() {
                    return Err(OpenfortivpnError::TlsHandshake(
                        "PKCS#11: multiple certificates found in store; specify a more specific URI (for example with id or object/label)".to_owned(),
                    ));
                }
                let ptr = unsafe { (ossl_store.info_get1_cert)(info.0) };
                if ptr.is_null() {
                    return Err(last_openssl_error(
                        "PKCS#11: could not get certificate from store",
                    ));
                }
                cert = Some(unsafe { X509::from_ptr(ptr) });
            }
            ossl_store::OSSL_STORE_INFO_PKEY => {
                if pkey.is_some() {
                    return Err(OpenfortivpnError::TlsHandshake(
                        "PKCS#11: multiple private keys found in store; specify a more specific URI (for example with id or object/label)".to_owned(),
                    ));
                }
                let ptr = unsafe { (ossl_store.info_get1_pkey)(info.0) };
                if ptr.is_null() {
                    return Err(last_openssl_error(
                        "PKCS#11: could not get private key from store",
                    ));
                }
                pkey = Some(unsafe { PKey::from_ptr(ptr) });
            }
            _ => {}
        }
    }

    let cert = cert.ok_or_else(|| {
        OpenfortivpnError::TlsHandshake("PKCS#11: could not load certificate from store".to_owned())
    })?;
    let pkey = pkey.ok_or_else(|| {
        OpenfortivpnError::TlsHandshake("PKCS#11: could not load private key from store".to_owned())
    })?;

    Ok((cert, pkey))
}

fn last_openssl_error(context: &str) -> OpenfortivpnError {
    let errors = openssl::error::ErrorStack::get();
    if errors.errors().is_empty() {
        OpenfortivpnError::TlsHandshake(context.to_owned())
    } else {
        OpenfortivpnError::TlsHandshake(format!("{context}: {errors}"))
    }
}

struct StoreCtx {
    ptr: *mut ossl_store::OSSL_STORE_CTX,
    close: ossl_store::OsslStoreClose,
}

impl StoreCtx {
    fn open(fns: &OsslStoreFns, uri: &CString) -> Result<Self> {
        let ptr = unsafe {
            (fns.open)(
                uri.as_ptr(),
                std::ptr::null_mut(),
                None,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ptr.is_null() {
            return Err(last_openssl_error("PKCS#11: OSSL_STORE_open failed"));
        }
        Ok(Self {
            ptr,
            close: fns.close,
        })
    }

    fn as_ptr(&mut self) -> *mut ossl_store::OSSL_STORE_CTX {
        self.ptr
    }
}

impl Drop for StoreCtx {
    fn drop(&mut self) {
        unsafe {
            (self.close)(self.ptr);
        }
    }
}

struct StoreInfo(
    *mut ossl_store::OSSL_STORE_INFO,
    ossl_store::OsslStoreInfoFree,
);

impl Drop for StoreInfo {
    fn drop(&mut self) {
        unsafe {
            (self.1)(self.0);
        }
    }
}

#[derive(Clone, Copy)]
struct OsslStoreFns {
    open: ossl_store::OsslStoreOpen,
    load: ossl_store::OsslStoreLoad,
    close: ossl_store::OsslStoreClose,
    info_free: ossl_store::OsslStoreInfoFree,
    info_get_type: ossl_store::OsslStoreInfoGetType,
    info_get1_cert: ossl_store::OsslStoreInfoGet1Cert,
    info_get1_pkey: ossl_store::OsslStoreInfoGet1Pkey,
}

impl OsslStoreFns {
    fn load() -> Result<Self> {
        Ok(Self {
            open: load_crypto_symbol("OSSL_STORE_open")?,
            load: load_crypto_symbol("OSSL_STORE_load")?,
            close: load_crypto_symbol("OSSL_STORE_close")?,
            info_free: load_crypto_symbol("OSSL_STORE_INFO_free")?,
            info_get_type: load_crypto_symbol("OSSL_STORE_INFO_get_type")?,
            info_get1_cert: load_crypto_symbol("OSSL_STORE_INFO_get1_CERT")?,
            info_get1_pkey: load_crypto_symbol("OSSL_STORE_INFO_get1_PKEY")?,
        })
    }
}

fn load_crypto_symbol<T: Copy>(name: &str) -> Result<T> {
    let name = CString::new(name).expect("static OpenSSL symbol names contain no NUL bytes");
    let symbol = unsafe { nix::libc::dlsym(nix::libc::RTLD_DEFAULT, name.as_ptr()) };
    if symbol.is_null() {
        return Err(OpenfortivpnError::TlsHandshake(
            "PKCS#11 requires OpenSSL 3 OSSL_STORE symbols; check that OpenSSL 3 and a PKCS#11 provider are available".to_owned(),
        ));
    }
    Ok(unsafe { std::mem::transmute_copy(&symbol) })
}

#[allow(non_camel_case_types)]
mod ossl_store {
    use std::os::raw::{c_char, c_int, c_void};

    pub enum OSSL_STORE_CTX {}
    pub enum OSSL_STORE_INFO {}
    pub type OSSL_STORE_post_process_info_fn = Option<
        unsafe extern "C" fn(info: *mut OSSL_STORE_INFO, arg: *mut c_void) -> *mut OSSL_STORE_INFO,
    >;

    pub const OSSL_STORE_INFO_PKEY: c_int = 4;
    pub const OSSL_STORE_INFO_CERT: c_int = 5;

    pub type OsslStoreOpen = unsafe extern "C" fn(
        uri: *const c_char,
        libctx: *mut c_void,
        post_process: OSSL_STORE_post_process_info_fn,
        post_process_arg: *mut c_void,
        params: *mut c_void,
    ) -> *mut OSSL_STORE_CTX;
    pub type OsslStoreLoad = unsafe extern "C" fn(ctx: *mut OSSL_STORE_CTX) -> *mut OSSL_STORE_INFO;
    pub type OsslStoreClose = unsafe extern "C" fn(ctx: *mut OSSL_STORE_CTX) -> c_int;
    pub type OsslStoreInfoFree = unsafe extern "C" fn(info: *mut OSSL_STORE_INFO);
    pub type OsslStoreInfoGetType = unsafe extern "C" fn(info: *const OSSL_STORE_INFO) -> c_int;
    pub type OsslStoreInfoGet1Cert =
        unsafe extern "C" fn(info: *const OSSL_STORE_INFO) -> *mut openssl_sys::X509;
    pub type OsslStoreInfoGet1Pkey =
        unsafe extern "C" fn(info: *const OSSL_STORE_INFO) -> *mut openssl_sys::EVP_PKEY;
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

fn verify_certificate(
    config: &Config,
    verify_result: X509VerifyResult,
    peer_cert_sha256: &str,
) -> Result<CertificateVerification> {
    if config.insecure_ssl {
        return Ok(CertificateVerification::Disabled);
    }

    if verify_result == X509VerifyResult::OK {
        return Ok(CertificateVerification::VerifiedByPki);
    }

    if config
        .trusted_certs
        .iter()
        .any(|digest| digest.eq_ignore_ascii_case(peer_cert_sha256))
    {
        return Ok(CertificateVerification::VerifiedByPinnedDigest);
    }

    Err(OpenfortivpnError::CertificateVerification(format!(
        "{}; add '--trusted-cert {}' if this gateway certificate is expected",
        verify_result.error_string(),
        peer_cert_sha256
    )))
}

fn cert_sha256_hex(cert: &openssl::x509::X509Ref) -> Result<String> {
    let digest = cert.digest(MessageDigest::sha256())?;
    Ok(bytes_to_lower_hex(&digest))
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

fn effective_cipher_list(config: &Config) -> Option<&str> {
    if let Some(cipher_list) = &config.cipher_list {
        return Some(cipher_list);
    }

    match (config.insecure_ssl, config.seclevel_1) {
        (false, false) => Some(DEFAULT_STRICT_CIPHER_LIST),
        (false, true) => Some(DEFAULT_STRICT_CIPHER_LIST_SECLEVEL_1),
        (true, true) => Some(DEFAULT_INSECURE_CIPHER_LIST_SECLEVEL_1),
        (true, false) => None,
    }
}

fn to_ssl_version(version: &TlsVersion) -> SslVersion {
    match version {
        TlsVersion::Tls10 => SslVersion::TLS1,
        TlsVersion::Tls11 => SslVersion::TLS1_1,
        TlsVersion::Tls12 => SslVersion::TLS1_2,
        TlsVersion::Tls13 => SslVersion::TLS1_3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_lower_hex() {
        assert_eq!(bytes_to_lower_hex(&[0x00, 0xab, 0xcd, 0xff]), "00abcdff");
    }

    #[test]
    fn chooses_default_cipher_list_like_c() {
        let mut cfg = Config::default();
        assert_eq!(
            effective_cipher_list(&cfg),
            Some(DEFAULT_STRICT_CIPHER_LIST)
        );

        cfg.seclevel_1 = true;
        assert_eq!(
            effective_cipher_list(&cfg),
            Some(DEFAULT_STRICT_CIPHER_LIST_SECLEVEL_1)
        );

        cfg.insecure_ssl = true;
        assert_eq!(
            effective_cipher_list(&cfg),
            Some(DEFAULT_INSECURE_CIPHER_LIST_SECLEVEL_1)
        );

        cfg.seclevel_1 = false;
        assert_eq!(effective_cipher_list(&cfg), None);
    }

    #[test]
    fn custom_cipher_list_wins() {
        let mut cfg = Config::default();
        cfg.cipher_list = Some("DEFAULT".to_owned());
        cfg.insecure_ssl = true;
        assert_eq!(effective_cipher_list(&cfg), Some("DEFAULT"));
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
    fn verifies_by_pin_when_pki_failed() {
        let mut cfg = Config::default();
        cfg.trusted_certs.push("ab".repeat(32));

        let result = verify_certificate(
            &cfg,
            X509VerifyResult::APPLICATION_VERIFICATION,
            &"ab".repeat(32),
        )
        .unwrap();

        assert_eq!(result, CertificateVerification::VerifiedByPinnedDigest);
    }

    #[test]
    fn insecure_ssl_disables_verification() {
        let mut cfg = Config::default();
        cfg.insecure_ssl = true;

        let result =
            verify_certificate(&cfg, X509VerifyResult::APPLICATION_VERIFICATION, "missing")
                .unwrap();

        assert_eq!(result, CertificateVerification::Disabled);
    }
}
