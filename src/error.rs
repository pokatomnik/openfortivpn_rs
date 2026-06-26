use thiserror::Error;

pub type Result<T> = std::result::Result<T, OpenfortivpnError>;

#[derive(Debug, Error)]
pub enum OpenfortivpnError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    #[error("server did not present a TLS certificate")]
    MissingPeerCertificate,

    #[error("TLS certificate verification failed: {0}")]
    CertificateVerification(String),

    #[error("HTTP protocol error: {0}")]
    HttpProtocol(String),

    #[error("VPN gateway denied permission")]
    PermissionDenied,

    #[error("authentication error: {0}")]
    Auth(String),

    #[error("pppd error: {0}")]
    Pppd(String),

    #[error("network configuration error: {0}")]
    Network(String),

    #[error("bad boolean value: {0}")]
    BadBoolean(String),

    #[error("bad integer value for {key}: {value}")]
    BadInteger { key: String, value: String },

    #[error("bad port for {key}: {value}")]
    BadPort { key: String, value: String },

    #[error("bad TLS version: {0}")]
    BadTlsVersion(String),

    #[error("bad certificate sha256 digest: {0}")]
    BadCertificateDigest(String),

    #[error("unknown configuration key: {0}")]
    UnknownConfigKey(String),

    #[error("HDLC output buffer too small")]
    HdlcBufferTooSmall,

    #[error("no HDLC frame found")]
    HdlcNoFrameFound,

    #[error("invalid HDLC frame")]
    HdlcInvalidFrame,

    #[error("bad HDLC checksum")]
    HdlcBadChecksum,
}
