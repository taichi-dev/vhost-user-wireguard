// SPDX-License-Identifier: MIT OR Apache-2.0

//! Top-level and module-specific error types.

use std::io;
use std::path::PathBuf;

/// Top-level daemon error returned from `lib.rs::run()`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("WireGuard error: {0}")]
    Wg(#[from] WgError),

    #[error("DHCP error: {0}")]
    Dhcp(#[from] DhcpError),

    #[error("privilege error: {0}")]
    Privilege(#[from] PrivilegeError),

    #[error("vhost-user error: {0}")]
    Vhost(#[from] VhostError),

    #[error("logging setup error: {0}")]
    Logging(#[from] LoggingError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Configuration and validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("I/O error reading config file {path}: {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("validation failed:\n{}", .issues.join("\n"))]
    Validation { issues: Vec<String> },

    #[error("unknown config version {version}")]
    UnknownVersion { version: u32 },
}

/// WireGuard-related errors.
#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("key file {path} has insecure permissions (mode {mode:#o}); world or group readable")]
    KeyFileMode { path: PathBuf, mode: u32 },

    #[error("invalid base64 key: {0}")]
    KeyBase64(#[from] base64::DecodeError),

    #[error("key has wrong length (expected 32 bytes, got {length})")]
    KeyLength { length: usize },

    #[error("I/O error loading key file {path}: {source}")]
    KeyFileRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("no key source configured (need private_key or private_key_file)")]
    NoKeySource,

    #[error("ambiguous key source: both private_key and private_key_file are set")]
    AmbiguousKeySource,

    #[error("socket bind error on port {port}: {source}")]
    SocketBind {
        port: u16,
        #[source]
        source: io::Error,
    },

    #[error("socket send error: {0}")]
    SocketSend(io::Error),

    #[error("timer fd error: {0}")]
    TimerFd(io::Error),

    #[error("encapsulation error: {0}")]
    Encap(String),

    #[error("peer not found for index {index}")]
    PeerNotFound { index: usize },
}

/// DHCP subsystem errors.
#[derive(Debug, thiserror::Error)]
pub enum DhcpError {
    #[error("dhcproto parse error: {0}")]
    Parse(#[from] dhcproto::error::DecodeError),

    #[error("dhcproto encode error: {0}")]
    Encode(#[from] dhcproto::error::EncodeError),

    #[error("lease file I/O error at {path}: {source}")]
    LeaseFileIo {
        path: std::path::PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("lease file JSON error: {0}")]
    LeaseFileJson(#[from] serde_json::Error),

    #[error("lease file has incompatible schema version {version}")]
    LeaseFileVersion { version: u32 },

    #[error("no addresses available in DHCP pool")]
    PoolExhausted,

    #[error("requested IP {ip} is not in subnet {subnet}")]
    IpOutsideSubnet {
        ip: std::net::Ipv4Addr,
        subnet: String,
    },
}

/// Privilege dropping errors.
#[derive(Debug, thiserror::Error)]
pub enum PrivilegeError {
    #[error("unknown user '{name}'")]
    UnknownUser { name: String },

    #[error("unknown group '{name}'")]
    UnknownGroup { name: String },

    #[error("setgid({gid}) failed: {source}")]
    Setgid {
        gid: u32,
        #[source]
        source: io::Error,
    },

    #[error("setuid({uid}) failed: {source}")]
    Setuid {
        uid: u32,
        #[source]
        source: io::Error,
    },

    #[error("capability operation failed: {0}")]
    Caps(String),

    #[error("prctl error: {source}")]
    Prctl {
        #[source]
        source: io::Error,
    },
}

/// vhost-user backend errors.
#[derive(Debug, thiserror::Error)]
pub enum VhostError {
    #[error("vhost-user backend error: {0}")]
    Backend(String),

    #[error("vring error: {0}")]
    Vring(String),

    #[error("guest memory error: {0}")]
    GuestMemory(String),

    #[error("eventfd error: {0}")]
    EventFd(io::Error),

    #[error("vhost-user socket error at {path}: {source}")]
    Socket {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Logging/tracing subscriber errors.
#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("invalid log level filter '{filter}': {source}")]
    InvalidFilter {
        filter: String,
        #[source]
        source: tracing_subscriber::filter::ParseError,
    },

    #[error("global tracing subscriber already installed")]
    AlreadyInstalled,
}
