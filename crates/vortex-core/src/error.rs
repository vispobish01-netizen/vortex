use thiserror::Error;

#[derive(Error, Debug)]
pub enum VortexError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML error: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("Tunnel error: {0}")]
    Tunnel(String),

    #[error("Firewall error: {0}")]
    Firewall(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Protocol parse error: {0}")]
    Parse(String),

    #[error("Profile not found: {0}")]
    NotFound(String),

    #[error("Command execution error: {0}")]
    Command(String),

    #[error("Generic error: {0}")]
    Other(String),
}

impl From<anyhow::Error> for VortexError {
    fn from(err: anyhow::Error) -> Self {
        VortexError::Other(err.to_string())
    }
}
