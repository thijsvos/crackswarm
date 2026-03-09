use thiserror::Error;

#[derive(Error, Debug)]
pub enum CrackError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Noise protocol error: {0}")]
    Noise(#[from] snow::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Worker not authorized: {0}")]
    Unauthorized(String),

    #[error("Hashcat error: {0}")]
    Hashcat(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Task error: {0}")]
    Task(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, CrackError>;
