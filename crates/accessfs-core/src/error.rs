use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("insecure permissions on {path}: {reason}")]
    InsecurePerms { path: PathBuf, reason: String },

    #[error("handler error: {0}")]
    Handler(String),
}

impl CoreError {
    pub fn config(msg: impl Into<String>) -> Self {
        CoreError::Config(msg.into())
    }

    pub fn handler(msg: impl Into<String>) -> Self {
        CoreError::Handler(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
