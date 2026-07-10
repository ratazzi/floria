use std::path::PathBuf;

use thiserror::Error;

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("secret not found: {0}")]
    NotFound(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("corrupt store entry {id}: {reason}")]
    Corrupt { id: String, reason: String },
}

impl StoreError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        StoreError::Io {
            path: path.into(),
            source,
        }
    }
}
