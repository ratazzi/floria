use std::path::PathBuf;

use thiserror::Error;

pub type CatalogResult<T> = Result<T, CatalogError>;

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("catalog io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("catalog database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("catalog encoding error: {0}")]
    Encoding(#[from] serde_json::Error),

    #[error("catalog security-state verification failed: {0}")]
    Integrity(#[from] floria_integrity::IntegrityError),

    #[error("invalid catalog value: {0}")]
    Validation(String),

    #[error("catalog object not found: {0}")]
    NotFound(String),

    #[error("catalog {kind} already exists: {id}")]
    AlreadyExists { kind: &'static str, id: String },

    #[error("environment key {key:?} conflicts between bindings {binding_ids:?}")]
    Conflict {
        key: String,
        binding_ids: Vec<String>,
    },

    #[error(
        "resource {resource_id:?} is still used by bindings {binding_ids:?} and surfaces {surface_ids:?}"
    )]
    ResourceInUse {
        resource_id: String,
        binding_ids: Vec<String>,
        surface_ids: Vec<String>,
    },

    #[error("catalog schema version {found} is not supported (expected {expected})")]
    UnsupportedSchema { found: i64, expected: i64 },
}

impl CatalogError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        CatalogError::Io { path: path.into(), source }
    }
}
