use thiserror::Error;

pub type SurfaceResult<T> = Result<T, SurfaceError>;

#[derive(Debug, Error)]
pub enum SurfaceError {
    #[error(transparent)]
    Catalog(#[from] accessfs_catalog::CatalogError),

    #[error("secret store error: {0}")]
    Store(#[from] accessfs_store::StoreError),

    #[error("surface not found: {0}")]
    NotFound(String),

    #[error("surface {surface_id:?} has unsupported kind {kind}")]
    UnsupportedSurface { surface_id: String, kind: String },

    #[error("resource {resource_id:?} is incompatible with dotenv: {reason}")]
    IncompatibleResource { resource_id: String, reason: String },

    #[error("resource {resource_id:?} value is not UTF-8")]
    InvalidUtf8 { resource_id: String },

    #[error("dotenv parse error on line {line}: {reason}")]
    DotenvParse { line: usize, reason: String },

    #[error("resolved resource {resource_id:?} is missing key {key:?}")]
    MissingKey { resource_id: String, key: String },

    #[error("rendered dotenv exceeds {limit} bytes")]
    TooLarge { limit: usize },
}
