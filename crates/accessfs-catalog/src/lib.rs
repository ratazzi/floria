//! Durable metadata catalog for projects, environments, typed resources, bindings, and surfaces.
//!
//! The catalog intentionally stores references to encrypted secrets, never their plaintext.
//! Resolution produces environment keys plus provenance so callers can preview and authorize
//! composition without decrypting a value.

mod catalog;
mod domain;
mod error;

pub use catalog::{resolve_catalog_snapshot, Catalog};
pub use domain::{
    Binding, BindingScope, CatalogSnapshot, EntrySelection, EntrySpec, Environment,
    Project, ResolvedEnvironment, ResolvedExport, Resource, ResourceBindingUsage, ResourceKind,
    ResourceSource, ResourceUsage, Surface, SurfaceKind, ValueShape,
};
pub use error::{CatalogError, CatalogResult};
