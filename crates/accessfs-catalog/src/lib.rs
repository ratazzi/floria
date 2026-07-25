//! Durable metadata catalog for projects, environments, typed resources, bindings, and surfaces.
//!
//! The catalog intentionally stores references to encrypted secrets, never their plaintext.
//! Resolution produces environment keys plus provenance so callers can preview and authorize
//! composition without decrypting a value.

mod catalog;
mod domain;
mod error;

pub use catalog::{resolve_catalog_snapshot, resolve_catalog_surface, Catalog};
pub use domain::{
    Binding, BindingScope, CatalogSnapshot, EntrySelection, EntrySpec, Environment, ItemLink,
    ItemMetadata, Project, ResolvedEnvironment, ResolvedExport, Resource, ResourceBindingUsage,
    ResourceCodec, ResourceKind, ResourceSource, ResourceUsage, SshRouteSpec, Surface,
    SurfaceInput, SurfaceKind, ValueShape,
};
pub use error::{CatalogError, CatalogResult};
