//! Durable metadata catalog for projects, environments, typed resources, bindings, and surfaces.
//!
//! The catalog intentionally stores references to encrypted secrets, never their plaintext.
//! Resolution produces environment keys plus provenance so callers can preview and authorize
//! composition without decrypting a value.

mod catalog;
mod domain;
mod error;

pub use catalog::{
    catalog_surface_semantic_revision, resolve_catalog_snapshot, resolve_catalog_surface, Catalog,
};
pub use domain::{
    Binding, BindingScope, CatalogSnapshot, EntrySelection, EntrySpec, Environment, FileBacking,
    FormatInputModel, FormatSpec, ItemLink, ItemMetadata, ManagedFileConfigurationRemoval,
    OriginKind, OriginSource, Project, ProjectCheckout, ProjectCheckoutKind, ResolvedEnvironment,
    ResolvedExport, Resource, ResourceBindingUsage, ResourceCodec, ResourceKind, ResourceOrigin,
    ResourceSource, ResourceUsage, SshRouteSpec, Surface, SurfaceFormat, SurfaceInput, SurfaceKind,
    ValueShape,
};
pub use error::{CatalogError, CatalogResult};
