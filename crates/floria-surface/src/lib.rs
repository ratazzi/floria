//! Typed resource resolution and rendering for catalog-backed local surfaces.

mod codec;
mod direnv;
mod dotenv;
mod error;
mod ini;
mod links;
mod lines;
mod mutation;
mod render;
mod registry;
mod resolver;
mod source;

pub use codec::{
    codec_capabilities, commit_secret_version, decode_resource, decode_source,
    validate_secret_bytes, Codec, CodecCapabilities, DecodedEntry,
};
pub use direnv::DIRENV_MAX_SIZE;
pub use dotenv::{parse_dotenv, render_dotenv, ParsedDotenvEntry, DOTENV_MAX_SIZE};
pub use error::{SurfaceError, SurfaceResult};
pub use ini::{parse_ini, ParsedIniEntry, INI_MAX_SIZE};
pub use links::{
    checkout_link_issues, ensure_file_surface_link, file_surface_instances,
    managed_file_links, protected_checkout_links,
    refresh_protected_checkout_links, release_protected_links_for_file_surfaces,
    remove_excluded_protected_checkout_links,
    remove_file_surface_link, replace_file_with_symlink,
    replace_regular_file_with_symlink_if_matches,
    replace_regular_file_with_symlink_if_unchanged, replace_symlink_with_file_if_target,
    restore_protected_checkout_links,
    ManagedLinkStatus, ManagedSymlink, ProtectedCheckoutLink, SurfaceLinkRemoval,
    SurfaceLinkState,
};
pub use lines::LINES_MAX_SIZE;
pub use mutation::ManagedMutationCoordinator;
pub use render::{
    renderer_for, RenderedSurface, Renderer, ResolvedBindingEntry, ResolvedDocument,
    ResolvedEntryMeta, ResolvedEnvironmentEntry,
};
pub use registry::{ResolvedAccessPlan, SurfaceBacking, SurfaceRegistry};
pub use resolver::{
    DirectEnvFileCommit, DirectEnvFileSnapshot, FrozenResourceVersion, SurfaceResolver,
    SurfaceSnapshot,
};
pub use source::compile_source;
