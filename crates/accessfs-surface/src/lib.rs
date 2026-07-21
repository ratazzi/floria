//! Typed resource resolution and rendering for catalog-backed local surfaces.

mod dotenv;
mod error;
mod links;
mod registry;
mod resolver;

pub use dotenv::{parse_dotenv, render_dotenv, DOTENV_MAX_SIZE};
pub use error::{SurfaceError, SurfaceResult};
pub use links::{
    ensure_file_surface_link, remove_file_surface_link, SurfaceLinkRemoval, SurfaceLinkState,
};
pub use registry::{RegisteredSurface, SurfaceBacking, SurfaceRegistry};
pub use resolver::{
    DirectEnvFileCommit, DirectEnvFileSnapshot, DotenvSnapshot, FrozenResourceVersion,
    SurfaceResolver,
};
