//! Typed resource resolution and rendering for catalog-backed local surfaces.

mod dotenv;
mod error;
mod links;
mod registry;
mod resolver;

pub use dotenv::{parse_dotenv, render_dotenv, DOTENV_MAX_SIZE};
pub use error::{SurfaceError, SurfaceResult};
pub use links::{ensure_dotenv_surface_link, SurfaceLinkState};
pub use registry::SurfaceRegistry;
pub use resolver::{DotenvSnapshot, FrozenResourceVersion, SurfaceResolver};
