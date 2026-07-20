//! Typed resource resolution and rendering for catalog-backed local surfaces.

mod dotenv;
mod error;
mod resolver;

pub use dotenv::{parse_dotenv, render_dotenv, DOTENV_MAX_SIZE};
pub use error::{SurfaceError, SurfaceResult};
pub use resolver::{DotenvSnapshot, FrozenResourceVersion, SurfaceResolver};
