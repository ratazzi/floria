//! Typed resource resolution and rendering for catalog-backed local surfaces.

mod codec;
mod dotenv;
mod error;
mod links;
mod lines;
mod registry;
mod resolver;

pub use codec::{
    codec_capabilities, decode_resource, decode_source, validate_secret_bytes, Codec,
    CodecCapabilities, DecodedEntry,
};
pub use dotenv::{parse_dotenv, render_dotenv, ParsedDotenvEntry, DOTENV_MAX_SIZE};
pub use error::{SurfaceError, SurfaceResult};
pub use links::{
    ensure_file_surface_link, remove_file_surface_link, SurfaceLinkRemoval, SurfaceLinkState,
};
pub use lines::LINES_MAX_SIZE;
pub use registry::{RegisteredSurface, SurfaceBacking, SurfaceRegistry};
pub use resolver::{
    DirectEnvFileCommit, DirectEnvFileSnapshot, DotenvSnapshot, FrozenResourceVersion,
    LinesSnapshot, SurfaceResolver,
};
