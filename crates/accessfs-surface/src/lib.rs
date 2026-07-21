//! Typed resource resolution and rendering for catalog-backed local surfaces.

mod codec;
mod direnv;
mod dotenv;
mod error;
mod ini;
mod links;
mod lines;
mod registry;
mod resolver;

pub use codec::{
    codec_capabilities, decode_resource, decode_source, validate_secret_bytes, Codec,
    CodecCapabilities, DecodedEntry,
};
pub use direnv::DIRENV_MAX_SIZE;
pub use dotenv::{parse_dotenv, render_dotenv, ParsedDotenvEntry, DOTENV_MAX_SIZE};
pub use error::{SurfaceError, SurfaceResult};
pub use ini::{parse_ini, ParsedIniEntry, INI_MAX_SIZE};
pub use links::{
    ensure_file_surface_link, remove_file_surface_link, SurfaceLinkRemoval, SurfaceLinkState,
};
pub use lines::LINES_MAX_SIZE;
pub use registry::{RegisteredSurface, SurfaceBacking, SurfaceRegistry};
pub use resolver::{
    DirectEnvFileCommit, DirectEnvFileSnapshot, DirenvSnapshot, DotenvSnapshot,
    FrozenResourceVersion, IniSnapshot, LinesSnapshot, ResolvedIniEntry, SurfaceResolver,
};
