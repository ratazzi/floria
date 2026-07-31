//! Byte layout for composed file surfaces.
//!
//! A resource [`crate::Codec`] describes how opaque source bytes are decoded. A `Renderer`
//! describes how an already resolved surface document is encoded. These are deliberately
//! orthogonal axes: for example, a dotenv surface can project values decoded from opaque,
//! dotenv, or INI resources.

use floria_catalog::SurfaceFormat;
use zeroize::Zeroizing;

use crate::direnv::{render_direnv_refs, DIRENV_MAX_SIZE};
use crate::dotenv::{render_dotenv_refs, DOTENV_MAX_SIZE};
use crate::error::{SurfaceError, SurfaceResult};
use crate::ini::{render_ini_refs, INI_MAX_SIZE};
use crate::lines::{render_lines_refs, LINES_MAX_SIZE};

/// Metadata for one rendered entry in its canonical output order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEntryMeta {
    pub audit_key: String,
    pub binding_id: String,
    pub resource_id: String,
}

/// One environment-projection value after catalog resolution and resource decoding.
#[derive(Debug)]
pub struct ResolvedEnvironmentEntry {
    pub export_key: String,
    pub source_address: String,
    pub binding_id: String,
    pub resource_id: String,
    pub value: Zeroizing<String>,
}

/// One selected binding entry after catalog validation and resource decoding.
#[derive(Debug)]
pub struct ResolvedBindingEntry {
    /// Stable catalog address. Renderers may also consume decoded structural metadata such as an
    /// INI section. Future hierarchical formats must extend this typed entry instead of parsing
    /// structure back out of an ad-hoc string address.
    pub address: String,
    pub key: Option<String>,
    pub section: Option<String>,
    pub binding_id: String,
    pub resource_id: String,
    pub value: Zeroizing<String>,
}

/// The two catalog-side document models currently supported by composed surfaces.
#[derive(Debug)]
pub enum ResolvedDocument {
    Environment(Vec<ResolvedEnvironmentEntry>),
    Bindings(Vec<ResolvedBindingEntry>),
}

/// Rendered bytes plus the entries that produced them, in the exact same canonical order.
#[derive(Debug)]
pub struct RenderedSurface {
    pub bytes: Vec<u8>,
    pub entries: Vec<ResolvedEntryMeta>,
}

/// One composed-surface output format.
///
/// Renderers are stateless. The resolver validates, freezes, and decodes through the catalog's
/// `FormatSpec`, then hands a typed document to the renderer for byte layout.
pub trait Renderer: Sync {
    fn format(&self) -> SurfaceFormat;

    /// Constant upper bound reported by frozen filesystem attributes.
    fn max_size(&self) -> usize;

    /// Lay out an already validated document as bytes.
    fn render(&self, document: ResolvedDocument) -> SurfaceResult<RenderedSurface>;
}

struct DotenvRenderer;
struct DirenvRenderer;
struct IniRenderer;
struct LinesRenderer;

static DOTENV_RENDERER: DotenvRenderer = DotenvRenderer;
static DIRENV_RENDERER: DirenvRenderer = DirenvRenderer;
static INI_RENDERER: IniRenderer = IniRenderer;
static LINES_RENDERER: LinesRenderer = LinesRenderer;
static RENDERERS: [&dyn Renderer; 4] = [
    &DOTENV_RENDERER,
    &DIRENV_RENDERER,
    &INI_RENDERER,
    &LINES_RENDERER,
];

pub fn renderer_for(format: SurfaceFormat) -> &'static dyn Renderer {
    RENDERERS
        .iter()
        .copied()
        .find(|renderer| renderer.format() == format)
        .expect("every SurfaceFormat must have a registered renderer")
}

impl Renderer for DotenvRenderer {
    fn format(&self) -> SurfaceFormat {
        SurfaceFormat::Dotenv
    }

    fn max_size(&self) -> usize {
        DOTENV_MAX_SIZE
    }

    fn render(&self, document: ResolvedDocument) -> SurfaceResult<RenderedSurface> {
        let ResolvedDocument::Environment(entries) = document else {
            return Err(wrong_document(self.format(), "environment projection"));
        };
        let bytes = render_dotenv_refs(
            entries
                .iter()
                .map(|entry| (entry.export_key.as_str(), entry.value.as_str())),
        )?;
        Ok(RenderedSurface {
            bytes,
            entries: environment_metadata(entries),
        })
    }
}

impl Renderer for DirenvRenderer {
    fn format(&self) -> SurfaceFormat {
        SurfaceFormat::Direnv
    }

    fn max_size(&self) -> usize {
        DIRENV_MAX_SIZE
    }

    fn render(&self, document: ResolvedDocument) -> SurfaceResult<RenderedSurface> {
        let ResolvedDocument::Environment(entries) = document else {
            return Err(wrong_document(self.format(), "environment projection"));
        };
        let bytes = render_direnv_refs(
            entries
                .iter()
                .map(|entry| (entry.export_key.as_str(), entry.value.as_str())),
        )?;
        Ok(RenderedSurface {
            bytes,
            entries: environment_metadata(entries),
        })
    }
}

impl Renderer for IniRenderer {
    fn format(&self) -> SurfaceFormat {
        SurfaceFormat::Ini
    }

    fn max_size(&self) -> usize {
        INI_MAX_SIZE
    }

    fn render(&self, document: ResolvedDocument) -> SurfaceResult<RenderedSurface> {
        let ResolvedDocument::Bindings(entries) = document else {
            return Err(wrong_document(self.format(), "binding entries"));
        };
        let (roots, sectioned): (Vec<_>, Vec<_>) = entries
            .into_iter()
            .partition(|entry| entry.section.is_none());
        let entries = roots.into_iter().chain(sectioned).collect::<Vec<_>>();
        let mut values = Vec::with_capacity(entries.len());
        for entry in &entries {
            let key = entry.key.as_deref().ok_or_else(|| {
                SurfaceError::IncompatibleResource {
                    resource_id: entry.resource_id.clone(),
                    reason: format!("entry {:?} has no INI key", entry.address),
                }
            })?;
            values.push((entry.section.as_deref(), key, entry.value.as_str()));
        }
        let bytes = render_ini_refs(values)?;
        Ok(RenderedSurface {
            bytes,
            entries: binding_metadata(entries),
        })
    }
}

impl Renderer for LinesRenderer {
    fn format(&self) -> SurfaceFormat {
        SurfaceFormat::Lines
    }

    fn max_size(&self) -> usize {
        LINES_MAX_SIZE
    }

    fn render(&self, document: ResolvedDocument) -> SurfaceResult<RenderedSurface> {
        let ResolvedDocument::Bindings(entries) = document else {
            return Err(wrong_document(self.format(), "binding entries"));
        };
        let bytes = render_lines_refs(
            entries
                .iter()
                .map(|entry| (entry.resource_id.as_str(), entry.value.as_str())),
        )?;
        Ok(RenderedSurface {
            bytes,
            entries: binding_metadata(entries),
        })
    }
}

fn environment_metadata(entries: Vec<ResolvedEnvironmentEntry>) -> Vec<ResolvedEntryMeta> {
    entries
        .into_iter()
        .map(|entry| ResolvedEntryMeta {
            audit_key: entry.export_key,
            binding_id: entry.binding_id,
            resource_id: entry.resource_id,
        })
        .collect()
}

fn binding_metadata(entries: Vec<ResolvedBindingEntry>) -> Vec<ResolvedEntryMeta> {
    entries
        .into_iter()
        .map(|entry| ResolvedEntryMeta {
            audit_key: entry.address,
            binding_id: entry.binding_id,
            resource_id: entry.resource_id,
        })
        .collect()
}

fn wrong_document(format: SurfaceFormat, expected: &str) -> SurfaceError {
    SurfaceError::IncompatibleResource {
        resource_id: "<resolved-document>".to_string(),
        reason: format!("{format:?} renderer requires {expected}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_entry(
        address: &str,
        key: Option<&str>,
        section: Option<&str>,
        value: &str,
    ) -> ResolvedBindingEntry {
        ResolvedBindingEntry {
            address: address.to_string(),
            key: key.map(str::to_string),
            section: section.map(str::to_string),
            binding_id: format!("binding-{address}"),
            resource_id: format!("resource-{address}"),
            value: Zeroizing::new(value.to_string()),
        }
    }

    #[test]
    fn registry_exposes_every_format_and_frozen_size() {
        for (format, max_size) in [
            (SurfaceFormat::Dotenv, DOTENV_MAX_SIZE),
            (SurfaceFormat::Direnv, DIRENV_MAX_SIZE),
            (SurfaceFormat::Ini, INI_MAX_SIZE),
            (SurfaceFormat::Lines, LINES_MAX_SIZE),
        ] {
            let renderer = renderer_for(format);
            assert_eq!(renderer.format(), format);
            assert_eq!(renderer.max_size(), max_size);
        }
    }

    #[test]
    fn rejects_the_wrong_document_model() {
        let error = renderer_for(SurfaceFormat::Dotenv)
            .render(ResolvedDocument::Bindings(Vec::new()))
            .unwrap_err();

        assert!(matches!(
            error,
            SurfaceError::IncompatibleResource { resource_id, .. }
                if resource_id == "<resolved-document>"
        ));
    }

    #[test]
    fn ini_bytes_and_metadata_share_root_first_order() {
        let rendered = renderer_for(SurfaceFormat::Ini)
            .render(ResolvedDocument::Bindings(vec![
                binding_entry(
                    "sections/fixture/keys/token",
                    Some("token"),
                    Some("fixture"),
                    "section-value",
                ),
                binding_entry("root/keys/region", Some("region"), None, "root-value"),
            ]))
            .unwrap();

        assert_eq!(
            rendered.bytes,
            b"region = root-value\n\n[fixture]\ntoken = section-value\n"
        );
        assert_eq!(
            rendered
                .entries
                .iter()
                .map(|entry| entry.audit_key.as_str())
                .collect::<Vec<_>>(),
            ["root/keys/region", "sections/fixture/keys/token"]
        );
    }
}
