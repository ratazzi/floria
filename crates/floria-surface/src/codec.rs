use std::collections::HashMap;

use floria_catalog::{
    Catalog, CatalogSnapshot, FileBacking, Resource, ResourceCodec, ResourceSource,
    SurfaceFormat, SurfaceInput, SurfaceKind, ValueShape,
};
use floria_store::{SecretId, SecretStore};
use zeroize::Zeroizing;

use crate::dotenv::parse_dotenv;
use crate::error::{SurfaceError, SurfaceResult};
use crate::ini::parse_ini;
use crate::lines::render_lines_refs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecCapabilities {
    pub raw_writeback: bool,
    pub preserves_entry_order: bool,
    pub hierarchical_addresses: bool,
}

#[derive(Debug)]
pub struct DecodedEntry {
    pub address: String,
    pub section: Option<String>,
    pub key: Option<String>,
    pub value: Zeroizing<String>,
}

/// Syntax adapter between opaque source bytes and catalog-addressed entries.
/// Projections consume decoded entries and remain independent of source syntax.
pub trait Codec: Sync {
    fn capabilities(&self) -> CodecCapabilities;
    fn decode(&self, resource_id: &str, bytes: &[u8]) -> SurfaceResult<Vec<DecodedEntry>>;
}

struct OpaqueCodec;

impl Codec for OpaqueCodec {
    fn capabilities(&self) -> CodecCapabilities {
        CodecCapabilities {
            raw_writeback: false,
            preserves_entry_order: true,
            hierarchical_addresses: false,
        }
    }

    fn decode(&self, resource_id: &str, bytes: &[u8]) -> SurfaceResult<Vec<DecodedEntry>> {
        let value = std::str::from_utf8(bytes)
            .map_err(|_| SurfaceError::InvalidUtf8 { resource_id: resource_id.to_string() })?;
        Ok(vec![DecodedEntry {
            address: "value".to_string(),
            section: None,
            key: None,
            value: Zeroizing::new(value.to_string()),
        }])
    }
}

struct DotenvCodec;

impl Codec for DotenvCodec {
    fn capabilities(&self) -> CodecCapabilities {
        CodecCapabilities {
            raw_writeback: true,
            preserves_entry_order: true,
            hierarchical_addresses: false,
        }
    }

    fn decode(&self, resource_id: &str, bytes: &[u8]) -> SurfaceResult<Vec<DecodedEntry>> {
        if bytes.len() > crate::dotenv::DOTENV_MAX_SIZE {
            return Err(SurfaceError::TooLarge { limit: crate::dotenv::DOTENV_MAX_SIZE });
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| SurfaceError::InvalidUtf8 { resource_id: resource_id.to_string() })?;
        parse_dotenv(text).map(|entries| {
            entries
                .into_iter()
                .map(|entry| DecodedEntry {
                    address: format!("keys/{}", entry.key),
                    section: None,
                    key: Some(entry.key),
                    value: entry.value,
                })
                .collect()
        })
    }
}

struct IniCodec;

impl Codec for IniCodec {
    fn capabilities(&self) -> CodecCapabilities {
        CodecCapabilities {
            raw_writeback: false,
            preserves_entry_order: true,
            hierarchical_addresses: true,
        }
    }

    fn decode(&self, resource_id: &str, bytes: &[u8]) -> SurfaceResult<Vec<DecodedEntry>> {
        if bytes.len() > crate::ini::INI_MAX_SIZE {
            return Err(SurfaceError::TooLarge { limit: crate::ini::INI_MAX_SIZE });
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| SurfaceError::InvalidUtf8 { resource_id: resource_id.to_string() })?;
        parse_ini(text).map(|entries| {
            entries
                .into_iter()
                .map(|entry| DecodedEntry {
                    address: entry.address,
                    section: entry.section,
                    key: Some(entry.key),
                    value: entry.value,
                })
                .collect()
        })
    }
}

static OPAQUE_CODEC: OpaqueCodec = OpaqueCodec;
static DOTENV_CODEC: DotenvCodec = DotenvCodec;
static INI_CODEC: IniCodec = IniCodec;

fn adapter(codec: ResourceCodec) -> &'static dyn Codec {
    match codec {
        ResourceCodec::Opaque => &OPAQUE_CODEC,
        ResourceCodec::Dotenv => &DOTENV_CODEC,
        ResourceCodec::Ini => &INI_CODEC,
    }
}

pub fn codec_capabilities(codec: ResourceCodec) -> CodecCapabilities {
    adapter(codec).capabilities()
}

pub fn decode_source(
    codec: ResourceCodec,
    resource_id: &str,
    bytes: &[u8],
) -> SurfaceResult<Vec<DecodedEntry>> {
    adapter(codec).decode(resource_id, bytes)
}

pub fn decode_resource(resource: &Resource, bytes: &[u8]) -> SurfaceResult<Vec<DecodedEntry>> {
    if resource.shape == ValueShape::Bytes {
        return Ok(Vec::new());
    }
    let mut decoded = decode_source(resource.codec, &resource.id, bytes)?;
    if resource.codec == ResourceCodec::Opaque && resource.shape == ValueShape::Scalar {
        let spec = &resource.entries[0];
        decoded[0].address = spec.address.clone();
        decoded[0].key = spec.key.clone();
        return Ok(decoded);
    }
    let expected = resource
        .entries
        .iter()
        .map(|entry| (entry.address.clone(), entry.key.clone()))
        .collect::<Vec<_>>();
    let actual = decoded
        .iter()
        .map(|entry| (entry.address.clone(), entry.key.clone()))
        .collect::<Vec<_>>();
    if !same_schema(&expected, &actual) {
        return Err(SurfaceError::ResourceEntriesChanged {
            resource_id: resource.id.clone(),
            expected: display_schema(&expected),
            actual: display_schema(&actual),
        });
    }

    let specs = resource
        .entries
        .iter()
        .map(|entry| (entry.address.as_str(), entry.key.clone()))
        .collect::<HashMap<_, _>>();
    for entry in &mut decoded {
        entry.key = specs.get(entry.address.as_str()).cloned().flatten();
    }
    Ok(decoded)
}

/// Validate replacement bytes against every catalog resource that references one stored secret.
/// The store remains format-blind; this cross-layer check belongs at mutation boundaries.
pub fn validate_secret_bytes(
    snapshot: &CatalogSnapshot,
    secret_id: &str,
    bytes: &[u8],
) -> SurfaceResult<()> {
    let line_binding_ids = snapshot
        .surfaces
        .iter()
        .filter(|surface| surface.kind == SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)))
        .filter_map(|surface| match &surface.input {
            SurfaceInput::Bindings { binding_ids } => Some(binding_ids.as_slice()),
            SurfaceInput::SshAgent { .. } | SurfaceInput::Resource { .. } => None,
        })
        .flatten()
        .collect::<std::collections::HashSet<_>>();

    for resource in snapshot.resources.iter().filter(|resource| {
        matches!(
            &resource.source,
            ResourceSource::SecretRef { secret_id: referenced } if referenced == secret_id
        )
    }) {
        let decoded = decode_resource(resource, bytes)?;
        let feeds_lines = snapshot.bindings.iter().any(|binding| {
            binding.resource_id == resource.id && line_binding_ids.contains(&binding.id)
        });
        if feeds_lines {
            let value = decoded.first().ok_or_else(|| SurfaceError::MissingKey {
                resource_id: resource.id.clone(),
                key: resource
                    .entries
                    .first()
                    .map(|entry| entry.address.clone())
                    .unwrap_or_else(|| "value".to_string()),
            })?;
            render_lines_refs(std::iter::once((resource.id.as_str(), value.value.as_str())))?;
        }
    }
    Ok(())
}

/// Validate bytes against every catalog consumer, then append one immutable store version.
///
/// This is the mutation choke point for filesystem writeback. The store intentionally remains
/// format-blind; when no catalog is configured, the skipped cross-layer validation is explicit.
pub fn commit_secret_version(
    catalog: Option<&Catalog>,
    store: &dyn SecretStore,
    id: &SecretId,
    bytes: &[u8],
) -> SurfaceResult<u32> {
    if let Some(catalog) = catalog {
        validate_secret_bytes(&catalog.snapshot()?, id.as_str(), bytes)?;
    } else {
        tracing::debug!(secret_id = %id, "no catalog configured; skipping schema validation");
    }
    store.append_version(id, bytes).map_err(Into::into)
}

fn same_schema(left: &[(String, Option<String>)], right: &[(String, Option<String>)]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort();
    right.sort();
    left == right
}

fn display_schema(schema: &[(String, Option<String>)]) -> Vec<String> {
    schema
        .iter()
        .map(|(address, key)| match key {
            Some(key) => format!("{address} ({key})"),
            None => address.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use floria_catalog::{EntrySpec, ResourceKind, ResourceSource, ValueShape};

    #[test]
    fn dotenv_adapter_preserves_document_order_and_hierarchical_identity() {
        let decoded = decode_source(
            ResourceCodec::Dotenv,
            "fixture-resource",
            b"SECOND=two\nFIRST=one\n",
        )
        .unwrap();

        assert_eq!(
            decoded.iter().map(|entry| entry.address.as_str()).collect::<Vec<_>>(),
            vec!["keys/SECOND", "keys/FIRST"]
        );
    }

    #[test]
    fn resource_decode_rejects_blob_schema_drift() {
        let resource = Resource {
            id: "fixture-env".to_string(),
            name: "Fixture Env".to_string(),
            kind: ResourceKind::EnvFile,
            shape: ValueShape::KeyValueSet,
            codec: ResourceCodec::Dotenv,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: "keys/FIXTURE".to_string(),
                label: "FIXTURE".to_string(),
                key: Some("FIXTURE".to_string()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: "fixture-secret".to_string() },
            enforcement: Default::default(),
            metadata: Default::default(),
            origin: Default::default(),
        };

        assert!(matches!(
            decode_resource(&resource, b"OTHER=value\n"),
            Err(SurfaceError::ResourceEntriesChanged { .. })
        ));
    }

    #[test]
    fn secret_validation_applies_codec_and_surface_constraints() {
        let resource = Resource {
            id: "fixture-line".to_string(),
            name: "Fixture Line".to_string(),
            kind: ResourceKind::SharedSecret,
            shape: ValueShape::Scalar,
            codec: ResourceCodec::Opaque,
            default_env_key: None,
            entries: vec![EntrySpec {
                address: "value".to_string(),
                label: "Fixture Line".to_string(),
                key: None,
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: "fixture-secret".to_string() },
            enforcement: Default::default(),
            metadata: Default::default(),
            origin: Default::default(),
        };
        let snapshot = CatalogSnapshot {
            resources: vec![resource],
            bindings: vec![floria_catalog::Binding {
                id: "fixture-binding".to_string(),
                project_id: "fixture-project".to_string(),
                scope: floria_catalog::BindingScope::Common,
                resource_id: "fixture-line".to_string(),
                selection: floria_catalog::EntrySelection::All,
                key_override: None,
                enabled: true,
                allow_override: false,
                position: 0,
            }],
            surfaces: vec![floria_catalog::Surface {
                id: "fixture-lines".to_string(),
                environment_id: "fixture-development".to_string(),
                name: "credentials.lines".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Lines)),
                path: std::path::PathBuf::from("/fixture/credentials.lines"),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["fixture-binding".to_string()],
                },
                enforcement: floria_core::authz::Enforcement::Prompt,
                position: 0,
            }],
            ..CatalogSnapshot::default()
        };

        validate_secret_bytes(&snapshot, "fixture-secret", b"one-line").unwrap();
        assert!(matches!(
            validate_secret_bytes(&snapshot, "fixture-secret", b"first\nsecond"),
            Err(SurfaceError::InvalidLineValue { .. })
        ));
        validate_secret_bytes(&snapshot, "unreferenced-secret", b"first\nsecond").unwrap();
    }
}
