use std::collections::{HashMap, HashSet};

use zeroize::Zeroizing;

use crate::error::{SurfaceError, SurfaceResult};

pub const INI_MAX_SIZE: usize = 1 << 20;

#[derive(Debug)]
pub struct ParsedIniEntry {
    pub address: String,
    pub section: Option<String>,
    pub key: String,
    pub value: Zeroizing<String>,
}

/// Parse a deterministic, ordered INI subset. Section and entry order are preserved;
/// repeated keys within the same section are rejected instead of silently shadowed.
pub fn parse_ini(input: &str) -> SurfaceResult<Vec<ParsedIniEntry>> {
    let mut section = None;
    let mut first_lines = HashMap::new();
    let mut entries = Vec::new();

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let Some(close) = line.find(']') else {
                return Err(parse_error(line_number, "unterminated section header"));
            };
            if !line[close + 1..].trim().is_empty() {
                return Err(parse_error(
                    line_number,
                    "unexpected characters after section header",
                ));
            }
            let name = line[1..close].trim();
            if name.is_empty() {
                return Err(parse_error(line_number, "section name cannot be empty"));
            }
            section = Some(name.to_string());
            continue;
        }

        let Some(separator) = line.find(['=', ':']) else {
            return Err(parse_error(line_number, "expected KEY=VALUE or KEY:VALUE"));
        };
        let key = line[..separator].trim();
        if key.is_empty() {
            return Err(parse_error(line_number, "entry key cannot be empty"));
        }
        let identity = (section.clone(), key.to_string());
        if let Some(first_line) = first_lines.insert(identity, line_number) {
            return Err(parse_error(
                line_number,
                format!(
                    "duplicate key {key:?} in {} (first declared on line {first_line})",
                    section
                        .as_deref()
                        .map(|name| format!("section {name:?}"))
                        .unwrap_or_else(|| "the root section".to_string())
                ),
            ));
        }
        entries.push(ParsedIniEntry {
            address: entry_address(section.as_deref(), key),
            section: section.clone(),
            key: key.to_string(),
            value: Zeroizing::new(line[separator + 1..].trim().to_string()),
        });
    }

    Ok(entries)
}

/// Render addressed values as deterministic INI. Root entries are emitted before sectioned
/// entries so composing multiple resources cannot accidentally place a root key in a section.
pub(crate) fn render_ini_refs<'a>(
    entries: impl IntoIterator<Item = (Option<&'a str>, &'a str, &'a str)>,
) -> SurfaceResult<Vec<u8>> {
    let entries = entries.into_iter().collect::<Vec<_>>();
    let mut identities = HashSet::new();
    for (section, key, value) in &entries {
        validate_render_entry(*section, key, value)?;
        if !identities.insert((*section, *key)) {
            return Err(SurfaceError::IniProjection {
                reason: format!(
                    "duplicate key {key:?} in {}",
                    section
                        .map(|name| format!("section {name:?}"))
                        .unwrap_or_else(|| "the root section".to_string())
                ),
            });
        }
    }

    let ordered = entries
        .iter()
        .copied()
        .filter(|(section, _, _)| section.is_none())
        .chain(entries.iter().copied().filter(|(section, _, _)| section.is_some()));
    let mut output = String::new();
    let mut active_section: Option<&str> = None;
    let mut emitted_section = false;
    for (section, key, value) in ordered {
        if let Some(section) = section {
            if active_section != Some(section) {
                if !output.is_empty() {
                    output.push('\n');
                }
                output.push('[');
                output.push_str(section);
                output.push_str("]\n");
                active_section = Some(section);
                emitted_section = true;
            }
        } else if emitted_section {
            unreachable!("root entries are canonicalized before sections");
        }
        output.push_str(key);
        output.push_str(" = ");
        output.push_str(value);
        output.push('\n');
        if output.len() > INI_MAX_SIZE {
            return Err(SurfaceError::TooLarge { limit: INI_MAX_SIZE });
        }
    }
    Ok(output.into_bytes())
}

fn validate_render_entry(section: Option<&str>, key: &str, value: &str) -> SurfaceResult<()> {
    if section.is_some_and(|name| {
        name.is_empty()
            || name.trim() != name
            || name.contains([']', '\n', '\r', '\0'])
    }) {
        return Err(SurfaceError::IniProjection {
            reason: format!("invalid section name {section:?}"),
        });
    }
    if key.is_empty()
        || key.trim() != key
        || key.contains(['=', ':', '\n', '\r', '\0'])
    {
        return Err(SurfaceError::IniProjection {
            reason: format!("invalid key {key:?}"),
        });
    }
    if value.contains(['\n', '\r', '\0']) {
        return Err(SurfaceError::IniProjection {
            reason: format!("key {key:?} has a multiline or NUL value"),
        });
    }
    Ok(())
}

fn entry_address(section: Option<&str>, key: &str) -> String {
    match section {
        Some(section) => format!(
            "sections/{}/keys/{}",
            escape_address_segment(section),
            escape_address_segment(key)
        ),
        None => format!("root/keys/{}", escape_address_segment(key)),
    }
}

fn escape_address_segment(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn parse_error(line: usize, reason: impl Into<String>) -> SurfaceError {
    SurfaceError::IniParse { line, reason: reason.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_order_and_allows_the_same_key_in_different_sections() {
        let entries = parse_ini(
            "region = fixture-global\n[fixture/one]\naccess_key = fixture-one\n[fixture-two]\naccess_key: fixture-two\n",
        )
        .unwrap();

        assert_eq!(
            entries.iter().map(|entry| entry.address.as_str()).collect::<Vec<_>>(),
            vec![
                "root/keys/region",
                "sections/fixture~1one/keys/access_key",
                "sections/fixture-two/keys/access_key",
            ]
        );
        assert_eq!(
            entries.iter().map(|entry| entry.section.as_deref()).collect::<Vec<_>>(),
            vec![None, Some("fixture/one"), Some("fixture-two")]
        );
    }

    #[test]
    fn rejects_duplicate_keys_with_an_actionable_line_number() {
        let error = parse_ini("[fixture]\nmode=one\nmode=two\n").unwrap_err();

        assert!(matches!(error, SurfaceError::IniParse { line: 3, .. }));
        assert!(error.to_string().contains("first declared on line 2"));
    }

    #[test]
    fn escapes_address_segments_without_changing_raw_keys() {
        let entries = parse_ini("[fixture~team]\nkey/name=fixture-value\n").unwrap();

        assert_eq!(entries[0].address, "sections/fixture~0team/keys/key~1name");
        assert_eq!(entries[0].key, "key/name");
    }

    #[test]
    fn renderer_canonicalizes_roots_then_preserves_section_order() {
        let rendered = render_ini_refs([
            (Some("fixture-one"), "mode", "one"),
            (None, "root", "fixture-root"),
            (Some("fixture-two"), "mode", "two"),
        ])
        .unwrap();

        assert_eq!(
            rendered,
            b"root = fixture-root\n\n[fixture-one]\nmode = one\n\n[fixture-two]\nmode = two\n"
        );
    }

    #[test]
    fn renderer_rejects_duplicate_section_keys() {
        let error = render_ini_refs([
            (Some("fixture"), "mode", "one"),
            (Some("fixture"), "mode", "two"),
        ])
        .unwrap_err();

        assert!(matches!(error, SurfaceError::IniProjection { .. }));
        assert!(error.to_string().contains("duplicate key"));
    }
}
