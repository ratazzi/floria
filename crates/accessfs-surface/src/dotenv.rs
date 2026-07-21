use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::error::{SurfaceError, SurfaceResult};

pub const DOTENV_MAX_SIZE: usize = 1 << 20;

/// Parse the deliberately small, deterministic dotenv subset accepted for EnvFile resources.
/// It supports blank/comment lines, optional `export`, unquoted values, and single/double quotes.
/// Multiline quoted values are rejected; renderers emit escaped newlines instead.
#[derive(Debug)]
pub struct ParsedDotenvEntry {
    pub key: String,
    pub value: Zeroizing<String>,
}

pub fn parse_dotenv(input: &str) -> SurfaceResult<Vec<ParsedDotenvEntry>> {
    let mut first_lines = HashMap::new();
    let mut values = Vec::new();
    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim_start();
        }
        let (key, raw_value) = line.split_once('=').ok_or_else(|| SurfaceError::DotenvParse {
            line: line_number,
            reason: "expected KEY=VALUE".to_string(),
        })?;
        let key = key.trim();
        if !valid_env_key(key) {
            return Err(SurfaceError::DotenvParse {
                line: line_number,
                reason: format!("invalid environment key {key:?}"),
            });
        }
        if let Some(first_line) = first_lines.insert(key.to_string(), line_number) {
            return Err(SurfaceError::DotenvParse {
                line: line_number,
                reason: format!(
                    "duplicate environment key {key:?} (first declared on line {first_line}); remove one declaration before importing"
                ),
            });
        }
        let value = Zeroizing::new(parse_value(raw_value.trim_start(), line_number)?);
        values.push(ParsedDotenvEntry { key: key.to_string(), value });
    }
    Ok(values)
}

fn parse_value(input: &str, line: usize) -> SurfaceResult<String> {
    if let Some(rest) = input.strip_prefix('"') {
        return parse_double_quoted(rest, line);
    }
    if let Some(rest) = input.strip_prefix('\'') {
        let Some(end) = rest.find('\'') else {
            return Err(SurfaceError::DotenvParse {
                line,
                reason: "unterminated single-quoted value".to_string(),
            });
        };
        ensure_quote_suffix(&rest[end + 1..], line)?;
        return Ok(rest[..end].to_string());
    }

    let mut end = input.len();
    let mut previous_whitespace = false;
    for (offset, ch) in input.char_indices() {
        if ch == '#' && previous_whitespace {
            end = offset;
            break;
        }
        previous_whitespace = ch.is_whitespace();
    }
    Ok(input[..end].trim_end().to_string())
}

fn parse_double_quoted(input: &str, line: usize) -> SurfaceResult<String> {
    let mut value = String::new();
    let mut chars = input.char_indices();
    while let Some((offset, ch)) = chars.next() {
        match ch {
            '"' => {
                ensure_quote_suffix(&input[offset + ch.len_utf8()..], line)?;
                return Ok(value);
            }
            '\\' => {
                let Some((_, escaped)) = chars.next() else {
                    return Err(SurfaceError::DotenvParse {
                        line,
                        reason: "trailing escape in double-quoted value".to_string(),
                    });
                };
                value.push(match escaped {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '\\' => '\\',
                    '"' => '"',
                    '$' => '$',
                    other => other,
                });
            }
            other => value.push(other),
        }
    }
    Err(SurfaceError::DotenvParse {
        line,
        reason: "unterminated double-quoted value".to_string(),
    })
}

fn ensure_quote_suffix(suffix: &str, line: usize) -> SurfaceResult<()> {
    let suffix = suffix.trim();
    if suffix.is_empty() || suffix.starts_with('#') {
        Ok(())
    } else {
        Err(SurfaceError::DotenvParse {
            line,
            reason: "unexpected characters after quoted value".to_string(),
        })
    }
}

/// Render an ordered key/value sequence as deterministic dotenv bytes.
pub fn render_dotenv(values: &[(String, String)]) -> SurfaceResult<Vec<u8>> {
    render_dotenv_refs(values.iter().map(|(key, value)| (key.as_str(), value.as_str())))
}

pub(crate) fn render_dotenv_refs<'a>(
    values: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> SurfaceResult<Vec<u8>> {
    let mut output = String::new();
    for (key, value) in values {
        if !valid_env_key(key) {
            return Err(SurfaceError::DotenvParse {
                line: 0,
                reason: format!("invalid environment key {key:?}"),
            });
        }
        output.push_str(key);
        output.push('=');
        push_value(&mut output, value);
        output.push('\n');
        if output.len() > DOTENV_MAX_SIZE {
            return Err(SurfaceError::TooLarge { limit: DOTENV_MAX_SIZE });
        }
    }
    Ok(output.into_bytes())
}

fn push_value(output: &mut String, value: &str) {
    if !value.is_empty() && value.chars().all(is_safe_unquoted) {
        output.push_str(value);
        return;
    }
    output.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '$' => output.push_str("\\$"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            other => output.push(other),
        }
    }
    output.push('"');
}

fn valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else { return false };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_safe_unquoted(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '/' | ':' | '@' | '%' | '+' | ',' | '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_dotenv_without_vendor_secret_shapes() {
        let values = parse_dotenv(
            "# fixture only\nexport API_HOST=http://127.0.0.1:8787\nMODE='local dev'\nNOTE=hello # comment\nESCAPED=\"line\\nfixture\"\n",
        )
        .unwrap();
        assert_eq!(
            values.iter().map(|entry| entry.key.as_str()).collect::<Vec<_>>(),
            vec!["API_HOST", "MODE", "NOTE", "ESCAPED"]
        );
        assert_eq!(values[0].value.as_str(), "http://127.0.0.1:8787");
        assert_eq!(values[1].value.as_str(), "local dev");
        assert_eq!(values[2].value.as_str(), "hello");
        assert_eq!(values[3].value.as_str(), "line\nfixture");
    }

    #[test]
    fn duplicate_key_is_rejected() {
        let error = parse_dotenv("FIXTURE=one\nFIXTURE=two\n").unwrap_err();
        assert!(matches!(error, SurfaceError::DotenvParse { line: 2, .. }));
        assert!(error.to_string().contains("remove one declaration before importing"));
    }

    #[test]
    fn renderer_is_stable_and_quotes_unsafe_values() {
        let rendered = render_dotenv(&[
            ("API_HOST".to_string(), "http://127.0.0.1:8787".to_string()),
            ("EMPTY".to_string(), String::new()),
            ("MESSAGE".to_string(), "fixture value\nnext".to_string()),
            ("REFERENCE".to_string(), "$FIXTURE".to_string()),
        ])
        .unwrap();
        assert_eq!(
            String::from_utf8(rendered).unwrap(),
            "API_HOST=http://127.0.0.1:8787\nEMPTY=\"\"\nMESSAGE=\"fixture value\\nnext\"\nREFERENCE=\"\\$FIXTURE\"\n"
        );
    }
}
