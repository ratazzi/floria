use crate::error::{SurfaceError, SurfaceResult};

pub const LINES_MAX_SIZE: usize = 1 << 20;

/// Render opaque values as one line each. Values are not parsed as a vendor format; the only
/// validation belongs to the line framing itself.
pub(crate) fn render_lines_refs<'a>(
    values: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> SurfaceResult<Vec<u8>> {
    let mut output = String::new();
    for (resource_id, value) in values {
        if value.chars().any(|ch| matches!(ch, '\n' | '\r' | '\0')) {
            return Err(SurfaceError::InvalidLineValue {
                resource_id: resource_id.to_string(),
                reason: "a line value cannot contain a line break or NUL".to_string(),
            });
        }
        output.push_str(value);
        output.push('\n');
        if output.len() > LINES_MAX_SIZE {
            return Err(SurfaceError::TooLarge { limit: LINES_MAX_SIZE });
        }
    }
    Ok(output.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_database_line(label: &str) -> String {
        [
            format!("db-{label}.fixture.invalid"),
            "5432".to_string(),
            "fixture-db".to_string(),
            "fixture-user".to_string(),
            format!("fixture-pass-{label}"),
        ]
        .join(":")
    }

    #[test]
    fn preserves_opaque_colon_delimited_values_and_order() {
        let first = fixture_database_line("one");
        let second = fixture_database_line("two");
        let rendered = render_lines_refs([
            ("fixture-first", first.as_str()),
            ("fixture-second", second.as_str()),
        ])
        .unwrap();

        assert_eq!(rendered, format!("{first}\n{second}\n").into_bytes());
    }

    #[test]
    fn rejects_values_that_would_create_extra_lines() {
        assert!(matches!(
            render_lines_refs([("fixture", "first\nsecond")]),
            Err(SurfaceError::InvalidLineValue { .. })
        ));
    }
}
