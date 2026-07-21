use crate::dotenv::valid_env_key;
use crate::error::{SurfaceError, SurfaceResult};

pub const DIRENV_MAX_SIZE: usize = 1 << 20;

/// Render values as inert shell assignments for direnv. Resources never contribute shell code;
/// every value is single-quoted and embedded quotes use the POSIX `'\''` sequence.
pub(crate) fn render_direnv_refs<'a>(
    values: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> SurfaceResult<Vec<u8>> {
    let mut output = String::new();
    for (key, value) in values {
        if !valid_env_key(key) {
            return Err(SurfaceError::DirenvProjection {
                reason: format!("invalid environment key {key:?}"),
            });
        }
        if value.contains('\0') {
            return Err(SurfaceError::DirenvProjection {
                reason: format!("key {key:?} contains a NUL value"),
            });
        }
        output.push_str("export ");
        output.push_str(key);
        output.push_str("='");
        let mut fragments = value.split('\'');
        if let Some(first) = fragments.next() {
            output.push_str(first);
        }
        for fragment in fragments {
            output.push_str("'\\''");
            output.push_str(fragment);
        }
        output.push_str("'\n");
        if output.len() > DIRENV_MAX_SIZE {
            return Err(SurfaceError::TooLarge { limit: DIRENV_MAX_SIZE });
        }
    }
    Ok(output.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_shell_metacharacters_and_embedded_quotes_as_data() {
        let rendered = render_direnv_refs([
            ("PLAIN", "fixture-value"),
            ("QUOTED", "fixture's value"),
            ("COMMAND", "$(printf fixture-command); `printf fixture-backtick`"),
            ("MULTILINE", "fixture-one\nfixture-two"),
        ])
        .unwrap();

        assert_eq!(
            std::str::from_utf8(&rendered).unwrap(),
            "export PLAIN='fixture-value'\nexport QUOTED='fixture'\\''s value'\nexport COMMAND='$(printf fixture-command); `printf fixture-backtick`'\nexport MULTILINE='fixture-one\nfixture-two'\n"
        );
    }

    #[test]
    fn rejects_nul_values() {
        let error = render_direnv_refs([("FIXTURE", "fixture\0value")]).unwrap_err();

        assert!(matches!(error, SurfaceError::DirenvProjection { .. }));
    }
}
