use serde::{Deserialize, Serialize};

const MAX_NOTE_BYTES: usize = 4096;
const MAX_LINKS: usize = 16;
const MAX_LINK_LABEL_BYTES: usize = 100;
const MAX_LINK_URL_BYTES: usize = 2048;

/// Non-secret context that helps a person recognize and navigate to an item.
///
/// Metadata is deliberately separate from secret content. Callers may display and search it, but
/// must never expose it through generated surfaces or include it in access audit events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<ItemLink>,
}

impl ItemMetadata {
    pub fn is_empty(&self) -> bool {
        self.note.is_none() && self.links.is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(note) = &self.note {
            if note.trim().is_empty() {
                return Err("metadata note must be omitted instead of blank".to_string());
            }
            if note.len() > MAX_NOTE_BYTES {
                return Err(format!("metadata note cannot exceed {MAX_NOTE_BYTES} bytes"));
            }
            if note.contains('\0') {
                return Err("metadata note cannot contain NUL".to_string());
            }
        }

        if self.links.len() > MAX_LINKS {
            return Err(format!("metadata cannot contain more than {MAX_LINKS} links"));
        }
        for link in &self.links {
            link.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemLink {
    pub label: String,
    pub url: String,
}

impl ItemLink {
    fn validate(&self) -> Result<(), String> {
        if self.label.trim().is_empty() {
            return Err("metadata link label cannot be blank".to_string());
        }
        if self.label.len() > MAX_LINK_LABEL_BYTES {
            return Err(format!(
                "metadata link label cannot exceed {MAX_LINK_LABEL_BYTES} bytes"
            ));
        }
        if self.url.trim() != self.url || self.url.chars().any(char::is_whitespace) {
            return Err("metadata link URL cannot contain surrounding or embedded whitespace"
                .to_string());
        }
        if self.url.len() > MAX_LINK_URL_BYTES {
            return Err(format!(
                "metadata link URL cannot exceed {MAX_LINK_URL_BYTES} bytes"
            ));
        }
        let destination = self
            .url
            .strip_prefix("https://")
            .or_else(|| self.url.strip_prefix("http://"));
        let Some(destination) = destination else {
            return Err("metadata link URL must use http:// or https://".to_string());
        };
        let authority = destination.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.is_empty() || authority.contains('@') {
            return Err(
                "metadata link URL must include a host and cannot contain credentials".to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_metadata_is_valid() {
        let metadata = ItemMetadata::default();
        assert!(metadata.is_empty());
        assert_eq!(metadata.validate(), Ok(()));
    }

    #[test]
    fn validates_links_as_non_secret_web_destinations() {
        let valid = ItemMetadata {
            note: Some("Used by the staging deployment".to_string()),
            links: vec![ItemLink {
                label: "Dashboard".to_string(),
                url: "https://example.invalid/account/tokens".to_string(),
            }],
        };
        assert_eq!(valid.validate(), Ok(()));

        let invalid = ItemMetadata {
            note: None,
            links: vec![ItemLink {
                label: "Dashboard".to_string(),
                url: "file:///tmp/credential".to_string(),
            }],
        };
        assert_eq!(
            invalid.validate().unwrap_err(),
            "metadata link URL must use http:// or https://"
        );

        let embedded_credentials = ItemMetadata {
            note: None,
            links: vec![ItemLink {
                label: "Dashboard".to_string(),
                url: "https://fixture-user:fixture-password@example.invalid".to_string(),
            }],
        };
        assert_eq!(
            embedded_credentials.validate().unwrap_err(),
            "metadata link URL must include a host and cannot contain credentials"
        );
    }
}
