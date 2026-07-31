use super::*;

/// Creation-time Security Level recommendations.
///
/// This module deliberately returns only an initial level. Callers must never use it to rewrite an
/// existing Managed Item: once a level is persisted, it belongs to the user.
pub(super) struct SecurityDefaults;

impl SecurityDefaults {
    pub(super) fn managed_file(path: &Path) -> Enforcement {
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let parent_name = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        if file_name == ".pgpass"
            || (parent_name == ".aws" && file_name == "credentials")
            || (parent_name == ".kube" && file_name == "config")
            || matches!(
                path.extension()
                    .and_then(|value| value.to_str())
                    .map(|value| value.to_ascii_lowercase())
                    .as_deref(),
                Some("key" | "p12" | "pfx" | "jks" | "keystore")
            )
        {
            Enforcement::Prompt
        } else {
            Enforcement::Allow
        }
    }

    pub(super) fn discovered_file(
        kind: DiscoveredFileKind,
        path: &Path,
    ) -> Enforcement {
        let semantic = match kind {
            DiscoveredFileKind::SshPrivateKey => Enforcement::TouchId,
            DiscoveredFileKind::AwsCredentials
            | DiscoveredFileKind::Pgpass
            | DiscoveredFileKind::PrivateKey => Enforcement::Prompt,
            DiscoveredFileKind::Dotenv
            | DiscoveredFileKind::Direnv
            | DiscoveredFileKind::Mise
            | DiscoveredFileKind::Certificate
            | DiscoveredFileKind::PublicKey
            | DiscoveredFileKind::ProtectedFile => Enforcement::Allow,
        };
        Self::strictest([semantic, Self::managed_file(path)])
    }

    pub(super) fn discovered_resource(kind: DiscoveredFileKind) -> Enforcement {
        match kind {
            DiscoveredFileKind::SshPrivateKey => Enforcement::TouchId,
            DiscoveredFileKind::AwsCredentials
            | DiscoveredFileKind::Pgpass
            | DiscoveredFileKind::PrivateKey => Enforcement::Prompt,
            DiscoveredFileKind::Dotenv
            | DiscoveredFileKind::Direnv
            | DiscoveredFileKind::Mise
            | DiscoveredFileKind::Certificate
            | DiscoveredFileKind::PublicKey
            | DiscoveredFileKind::ProtectedFile => Enforcement::Allow,
        }
    }

    pub(super) fn composed_surface(
        members: impl IntoIterator<Item = Enforcement>,
    ) -> Enforcement {
        Self::strictest(members)
    }

    fn strictest(levels: impl IntoIterator<Item = Enforcement>) -> Enforcement {
        levels
            .into_iter()
            .max_by_key(|level| match level {
                Enforcement::Allow => 0,
                Enforcement::Prompt => 1,
                Enforcement::TouchId => 2,
                Enforcement::Deny => 3,
            })
            .unwrap_or(Enforcement::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routine_files_start_in_audit_only() {
        assert_eq!(
            SecurityDefaults::managed_file(Path::new("/workspace/project/.envrc")),
            Enforcement::Allow
        );
        assert_eq!(
            SecurityDefaults::managed_file(Path::new("/workspace/project/certificate.pem")),
            Enforcement::Allow
        );
    }

    #[test]
    fn known_credential_files_start_with_confirmation() {
        for path in [
            "/Users/example/.pgpass",
            "/Users/example/.aws/credentials",
            "/Users/example/.kube/config",
            "/workspace/project/config/credentials/production.key",
            "/workspace/project/certificate.p12",
        ] {
            assert_eq!(
                SecurityDefaults::managed_file(Path::new(path)),
                Enforcement::Prompt,
                "{path}"
            );
        }
    }

    #[test]
    fn discovered_ssh_identity_starts_with_touch_id() {
        assert_eq!(
            SecurityDefaults::discovered_resource(DiscoveredFileKind::SshPrivateKey),
            Enforcement::TouchId
        );
        assert_eq!(
            SecurityDefaults::discovered_file(
                DiscoveredFileKind::SshPrivateKey,
                Path::new("/Users/example/.ssh/deploy")
            ),
            Enforcement::TouchId
        );
    }

    #[test]
    fn composed_surface_uses_its_strictest_member() {
        assert_eq!(
            SecurityDefaults::composed_surface([
                Enforcement::Allow,
                Enforcement::TouchId,
                Enforcement::Prompt,
            ]),
            Enforcement::TouchId
        );
        assert_eq!(
            SecurityDefaults::composed_surface(std::iter::empty()),
            Enforcement::Allow
        );
    }
}
