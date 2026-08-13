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

        if Self::production_environment([file_name.as_str()])
            || file_name == ".pgpass"
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
        environment: Option<&str>,
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
        Self::strictest([
            semantic,
            Self::managed_file(path),
            Self::environment(environment),
        ])
    }

    pub(super) fn discovered_resource(
        kind: DiscoveredFileKind,
        environment: Option<&str>,
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
        Self::strictest([semantic, Self::environment(environment)])
    }

    pub(super) fn composed_surface(
        members: impl IntoIterator<Item = Enforcement>,
        environment: Option<&str>,
    ) -> Enforcement {
        Self::strictest(
            members
                .into_iter()
                .chain(std::iter::once(Self::environment(environment))),
        )
    }

    fn environment(environment: Option<&str>) -> Enforcement {
        if Self::production_environment(environment) {
            Enforcement::Prompt
        } else {
            Enforcement::Allow
        }
    }

    fn production_environment<'a>(parts: impl IntoIterator<Item = &'a str>) -> bool {
        parts.into_iter().any(|part| {
            part.split(|character: char| !character.is_ascii_alphanumeric())
                .any(|word| {
                    word.eq_ignore_ascii_case("production")
                        || word.eq_ignore_ascii_case("prod")
                })
        })
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
    fn discovered_production_files_start_with_confirmation() {
        assert_eq!(
            SecurityDefaults::discovered_file(
                DiscoveredFileKind::Dotenv,
                Path::new("/workspace/project/.env.production"),
                Some("production"),
            ),
            Enforcement::Prompt
        );
        assert_eq!(
            SecurityDefaults::discovered_resource(
                DiscoveredFileKind::Dotenv,
                Some("Production")
            ),
            Enforcement::Prompt
        );
        assert_eq!(
            SecurityDefaults::discovered_resource(
                DiscoveredFileKind::Dotenv,
                Some("development")
            ),
            Enforcement::Allow
        );
    }

    #[test]
    fn discovered_ssh_identity_starts_with_touch_id() {
        assert_eq!(
            SecurityDefaults::discovered_resource(
                DiscoveredFileKind::SshPrivateKey,
                None
            ),
            Enforcement::TouchId
        );
        assert_eq!(
            SecurityDefaults::discovered_file(
                DiscoveredFileKind::SshPrivateKey,
                Path::new("/Users/example/.ssh/deploy"),
                None,
            ),
            Enforcement::TouchId
        );
    }

    #[test]
    fn composed_surface_uses_its_strictest_member() {
        assert_eq!(
            SecurityDefaults::composed_surface(
                [Enforcement::Allow, Enforcement::TouchId, Enforcement::Prompt],
                None,
            ),
            Enforcement::TouchId
        );
        assert_eq!(
            SecurityDefaults::composed_surface(std::iter::empty(), None),
            Enforcement::Allow
        );
        assert_eq!(
            SecurityDefaults::composed_surface([Enforcement::Allow], Some("production")),
            Enforcement::Prompt
        );
    }
}
