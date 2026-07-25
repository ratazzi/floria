use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::ops::Range;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::protocol::{SshConfigState, SshConfigStatus};
use crate::server::SshConfigManager;

const MANAGED_BEGIN: &str = "# >>> Floria SSH host routing >>>";
const MANAGED_END: &str = "# <<< Floria SSH host routing <<<";
const MAX_CONFIG_SIZE: u64 = 1 << 20;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Owns the one small, reversible mutation Floria may make to OpenSSH configuration. The
/// generated routing file remains separate; this manager only inserts or removes its marked
/// top-level `Include` block.
pub struct ManagedSshConfig {
    user_config: PathBuf,
    generated_config: PathBuf,
    mutation: Mutex<()>,
}

impl ManagedSshConfig {
    pub fn new(user_config: impl Into<PathBuf>, generated_config: impl Into<PathBuf>) -> Self {
        ManagedSshConfig {
            user_config: user_config.into(),
            generated_config: generated_config.into(),
            mutation: Mutex::new(()),
        }
    }

    pub fn status(&self) -> io::Result<SshConfigStatus> {
        self.validate_user_config_path()?;
        let config = self.read()?;
        self.inspect(config.as_ref())
    }

    pub fn install(&self) -> io::Result<SshConfigStatus> {
        let _guard = self.mutation.lock().expect("SSH config manager poisoned");
        let config = self.read()?;
        let status = self.inspect(config.as_ref())?;
        if status.state == SshConfigState::External {
            return Ok(status);
        }
        if !status.writable {
            return Err(invalid(
                "~/.ssh/config is a symbolic link or is not a regular file; copy the Include line into its source instead",
            ));
        }

        let mut existing = config.map(|config| config.content).unwrap_or_default();
        if let Some(range) = managed_range(&existing)? {
            if !managed_block_is_owned(&existing, &range, &status.include_line) {
                return Err(invalid(
                    "the Floria marker block contains unrecognized settings; edit it manually to avoid data loss",
                ));
            }
            existing.replace_range(range, "");
        }
        let block = self.managed_block()?;
        let content = if existing.is_empty() {
            block
        } else {
            format!("{block}\n{existing}")
        };
        self.write(&content, config_mode(&self.user_config)?)?;
        self.status()
    }

    pub fn remove(&self) -> io::Result<SshConfigStatus> {
        let _guard = self.mutation.lock().expect("SSH config manager poisoned");
        self.validate_user_config_path()?;
        let Some(config) = self.read()? else { return self.status() };
        let status = self.inspect(Some(&config))?;
        if !status.writable {
            return Err(invalid(
                "~/.ssh/config is a symbolic link or is not a regular file; remove the Include line from its source instead",
            ));
        }
        let Some(range) = managed_range(&config.content)? else { return Ok(status) };
        if !managed_block_is_owned(&config.content, &range, &status.include_line) {
            return Err(invalid(
                "the Floria marker block contains unrecognized settings; edit it manually to avoid data loss",
            ));
        }
        let mut content = config.content;
        content.replace_range(range, "");
        if content.starts_with('\n') {
            content.remove(0);
        }
        self.write(&content, config.mode)?;
        self.status()
    }

    fn inspect(&self, config: Option<&ConfigFile>) -> io::Result<SshConfigStatus> {
        let include_line = self.include_line()?;
        let (state, writable) = match config {
            None => (SshConfigState::Disabled, true),
            Some(config) => {
                let first_section = first_host_or_match(&config.content);
                let range = match managed_range(&config.content) {
                    Ok(range) => range,
                    Err(_) => {
                        return Ok(self.status_value(
                            SshConfigState::NeedsRepair,
                            false,
                            include_line,
                        ))
                    }
                };
                if range.as_ref().is_some_and(|range| {
                    !managed_block_is_owned(&config.content, range, &include_line)
                }) {
                    return Ok(self.status_value(
                        SshConfigState::NeedsRepair,
                        false,
                        include_line,
                    ));
                }
                let state = if range.as_ref().is_some_and(|range| range.start < first_section) {
                    SshConfigState::Managed
                } else if has_top_level_include(&config.content, &include_line, range.as_ref()) {
                    SshConfigState::External
                } else if range.is_some() {
                    SshConfigState::NeedsRepair
                } else {
                    SshConfigState::Disabled
                };
                (state, config.writable)
            }
        };
        Ok(self.status_value(state, writable, include_line))
    }

    fn status_value(
        &self,
        state: SshConfigState,
        writable: bool,
        include_line: String,
    ) -> SshConfigStatus {
        SshConfigStatus {
            state,
            writable,
            user_config: self.user_config.clone(),
            generated_config: self.generated_config.clone(),
            include_line,
        }
    }

    fn read(&self) -> io::Result<Option<ConfigFile>> {
        let metadata = match fs::symlink_metadata(&self.user_config) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let writable = metadata.file_type().is_file() && !metadata.file_type().is_symlink();
        if !metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
            return Err(invalid("~/.ssh/config is not a regular file"));
        }
        let target_metadata = fs::metadata(&self.user_config)?;
        if target_metadata.len() > MAX_CONFIG_SIZE {
            return Err(invalid("~/.ssh/config is larger than 1 MiB"));
        }
        let bytes = fs::read(&self.user_config)?;
        let content = String::from_utf8(bytes)
            .map_err(|_| invalid("~/.ssh/config is not valid UTF-8"))?;
        Ok(Some(ConfigFile {
            content,
            mode: target_metadata.mode() & 0o777,
            writable,
        }))
    }

    fn write(&self, content: &str, mode: u32) -> io::Result<()> {
        let parent = self
            .user_config
            .parent()
            .ok_or_else(|| invalid("~/.ssh/config has no parent directory"))?;
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }

        let mut temporary = None;
        for _ in 0..16 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".config.floria.{}.{sequence}.tmp", std::process::id()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&path)
            {
                Ok(file) => {
                    temporary = Some((path, file));
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let (temporary_path, mut file) = temporary
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "cannot allocate SSH config temporary file",
                )
            })?;
        let result = (|| {
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary_path, &self.user_config)?;
            fs::set_permissions(&self.user_config, fs::Permissions::from_mode(mode))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    fn include_line(&self) -> io::Result<String> {
        let path = self
            .generated_config
            .to_str()
            .ok_or_else(|| invalid("generated SSH config path is not valid UTF-8"))?;
        if path.chars().any(|character| character == '\n' || character == '\r') {
            return Err(invalid("generated SSH config path contains a line break"));
        }
        Ok(format!("Include {}", quote(path)))
    }

    fn validate_user_config_path(&self) -> io::Result<()> {
        let path = self
            .user_config
            .to_str()
            .ok_or_else(|| invalid("user SSH config path is not valid UTF-8"))?;
        if path.chars().any(|character| character == '\n' || character == '\r') {
            return Err(invalid("user SSH config path contains a line break"));
        }
        Ok(())
    }

    fn managed_block(&self) -> io::Result<String> {
        Ok(format!("{MANAGED_BEGIN}\n{}\n{MANAGED_END}\n", self.include_line()?))
    }
}

impl SshConfigManager for ManagedSshConfig {
    fn status(&self) -> io::Result<SshConfigStatus> {
        ManagedSshConfig::status(self)
    }

    fn install(&self) -> io::Result<SshConfigStatus> {
        ManagedSshConfig::install(self)
    }

    fn remove(&self) -> io::Result<SshConfigStatus> {
        ManagedSshConfig::remove(self)
    }
}

struct ConfigFile {
    content: String,
    mode: u32,
    writable: bool,
}

fn config_mode(path: &Path) -> io::Result<u32> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.mode() & 0o777),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0o600),
        Err(error) => Err(error),
    }
}

fn managed_range(content: &str) -> io::Result<Option<Range<usize>>> {
    let mut open = None;
    let mut found = None;
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        let end = offset + line.len();
        match line.trim() {
            MANAGED_BEGIN => {
                if open.is_some() || found.is_some() {
                    return Err(invalid("~/.ssh/config contains duplicate Floria markers"));
                }
                open = Some(offset);
            }
            MANAGED_END => {
                let start = open
                    .take()
                    .ok_or_else(|| invalid("~/.ssh/config contains an unmatched Floria marker"))?;
                found = Some(start..end);
            }
            _ => {}
        }
        offset = end;
    }
    if open.is_some() {
        return Err(invalid("~/.ssh/config contains an unmatched Floria marker"));
    }
    Ok(found)
}

fn first_host_or_match(content: &str) -> usize {
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        let directive = line.trim_start().split_ascii_whitespace().next().unwrap_or("");
        if directive.eq_ignore_ascii_case("host") || directive.eq_ignore_ascii_case("match") {
            return offset;
        }
        offset += line.len();
    }
    content.len()
}

fn managed_block_is_owned(content: &str, range: &Range<usize>, include_line: &str) -> bool {
    let lines = content[range.clone()]
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    lines == [MANAGED_BEGIN, include_line, MANAGED_END]
}

fn has_top_level_include(
    content: &str,
    include_line: &str,
    managed: Option<&Range<usize>>,
) -> bool {
    let first_section = first_host_or_match(content);
    let mut offset = 0;
    for line in content.split_inclusive('\n') {
        if offset >= first_section {
            return false;
        }
        let outside_managed = managed.is_none_or(|range| !range.contains(&offset));
        if outside_managed && same_include(line, include_line) {
            return true;
        }
        offset += line.len();
    }
    false
}

fn same_include(line: &str, include_line: &str) -> bool {
    let mut actual = line.trim().splitn(2, char::is_whitespace);
    let Some(expected_path) = include_line.strip_prefix("Include ") else { return false };
    actual.next().is_some_and(|directive| directive.eq_ignore_ascii_case("include"))
        && actual.next().map(str::trim_start) == Some(expected_path)
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_at_top_and_removes_only_the_managed_block() {
        let dir = tempfile::tempdir().unwrap();
        let ssh_dir = dir.path().join(".ssh");
        fs::create_dir(&ssh_dir).unwrap();
        let config = ssh_dir.join("config");
        fs::write(&config, "Host *\n    AddKeysToAgent yes\n").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o640)).unwrap();
        let generated = dir.path().join("Library/Application Support/floria/ssh/config");
        let manager = ManagedSshConfig::new(&config, &generated);

        let status = manager.install().unwrap();
        assert_eq!(status.state, SshConfigState::Managed);
        let installed = fs::read_to_string(&config).unwrap();
        assert!(installed.starts_with(MANAGED_BEGIN));
        assert!(installed.contains(&format!("Include \"{}\"", generated.display())));
        assert!(installed.ends_with("Host *\n    AddKeysToAgent yes\n"));
        assert_eq!(fs::metadata(&config).unwrap().mode() & 0o777, 0o640);

        let status = manager.remove().unwrap();
        assert_eq!(status.state, SshConfigState::Disabled);
        assert_eq!(fs::read_to_string(&config).unwrap(), "Host *\n    AddKeysToAgent yes\n");
    }

    #[test]
    fn recognizes_external_top_level_include_without_claiming_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        let generated = dir.path().join("generated config");
        fs::write(
            &config,
            format!("Include \"{}\"\nHost *\n    ForwardAgent no\n", generated.display()),
        )
        .unwrap();
        let manager = ManagedSshConfig::new(&config, &generated);

        let status = manager.install().unwrap();
        assert_eq!(status.state, SshConfigState::External);
        assert!(!fs::read_to_string(&config).unwrap().contains(MANAGED_BEGIN));
        assert_eq!(manager.remove().unwrap().state, SshConfigState::External);
    }

    #[test]
    fn repairs_a_managed_block_that_was_moved_inside_a_host_section() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        let generated = dir.path().join("generated");
        let manager = ManagedSshConfig::new(&config, &generated);
        fs::write(
            &config,
            format!(
                "Host fixture\n    User fixture\n\n{}",
                manager.managed_block().unwrap()
            ),
        )
        .unwrap();

        assert_eq!(manager.status().unwrap().state, SshConfigState::NeedsRepair);
        assert_eq!(manager.install().unwrap().state, SshConfigState::Managed);
        assert!(fs::read_to_string(&config).unwrap().starts_with(MANAGED_BEGIN));
    }

    #[test]
    fn refuses_to_rewrite_a_symlink_or_malformed_markers() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("dotfiles-ssh-config");
        fs::write(&target, "Host *\n").unwrap();
        let link = dir.path().join("config");
        symlink(&target, &link).unwrap();
        let manager = ManagedSshConfig::new(&link, dir.path().join("generated"));

        assert!(!manager.status().unwrap().writable);
        assert_eq!(manager.install().unwrap_err().kind(), io::ErrorKind::InvalidInput);

        let malformed = dir.path().join("malformed");
        fs::write(&malformed, format!("{MANAGED_BEGIN}\n")).unwrap();
        let manager = ManagedSshConfig::new(&malformed, dir.path().join("generated"));
        let status = manager.status().unwrap();
        assert_eq!(status.state, SshConfigState::NeedsRepair);
        assert!(!status.writable);
        assert_eq!(manager.install().unwrap_err().kind(), io::ErrorKind::InvalidInput);

        let modified = dir.path().join("modified");
        fs::write(
            &modified,
            format!("{MANAGED_BEGIN}\n    User fixture\n{MANAGED_END}\n"),
        )
        .unwrap();
        let manager = ManagedSshConfig::new(&modified, dir.path().join("generated"));
        let status = manager.status().unwrap();
        assert_eq!(status.state, SshConfigState::NeedsRepair);
        assert!(!status.writable);
        assert_eq!(manager.remove().unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(fs::read_to_string(modified).unwrap().contains("User fixture"));
    }
}
