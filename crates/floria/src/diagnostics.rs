use std::collections::BTreeSet;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use floria_catalog::{Catalog, CatalogSnapshot};
use floria_control::{
    DiagnosticsReport, RuntimeDiagnosticsExporter, RuntimeHealthReporter, CONTROL_PROTOCOL_VERSION,
};
use serde_json::{json, Value};

const FORMAT_VERSION: u32 = 1;
const MAX_LOG_BYTES: u64 = 512 * 1024;
const MAX_LOG_LINES: usize = 400;

pub(crate) struct RuntimeDiagnostics {
    catalog: Catalog,
    health: Arc<dyn RuntimeHealthReporter>,
    support_dir: PathBuf,
    mount_path: PathBuf,
}

impl RuntimeDiagnostics {
    pub(crate) fn new(
        catalog: Catalog,
        health: Arc<dyn RuntimeHealthReporter>,
        support_dir: PathBuf,
        mount_path: PathBuf,
    ) -> Self {
        RuntimeDiagnostics {
            catalog,
            health,
            support_dir,
            mount_path,
        }
    }

    fn export_bundle(
        &self,
        destination: &Path,
        include_paths: bool,
    ) -> Result<DiagnosticsReport, String> {
        validate_destination(destination)?;
        let temporary = temporary_path(destination)?;
        let mut cleanup = CleanupDirectory::new(temporary.clone());

        create_private_directory(&temporary)
            .map_err(|error| io_error("create diagnostics workspace", error))?;

        let snapshot = self.catalog.snapshot().ok();
        let known_paths = known_paths(snapshot.as_ref(), &self.support_dir, &self.mount_path);
        write_json(
            &temporary.join("health.json"),
            &serde_json::to_value(self.health.report())
                .map_err(|error| format!("encode health report: {error}"))?,
        )?;
        write_json(
            &temporary.join("inventory.json"),
            &inventory(
                snapshot.as_ref(),
                include_paths,
                &self.support_dir,
                &self.mount_path,
            ),
        )?;

        let log_directory = temporary.join("logs");
        let source_logs = self.support_dir.join("logs");
        for name in ["daemon.stdout.log", "daemon.stderr.log"] {
            let Some(log) = read_log_summary(&source_logs.join(name), &known_paths, include_paths)?
            else {
                continue;
            };
            if !log_directory.exists() {
                create_private_directory(&log_directory)
                    .map_err(|error| io_error("create diagnostics log directory", error))?;
            }
            write_private(&log_directory.join(name), log.as_bytes())?;
        }

        write_private(
            &temporary.join("README.txt"),
            readme(include_paths).as_bytes(),
        )?;
        let files_before_manifest = inventory_files(&temporary)?;
        let manifest = json!({
            "format_version": FORMAT_VERSION,
            "generated_unix_seconds": now_unix_seconds(),
            "floria_version": env!("CARGO_PKG_VERSION"),
            "control_protocol_version": CONTROL_PROTOCOL_VERSION,
            "catalog_schema_version": self.catalog.schema_version(),
            "store_format_version": floria_store::STORE_FORMAT_VERSION,
            "platform": std::env::consts::OS,
            "architecture": std::env::consts::ARCH,
            "paths_included": include_paths,
            "contents": files_before_manifest,
        });
        write_json(&temporary.join("manifest.json"), &manifest)?;

        let (files, bytes) = bundle_size(&temporary)?;
        std::fs::rename(&temporary, destination)
            .map_err(|error| io_error("publish diagnostics bundle", error))?;
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error("secure diagnostics bundle", error))?;
        cleanup.disarm();

        Ok(DiagnosticsReport {
            path: destination.to_path_buf(),
            paths_included: include_paths,
            files,
            bytes,
        })
    }
}

impl RuntimeDiagnosticsExporter for RuntimeDiagnostics {
    fn export(&self, destination: &Path, include_paths: bool) -> Result<DiagnosticsReport, String> {
        self.export_bundle(destination, include_paths)
    }
}

fn validate_destination(destination: &Path) -> Result<(), String> {
    if !destination.is_absolute() {
        return Err("diagnostics destination must be absolute".to_string());
    }
    if destination.exists() {
        return Err("diagnostics destination already exists".to_string());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "diagnostics destination has no parent directory".to_string())?;
    if !parent.is_dir() {
        return Err("diagnostics destination parent does not exist".to_string());
    }
    Ok(())
}

fn temporary_path(destination: &Path) -> Result<PathBuf, String> {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "diagnostics destination must have a UTF-8 name".to_string())?;
    Ok(destination.with_file_name(format!(
        ".{name}.partial-{}-{}",
        std::process::id(),
        now_unix_nanos()
    )))
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let mut body =
        serde_json::to_vec_pretty(value).map_err(|error| format!("encode diagnostics: {error}"))?;
    body.push(b'\n');
    write_private(path, &body)
}

fn write_private(path: &Path, body: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| io_error("create diagnostics file", error))?;
    file.write_all(body)
        .map_err(|error| io_error("write diagnostics file", error))?;
    file.sync_all()
        .map_err(|error| io_error("sync diagnostics file", error))
}

fn inventory(
    snapshot: Option<&CatalogSnapshot>,
    include_paths: bool,
    support_dir: &Path,
    mount_path: &Path,
) -> Value {
    let counts = snapshot.map(|snapshot| {
        json!({
            "projects": snapshot.projects.len(),
            "checkouts": snapshot.checkouts.len(),
            "environments": snapshot.environments.len(),
            "resources": snapshot.resources.len(),
            "bindings": snapshot.bindings.len(),
            "surfaces": snapshot.surfaces.len(),
        })
    });
    let locations = include_paths.then(|| {
        let mut paths = known_paths(snapshot, support_dir, mount_path);
        paths.sort();
        paths.dedup();
        paths
    });
    json!({
        "catalog_readable": snapshot.is_some(),
        "counts": counts,
        "locations": locations,
    })
}

fn known_paths(
    snapshot: Option<&CatalogSnapshot>,
    support_dir: &Path,
    mount_path: &Path,
) -> Vec<String> {
    let mut paths = BTreeSet::new();
    add_path(&mut paths, support_dir);
    add_path(&mut paths, mount_path);
    if let Ok(home) = std::env::var("HOME") {
        add_path(&mut paths, Path::new(&home));
    }
    if let Some(snapshot) = snapshot {
        for project in &snapshot.projects {
            add_path(&mut paths, &project.path);
        }
        for checkout in &snapshot.checkouts {
            add_path(&mut paths, &checkout.path);
            if let Some(path) = &checkout.git_common_dir {
                add_path(&mut paths, path);
            }
        }
        for path in snapshot.endpoints.values() {
            add_path(&mut paths, path);
        }
        for surface in &snapshot.surfaces {
            add_path(&mut paths, &surface.path);
        }
        for resource in &snapshot.resources {
            for source in &resource.origin.sources {
                add_path(&mut paths, &source.path);
            }
        }
    }
    let mut paths = paths.into_iter().collect::<Vec<_>>();
    paths.sort_by_key(|path| std::cmp::Reverse(path.len()));
    paths
}

fn add_path(paths: &mut BTreeSet<String>, path: &Path) {
    if path.is_absolute() && path != Path::new("/") {
        paths.insert(path.to_string_lossy().into_owned());
    }
}

fn read_log_summary(
    path: &Path,
    known_paths: &[String],
    include_paths: bool,
) -> Result<Option<String>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("inspect daemon log", error)),
    };
    let mut file = File::open(path).map_err(|error| io_error("open daemon log", error))?;
    let start = metadata.len().saturating_sub(MAX_LOG_BYTES);
    file.seek(SeekFrom::Start(start))
        .map_err(|error| io_error("seek daemon log", error))?;
    let mut body = String::new();
    file.read_to_string(&mut body)
        .map_err(|error| io_error("read daemon log", error))?;
    if start > 0 {
        if let Some(newline) = body.find('\n') {
            body.drain(..=newline);
        }
    }

    let mut lines = Vec::<LogSummary>::new();
    for line in body.lines().filter_map(summarize_log_line) {
        let key = log_event_key(&line);
        if let Some(previous) = lines.last_mut().filter(|previous| previous.key == key) {
            previous.latest = line;
            previous.count += 1;
        } else {
            lines.push(LogSummary {
                latest: line,
                key,
                count: 1,
            });
        }
    }
    if lines.len() > MAX_LOG_LINES {
        lines.drain(..lines.len() - MAX_LOG_LINES);
    }
    if !include_paths {
        for line in &mut lines {
            line.latest = redact_paths(&line.latest, known_paths);
        }
    }
    if lines.is_empty() {
        Ok(None)
    } else {
        Ok(Some(format!(
            "{}\n",
            lines
                .into_iter()
                .map(|line| {
                    if line.count == 1 {
                        line.latest
                    } else {
                        format!("{} [repeated {} times]", line.latest, line.count)
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        )))
    }
}

struct LogSummary {
    latest: String,
    key: String,
    count: usize,
}

fn log_event_key(line: &str) -> String {
    [" WARN ", " ERROR ", "panicked at", "SIG"]
        .iter()
        .filter_map(|marker| line.find(marker))
        .min()
        .map(|index| line[index..].to_string())
        .unwrap_or_else(|| line.to_string())
}

fn summarize_log_line(line: &str) -> Option<String> {
    let line = strip_ansi(line);
    if !line.contains(" WARN ")
        && !line.contains(" ERROR ")
        && !line.contains("panicked at")
        && !line.contains("SIG")
    {
        return None;
    }
    let field_markers = [
        " path=",
        " error=",
        " socket=",
        " mount=",
        " surface=",
        " executable=",
        " bundle_id=",
        " team_id=",
        " pid=",
        " source=",
        " destination=",
        " backup=",
        " cwd=",
        " endpoint=",
        " uid=",
        " fh=",
        " rule=",
        " size=",
    ];
    let end = field_markers
        .iter()
        .filter_map(|marker| line.find(marker))
        .min()
        .unwrap_or(line.len());
    Some(line[..end].trim_end().to_string())
}

fn redact_paths(line: &str, known_paths: &[String]) -> String {
    let mut redacted = line.to_string();
    for (index, path) in known_paths.iter().enumerate() {
        redacted = redacted.replace(path, &format!("<path:{}>", index + 1));
    }
    redact_unknown_absolute_paths(&redacted)
}

fn redact_unknown_absolute_paths(text: &str) -> String {
    let chars = text.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        let boundary = index == 0
            || chars[index - 1].is_whitespace()
            || matches!(chars[index - 1], '=' | '(' | '[' | '{' | '"' | '\'');
        if chars[index] == '/' && boundary {
            output.push_str("<path>");
            index += 1;
            while index < chars.len()
                && !chars[index].is_whitespace()
                && !matches!(chars[index], ')' | ']' | '}' | '"' | '\'' | ',')
            {
                index += 1;
            }
        } else {
            output.push(chars[index]);
            index += 1;
        }
    }
    output
}

fn strip_ansi(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == 0x1b && bytes.get(index + 1) == Some(&b'[') {
            index += 2;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if (0x40..=0x7e).contains(&byte) {
                    break;
                }
            }
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn readme(include_paths: bool) -> String {
    let path_note = if include_paths {
        "File-system locations were included because the user explicitly requested them."
    } else {
        "File-system locations were omitted or replaced with redacted placeholders."
    };
    format!(
        "Floria Diagnostics\n\n\
         This bundle contains health results, aggregate inventory counts, and bounded warning/error \
         summaries. It never contains the encrypted store, catalog database, configuration file, \
         audit history, private keys, or decrypted secret values.\n\n{path_note}\n"
    )
}

fn inventory_files(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files(root: &Path, directory: &Path, files: &mut Vec<String>) -> Result<(), String> {
    for entry in std::fs::read_dir(directory)
        .map_err(|error| io_error("read diagnostics directory", error))?
    {
        let entry = entry.map_err(|error| io_error("read diagnostics entry", error))?;
        let file_type = entry
            .file_type()
            .map_err(|error| io_error("inspect diagnostics entry", error))?;
        if file_type.is_dir() {
            collect_files(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| "diagnostics entry escaped its bundle".to_string())?
                .to_string_lossy()
                .into_owned();
            files.push(relative);
        } else {
            return Err("diagnostics bundle contains an unsupported entry".to_string());
        }
    }
    Ok(())
}

fn bundle_size(root: &Path) -> Result<(usize, u64), String> {
    let files = inventory_files(root)?;
    let mut bytes = 0u64;
    for relative in &files {
        bytes = bytes.saturating_add(
            std::fs::metadata(root.join(relative))
                .map_err(|error| io_error("inspect diagnostics file", error))?
                .len(),
        );
    }
    Ok((files.len(), bytes))
}

fn io_error(action: &str, error: io::Error) -> String {
    format!("{action}: {error}")
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

struct CleanupDirectory {
    path: PathBuf,
    armed: bool,
}

impl CleanupDirectory {
    fn new(path: PathBuf) -> Self {
        CleanupDirectory { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CleanupDirectory {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use floria_control::{HealthCheck, HealthReport, HealthStatus};

    struct Healthy;

    impl RuntimeHealthReporter for Healthy {
        fn report(&self) -> HealthReport {
            HealthReport::new(vec![HealthCheck {
                id: "catalog".to_string(),
                status: HealthStatus::Healthy,
                title: "Library".to_string(),
                message: "Ready".to_string(),
                guidance: None,
            }])
        }
    }

    #[test]
    fn default_bundle_excludes_private_data_and_redacts_paths() {
        let directory = tempfile::tempdir().unwrap();
        let support = directory.path().join("Library/Application Support/floria");
        std::fs::create_dir_all(support.join("logs")).unwrap();
        std::fs::write(
            support.join("logs/daemon.stderr.log"),
            "2026-01-01 WARN floria: link failed path=/Users/alice/work/private/.env error=nope\n",
        )
        .unwrap();
        let catalog = Catalog::open(support.join("catalog.sqlite")).unwrap();
        let diagnostics = RuntimeDiagnostics::new(
            catalog,
            Arc::new(Healthy),
            support,
            PathBuf::from("/Users/alice/.floria"),
        );
        let destination = directory.path().join("Floria Diagnostics");

        let report = diagnostics.export_bundle(&destination, false).unwrap();

        assert!(!report.paths_included);
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let all = inventory_files(&destination)
            .unwrap()
            .into_iter()
            .map(|path| std::fs::read_to_string(destination.join(path)).unwrap())
            .collect::<String>();
        assert!(!all.contains("/Users/alice"));
        assert!(!all.contains("catalog.sqlite"));
        assert!(!all.contains("super-secret-value"));
        assert!(all.contains("\"paths_included\": false"));
    }

    #[test]
    fn include_paths_is_explicit_and_destination_is_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let support = directory.path().join("support");
        std::fs::create_dir_all(&support).unwrap();
        let catalog = Catalog::open(support.join("catalog.sqlite")).unwrap();
        let diagnostics = RuntimeDiagnostics::new(
            catalog,
            Arc::new(Healthy),
            support.clone(),
            PathBuf::from("/Users/alice/.floria"),
        );
        let destination = directory.path().join("diagnostics");

        diagnostics.export_bundle(&destination, true).unwrap();
        let inventory = std::fs::read_to_string(destination.join("inventory.json")).unwrap();
        assert!(inventory.contains(support.to_string_lossy().as_ref()));
        assert!(diagnostics.export_bundle(&destination, true).is_err());
    }

    #[test]
    fn log_summary_keeps_the_event_but_drops_structured_fields() {
        let line = "2026 WARN floria: mount failed path=/private/data error=denied";
        assert_eq!(
            summarize_log_line(line).as_deref(),
            Some("2026 WARN floria: mount failed")
        );
        assert_eq!(
            redact_unknown_absolute_paths("failed at /Users/alice/project"),
            "failed at <path>"
        );

        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("daemon.stderr.log");
        std::fs::write(
            &log,
            "2026-01-01 WARN floria: link failed path=/one\n\
             2026-01-02 WARN floria: link failed path=/two\n",
        )
        .unwrap();
        let summary = read_log_summary(&log, &[], false).unwrap().unwrap();
        assert!(summary.contains("[repeated 2 times]"));
        assert!(!summary.contains("/one"));
        assert!(!summary.contains("/two"));
    }
}
