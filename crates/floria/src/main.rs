use std::ffi::{CStr, CString, OsString};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};

use floria_catalog::{
    Catalog, CatalogSnapshot, ResourceKind, ResourceSource, Surface,
};
use floria_agent::{ManagedObject, ManagedPolicyItem};
use floria_control::{
    ActiveGrant as ControlActiveGrant, BackupReport as ControlBackupReport, BackupService,
    CatalogObserver, ControlClient, ControlCommand, ControlResult, ControlRuntimeServices,
    ControlServer, ManagedSshConfig, ProtectedFile, RuntimeDiagnosticsExporter,
    RecoveryKeyExporter, RuntimeHealthReporter, RuntimePolicyController, SshConfigManager,
    ReplicationDevice as ControlReplicationDevice,
    ReplicationEnrollment as ControlReplicationEnrollment, ReplicationMode, ReplicationStatus,
    RuntimeReplicationService, SshIdentity, SshIdentityDiscovery,
};
use floria_core::audit::{AuditAuthority, AuditCheckpoint, AuditLog};
use floria_core::authz::{Authorizer, PolicyMode, PolicyModeStatus};
use floria_core::config::{Config, ResolvedConfig, StoreKeySource};
use floria_discover::{GitCheckoutMonitor, MonitoredGitProject};
use floria_platform::{CodeSignedPeerVerifier, PeerAccess, SocketPeerVerifier};
use floria_replication::{
    DeviceEnrollment, ReplicationEngine, ReplicationError, ReplicationReport,
    ReplicationRuntime,
};
use floria_store::{
    AgeDirStore, KeychainKeyProvider, SecretId, SecretRecord, SecretStore, SshKeyProvider,
};
use floria_surface::{
    ensure_file_surface_link_in_snapshot, file_surface_instances, protected_checkout_links,
    refresh_protected_checkout_links, release_protected_links_for_file_surfaces,
    remove_file_surface_link, ManagedMutationObserver, ProtectedCheckoutLink,
    SurfaceLinkRemoval, SurfaceLinkState, SurfaceRegistry,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

mod diagnostics;
mod health;
mod recovery;

use diagnostics::RuntimeDiagnostics;
use health::RuntimeHealth;
use recovery::RuntimeRecoveryKeyExporter;

const RUNTIME_CONFIG_RELATIVE_PATH: &str =
    "Library/Application Support/floria/floria.toml";

fn default_config_path() -> PathBuf {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .map(|home| home.join(RUNTIME_CONFIG_RELATIVE_PATH))
        .unwrap_or_else(|| PathBuf::from("floria.toml"))
}

/// Floria: a userspace filesystem that exposes dynamic content as plain local files (macOS/macFUSE).
#[derive(Parser)]
#[command(name = "floria", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Mount in the foreground (blocks until unmounted).
    Mount {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Unmount the given mount point.
    Unmount {
        /// Mount point path; defaults to the value from config.
        path: Option<PathBuf>,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Self-check: macFUSE readiness, mount point, config, and content-source permissions.
    Doctor {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Protect a regular file in place through the running Floria daemon.
    Protect {
        /// File to protect.
        path: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Restore a protected file as plaintext and delete its encrypted history.
    Unprotect {
        /// Original path of the protected file, or its id.
        target: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Decrypt a protected secret to stdout (or a file with --to). Accepts a source path or an id.
    Reveal {
        /// Original path of the protected file, or its store id.
        target: String,
        /// Reveal a specific version instead of the current head.
        #[arg(long)]
        version: Option<u32>,
        /// Write the plaintext here instead of stdout (restores the original mode).
        #[arg(long)]
        to: Option<PathBuf>,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Show the version history of a protected secret.
    History {
        /// Original path of the protected file, or its store id.
        target: String,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Roll back a protected secret's head to an earlier version (repoints; nothing is deleted).
    Rollback {
        /// Original path of the protected file, or its store id.
        target: String,
        /// Version to make current.
        version: u32,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// List protected secrets.
    List {
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Query the daemon's catalog control plane.
    Control {
        #[command(subcommand)]
        command: ControlCmd,
        /// Override the derived control socket path.
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Create, join, or synchronize a portable Floria replication package.
    Sync {
        #[command(subcommand)]
        command: SyncCmd,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Create or verify an encrypted backup of all Floria-managed data.
    Backup {
        #[command(subcommand)]
        command: BackupCmd,
    },
    /// Export a bounded support bundle without secret plaintext or encrypted data.
    Diagnostics {
        #[command(subcommand)]
        command: DiagnosticsCmd,
    },
    /// Manage the store's decryption key.
    Keys {
        #[command(subcommand)]
        command: KeysCmd,
    },
}

#[derive(Subcommand)]
enum BackupCmd {
    /// Create a new immutable backup directory and verify it before publishing.
    Create {
        /// New directory to create. Existing paths are never overwritten.
        destination: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Verify checksums, catalog integrity, references, and every encrypted version.
    Verify {
        /// Existing backup directory.
        backup: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Restore a verified backup into a new standalone data directory.
    Restore {
        /// Existing backup directory.
        backup: PathBuf,
        /// New standalone data directory. Existing paths are never overwritten.
        destination: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Activate a standalone restored data directory after taking a safety backup.
    Activate {
        /// Standalone data directory created by `backup restore`.
        restored: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum SyncCmd {
    Status,
    Create { directory: PathBuf },
    Open { directory: PathBuf },
    Now,
    /// Resolve a sync conflict by keeping this Mac's current managed state.
    ResolveCurrent,
    /// Remove another enrolled Mac and rotate the sync-folder encryption key.
    RemoveDevice { device_id: String },
    /// Replace this Mac's revoked identity and create a new approval request.
    RequestAccessAgain,
    Disable,
    /// Print this Mac's public enrollment request as JSON.
    Enrollment,
    /// Approve a public enrollment request exported by another Mac.
    Enroll { request: PathBuf },
}

#[derive(Subcommand)]
enum DiagnosticsCmd {
    /// Export redacted health, inventory, and daemon warning/error summaries.
    Export {
        /// New directory to create. Existing paths are never overwritten.
        destination: PathBuf,
        /// Include local file-system paths. Paths are omitted by default.
        #[arg(long)]
        include_paths: bool,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Copy the store's ssh private key into the login Keychain (decrypted; passphrase from
    /// FLORIA_KEY_PASSPHRASE if the key is protected). With the file gone, `key_source = "auto"`
    /// reads the Keychain instead.
    Import {
        /// Delete the on-disk private key file after a successful import and verification.
        #[arg(long)]
        remove_file: bool,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Export the active store key into a password-encrypted recovery file.
    ExportRecovery {
        /// New recovery-key file. Existing paths are never overwritten.
        destination: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Import a password-encrypted recovery key into an empty Keychain-backed store.
    ImportRecovery {
        /// Recovery-key file created by `keys export-recovery`.
        source: PathBuf,
        #[arg(short, long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ControlCmd {
    /// Check that the daemon control socket and catalog schema are available.
    Ping,
    /// Report the running daemon's redacted system health as JSON.
    Health,
    /// Show or change the daemon-wide runtime policy mode.
    Policy {
        /// Omit to show the current mode. Audit-only without a duration stays active until reset.
        #[arg(value_enum)]
        mode: Option<ControlPolicyMode>,
        #[arg(long)]
        duration_secs: Option<u64>,
    },
    /// Print the complete metadata catalog as JSON (never secret plaintext).
    Snapshot,
    /// Discover supported project configuration. Add --apply only after reviewing the plan.
    Discover {
        path: PathBuf,
        #[arg(long)]
        apply: bool,
    },
    /// Resolve environment keys and provenance without decrypting values.
    Resolve {
        project_id: String,
        environment_id: String,
    },
    /// Show every binding and surface affected by a resource.
    Usage { resource_id: String },
    /// List the public identities advertised by an upstream SSH agent.
    SshDiscover { endpoint: PathBuf },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ControlPolicyMode {
    Normal,
    AuditOnly,
}

impl From<ControlPolicyMode> for PolicyMode {
    fn from(mode: ControlPolicyMode) -> Self {
        match mode {
            ControlPolicyMode::Normal => PolicyMode::Normal,
            ControlPolicyMode::AuditOnly => PolicyMode::AuditOnly,
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let command = Cli::parse().command;
    enforce_packaged_command_boundary(&command)?;
    match command {
        Cmd::Mount { config } => cmd_mount(&config),
        Cmd::Unmount { path, config } => cmd_unmount(path, &config),
        Cmd::Doctor { config } => cmd_doctor(&config),
        Cmd::Protect { path, config } => cmd_protect(&path, &config),
        Cmd::Unprotect { target, config } => cmd_unprotect(&target, &config),
        Cmd::Reveal { target, version, to, config } => cmd_reveal(&target, version, to, &config),
        Cmd::History { target, config } => cmd_history(&target, &config),
        Cmd::Rollback { target, version, config } => cmd_rollback(&target, version, &config),
        Cmd::List { config } => cmd_list(&config),
        Cmd::Control { command, socket, config } => cmd_control(command, socket, &config),
        Cmd::Sync { command, config } => cmd_sync(command, &config),
        Cmd::Backup { command } => match command {
            BackupCmd::Create { destination, config } => {
                cmd_backup_create(&destination, &config)
            }
            BackupCmd::Verify { backup, config } => cmd_backup_verify(&backup, &config),
            BackupCmd::Restore { backup, destination, config } => {
                cmd_backup_restore(&backup, &destination, &config)
            }
            BackupCmd::Activate { restored, config } => {
                cmd_backup_activate(&restored, &config)
            }
        },
        Cmd::Diagnostics { command } => match command {
            DiagnosticsCmd::Export { destination, include_paths, config } => {
                cmd_diagnostics_export(&destination, include_paths, &config)
            }
        },
        Cmd::Keys { command } => match command {
            KeysCmd::Import { remove_file, config } => cmd_keys_import(remove_file, &config),
            KeysCmd::ExportRecovery { destination, config } => {
                cmd_keys_export_recovery(&destination, &config)
            }
            KeysCmd::ImportRecovery { source, config } => {
                cmd_keys_import_recovery(&source, &config)
            }
        },
    }
}

/// Pick the store's key provider from config. `auto` prefers the on-disk ssh key (dev: zero
/// Keychain interaction) and falls back to the Keychain when the file is absent (after
/// `keys import --remove-file`). Both sources hold the same key, so blobs stay interchangeable.
fn store_key_provider(cfg: &ResolvedConfig) -> (Arc<dyn floria_store::KeyProvider>, &'static str) {
    let ssh = || -> Arc<dyn floria_store::KeyProvider> {
        let passphrase = std::env::var("FLORIA_KEY_PASSPHRASE")
            .ok()
            .map(zeroize::Zeroizing::new);
        Arc::new(SshKeyProvider::new(cfg.store_ssh_key.clone(), passphrase))
    };
    match cfg.store_key_source {
        StoreKeySource::Ssh => (ssh(), "ssh"),
        StoreKeySource::Keychain => (Arc::new(KeychainKeyProvider), "keychain"),
        StoreKeySource::Auto => {
            if cfg.store_ssh_key.exists() {
                (ssh(), "auto: ssh file")
            } else {
                (Arc::new(KeychainKeyProvider), "auto: keychain")
            }
        }
    }
}

/// Open the secret store from config. The private key passphrase, if any, comes from
/// `FLORIA_KEY_PASSPHRASE` (dev convenience; interactive/Touch ID unlock is a later milestone).
fn open_store(cfg: &ResolvedConfig) -> Result<AgeDirStore> {
    open_store_with_provider(cfg).map(|(store, _)| store)
}

fn open_store_with_provider(
    cfg: &ResolvedConfig,
) -> Result<(AgeDirStore, Arc<dyn floria_store::KeyProvider>)> {
    let (keys, source) = store_key_provider(cfg);
    tracing::info!(source, "store key source");
    let store = AgeDirStore::open(cfg.store_root.clone(), Arc::clone(&keys))
        .with_context(|| format!("opening store at {}", cfg.store_root.display()))?;
    Ok((store, keys))
}

fn initialize_store_key_if_needed(cfg: &ResolvedConfig) -> Result<()> {
    let uses_keychain = match cfg.store_key_source {
        StoreKeySource::Keychain => true,
        StoreKeySource::Auto => !cfg.store_ssh_key.exists(),
        StoreKeySource::Ssh => false,
    };
    if uses_keychain {
        let created = KeychainKeyProvider::initialize_if_missing(&cfg.store_root)
            .context("initializing the dedicated Floria store key")?;
        if created {
            tracing::info!("created dedicated Floria store key in the login Keychain");
        }
    }
    Ok(())
}

fn cmd_backup_create(destination: &Path, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let catalog_path = support_dir(&cfg)?.join("catalog.sqlite");
    if !catalog_path.is_file() {
        anyhow::bail!(
            "catalog does not exist at {}; start Floria before creating a backup",
            catalog_path.display()
        );
    }
    let state_authenticator = Arc::new(
        floria_integrity::StateAuthenticator::keychain()
            .context("opening the Keychain security-state authority")?,
    );
    let catalog = Catalog::open_authenticated(
        &catalog_path,
        Arc::clone(&state_authenticator),
    )
        .with_context(|| format!("opening catalog at {}", catalog_path.display()))?;
    let store = open_store(&cfg)?
        .authenticate(Arc::clone(&state_authenticator))
        .context("authenticating encrypted-store security state")?;
    let report = floria_backup::create(&catalog, &store, destination)
        .with_context(|| format!("creating backup at {}", destination.display()))?;
    print_backup_report("created and verified", &report);
    Ok(())
}

fn cmd_backup_verify(backup: &Path, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let store = open_store(&cfg)?;
    let report = floria_backup::verify(backup, &store)
        .with_context(|| format!("verifying backup at {}", backup.display()))?;
    print_backup_report("verified", &report);
    Ok(())
}

fn cmd_backup_restore(backup: &Path, destination: &Path, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let store = open_store(&cfg)?;
    let report = floria_backup::restore(backup, &store, destination).with_context(|| {
        format!(
            "restoring backup {} into {}",
            backup.display(),
            destination.display()
        )
    })?;
    print_backup_report("restored and verified", &report);
    println!("active Floria data was not changed");
    Ok(())
}

fn cmd_backup_activate(restored: &Path, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let support = support_dir(&cfg)?.to_path_buf();
    let _instance = DaemonInstance::acquire(&support)
        .context("stopping concurrent daemon startup during restore activation")?;
    if let Some(mount) = exact_mount(&cfg.mount_path)? {
        anyhow::bail!(
            "refusing to activate restored data while {} is mounted by {:?} ({:?}); \
             quit Floria and unmount it first",
            cfg.mount_path.display(),
            mount.source,
            mount.fs_type
        );
    }

    let catalog_path = support.join("catalog.sqlite");
    let state_authenticator = Arc::new(
        floria_integrity::StateAuthenticator::keychain()
            .context("opening the Keychain security-state authority")?,
    );
    let store = open_store(&cfg)?
        .authenticate(Arc::clone(&state_authenticator))
        .context("authenticating active data before restore")?;
    let backups = support.join("backups");
    std::fs::create_dir_all(&backups)
        .with_context(|| format!("creating backup directory {}", backups.display()))?;
    std::fs::set_permissions(&backups, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("securing backup directory {}", backups.display()))?;
    let safety_backup = backups.join(format!(
        "pre-restore-{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs(),
        std::process::id()
    ));
    let report = floria_backup::activate_restored_data(
        restored,
        &catalog_path,
        &store,
        &safety_backup,
        state_authenticator,
    )
    .with_context(|| format!("activating restored data from {}", restored.display()))?;
    print_backup_report("activated and verified", &report.active);
    println!(
        "previous data is preserved in verified backup {}",
        report.safety_backup.path.display()
    );
    Ok(())
}

fn print_backup_report(action: &str, report: &floria_backup::BackupReport) {
    println!(
        "{action} {}: {} projects, {} resources, {} secrets, {} versions, {} files",
        report.path.display(),
        report.projects,
        report.resources,
        report.secrets,
        report.versions,
        report.files,
    );
}

fn cmd_diagnostics_export(
    destination: &Path,
    include_paths: bool,
    config: &Path,
) -> Result<()> {
    let cfg = load(config)?;
    let mut client = connect_control(&cfg)?;
    let result = client.request(ControlCommand::DiagnosticsExport {
        destination: destination.to_path_buf(),
        include_paths,
    })?;
    let ControlResult::Diagnostics(report) = result else {
        anyhow::bail!("daemon returned an unexpected diagnostics response");
    };
    println!(
        "exported {} diagnostics files ({} bytes) to {}{}",
        report.files,
        report.bytes,
        report.path.display(),
        if report.paths_included {
            " with local paths included"
        } else {
            ""
        }
    );
    Ok(())
}

fn cmd_keys_import(remove_file: bool, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    if matches!(cfg.store_key_source, StoreKeySource::Keychain)
        || matches!(cfg.store_key_source, StoreKeySource::Auto) && !cfg.store_ssh_key.exists()
    {
        anyhow::bail!("the configured store already reads its key from Keychain");
    }
    let key_path = &cfg.store_ssh_key;
    let decrypted = recovery::read_ssh_private_key(key_path)?;
    open_store(&cfg)?
        .verify_all()
        .context("verifying that the configured SSH key decrypts every store version")?;
    KeychainKeyProvider::import(&decrypted)?;

    // Verify the roundtrip end to end before touching the file: the Keychain copy must decrypt
    // exactly like the file-based provider encrypts.
    let provider = KeychainKeyProvider;
    floria_store::KeyProvider::identity(&provider)?;
    floria_store::KeyProvider::recipients(&provider)?;
    println!(
        "imported {} into the login Keychain ({}/{})",
        key_path.display(),
        floria_store::KEYCHAIN_SERVICE,
        floria_store::KEYCHAIN_ACCOUNT
    );

    if remove_file {
        std::fs::remove_file(key_path)
            .with_context(|| format!("removing {}", key_path.display()))?;
        println!(
            "removed {}; key_source = \"auto\" now reads the Keychain",
            key_path.display()
        );
    } else {
        println!(
            "the on-disk key is kept; \"auto\" keeps preferring it until the file is removed"
        );
    }
    Ok(())
}

fn cmd_keys_export_recovery(destination: &Path, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    open_store(&cfg)?
        .verify_all()
        .context("verifying that the active key decrypts every store version")?;
    let private_key = match cfg.store_key_source {
        StoreKeySource::Ssh => recovery::read_ssh_private_key(&cfg.store_ssh_key)?,
        StoreKeySource::Auto if cfg.store_ssh_key.exists() => {
            recovery::read_ssh_private_key(&cfg.store_ssh_key)?
        }
        StoreKeySource::Auto | StoreKeySource::Keychain => {
            KeychainKeyProvider::export_private_key().context("reading the store key from Keychain")?
        }
    };
    let passphrase = recovery_passphrase(true)?;
    let path = floria_store::export_recovery_key(&private_key, &passphrase, destination)
        .with_context(|| format!("exporting recovery key to {}", destination.display()))?;
    println!("exported password-encrypted recovery key to {}", path.display());
    println!("store this file and its passphrase separately from the Mac");
    Ok(())
}

fn cmd_keys_import_recovery(source: &Path, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    if matches!(cfg.store_key_source, StoreKeySource::Ssh)
        || matches!(cfg.store_key_source, StoreKeySource::Auto) && cfg.store_ssh_key.exists()
    {
        anyhow::bail!(
            "this config uses the SSH key file at {}; recovery import targets a \
             Keychain-backed store",
            cfg.store_ssh_key.display()
        );
    }
    let passphrase = recovery_passphrase(false)?;
    let private_key = floria_store::decrypt_recovery_key(source, &passphrase)
        .with_context(|| format!("decrypting recovery key {}", source.display()))?;
    let imported = KeychainKeyProvider::import_recovery_key(&private_key, &cfg.store_root)
        .context("importing the recovery key into Keychain")?;
    let provider = KeychainKeyProvider;
    floria_store::KeyProvider::identity(&provider)?;
    floria_store::KeyProvider::recipients(&provider)?;
    let action = if imported { "imported" } else { "already installed" };
    println!("{action} recovery key in the login Keychain");
    Ok(())
}

fn recovery_passphrase(confirm: bool) -> Result<zeroize::Zeroizing<String>> {
    let passphrase = zeroize::Zeroizing::new(
        std::env::var("FLORIA_RECOVERY_PASSPHRASE")
            .context("set FLORIA_RECOVERY_PASSPHRASE for this operation")?,
    );
    if confirm {
        let confirmation = zeroize::Zeroizing::new(
            std::env::var("FLORIA_RECOVERY_PASSPHRASE_CONFIRM")
                .context("set FLORIA_RECOVERY_PASSPHRASE_CONFIRM when exporting")?,
        );
        if *passphrase != *confirmation {
            anyhow::bail!("recovery passphrase confirmation does not match");
        }
    }
    Ok(passphrase)
}

fn cmd_protect(path: &Path, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let absolute = absolute_cli_path(path)?;
    let mut client = connect_control(&cfg)?;
    match client.request(ControlCommand::FileProtect { path: absolute })? {
        ControlResult::FileProtected { file, created } => {
            let action = if created { "protected" } else { "already protected" };
            println!(
                "{action} {} as {} (version {})",
                file.source_path.display(),
                file.id,
                file.current_version
            );
            Ok(())
        }
        result => anyhow::bail!("daemon returned an unexpected protect result: {result:?}"),
    }
}

fn cmd_unprotect(target: &str, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let mut client = connect_control(&cfg)?;
    let file = resolve_protected_file(&mut client, target)?;
    match client.request(ControlCommand::FileRestore { id: file.id })? {
        ControlResult::FileRestored { path, storage_deleted: true } => {
            println!("restored plaintext and stopped protecting {}", path.display());
            Ok(())
        }
        ControlResult::FileRestored { path, storage_deleted: false } => {
            anyhow::bail!(
                "restored plaintext at {}, but encrypted history could not be deleted; \
                 check the daemon log",
                path.display()
            )
        }
        result => anyhow::bail!("daemon returned an unexpected unprotect result: {result:?}"),
    }
}

fn cmd_reveal(target: &str, version: Option<u32>, to: Option<PathBuf>, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let store = open_store(&cfg)?;
    let record = resolve_target(&store, target)?;
    let plaintext = match version {
        Some(v) => store.get_version(&record.id, v)?,
        None => store.get(&record.id)?,
    };

    match to {
        Some(dest) => {
            write_revealed_file(&dest, &plaintext[..], record.mode)?;
            eprintln!("wrote {} bytes to {}", plaintext.len(), dest.display());
        }
        None => std::io::stdout().write_all(&plaintext[..])?,
    }
    Ok(())
}

fn write_revealed_file(destination: &Path, plaintext: &[u8], mode: u32) -> Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .with_context(|| {
            format!(
                "creating new reveal destination {} (it must not already exist)",
                destination.display()
            )
        })?;

    let result = (|| -> Result<()> {
        output
            .write_all(plaintext)
            .with_context(|| format!("writing {}", destination.display()))?;
        output
            .sync_all()
            .with_context(|| format!("syncing {}", destination.display()))?;
        std::fs::set_permissions(
            destination,
            std::os::unix::fs::PermissionsExt::from_mode(mode),
        )
        .with_context(|| format!("setting permissions on {}", destination.display()))
    })();
    drop(output);

    if let Err(error) = result {
        let _ = std::fs::remove_file(destination);
        return Err(error);
    }
    Ok(())
}

fn cmd_history(target: &str, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let mut client = connect_control(&cfg)?;
    let file = resolve_protected_file(&mut client, target)?;
    let result = client.request(ControlCommand::ProtectedFileHistory { id: file.id.clone() })?;
    let ControlResult::ProtectedFileHistory { id, versions } = result else {
        anyhow::bail!("daemon returned an unexpected history result: {result:?}");
    };
    println!("{}  {}", id, file.source_path.display());
    for version in versions {
        let head = if version.current { " (current)" } else { "" };
        let note = version.note.map(|note| format!("  {note}")).unwrap_or_default();
        println!(
            "  v{}  {} bytes  {}{head}{note}",
            version.version, version.size, version.created
        );
    }
    Ok(())
}

fn cmd_rollback(target: &str, version: u32, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let mut client = connect_control(&cfg)?;
    let file = resolve_protected_file(&mut client, target)?;
    match client.request(ControlCommand::ProtectedFileRollback {
        id: file.id,
        version,
    })? {
        ControlResult::ProtectedFileRolledBack { file } => {
            println!("{} → head is now v{}", file.id, file.current_version);
            Ok(())
        }
        result => anyhow::bail!("daemon returned an unexpected rollback result: {result:?}"),
    }
}

fn cmd_list(config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let mut client = connect_control(&cfg)?;
    let result = client.request(ControlCommand::ProtectedFiles)?;
    let ControlResult::ProtectedFiles(files) = result else {
        anyhow::bail!("daemon returned an unexpected list result: {result:?}");
    };
    if files.is_empty() {
        println!("no protected files");
        return Ok(());
    }
    for file in files {
        println!(
            "{}  {}  (v{}, {} bytes, mode {:04o})",
            file.id,
            file.source_path.display(),
            file.current_version,
            file.size,
            file.mode
        );
    }
    Ok(())
}

fn connect_control(cfg: &ResolvedConfig) -> Result<ControlClient> {
    let socket = support_dir(cfg)?.join("control.sock");
    ControlClient::connect(&socket)
        .with_context(|| format!("connecting to control socket {}", socket.display()))
}

fn resolve_protected_file(client: &mut ControlClient, target: &str) -> Result<ProtectedFile> {
    let command = if target.parse::<SecretId>().is_ok() {
        ControlCommand::ProtectedFileLookup {
            id: Some(target.to_string()),
            path: None,
        }
    } else {
        ControlCommand::ProtectedFileLookup {
            id: None,
            path: Some(absolute_cli_path(Path::new(target))?),
        }
    };
    let result = client.request(command)?;
    let ControlResult::ProtectedFile(file) = result else {
        anyhow::bail!("daemon returned an unexpected file lookup result: {result:?}");
    };
    Ok(file)
}

/// Make a user-supplied path absolute without following the final component, which may already be
/// a Floria-managed symlink.
fn absolute_cli_path(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving the current directory")?
            .join(path)
    };
    let name = path
        .file_name()
        .with_context(|| format!("path must name a file: {}", path.display()))?;
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let parent = std::fs::canonicalize(parent)
        .with_context(|| format!("resolving parent directory {}", parent.display()))?;
    Ok(parent.join(name))
}

/// Resolve a reveal target that may be a store id or a source path.
fn resolve_target(store: &AgeDirStore, target: &str) -> Result<SecretRecord> {
    if let Ok(id) = target.parse::<SecretId>() {
        if let Some(r) = store.list()?.into_iter().find(|r| r.id == id) {
            return Ok(r);
        }
    }
    let abs = reveal_lookup_path(Path::new(target))?;
    store
        .get_by_path(&abs)?
        .with_context(|| format!("no protected secret for {target:?}"))
}

fn reveal_lookup_path(path: &Path) -> Result<PathBuf> {
    absolute_cli_path(path)
}

fn load(config: &Path) -> Result<ResolvedConfig> {
    if option_env!("FLORIA_SIGNING_TEAM_ID").is_some() {
        let expected = packaged_runtime_config_path()?;
        if config != expected {
            anyhow::bail!(
                "packaged Floria only accepts its managed config at {}; got {}",
                expected.display(),
                config.display()
            );
        }
        let bundled = packaged_config_path()?;
        let resolved = Config::load(&bundled)
            .with_context(|| format!("loading signed bundled config {}", bundled.display()))?;
        if resolved.store_key_source != StoreKeySource::Keychain || !resolved.files.is_empty() {
            anyhow::bail!(
                "signed bundled config must use the Keychain store key and cannot declare command-backed files"
            );
        }
        return Ok(resolved);
    }
    Config::load(config).with_context(|| format!("loading config {}", config.display()))
}

/// A signed helper can be launched by any same-user process. Code signing authenticates the
/// executable, not human intent, so packaged builds expose only daemon lifecycle and metadata
/// commands directly. Sensitive operations must cross the GUI-authenticated control boundary.
fn enforce_packaged_command_boundary(command: &Cmd) -> Result<()> {
    if option_env!("FLORIA_SIGNING_TEAM_ID").is_none() {
        return Ok(());
    }
    if matches!(
        command,
        Cmd::Mount { .. }
            | Cmd::Unmount { .. }
            | Cmd::Doctor { .. }
            | Cmd::History { .. }
            | Cmd::List { .. }
            | Cmd::Control { .. }
    ) {
        Ok(())
    } else {
        anyhow::bail!(
            "this operation is disabled in the packaged Floria helper; use the Floria app so sensitive actions cross the authenticated control boundary"
        )
    }
}

fn packaged_runtime_config_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is required for packaged Floria")?;
    Ok(PathBuf::from(home).join(RUNTIME_CONFIG_RELATIVE_PATH))
}

fn packaged_config_path() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("resolving packaged Floria executable")?;
    let resources = executable
        .parent()
        .filter(|path| path.file_name().is_some_and(|name| name == "Resources"))
        .context("packaged Floria helper is not inside an app Resources directory")?;
    let config = resources.join("floria.toml");
    if !config.is_file() {
        anyhow::bail!("signed bundled config is missing at {}", config.display());
    }
    Ok(config)
}

fn cmd_mount(config: &Path) -> Result<()> {
    let cfg = load(config)?;
    std::fs::create_dir_all(&cfg.mount_path)
        .with_context(|| format!("creating mount point {}", cfg.mount_path.display()))?;
    let support_dir = support_dir(&cfg)?.to_path_buf();
    let _instance = DaemonInstance::acquire(&support_dir)?;
    tracing::info!("checking the dedicated Floria store key in the login Keychain");
    initialize_store_key_if_needed(&cfg)?;
    recover_stale_mount(&cfg.mount_path)?;
    let catalog_path = support_dir.join("catalog.sqlite");
    let (store, key_provider) = open_store_with_provider(&cfg)?;
    let state_authenticator = Arc::new(
        floria_integrity::StateAuthenticator::keychain()
            .context("opening the Keychain security-state authority")?,
    );
    if catalog_path.exists() {
        if let Some(report) =
            floria_backup::recover_interrupted_activation(
                &catalog_path,
                &store,
                Arc::clone(&state_authenticator),
            )
                .context("recovering an interrupted data restore")?
        {
            tracing::warn!(
                safety_backup = %report.safety_backup.path.display(),
                "finished an interrupted data restore"
            );
        }
    }
    let (agent_peer_verifier, control_peer_verifier) = local_peer_verifiers()?;
    let store = store
        .authenticate(Arc::clone(&state_authenticator))
        .context("authenticating encrypted-store security state")?;
    let control_path = support_dir.join("control.sock");
    let catalog = Catalog::open_authenticated(
        &catalog_path,
        Arc::clone(&state_authenticator),
    )
        .with_context(|| format!("opening catalog at {}", catalog_path.display()))?;
    let concrete_store = Arc::new(store);
    let mutations = Arc::new(floria_surface::ManagedMutationCoordinator::new());
    let replication = Arc::new(
        DaemonReplicationService::start(
            support_dir.join("replication"),
            Arc::clone(&state_authenticator),
            Arc::new(catalog.clone()),
            Arc::clone(&concrete_store),
            Arc::clone(&mutations),
        )
        .context("starting replication runtime")?,
    );
    let replication_mutation_observer: Arc<dyn ManagedMutationObserver> = replication.clone();
    mutations.observe(Arc::downgrade(&replication_mutation_observer));
    if replication.status().mode == ReplicationMode::Active {
        match replication.sync() {
            Ok(status) => tracing::info!(
                imported = status.imported,
                published = status.published,
                pending = status.pending,
                "synchronized configured replication package"
            ),
            Err(error) => tracing::warn!(%error, "initial replication sync failed"),
        }
    }
    let snapshot = catalog.snapshot().context("loading initial surface registry")?;
    let checkout_monitor = Arc::new(
        GitCheckoutMonitor::start(monitored_git_projects(&snapshot))
            .context("starting Git checkout monitor")?,
    );
    let surface_registry = Arc::new(SurfaceRegistry::from_snapshot(&snapshot));
    let linked_file_surfaces =
        file_surface_instances(&snapshot).context("materializing project checkout links")?;
    let backup: Arc<dyn BackupService> =
        Arc::new(DaemonBackupService { store: Arc::clone(&concrete_store) });
    let recovery_key: Arc<dyn RecoveryKeyExporter> = Arc::new(
        RuntimeRecoveryKeyExporter::new(
            Arc::clone(&concrete_store),
            cfg.store_key_source,
            cfg.store_ssh_key.clone(),
        ),
    );
    let store: Arc<dyn SecretStore> = concrete_store.clone();
    let health: Arc<dyn RuntimeHealthReporter> = Arc::new(RuntimeHealth::new(
        catalog.clone(),
        Arc::clone(&store),
        Arc::clone(&key_provider),
        cfg.mount_path.clone(),
        cfg.store_root.clone(),
    ));
    let diagnostics: Arc<dyn RuntimeDiagnosticsExporter> = Arc::new(RuntimeDiagnostics::new(
        catalog.clone(),
        Arc::clone(&health),
        support_dir.clone(),
        cfg.mount_path.clone(),
    ));
    let records = store.list()?;
    release_protected_links_for_file_surfaces(
        &snapshot,
        &records,
        &linked_file_surfaces,
        &cfg.mount_path,
    )
    .context("transitioning protected worktree links to configured surfaces")?;
    reconcile_file_links(&snapshot, &linked_file_surfaces, &cfg.mount_path);
    let mut linked_protected_files = Vec::new();
    refresh_protected_checkout_links(
        &mut linked_protected_files,
        protected_checkout_links(&snapshot, &records, &cfg.mount_path),
        store.as_ref(),
    )
    .context("materializing protected files in project worktrees")?;
    let agent = floria_agent::SocketAgent::start(
        &cfg,
        agent_peer_verifier,
        Arc::clone(&state_authenticator),
    )
        .context("starting agent socket")?;
    agent.replace_managed_policy(managed_policy_items(&snapshot, &records));
    let audit_authority = Arc::new(AuthenticatedAuditAuthority::new(
        Arc::clone(&state_authenticator),
        cfg.audit_log.with_extension("integrity.json"),
    ));
    let audit = Arc::new(
        AuditLog::open_authenticated(&cfg.audit_log, audit_authority)
            .context("opening authenticated audit log")?,
    );
    let ssh_authorizer: Arc<dyn Authorizer> = agent.clone();
    let managed_keys: Arc<dyn floria_agent::ManagedKeyReader> =
        Arc::new(StoreManagedKeyReader { store: Arc::clone(&store) });
    let generated_ssh_config = support_dir.join("ssh/config");
    let ssh_runtime_dir = support_dir.join("runtime/sockets");
    let ssh_runtime = Arc::new(
        floria_agent::SshAgentRuntime::new(
            ssh_runtime_dir.clone(),
            &generated_ssh_config,
            ssh_authorizer,
            Arc::clone(&audit),
            managed_keys,
        )
        .context("creating SSH agent runtime")?,
    );
    ssh_runtime
        .replace(&snapshot)
        .context("starting SSH agent surfaces")?;
    let observer: Arc<dyn CatalogObserver> = Arc::new(RuntimeCatalogObserver {
        surface_registry: Arc::clone(&surface_registry),
        mount_path: cfg.mount_path.clone(),
        store: Arc::clone(&store),
        agent: Arc::clone(&agent),
        ssh_runtime: Arc::clone(&ssh_runtime),
        linked_file_surfaces: Mutex::new(linked_file_surfaces),
        linked_protected_files: Mutex::new(linked_protected_files),
        checkout_monitor: Arc::clone(&checkout_monitor),
    });
    let policy: Arc<dyn RuntimePolicyController> = Arc::new(AgentPolicyController {
        agent: Arc::clone(&agent),
    });
    let ssh_discovery: Arc<dyn SshIdentityDiscovery> = Arc::new(AgentSshIdentityDiscovery);
    let home = std::env::var_os("HOME").context("HOME is required for SSH config integration")?;
    let ssh_config: Arc<dyn SshConfigManager> = Arc::new(ManagedSshConfig::new(
        PathBuf::from(home).join(".ssh/config"),
        generated_ssh_config,
    ));
    let replication_worker = Arc::clone(&replication);
    let replication_observer = Arc::clone(&observer);
    let replication_catalog = catalog.clone();
    std::thread::Builder::new()
        .name("floria-replication".to_string())
        .spawn(move || {
            run_replication_worker(
                replication_worker,
                replication_observer,
                replication_catalog,
            )
        })
        .context("starting replication worker")?;
    let replication: Arc<dyn RuntimeReplicationService> = replication;
    let _control = ControlServer::start_runtime_with_services(
        &control_path,
        catalog.clone(),
        Arc::clone(&store),
        cfg.mount_path.clone(),
        ControlRuntimeServices {
            mutations: Arc::clone(&mutations),
            observer,
            checkout_monitor,
            policy,
            ssh_discovery,
            ssh_config,
            backup,
            recovery_key,
            health,
            diagnostics,
            replication,
            record_sync: None,
            audit_log: Arc::clone(&audit),
            peer_verifier: control_peer_verifier,
        },
    )
        .with_context(|| format!("starting control socket at {}", control_path.display()))?;
    tracing::info!(socket = %control_path.display(), "control socket listening");
    floria_fs::mount_with_audit(
        cfg,
        agent,
        Some(store),
        Some(catalog),
        Some(surface_registry),
        audit,
        mutations,
    )
    .context("mount failed")
}

struct AgentPolicyController {
    agent: Arc<floria_agent::SocketAgent>,
}

struct AgentSshIdentityDiscovery;

const AUDIT_CHECKPOINT_DOMAIN: &str = "audit-log-checkpoint";
const AUDIT_EVENT_DOMAIN: &str = "audit-log-event";

struct AuthenticatedAuditAuthority {
    authenticator: Arc<floria_integrity::StateAuthenticator>,
    checkpoint_path: PathBuf,
    generation: Mutex<Option<u64>>,
}

impl AuthenticatedAuditAuthority {
    fn new(
        authenticator: Arc<floria_integrity::StateAuthenticator>,
        checkpoint_path: PathBuf,
    ) -> Self {
        Self {
            authenticator,
            checkpoint_path,
            generation: Mutex::new(None),
        }
    }
}

impl AuditAuthority for AuthenticatedAuditAuthority {
    fn load_checkpoint(&self) -> std::io::Result<Option<AuditCheckpoint>> {
        let loaded = self
            .authenticator
            .load::<AuditCheckpoint>(&self.checkpoint_path, AUDIT_CHECKPOINT_DOMAIN)
            .map_err(std::io::Error::other)?;
        *self
            .generation
            .lock()
            .map_err(|_| std::io::Error::other("audit checkpoint lock poisoned"))? =
            Some(loaded.generation);
        if loaded.value.is_none() && loaded.generation != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "audit checkpoint file is missing at authenticated generation {}",
                    loaded.generation
                ),
            ));
        }
        Ok(loaded.value)
    }

    fn authenticate(&self, payload: &[u8]) -> std::io::Result<String> {
        Ok(self
            .authenticator
            .authenticate_detached(AUDIT_EVENT_DOMAIN, payload))
    }

    fn verify(&self, payload: &[u8], tag: &str) -> std::io::Result<()> {
        self.authenticator
            .verify_detached(AUDIT_EVENT_DOMAIN, payload, tag)
            .map_err(std::io::Error::other)
    }

    fn persist_checkpoint(&self, checkpoint: &AuditCheckpoint) -> std::io::Result<()> {
        let mut generation = self
            .generation
            .lock()
            .map_err(|_| std::io::Error::other("audit checkpoint lock poisoned"))?;
        let current = generation.ok_or_else(|| {
            std::io::Error::other("audit checkpoint was not loaded before persistence")
        })?;
        *generation = Some(
            self.authenticator
                .persist(
                    &self.checkpoint_path,
                    AUDIT_CHECKPOINT_DOMAIN,
                    current,
                    checkpoint,
                )
                .map_err(std::io::Error::other)?,
        );
        Ok(())
    }
}

struct DaemonBackupService {
    store: Arc<AgeDirStore>,
}

impl BackupService for DaemonBackupService {
    fn create(
        &self,
        catalog: &Catalog,
        destination: &Path,
    ) -> Result<ControlBackupReport, String> {
        floria_backup::create(catalog, &self.store, destination)
            .map(control_backup_report)
            .map_err(|error| error.to_string())
    }

    fn verify(&self, backup: &Path) -> Result<ControlBackupReport, String> {
        floria_backup::verify(backup, &self.store)
            .map(control_backup_report)
            .map_err(|error| error.to_string())
    }
}

fn control_backup_report(report: floria_backup::BackupReport) -> ControlBackupReport {
    ControlBackupReport {
        path: report.path,
        catalog_schema: report.catalog_schema,
        projects: report.projects,
        resources: report.resources,
        secrets: report.secrets,
        versions: report.versions,
        plaintext_bytes: report.plaintext_bytes,
        files: report.files,
    }
}

const REPLICATION_SETTINGS_DOMAIN: &str = "replication-runtime-settings";
const REPLICATION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

struct ReplicationDirectoryWatcher {
    watcher: RecommendedWatcher,
    receiver: mpsc::Receiver<()>,
    directory: Option<PathBuf>,
}

impl ReplicationDirectoryWatcher {
    fn new() -> notify::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let watcher = notify::recommended_watcher(move |result: notify::Result<notify::Event>| {
            match result {
                Ok(event) if !matches!(event.kind, EventKind::Access(_)) => {
                    let _ = sender.try_send(());
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "replication directory watcher deferred to polling");
                    let _ = sender.try_send(());
                }
            }
        })?;
        Ok(Self { watcher, receiver, directory: None })
    }

    fn replace_directory(&mut self, directory: Option<&Path>) {
        let requested = directory.map(Path::to_path_buf);
        if self.directory == requested {
            return;
        }
        if let Some(previous) = self.directory.take() {
            if let Err(error) = self.watcher.unwatch(&previous) {
                tracing::debug!(
                    %error,
                    path = %previous.display(),
                    "replication directory was already unwatched"
                );
            }
        }
        let Some(requested) = requested else { return };
        match self.watcher.watch(&requested, RecursiveMode::Recursive) {
            Ok(()) => self.directory = Some(requested),
            Err(error) => tracing::debug!(
                %error,
                path = %requested.display(),
                "replication directory watcher is waiting for the polling fallback"
            ),
        }
    }

    fn wait_for(&self, timeout: std::time::Duration) -> bool {
        match self.receiver.recv_timeout(timeout) {
            Ok(()) => true,
            Err(mpsc::RecvTimeoutError::Timeout) => false,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(timeout);
                false
            }
        }
    }
}

fn run_replication_worker(
    replication: Arc<DaemonReplicationService>,
    observer: Arc<dyn CatalogObserver>,
    catalog: Catalog,
) -> ! {
    let mut watcher = match ReplicationDirectoryWatcher::new() {
        Ok(watcher) => Some(watcher),
        Err(error) => {
            tracing::warn!(%error, "replication directory events unavailable; using polling");
            None
        }
    };
    loop {
        let before_wait = replication.status();
        if let Some(watcher) = watcher.as_mut() {
            watcher.replace_directory(before_wait.directory.as_deref());
            watcher.wait_for(REPLICATION_POLL_INTERVAL);
        } else {
            std::thread::sleep(REPLICATION_POLL_INTERVAL);
        }

        let mode = replication.status().mode;
        if matches!(mode, ReplicationMode::Off | ReplicationMode::Fenced) {
            continue;
        }
        match replication.sync() {
            Ok(status) if status.imported > 0 => match catalog.snapshot() {
                Ok(snapshot) => observer.catalog_changed(&snapshot),
                Err(error) => tracing::warn!(
                    %error,
                    "refreshing runtime after replication import failed"
                ),
            },
            Ok(_) => {}
            Err(error) => tracing::debug!(%error, "replication sync deferred"),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct ReplicationRuntimeSettings {
    directory: Option<PathBuf>,
}

struct ReplicationRuntimeState {
    settings_generation: u64,
    settings: ReplicationRuntimeSettings,
    engine: Option<ReplicationEngine>,
    mode: ReplicationMode,
    device_id: Option<String>,
    vault_id: Option<String>,
    last_report: ReplicationReport,
    message: Option<String>,
}

struct DaemonReplicationService {
    local_directory: PathBuf,
    settings_path: PathBuf,
    authenticator: Arc<floria_integrity::StateAuthenticator>,
    catalog: Arc<Catalog>,
    store: Arc<AgeDirStore>,
    mutations: Arc<floria_surface::ManagedMutationCoordinator>,
    state: Mutex<ReplicationRuntimeState>,
}

impl DaemonReplicationService {
    fn start(
        local_directory: PathBuf,
        authenticator: Arc<floria_integrity::StateAuthenticator>,
        catalog: Arc<Catalog>,
        store: Arc<AgeDirStore>,
        mutations: Arc<floria_surface::ManagedMutationCoordinator>,
    ) -> Result<Self> {
        std::fs::create_dir_all(&local_directory).with_context(|| {
            format!("creating replication state at {}", local_directory.display())
        })?;
        std::fs::set_permissions(
            &local_directory,
            std::fs::Permissions::from_mode(0o700),
        )
        .with_context(|| {
            format!("securing replication state at {}", local_directory.display())
        })?;
        let settings_path = local_directory.join("settings.json");
        let loaded = authenticator
            .load::<ReplicationRuntimeSettings>(
                &settings_path,
                REPLICATION_SETTINGS_DOMAIN,
            )
            .context("loading authenticated replication settings")?;
        let (settings_generation, settings) = match loaded.value {
            Some(settings) => (loaded.generation, settings),
            None if loaded.generation == 0 => {
                let settings = ReplicationRuntimeSettings::default();
                let generation = authenticator
                    .persist(
                        &settings_path,
                        REPLICATION_SETTINGS_DOMAIN,
                        0,
                        &settings,
                    )
                    .context("initializing authenticated replication settings")?;
                (generation, settings)
            }
            None => anyhow::bail!(
                "replication settings are missing at authenticated generation {}",
                loaded.generation
            ),
        };
        let service = Self {
            local_directory,
            settings_path,
            authenticator,
            catalog,
            store,
            mutations,
            state: Mutex::new(ReplicationRuntimeState {
                settings_generation,
                settings,
                engine: None,
                mode: ReplicationMode::Off,
                device_id: None,
                vault_id: None,
                last_report: ReplicationReport::default(),
                message: None,
            }),
        };
        service.restore_configured_engine();
        Ok(service)
    }

    fn replication_runtime(&self) -> ReplicationRuntime {
        ReplicationRuntime::new(
            &self.local_directory,
            Arc::clone(&self.authenticator),
            Arc::clone(&self.catalog),
            Arc::clone(&self.store),
            Arc::clone(&self.mutations),
        )
    }

    fn restore_configured_engine(&self) {
        let directory = self
            .state
            .lock()
            .expect("replication runtime state poisoned")
            .settings
            .directory
            .clone();
        let Some(_directory) = directory else { return };
        let result = self.open_engine();
        let mut state = self.state.lock().expect("replication runtime state poisoned");
        match result {
            Ok(engine) => {
                state.device_id = Some(engine.device_id().to_string());
                state.vault_id = Some(engine.vault_id().to_string());
                state.mode = ReplicationMode::Active;
                state.message = None;
                state.engine = Some(engine);
            }
            Err(ReplicationError::EnrollmentRequired { device_id }) => {
                state.device_id = Some(device_id);
                state.mode = ReplicationMode::WaitingForEnrollment;
                state.message = Some(
                    "This Mac is waiting for the Mac that created this sync folder to approve it"
                        .to_string(),
                );
            }
            Err(ReplicationError::DeviceRevoked { device_id, .. }) => {
                state.device_id = Some(device_id);
                state.vault_id = None;
                state.mode = ReplicationMode::Removed;
                state.message = Some("This Mac was removed from this sync folder".to_string());
                state.engine = None;
            }
            Err(error) => {
                state.mode = ReplicationMode::Error;
                state.message = Some(error.to_string());
            }
        }
    }

    /// The store already is the vault; the engine only needs the runtime. The configured sync
    /// directory is the store's shared-location pointer, resolved at store open.
    fn open_engine(&self) -> floria_replication::ReplicationResult<ReplicationEngine> {
        ReplicationEngine::for_runtime(self.replication_runtime())
    }

    fn persist_directory(
        &self,
        state: &mut ReplicationRuntimeState,
        directory: Option<PathBuf>,
    ) -> Result<(), String> {
        let settings = ReplicationRuntimeSettings { directory };
        let generation = self
            .authenticator
            .persist(
                &self.settings_path,
                REPLICATION_SETTINGS_DOMAIN,
                state.settings_generation,
                &settings,
            )
            .map_err(|error| error.to_string())?;
        state.settings_generation = generation;
        state.settings = settings;
        Ok(())
    }

    fn run_sync(
        engine: &ReplicationEngine,
    ) -> floria_replication::ReplicationResult<ReplicationReport> {
        let mut report = engine.sync()?;
        if report.local_device_fenced || report.conflicts > 0 || report.damaged > 0 {
            return Ok(report);
        }
        if engine.stage_current_snapshot(&replication_timestamp())? {
            let published = engine.sync()?;
            report.published += published.published;
            report.imported += published.imported;
            report.recovered_local += published.recovered_local;
            report.observed = published.observed;
            report.pending = published.pending;
            report.damaged = published.damaged;
            report.damaged_files = published.damaged_files;
            report.conflicts = published.conflicts;
            report.local_device_fenced = published.local_device_fenced;
            report.messages.extend(published.messages);
        }
        Ok(report)
    }

    fn status_from(&self, state: &ReplicationRuntimeState) -> ReplicationStatus {
        ReplicationStatus {
            mode: state.mode,
            directory: state.settings.directory.clone(),
            device_id: state.device_id.clone(),
            vault_id: state.vault_id.clone(),
            device_fingerprint: Some(floria_store::vault::signing_key_fingerprint(
                &self.store.device().enrollment().signing_public_key,
            )),
            pending_enrollments: state
                .last_report
                .pending_enrollments
                .iter()
                .map(|pending| floria_control::ReplicationPendingEnrollment {
                    device_id: pending.device_id.clone(),
                    device_name: pending.device_name.clone(),
                    fingerprint: pending.fingerprint.clone(),
                    requested_at: pending.requested_at.clone(),
                })
                .collect(),
            key_generation: state.engine.as_ref().map(ReplicationEngine::current_generation),
            published: state.last_report.published,
            imported: state.last_report.imported,
            pending: state.last_report.pending,
            conflicts: state.last_report.conflicts,
            damaged: state.last_report.damaged,
            damaged_files: state.last_report.damaged_files.clone(),
            devices: state
                .engine
                .as_ref()
                .map(|engine| {
                    engine
                        .devices()
                        .into_iter()
                        .map(|device| ControlReplicationDevice {
                            device_id: device.device_id,
                            device_name: device.device_name,
                            enrolled_generation: device.enrolled_generation,
                            revoked_generation: device.revoked_generation,
                            is_genesis: device.is_genesis,
                            is_current: device.is_current,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            message: state.message.clone(),
        }
    }

    fn update_after_sync(
        &self,
        state: &mut ReplicationRuntimeState,
        report: ReplicationReport,
    ) -> ReplicationStatus {
        state.mode = if report.local_device_fenced {
            ReplicationMode::Fenced
        } else {
            ReplicationMode::Active
        };
        state.message = report.messages.first().cloned();
        state.last_report = report;
        self.status_from(state)
    }
}

impl RuntimeReplicationService for DaemonReplicationService {
    fn status(&self) -> ReplicationStatus {
        self.status_from(
            &self.state.lock().expect("replication runtime state poisoned"),
        )
    }

    fn create(&self, directory: &Path) -> Result<ReplicationStatus, String> {
        // Enabling sync moves the authoritative shared half into the chosen synced location;
        // this Mac was the (single-device) vault's genesis all along.
        ReplicationEngine::enable_sync_at(&self.store, directory)
            .map_err(|error| error.to_string())?;
        let engine = self.open_engine().map_err(|error| error.to_string())?;
        let report = Self::run_sync(&engine).map_err(|error| error.to_string())?;
        let mut state = self.state.lock().expect("replication runtime state poisoned");
        self.persist_directory(&mut state, Some(directory.to_path_buf()))?;
        state.device_id = Some(engine.device_id().to_string());
        state.vault_id = Some(engine.vault_id().to_string());
        state.engine = Some(engine);
        Ok(self.update_after_sync(&mut state, report))
    }

    fn open(&self, directory: &Path) -> Result<ReplicationStatus, String> {
        // First-time join: adopt the vault and drop the self-signed request into this device's
        // namespace. Re-opening the already-adopted folder (e.g. after a restart) skips both.
        if self.store.shared_root() != directory {
            ReplicationEngine::join_vault_at(
                &self.store,
                directory,
                local_device_name(),
                &replication_timestamp(),
            )
            .map_err(|error| error.to_string())?;
        }
        match self.open_engine() {
            Ok(engine) => {
                let report = Self::run_sync(&engine).map_err(|error| error.to_string())?;
                let mut state = self.state.lock().expect("replication runtime state poisoned");
                self.persist_directory(&mut state, Some(directory.to_path_buf()))?;
                state.device_id = Some(engine.device_id().to_string());
                state.vault_id = Some(engine.vault_id().to_string());
                state.engine = Some(engine);
                Ok(self.update_after_sync(&mut state, report))
            }
            Err(ReplicationError::EnrollmentRequired { device_id }) => {
                let mut state = self.state.lock().expect("replication runtime state poisoned");
                self.persist_directory(&mut state, Some(directory.to_path_buf()))?;
                state.engine = None;
                state.device_id = Some(device_id);
                state.vault_id = None;
                state.mode = ReplicationMode::WaitingForEnrollment;
                state.message = Some(
                    "This Mac is waiting for the Mac that created this sync folder to approve it"
                        .to_string(),
                );
                Ok(self.status_from(&state))
            }
            Err(ReplicationError::DeviceRevoked { device_id, .. }) => {
                let mut state = self.state.lock().expect("replication runtime state poisoned");
                self.persist_directory(&mut state, Some(directory.to_path_buf()))?;
                state.engine = None;
                state.device_id = Some(device_id);
                state.vault_id = None;
                state.mode = ReplicationMode::Removed;
                state.message = Some("This Mac was removed from this sync folder".to_string());
                Ok(self.status_from(&state))
            }
            Err(error) => Err(error.to_string()),
        }
    }

    fn sync(&self) -> Result<ReplicationStatus, String> {
        {
            let state = self.state.lock().expect("replication runtime state poisoned");
            if state.engine.is_none()
                && state.settings.directory.is_some()
                && state.mode != ReplicationMode::Off
            {
                drop(state);
                self.restore_configured_engine();
            }
        }
        let mut state = self.state.lock().expect("replication runtime state poisoned");
        let report = {
            let engine = state.engine.as_ref().ok_or_else(|| {
                state
                    .message
                    .clone()
                    .unwrap_or_else(|| "replication is not active".to_string())
            })?;
            Self::run_sync(engine)
        };
        let report = match report {
            Ok(report) => report,
            Err(ReplicationError::DeviceRevoked { device_id, .. }) => {
                state.engine = None;
                state.device_id = Some(device_id);
                state.vault_id = None;
                state.mode = ReplicationMode::Removed;
                state.message = Some("This Mac was removed from this sync folder".to_string());
                return Ok(self.status_from(&state));
            }
            Err(error) => {
                state.mode = ReplicationMode::Error;
                state.message = Some(error.to_string());
                return Err(error.to_string());
            }
        };
        Ok(self.update_after_sync(&mut state, report))
    }

    fn resolve_with_current(&self) -> Result<ReplicationStatus, String> {
        let mut state = self.state.lock().expect("replication runtime state poisoned");
        let report = {
            let engine = state.engine.as_ref().ok_or_else(|| {
                state
                    .message
                    .clone()
                    .unwrap_or_else(|| "replication is not active".to_string())
            })?;
            engine
                .resolve_conflict_with_current(&replication_timestamp())
                .map_err(|error| error.to_string())
        };
        let report = match report {
            Ok(report) => report,
            Err(error) => {
                state.mode = ReplicationMode::Error;
                state.message = Some(error.clone());
                return Err(error);
            }
        };
        Ok(self.update_after_sync(&mut state, report))
    }

    fn revoke_device(&self, device_id: &str) -> Result<ReplicationStatus, String> {
        let mut state = self.state.lock().expect("replication runtime state poisoned");
        let report = state
            .engine
            .as_ref()
            .ok_or_else(|| "replication is not active on this Mac".to_string())?
            .revoke_device(device_id)
            .map_err(|error| error.to_string())?;
        Ok(self.update_after_sync(&mut state, report))
    }

    fn request_reenrollment(&self) -> Result<ReplicationStatus, String> {
        let mut state = self.state.lock().expect("replication runtime state poisoned");
        if state.mode != ReplicationMode::Removed || state.engine.is_some() {
            return Err("this Mac does not have a revoked sync identity".to_string());
        }
        floria_replication::request_reenrollment(
            &self.store,
            local_device_name(),
            &replication_timestamp(),
        )
        .map_err(|error| error.to_string())?;
        state.device_id = Some(self.store.device().device_id().to_string());
        state.mode = ReplicationMode::WaitingForEnrollment;
        state.message = Some(
            "This Mac has a new identity and is waiting for the Mac that created this sync folder to approve it"
                .to_string(),
        );
        Ok(self.status_from(&state))
    }

    fn disable(&self) -> Result<ReplicationStatus, String> {
        let mut state = self.state.lock().expect("replication runtime state poisoned");
        self.persist_directory(&mut state, None)?;
        state.engine = None;
        state.mode = ReplicationMode::Off;
        state.vault_id = None;
        state.last_report = ReplicationReport::default();
        state.message = None;
        Ok(self.status_from(&state))
    }

    fn enrollment(&self) -> Result<ControlReplicationEnrollment, String> {
        let enrollment = self.store.device().enrollment_named(local_device_name());
        Ok(control_replication_enrollment(enrollment))
    }

    fn approve(&self, device_id: &str) -> Result<ReplicationStatus, String> {
        let mut state = self.state.lock().expect("replication runtime state poisoned");
        let engine = state
            .engine
            .as_mut()
            .ok_or_else(|| "replication is not active on this Mac".to_string())?;
        engine.enroll_requested(device_id).map_err(|error| error.to_string())?;
        let report = Self::run_sync(engine).map_err(|error| error.to_string())?;
        Ok(self.update_after_sync(&mut state, report))
    }

    fn enroll(
        &self,
        enrollment: ControlReplicationEnrollment,
    ) -> Result<ReplicationStatus, String> {
        let mut state = self.state.lock().expect("replication runtime state poisoned");
        let engine = state
            .engine
            .as_mut()
            .ok_or_else(|| "replication is not active on this Mac".to_string())?;
        engine
            .enroll_device(DeviceEnrollment {
                device_id: enrollment.device_id,
                signing_public_key: enrollment.signing_public_key,
                wrapping_recipient: enrollment.wrapping_recipient,
                device_name: enrollment.device_name,
            })
            .map_err(|error| error.to_string())?;
        Ok(self.status_from(&state))
    }
}

impl ManagedMutationObserver for DaemonReplicationService {
    fn managed_mutation_committed(&self) {
        let mut state = self.state.lock().expect("replication runtime state poisoned");
        if state.mode != ReplicationMode::Active {
            return;
        }
        let Some(engine) = state.engine.as_ref() else { return };
        if let Err(error) = engine.stage_committed_snapshot(&replication_timestamp()) {
            tracing::error!(%error, "staging committed state for replication failed");
            state.mode = ReplicationMode::Error;
            state.message = Some(error.to_string());
        }
    }
}

fn control_replication_enrollment(enrollment: DeviceEnrollment) -> ControlReplicationEnrollment {
    ControlReplicationEnrollment {
        device_id: enrollment.device_id,
        signing_public_key: enrollment.signing_public_key,
        wrapping_recipient: enrollment.wrapping_recipient,
        device_name: enrollment.device_name,
    }
}

fn local_device_name() -> Option<String> {
    let mut buffer = [0 as libc::c_char; 256];
    if unsafe { libc::gethostname(buffer.as_mut_ptr(), buffer.len() - 1) } != 0 {
        return None;
    }
    let value = unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_string_lossy();
    let value = value.trim();
    let value = value.strip_suffix(".local").unwrap_or(value).trim();
    if value.is_empty() || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.chars().take(80).collect())
}

fn replication_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

struct StoreManagedKeyReader {
    store: Arc<dyn SecretStore>,
}

impl floria_agent::ManagedKeyReader for StoreManagedKeyReader {
    fn read_private_key(&self, secret_id: &str) -> std::io::Result<zeroize::Zeroizing<Vec<u8>>> {
        let id = secret_id
            .parse::<SecretId>()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        self.store
            .get(&id)
            .map_err(std::io::Error::other)
    }
}

impl SshIdentityDiscovery for AgentSshIdentityDiscovery {
    fn discover(&self, endpoint: &Path) -> std::io::Result<Vec<SshIdentity>> {
        floria_agent::discover_identities(endpoint).map(|identities| {
            identities
                .into_iter()
                .map(|identity| SshIdentity {
                    address: identity.address,
                    fingerprint: identity.fingerprint,
                    comment: identity.comment,
                })
                .collect()
        })
    }
}

impl RuntimePolicyController for AgentPolicyController {
    fn policy_mode(&self) -> PolicyModeStatus {
        self.agent.policy_mode()
    }

    fn set_policy_mode(
        &self,
        mode: PolicyMode,
        duration_secs: Option<u64>,
    ) -> std::io::Result<PolicyModeStatus> {
        self.agent.set_policy_mode(mode, duration_secs)
    }

    fn active_grants(&self) -> std::io::Result<Vec<ControlActiveGrant>> {
        self.agent.active_grants().map(|grants| {
            grants
                .into_iter()
                .map(|grant| ControlActiveGrant {
                    id: grant.id,
                    subject: grant.subject,
                    object: grant.object,
                    operation: grant.operation.as_str().to_string(),
                    enforcement: grant.enforcement,
                    expires_at: grant.expires_at,
                    client: grant.metadata.client,
                    executable: grant.metadata.executable,
                    bundle_id: grant.metadata.bundle_id,
                    target: grant.metadata.target,
                })
                .collect()
        })
    }

    fn revoke_grant(&self, id: &str) -> std::io::Result<bool> {
        self.agent.revoke_grant(id)
    }

    fn clear_grants(&self) -> std::io::Result<()> {
        self.agent.clear_grants()
    }
}

struct RuntimeCatalogObserver {
    surface_registry: Arc<SurfaceRegistry>,
    mount_path: PathBuf,
    store: Arc<dyn SecretStore>,
    agent: Arc<floria_agent::SocketAgent>,
    ssh_runtime: Arc<floria_agent::SshAgentRuntime>,
    linked_file_surfaces: Mutex<Vec<Surface>>,
    linked_protected_files: Mutex<Vec<ProtectedCheckoutLink>>,
    checkout_monitor: Arc<GitCheckoutMonitor>,
}

impl CatalogObserver for RuntimeCatalogObserver {
    fn catalog_changed(&self, snapshot: &CatalogSnapshot) {
        self.checkout_monitor
            .replace_projects(monitored_git_projects(snapshot));
        let next_links = match file_surface_instances(snapshot) {
            Ok(links) => links,
            Err(error) => {
                tracing::warn!(%error, "materializing project checkout links failed");
                return;
            }
        };
        let mut previous_links = self
            .linked_file_surfaces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cleanup_removed_file_links(&previous_links, &next_links, &self.mount_path);
        let records = self.store.list();
        if let Ok(records) = &records {
            if let Err(error) = release_protected_links_for_file_surfaces(
                snapshot,
                records,
                &next_links,
                &self.mount_path,
            ) {
                tracing::warn!(
                    %error,
                    "transitioning protected worktree links to configured surfaces failed"
                );
            }
            let next_protected_files =
                protected_checkout_links(snapshot, records, &self.mount_path);
            let mut previous_protected_files = self
                .linked_protected_files
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Err(error) = refresh_protected_checkout_links(
                &mut previous_protected_files,
                next_protected_files,
                self.store.as_ref(),
            ) {
                tracing::warn!(%error, "refreshing protected worktree links failed");
            }
        } else if let Err(error) = &records {
            tracing::warn!(%error, "listing protected files for runtime refresh failed");
        }
        self.surface_registry.replace(snapshot);
        reconcile_file_links(snapshot, &next_links, &self.mount_path);
        *previous_links = next_links;
        drop(previous_links);
        if let Err(error) = self.ssh_runtime.replace(snapshot) {
            tracing::warn!(%error, "refreshing SSH agent surfaces failed");
        }
        if let Ok(records) = records {
            self.agent
                .replace_managed_policy(managed_policy_items(snapshot, &records));
        }
    }
}

fn monitored_git_projects(snapshot: &CatalogSnapshot) -> Vec<MonitoredGitProject> {
    snapshot
        .projects
        .iter()
        .map(|project| MonitoredGitProject {
            id: project.id.clone(),
            root: project.path.clone(),
        })
        .collect()
}

fn managed_policy_items(
    snapshot: &CatalogSnapshot,
    records: &[SecretRecord],
) -> Vec<ManagedPolicyItem> {
    let mut items = Vec::new();
    let configured_secret_ids = snapshot.file_surface_secret_ids();

    // File-origin secrets are independently managed items. Managed-origin secrets inherit from
    // their Resource below. Once a file is explicitly configured, its Resource owns this policy
    // so the former byte-preserving file does not remain as a hidden stricter rule.
    for record in records.iter().filter(|record| {
        record.source_path().is_some() && !configured_secret_ids.contains(record.id.as_str())
    }) {
        items.push(ManagedPolicyItem {
            object: ManagedObject::Secret { secret_id: record.id.to_string() },
            enforcement: record.enforcement,
        });
    }

    for resource in &snapshot.resources {
        if matches!(resource.kind, ResourceKind::SshIdentity | ResourceKind::SshAgent) {
            items.push(ManagedPolicyItem {
                object: ManagedObject::SshResource { resource_id: resource.id.clone() },
                enforcement: resource.enforcement,
            });
        }
        let ResourceSource::SecretRef { secret_id } = &resource.source else { continue };
        items.push(ManagedPolicyItem {
            object: ManagedObject::Secret { secret_id: secret_id.clone() },
            enforcement: resource.enforcement,
        });
    }

    for surface in &snapshot.surfaces {
        items.push(ManagedPolicyItem {
            object: ManagedObject::Surface {
                surface_id: surface.id.clone(),
                item_id: snapshot.managed_item_id_for_surface(surface).to_string(),
            },
            enforcement: surface.enforcement,
        });
    }

    items
}

fn cleanup_removed_file_links(
    previous: &[Surface],
    current: &[Surface],
    mount_path: &Path,
) {
    for surface in previous {
        let still_present = current.iter().any(|current| {
            current.id == surface.id
                && current.path == surface.path
                && current.kind.is_file()
        });
        if still_present {
            continue;
        }
        let path = surface.path.as_deref().expect("file surface has a project path");
        match remove_file_surface_link(surface, mount_path) {
            Ok(SurfaceLinkRemoval::Removed) => tracing::info!(
                surface = %surface.id,
                path = %path.display(),
                "removed project surface link"
            ),
            Ok(SurfaceLinkRemoval::Missing | SurfaceLinkRemoval::Preserved) => {}
            Err(error) => tracing::warn!(
                surface = %surface.id,
                path = %path.display(),
                %error,
                "removed surface link needs attention"
            ),
        }
    }
}

fn reconcile_file_links(
    snapshot: &CatalogSnapshot,
    surfaces: &[Surface],
    mount_path: &Path,
) {
    for surface in surfaces {
        let path = surface.path.as_deref().expect("file surface has a project path");
        match ensure_file_surface_link_in_snapshot(snapshot, surface, mount_path) {
            Ok(SurfaceLinkState::Created) => tracing::info!(
                surface = %surface.id,
                path = %path.display(),
                "created project surface link"
            ),
            Ok(SurfaceLinkState::Ready) => tracing::debug!(
                surface = %surface.id,
                path = %path.display(),
                "project surface link is ready"
            ),
            Err(error) => tracing::warn!(
                surface = %surface.id,
                path = %path.display(),
                %error,
                "project surface link needs attention"
            ),
        }
    }
}

fn cmd_sync(command: SyncCmd, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let mut client = connect_control(&cfg)?;
    let command = match command {
        SyncCmd::Status => ControlCommand::ReplicationStatus,
        SyncCmd::Create { directory } => ControlCommand::ReplicationCreate {
            directory: absolute_cli_path(&directory)?,
        },
        SyncCmd::Open { directory } => ControlCommand::ReplicationOpen {
            directory: absolute_cli_path(&directory)?,
        },
        SyncCmd::Now => ControlCommand::ReplicationSync,
        SyncCmd::ResolveCurrent => ControlCommand::ReplicationResolveWithCurrent,
        SyncCmd::RemoveDevice { device_id } => {
            ControlCommand::ReplicationRevokeDevice { device_id }
        }
        SyncCmd::RequestAccessAgain => ControlCommand::ReplicationRequestReenrollment,
        SyncCmd::Disable => ControlCommand::ReplicationDisable,
        SyncCmd::Enrollment => ControlCommand::ReplicationEnrollment,
        SyncCmd::Enroll { request } => {
            let bytes = std::fs::read(&request)
                .with_context(|| format!("reading enrollment request {}", request.display()))?;
            let enrollment = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing enrollment request {}", request.display()))?;
            ControlCommand::ReplicationEnroll { enrollment }
        }
    };
    match client.request(command)? {
        ControlResult::ReplicationStatus(status) => {
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        ControlResult::ReplicationEnrollment(enrollment) => {
            println!("{}", serde_json::to_string_pretty(&enrollment)?);
            Ok(())
        }
        result => anyhow::bail!("daemon returned an unexpected replication response: {result:?}"),
    }
}

fn cmd_control(command: ControlCmd, socket: Option<PathBuf>, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let mut client = match socket {
        Some(socket) => ControlClient::connect(&socket)
            .with_context(|| format!("connecting to control socket {}", socket.display()))?,
        None => connect_control(&cfg)?,
    };
    let command = match command {
        ControlCmd::Ping => ControlCommand::Ping,
        ControlCmd::Health => ControlCommand::Health,
        ControlCmd::Policy { mode: None, duration_secs: None } => ControlCommand::PolicyModeGet,
        ControlCmd::Policy { mode: None, duration_secs: Some(_) } => {
            anyhow::bail!("--duration-secs requires a policy mode")
        }
        ControlCmd::Policy { mode: Some(mode), duration_secs } => {
            ControlCommand::PolicyModeSet { mode: mode.into(), duration_secs }
        }
        ControlCmd::Snapshot => ControlCommand::Snapshot,
        ControlCmd::Discover { path, apply } => {
            let path = std::fs::canonicalize(&path)
                .with_context(|| format!("resolving discovery path {}", path.display()))?;
            if apply {
                ControlCommand::DiscoverApply {
                    paths: vec![path],
                    imports: None,
                    separate_entries: Vec::new(),
                    promote_entries: Vec::new(),
                    demote_entries: Vec::new(),
                }
            } else {
                ControlCommand::Discover { paths: vec![path] }
            }
        }
        ControlCmd::Resolve { project_id, environment_id } => {
            ControlCommand::ResolveEnvironment { project_id, environment_id }
        }
        ControlCmd::Usage { resource_id } => ControlCommand::ResourceUsage { resource_id },
        ControlCmd::SshDiscover { endpoint } => ControlCommand::SshAgentDiscover { endpoint },
    };
    match client.request(command)? {
        ControlResult::Pong {
            protocol_version,
            daemon_version,
            schema_version,
            minimum_schema_version,
            store_format_version,
            minimum_store_format_version,
        } => {
            println!(
                "daemon v{daemon_version} ready; control protocol v{protocol_version}; catalog schema v{schema_version} (supports {minimum_schema_version}..={schema_version}); store format v{store_format_version} (supports {minimum_store_format_version}..={store_format_version})"
            );
        }
        ControlResult::Health(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ControlResult::PolicyMode(status) => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        ControlResult::ActiveGrants(grants) => {
            println!("{}", serde_json::to_string_pretty(&grants)?);
        }
        ControlResult::AccessHistory(events) => {
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        ControlResult::Backup(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ControlResult::RecoveryKey(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ControlResult::Diagnostics(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ControlResult::ReplicationStatus(status) => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        ControlResult::ReplicationEnrollment(enrollment) => {
            println!("{}", serde_json::to_string_pretty(&enrollment)?);
        }
        ControlResult::RecordSyncStatus(status) => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        ControlResult::RecordSyncOutbound(batch) => {
            println!("{}", serde_json::to_string_pretty(&batch)?);
        }
        ControlResult::RecordSyncSettlement(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ControlResult::RecordSyncInbound(report) => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        ControlResult::Snapshot(snapshot) => {
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        }
        ControlResult::Discovery(plan) => {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        ControlResult::DiscoveryJob(status) => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        ControlResult::DiscoveryApplied(result) => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        ControlResult::DiscoveryReferenceResolved(result) => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        ControlResult::ProjectCheckoutInventory(result) => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        ControlResult::ProjectCheckoutDiscovery(result) => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        ControlResult::SshAgentIdentities(identities) => {
            println!("{}", serde_json::to_string_pretty(&identities)?);
        }
        ControlResult::SshIdentityCreated { resource } => {
            println!("created managed SSH identity {}", resource.id);
        }
        ControlResult::SshConfig(status) => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        ControlResult::ProtectedFiles(files) => {
            println!("{}", serde_json::to_string_pretty(&files)?);
        }
        ControlResult::ProtectedFile(file) => {
            println!("{}", serde_json::to_string_pretty(&file)?);
        }
        ControlResult::FileProtected { file, created } => {
            let action = if created { "protected" } else { "already protected" };
            println!("{action} {} as {}", file.source_path.display(), file.id);
        }
        ControlResult::ProtectedFileHistory { id, versions } => {
            println!("{}", serde_json::to_string_pretty(&(id, versions))?);
        }
        ControlResult::ProtectedFileRolledBack { file } => {
            println!("{} now points to version {}", file.id, file.current_version);
        }
        ControlResult::ProtectedFileUpdated { file } => {
            println!("updated {} to version {}", file.id, file.current_version);
        }
        ControlResult::ManagedFileConfigured { surface } => {
            let path = surface.path.expect("configured file surface has a project path");
            println!("configured {} as {}", path.display(), surface.id);
        }
        ControlResult::FileRestored { path, storage_deleted } => {
            println!("restored {} (history deleted: {storage_deleted})", path.display());
        }
        ControlResult::ResolvedEnvironment(resolved) => {
            println!("{}", serde_json::to_string_pretty(&resolved)?);
        }
        ControlResult::ResourceUsage(usage) => {
            println!("{}", serde_json::to_string_pretty(&usage)?);
        }
        ControlResult::SharedSecretCreated { resource, version } => {
            println!("created shared secret resource {} at version {version}", resource.id);
        }
        ControlResult::SharedSecretRotated { resource_id, version } => {
            println!("rotated shared secret resource {resource_id} to version {version}");
        }
        ControlResult::EnvFileCreated { resource, version } => {
            println!("created env file resource {} at version {version}", resource.id);
        }
        ControlResult::Empty => anyhow::bail!("daemon returned an empty control response"),
    }
    Ok(())
}

fn support_dir(cfg: &ResolvedConfig) -> Result<&Path> {
    cfg.agent_socket.parent().with_context(|| {
        format!("agent socket has no parent directory: {}", cfg.agent_socket.display())
    })
}

fn bundled_gui_executable(daemon_executable: &Path) -> Option<PathBuf> {
    let resources = daemon_executable.parent()?;
    if resources.file_name()? != "Resources" {
        return None;
    }
    let contents = resources.parent()?;
    if contents.file_name()? != "Contents" {
        return None;
    }
    Some(contents.join("MacOS/Floria"))
}

fn trusted_gui_executable(daemon_executable: &Path) -> Result<PathBuf> {
    if let Some(path) = bundled_gui_executable(daemon_executable) {
        if path.is_file() {
            return Ok(path);
        }
    }

    if let Some(path) = std::env::var_os("FLORIA_TRUSTED_GUI_EXECUTABLE").map(PathBuf::from) {
        if path.is_file() {
            return Ok(path);
        }
        anyhow::bail!(
            "FLORIA_TRUSTED_GUI_EXECUTABLE does not point to a file: {}",
            path.display()
        );
    }

    let installed = PathBuf::from("/Applications/Floria.app/Contents/MacOS/Floria");
    if installed.is_file() {
        return Ok(installed);
    }

    anyhow::bail!(
        "could not locate the trusted Floria GUI executable; install Floria.app or set \
         FLORIA_TRUSTED_GUI_EXECUTABLE for an unbundled development run"
    )
}

const GUI_CODE_IDENTIFIER: &str = "floria.hola.ac";
const DAEMON_CODE_IDENTIFIER: &str = "floria.hola.ac.daemon";

fn local_peer_verifiers(
) -> Result<(Arc<dyn SocketPeerVerifier>, Arc<dyn SocketPeerVerifier>)> {
    if let Some(team_id) = option_env!("FLORIA_SIGNING_TEAM_ID") {
        validate_team_id(team_id)?;
        let gui_requirement = product_code_requirement(GUI_CODE_IDENTIFIER, team_id);
        let daemon_requirement = product_code_requirement(DAEMON_CODE_IDENTIFIER, team_id);
        let agent: Arc<dyn SocketPeerVerifier> = Arc::new(
            CodeSignedPeerVerifier::from_requirements([(
                GUI_CODE_IDENTIFIER,
                gui_requirement.clone(),
                PeerAccess::Full,
            )])
            .context("building agent socket peer policy")?,
        );
        let control: Arc<dyn SocketPeerVerifier> = Arc::new(
            CodeSignedPeerVerifier::from_requirements([
                (GUI_CODE_IDENTIFIER, gui_requirement, PeerAccess::Full),
                (
                    DAEMON_CODE_IDENTIFIER,
                    daemon_requirement,
                    PeerAccess::ReadOnly,
                ),
            ])
            .context("building control socket peer policy")?,
        );
        tracing::info!(team_id, "loaded embedded production socket code-signing policy");
        return Ok((agent, control));
    }

    if option_env!("FLORIA_INSECURE_DEVELOPMENT_BUILD") != Some("1") {
        anyhow::bail!(
            "this build has no embedded Floria signing Team ID; refusing to derive socket trust \
             from mutable executable paths. Build a signed release with FLORIA_SIGNING_TEAM_ID, \
             or use scripts/build-app for an explicitly insecure local development build"
        );
    }

    let daemon_executable =
        std::env::current_exe().context("resolving daemon executable for development peer policy")?;
    let gui_executable = trusted_gui_executable(&daemon_executable)?;
    let agent: Arc<dyn SocketPeerVerifier> = Arc::new(
        CodeSignedPeerVerifier::from_executables_for_development([(
            &gui_executable,
            PeerAccess::Full,
        )])
            .context("building development agent socket peer policy")?,
    );
    let control: Arc<dyn SocketPeerVerifier> = Arc::new(
        CodeSignedPeerVerifier::from_executables_for_development([
            (&gui_executable, PeerAccess::Full),
            (&daemon_executable, PeerAccess::Full),
        ])
        .context("building development control socket peer policy")?,
    );
    tracing::warn!(
        gui = %gui_executable.display(),
        daemon = %daemon_executable.display(),
        "INSECURE DEVELOPMENT BUILD: socket trust is derived from mutable executable paths"
    );
    Ok((agent, control))
}

fn validate_team_id(team_id: &str) -> Result<()> {
    if team_id.len() == 10
        && team_id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        Ok(())
    } else {
        anyhow::bail!("FLORIA_SIGNING_TEAM_ID must be a 10-character uppercase Apple Team ID")
    }
}

fn product_code_requirement(identifier: &str, team_id: &str) -> String {
    format!(
        "anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team_id}\""
    )
}

fn cmd_unmount(path: Option<PathBuf>, config: &Path) -> Result<()> {
    let target = match path {
        Some(p) => p,
        None => load(config)?.mount_path,
    };
    let Some(mount) = exact_mount(&target)? else {
        println!("already unmounted {}", target.display());
        return Ok(());
    };
    if !mount.is_floria() {
        anyhow::bail!(
            "refusing to unmount {} because it is owned by {:?} ({:?}), not Floria",
            target.display(),
            mount.source,
            mount.fs_type
        );
    }
    unmount_target(&target)?;
    println!("unmounted {}", target.display());
    Ok(())
}

fn unmount_target(target: &Path) -> Result<()> {
    // Prefer diskutil (cleaner for macFUSE volumes), fall back to umount.
    let ok = run("diskutil", &["unmount", &target.to_string_lossy()])
        || run("umount", &[&target.to_string_lossy()]);
    if ok {
        Ok(())
    } else {
        anyhow::bail!("failed to unmount {}", target.display())
    }
}

struct DaemonInstance {
    _lock: File,
}

impl DaemonInstance {
    fn acquire(support_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(support_dir)
            .with_context(|| format!("creating support directory {}", support_dir.display()))?;
        std::fs::set_permissions(support_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("securing support directory {}", support_dir.display()))?;

        let lock_path = support_dir.join("daemon.lock");
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .with_context(|| format!("opening daemon lock {}", lock_path.display()))?;
        validate_daemon_lock(&lock, &lock_path)?;

        match lock.try_lock() {
            Ok(()) => Ok(Self { _lock: lock }),
            Err(std::fs::TryLockError::WouldBlock) => {
                anyhow::bail!("another floria daemon is already running")
            }
            Err(std::fs::TryLockError::Error(error)) => {
                Err(error).with_context(|| format!("locking daemon instance {}", lock_path.display()))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonLockState {
    Free,
    Held,
}

fn daemon_lock_state(support_dir: &Path) -> Result<DaemonLockState> {
    let lock_path = support_dir.join("daemon.lock");
    let lock = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
    {
        Ok(lock) => lock,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DaemonLockState::Free);
        }
        Err(error) => {
            return Err(error).with_context(|| format!("opening daemon lock {}", lock_path.display()));
        }
    };
    validate_daemon_lock(&lock, &lock_path)?;
    match lock.try_lock() {
        Ok(()) => Ok(DaemonLockState::Free),
        Err(std::fs::TryLockError::WouldBlock) => Ok(DaemonLockState::Held),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(error).with_context(|| format!("inspecting daemon lock {}", lock_path.display()))
        }
    }
}

fn validate_daemon_lock(lock: &File, path: &Path) -> Result<()> {
    let metadata = lock
        .metadata()
        .with_context(|| format!("inspecting daemon lock {}", path.display()))?;
    if metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o077 == 0
    {
        return Ok(());
    }
    anyhow::bail!(
        "daemon lock must be a private regular file owned by the current user: {}",
        path.display()
    )
}

#[derive(Debug, PartialEq, Eq)]
struct MountedFilesystem {
    source: OsString,
    fs_type: OsString,
}

impl MountedFilesystem {
    fn is_floria(&self) -> bool {
        self.source == "floria" && self.fs_type == "macfuse"
    }
}

fn exact_mount(path: &Path) -> Result<Option<MountedFilesystem>> {
    let path_bytes = path.as_os_str().as_bytes();
    let c_path = CString::new(path_bytes)
        .with_context(|| format!("mount path contains a NUL byte: {}", path.display()))?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::statfs(c_path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("inspecting mount point {}", path.display()));
    }
    let stats = unsafe { stats.assume_init() };
    let mounted_at = unsafe { CStr::from_ptr(stats.f_mntonname.as_ptr()) };
    if mounted_at.to_bytes() != path_bytes {
        return Ok(None);
    }

    let source = unsafe { CStr::from_ptr(stats.f_mntfromname.as_ptr()) };
    let fs_type = unsafe { CStr::from_ptr(stats.f_fstypename.as_ptr()) };
    Ok(Some(MountedFilesystem {
        source: OsString::from_vec(source.to_bytes().to_vec()),
        fs_type: OsString::from_vec(fs_type.to_bytes().to_vec()),
    }))
}

fn recover_stale_mount(path: &Path) -> Result<()> {
    let Some(mount) = exact_mount(path)? else {
        return Ok(());
    };
    if !mount.is_floria() {
        anyhow::bail!(
            "mount point {} is occupied by {:?} ({:?}); refusing to unmount it",
            path.display(),
            mount.source,
            mount.fs_type
        );
    }

    tracing::warn!(
        mount = %path.display(),
        "recovering stale floria mount left by a previous daemon"
    );
    unmount_target(path).context("recovering stale floria mount")
}

fn cmd_doctor(config: &Path) -> Result<()> {
    let mut ok = true;

    // 1. Is macFUSE installed.
    let macfuse = Path::new("/Library/Filesystems/macfuse.fs").exists();
    report("macFUSE installed", macfuse, "/Library/Filesystems/macfuse.fs not found; run `brew install --cask macfuse` and approve the kext");
    ok &= macfuse;
    if macfuse {
        let kernel_backend = macfuse_kernel_backend_ready_in(Path::new("/dev"));
        report(
            "macFUSE kernel backend ready",
            kernel_backend,
            "macFUSE is installed but its kernel device is absent; on Apple silicon, enable third-party kernel extensions in recoveryOS, return to Floria and recheck, then approve macFUSE and restart when macOS asks",
        );
        ok &= kernel_backend;
    }

    // 2. Whether the config loads (including permission checks).
    match load(config) {
        Ok(cfg) => {
            report("config loads", true, "");
            let mp_ok = cfg
                .mount_path
                .parent()
                .map(|p| p.exists())
                .unwrap_or(false);
            report(
                "mount point parent exists",
                mp_ok,
                &format!("parent directory of {} does not exist", cfg.mount_path.display()),
            );
            ok &= mp_ok;

            let (provider, key_source) = store_key_provider(&cfg);
            match provider.recipients() {
                Ok(_) => report(&format!("store key source ({key_source})"), true, ""),
                Err(error) => {
                    report(
                        &format!("store key source ({key_source})"),
                        false,
                        &error.to_string(),
                    );
                    ok = false;
                }
            }

            match validate_existing_audit_log(&cfg.audit_log) {
                Ok(()) => report("audit log permissions", true, ""),
                Err(error) => {
                    report("audit log permissions", false, &format!("{error:#}"));
                    ok = false;
                }
            }

            match (support_dir(&cfg), exact_mount(&cfg.mount_path)) {
                (Ok(support_dir), Ok(mount)) => {
                    match (daemon_lock_state(support_dir), mount) {
                        (Ok(DaemonLockState::Held), Some(mount)) if mount.is_floria() => {
                            report("daemon lifecycle (running)", true, "");
                        }
                        (Ok(DaemonLockState::Free), None) => {
                            report("daemon lifecycle (not running; mount path free)", true, "");
                        }
                        (Ok(DaemonLockState::Free), Some(mount)) if mount.is_floria() => {
                            report(
                                "daemon lifecycle",
                                false,
                                "stale Floria macFUSE mount found without a live daemon",
                            );
                            ok = false;
                        }
                        (Ok(DaemonLockState::Held), None) => {
                            report(
                                "daemon lifecycle",
                                false,
                                "daemon lock is held but the configured mount is absent",
                            );
                            ok = false;
                        }
                        (Ok(_), Some(mount)) => {
                            report(
                                "daemon lifecycle",
                                false,
                                &format!(
                                    "mount point is occupied by {:?} ({:?})",
                                    mount.source, mount.fs_type
                                ),
                            );
                            ok = false;
                        }
                        (Err(error), _) => {
                            report("daemon lifecycle", false, &format!("{error:#}"));
                            ok = false;
                        }
                    }
                }
                (Err(error), _) | (_, Err(error)) => {
                    report("daemon lifecycle", false, &format!("{error:#}"));
                    ok = false;
                }
            }

            println!("  resolved {} virtual file(s):", cfg.files.len());
            for f in &cfg.files {
                let kind = match f.source.storage_disposition() {
                    floria_core::source::StorageDisposition::InlinePlaintext => {
                        format!("inline, {} bytes", f.source.exact_size().unwrap_or(0))
                    }
                    floria_core::source::StorageDisposition::Computed => {
                        format!("computed, up to {} bytes", f.declared_size.unwrap_or(0))
                    }
                    floria_core::source::StorageDisposition::EncryptedReference => {
                        "encrypted reference".to_string()
                    }
                };
                println!("    - {}  ({kind})", f.path);
            }
        }
        Err(e) => {
            report("config loads", false, &format!("{e:#}"));
            ok = false;
        }
    }

    if ok {
        println!("\nall checks passed ✓");
        Ok(())
    } else {
        anyhow::bail!("doctor found problems (see above)")
    }
}

fn validate_existing_audit_log(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting audit log {}", path.display()));
        }
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        anyhow::bail!("audit log must be a regular file: {}", path.display());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        anyhow::bail!(
            "audit log must be owned by the current user: {}",
            path.display()
        );
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "audit log must be private, found mode {mode:04o}: {}; run `chmod 600 {}`",
            path.display(),
            shell_quote(path)
        );
    }
    Ok(())
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn macfuse_kernel_backend_ready_in(device_directory: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(device_directory) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| is_macfuse_device_name(&entry.file_name()))
}

fn is_macfuse_device_name(name: &std::ffi::OsStr) -> bool {
    let bytes = name.as_bytes();
    let Some(suffix) = bytes.strip_prefix(b"macfuse") else {
        return false;
    };
    !suffix.is_empty() && suffix.iter().all(|byte| byte.is_ascii_digit())
}

fn report(name: &str, ok: bool, hint: &str) {
    let mark = if ok { "✓" } else { "✗" };
    if ok || hint.is_empty() {
        println!("  [{mark}] {name}");
    } else {
        println!("  [{mark}] {name} — {hint}");
    }
}

fn run(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use floria_catalog::{
        Binding, BindingScope, EntrySelection, EntrySpec, FileBacking, Resource, ResourceCodec,
        ResourceKind, SurfaceFormat, SurfaceInput, SurfaceKind, ValueShape,
    };
    use floria_core::authz::Enforcement;
    use floria_store::SecretOrigin;
    use ssh_key::{Algorithm, LineEnding, PrivateKey};

    fn test_store_key(directory: &Path) -> Arc<dyn floria_store::KeyProvider> {
        let path = directory.join("id_ed25519");
        let private = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)
            .unwrap();
        std::fs::write(&path, private.to_openssh(LineEnding::LF).unwrap()).unwrap();
        std::fs::write(
            path.with_extension("pub"),
            private.public_key().to_openssh().unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        Arc::new(SshKeyProvider::new(path, None))
    }

    fn resource(id: &str, secret_id: &str, enforcement: Enforcement) -> Resource {
        Resource {
            id: id.to_string(),
            name: id.to_string(),
            kind: ResourceKind::SharedSecret,
            shape: ValueShape::Scalar,
            codec: ResourceCodec::Opaque,
            default_env_key: Some(id.to_uppercase()),
            entries: vec![EntrySpec {
                address: "value".to_string(),
                label: id.to_string(),
                key: Some(id.to_uppercase()),
                sensitive: true,
            }],
            source: ResourceSource::SecretRef { secret_id: secret_id.to_string() },
            enforcement,
            metadata: Default::default(),
            origin: Default::default(),
        }
    }

    fn binding(id: &str, resource_id: &str) -> Binding {
        Binding {
            id: id.to_string(),
            project_id: "fixture-project".to_string(),
            scope: BindingScope::Common,
            resource_id: resource_id.to_string(),
            selection: EntrySelection::All,
            key_override: None,
            enabled: true,
            allow_override: false,
            position: 0,
        }
    }

    #[test]
    fn bundled_daemon_resolves_the_gui_in_the_same_app() {
        assert_eq!(
            bundled_gui_executable(Path::new(
                "/Applications/Floria.app/Contents/Resources/floria"
            )),
            Some(PathBuf::from(
                "/Applications/Floria.app/Contents/MacOS/Floria"
            ))
        );
    }

    #[test]
    fn unbundled_daemon_does_not_infer_a_gui_peer() {
        assert_eq!(
            bundled_gui_executable(Path::new("/workspace/floria/target/release/floria")),
            None
        );
    }

    fn parsed_config(args: &[&str]) -> PathBuf {
        match Cli::try_parse_from(args.iter().copied()).unwrap().command {
            Cmd::Mount { config }
            | Cmd::Unmount { config, .. }
            | Cmd::Doctor { config }
            | Cmd::Protect { config, .. }
            | Cmd::Unprotect { config, .. }
            | Cmd::Reveal { config, .. }
            | Cmd::History { config, .. }
            | Cmd::Rollback { config, .. }
            | Cmd::List { config }
            | Cmd::Control { config, .. }
            | Cmd::Sync { config, .. } => config,
            Cmd::Backup { command } => match command {
                BackupCmd::Create { config, .. }
                | BackupCmd::Verify { config, .. }
                | BackupCmd::Restore { config, .. }
                | BackupCmd::Activate { config, .. } => config,
            },
            Cmd::Diagnostics { command } => match command {
                DiagnosticsCmd::Export { config, .. } => config,
            },
            Cmd::Keys { command } => match command {
                KeysCmd::Import { config, .. }
                | KeysCmd::ExportRecovery { config, .. }
                | KeysCmd::ImportRecovery { config, .. } => config,
            },
        }
    }

    #[test]
    fn every_cli_command_uses_the_managed_config_by_default_and_allows_an_override() {
        let commands: &[&[&str]] = &[
            &["floria", "mount"],
            &["floria", "unmount"],
            &["floria", "doctor"],
            &["floria", "protect", "/tmp/.env"],
            &["floria", "unprotect", "/tmp/.env"],
            &["floria", "reveal", "/tmp/.env"],
            &["floria", "history", "/tmp/.env"],
            &["floria", "rollback", "/tmp/.env", "1"],
            &["floria", "list"],
            &["floria", "control", "ping"],
            &["floria", "sync", "status"],
            &["floria", "backup", "create", "/tmp/backup"],
            &["floria", "backup", "verify", "/tmp/backup"],
            &[
                "floria",
                "backup",
                "restore",
                "/tmp/backup",
                "/tmp/restored",
            ],
            &["floria", "backup", "activate", "/tmp/restored"],
            &["floria", "diagnostics", "export", "/tmp/diagnostics"],
            &["floria", "keys", "import"],
            &["floria", "keys", "export-recovery", "/tmp/recovery.age"],
            &["floria", "keys", "import-recovery", "/tmp/recovery.age"],
        ];

        for args in commands {
            assert_eq!(parsed_config(args), default_config_path(), "{args:?}");
        }

        assert_eq!(
            parsed_config(&[
                "floria",
                "doctor",
                "--config",
                "/tmp/custom-floria.toml",
            ]),
            PathBuf::from("/tmp/custom-floria.toml")
        );
    }

    #[test]
    fn replication_runtime_creates_disables_and_reopens_one_portable_package() {
        let directory = tempfile::tempdir().unwrap();
        let keys = test_store_key(directory.path());
        let store = Arc::new(
            AgeDirStore::open(directory.path().join("store"), Arc::clone(&keys)).unwrap(),
        );
        let catalog = Arc::new(Catalog::open(directory.path().join("catalog.sqlite")).unwrap());
        let service = DaemonReplicationService::start(
            directory.path().join("local-replication"),
            Arc::new(floria_integrity::StateAuthenticator::for_tests([91; 32])),
            catalog,
            store,
            Arc::new(floria_surface::ManagedMutationCoordinator::new()),
        )
        .unwrap();
        let package = directory.path().join("Personal.floriavault");

        assert_eq!(service.status().mode, ReplicationMode::Off);
        let created = service.create(&package).unwrap();
        assert_eq!(created.mode, ReplicationMode::Active);
        assert_eq!(created.published, 1);
        assert_eq!(created.devices.len(), 1);
        assert!(created.devices[0].is_current);
        assert!(created.devices[0].is_genesis);
        assert!(package.join("vault.json").is_file());
        assert!(service.enrollment().unwrap().device_id.len() > 30);

        assert_eq!(service.disable().unwrap().mode, ReplicationMode::Off);
        let reopened = service.open(&package).unwrap();
        assert_eq!(reopened.mode, ReplicationMode::Active);
        assert_eq!(reopened.directory.as_deref(), Some(package.as_path()));
        assert_eq!(service.sync().unwrap().mode, ReplicationMode::Active);
    }

    #[test]
    fn replication_directory_watcher_wakes_for_nested_package_changes() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("objects");
        std::fs::create_dir(&nested).unwrap();
        let mut watcher = ReplicationDirectoryWatcher::new().unwrap();
        watcher.replace_directory(Some(directory.path()));

        std::fs::write(nested.join("arrived.age"), b"fixture").unwrap();

        assert!(watcher.wait_for(std::time::Duration::from_secs(5)));
    }

    #[test]
    fn removed_mac_reenrolls_with_a_new_identity_without_touching_its_library() {
        let directory = tempfile::tempdir().unwrap();
        let package = directory.path().join("Personal.floriavault");
        let genesis_root = directory.path().join("genesis");
        let joining_root = directory.path().join("joining");
        std::fs::create_dir_all(&genesis_root).unwrap();
        std::fs::create_dir_all(&joining_root).unwrap();

        let genesis_keys = test_store_key(&genesis_root);
        let genesis_store = Arc::new(
            AgeDirStore::open(genesis_root.join("store"), Arc::clone(&genesis_keys)).unwrap(),
        );
        let genesis_catalog =
            Arc::new(Catalog::open(genesis_root.join("catalog.sqlite")).unwrap());
        let genesis = DaemonReplicationService::start(
            genesis_root.join("replication"),
            Arc::new(floria_integrity::StateAuthenticator::for_tests([92; 32])),
            genesis_catalog,
            genesis_store,
            Arc::new(floria_surface::ManagedMutationCoordinator::new()),
        )
        .unwrap();

        let joining_keys = test_store_key(&joining_root);
        let joining_store = Arc::new(
            AgeDirStore::open(joining_root.join("store"), Arc::clone(&joining_keys)).unwrap(),
        );
        let joining_catalog =
            Arc::new(Catalog::open(joining_root.join("catalog.sqlite")).unwrap());
        let joining = DaemonReplicationService::start(
            joining_root.join("replication"),
            Arc::new(floria_integrity::StateAuthenticator::for_tests([93; 32])),
            Arc::clone(&joining_catalog),
            Arc::clone(&joining_store),
            Arc::new(floria_surface::ManagedMutationCoordinator::new()),
        )
        .unwrap();

        genesis.create(&package).unwrap();
        let first_request = joining.enrollment().unwrap();
        let removed_device_id = first_request.device_id.clone();
        genesis.enroll(first_request).unwrap();
        assert_eq!(joining.open(&package).unwrap().mode, ReplicationMode::Active);

        let local_secret = joining_store
            .put(floria_store::NewSecret::managed("local fixture"), b"still here")
            .unwrap();
        let catalog_before = joining_catalog.snapshot().unwrap();

        genesis.revoke_device(&removed_device_id).unwrap();
        let removed = joining.sync().unwrap();
        assert_eq!(removed.mode, ReplicationMode::Removed);
        assert_eq!(removed.device_id.as_deref(), Some(removed_device_id.as_str()));

        let waiting = joining.request_reenrollment().unwrap();
        assert_eq!(waiting.mode, ReplicationMode::WaitingForEnrollment);
        let replacement_device_id = waiting.device_id.clone().unwrap();
        assert_ne!(replacement_device_id, removed_device_id);
        assert_eq!(joining_catalog.snapshot().unwrap(), catalog_before);
        assert_eq!(joining_store.get(&local_secret).unwrap().as_slice(), b"still here");

        let replacement_request = joining.enrollment().unwrap();
        assert_eq!(replacement_request.device_id, replacement_device_id);
        genesis.enroll(replacement_request).unwrap();

        // The library was written under vault generation 1, which the store already holds; the
        // replacement enrollment adds envelopes for every generation, so rejoining only installs
        // the missing generation 2 key — no re-key, no data loss.
        let rejoined = joining.open(&package).unwrap();
        assert_eq!(rejoined.mode, ReplicationMode::Active);
        assert_eq!(joining_catalog.snapshot().unwrap(), catalog_before);
        assert_eq!(joining_store.get(&local_secret).unwrap().as_slice(), b"still here");
        assert!(joining_store.generation_identity(2).is_ok());
    }

    #[test]
    fn protect_has_one_managed_lifecycle_without_legacy_storage_switches() {
        let protect = Cli::try_parse_from(["floria", "protect", "/tmp/.env"]).unwrap();
        match protect.command {
            Cmd::Protect { path, config } => {
                assert_eq!(path, PathBuf::from("/tmp/.env"));
                assert_eq!(config, default_config_path());
            }
            _ => panic!("expected protect"),
        }

        for flag in ["--link", "--remove", "--force"] {
            assert!(Cli::try_parse_from(["floria", "protect", "/tmp/.env", flag]).is_err());
        }
    }

    #[test]
    fn unprotect_is_an_explicit_plaintext_restore_command() {
        let unprotect = Cli::try_parse_from(["floria", "unprotect", "/tmp/.env"]).unwrap();
        match unprotect.command {
            Cmd::Unprotect { target, config } => {
                assert_eq!(target, "/tmp/.env");
                assert_eq!(config, default_config_path());
            }
            _ => panic!("expected unprotect"),
        }
    }

    #[test]
    fn reveal_lookup_preserves_a_managed_source_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join(".env");
        let mount_target = dir.path().join("mounted-secret");
        std::fs::write(&mount_target, b"fixture").unwrap();
        std::os::unix::fs::symlink(&mount_target, &source).unwrap();

        let expected = std::fs::canonicalize(dir.path()).unwrap().join(".env");
        assert_eq!(reveal_lookup_path(&source).unwrap(), expected);
    }

    #[test]
    fn reveal_destination_is_private_exact_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("revealed");
        let plaintext = b"fixture-content\n";

        write_revealed_file(&destination, plaintext, 0o640).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), plaintext);
        assert_eq!(
            std::fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let error = write_revealed_file(&destination, b"replacement", 0o600).unwrap_err();
        assert!(error.to_string().contains("must not already exist"));
        assert_eq!(std::fs::read(&destination).unwrap(), plaintext);
    }

    #[test]
    fn backup_commands_use_the_standard_config_by_default() {
        let create = Cli::try_parse_from(["floria", "backup", "create", "/tmp/floria-backup"])
            .unwrap();
        match create.command {
            Cmd::Backup {
                command: BackupCmd::Create { destination, config },
            } => {
                assert_eq!(destination, PathBuf::from("/tmp/floria-backup"));
                assert_eq!(config, default_config_path());
            }
            _ => panic!("expected backup create"),
        }

        let verify = Cli::try_parse_from(["floria", "backup", "verify", "/tmp/floria-backup"])
            .unwrap();
        match verify.command {
            Cmd::Backup {
                command: BackupCmd::Verify { backup, config },
            } => {
                assert_eq!(backup, PathBuf::from("/tmp/floria-backup"));
                assert_eq!(config, default_config_path());
            }
            _ => panic!("expected backup verify"),
        }

        let restore = Cli::try_parse_from([
            "floria",
            "backup",
            "restore",
            "/tmp/floria-backup",
            "/tmp/floria-restored",
        ])
        .unwrap();
        match restore.command {
            Cmd::Backup {
                command: BackupCmd::Restore { backup, destination, config },
            } => {
                assert_eq!(backup, PathBuf::from("/tmp/floria-backup"));
                assert_eq!(destination, PathBuf::from("/tmp/floria-restored"));
                assert_eq!(config, default_config_path());
            }
            _ => panic!("expected backup restore"),
        }

        let activate =
            Cli::try_parse_from(["floria", "backup", "activate", "/tmp/floria-restored"])
                .unwrap();
        match activate.command {
            Cmd::Backup {
                command: BackupCmd::Activate { restored, config },
            } => {
                assert_eq!(restored, PathBuf::from("/tmp/floria-restored"));
                assert_eq!(config, default_config_path());
            }
            _ => panic!("expected backup activate"),
        }
    }

    #[test]
    fn diagnostics_export_is_redacted_by_default_and_requires_an_explicit_path_opt_in() {
        let redacted = Cli::try_parse_from([
            "floria",
            "diagnostics",
            "export",
            "/tmp/Floria Diagnostics",
        ])
        .unwrap();
        match redacted.command {
            Cmd::Diagnostics {
                command:
                    DiagnosticsCmd::Export {
                        destination,
                        include_paths,
                        config,
                    },
            } => {
                assert_eq!(destination, PathBuf::from("/tmp/Floria Diagnostics"));
                assert!(!include_paths);
                assert_eq!(config, default_config_path());
            }
            _ => panic!("expected diagnostics export"),
        }

        let with_paths = Cli::try_parse_from([
            "floria",
            "diagnostics",
            "export",
            "/tmp/diagnostics",
            "--include-paths",
        ])
        .unwrap();
        assert!(matches!(
            with_paths.command,
            Cmd::Diagnostics {
                command: DiagnosticsCmd::Export { include_paths: true, .. },
            }
        ));
    }

    #[test]
    fn recovery_key_commands_use_explicit_files_and_the_standard_config() {
        let export =
            Cli::try_parse_from(["floria", "keys", "export-recovery", "/tmp/recovery.age"])
                .unwrap();
        match export.command {
            Cmd::Keys {
                command: KeysCmd::ExportRecovery { destination, config },
            } => {
                assert_eq!(destination, PathBuf::from("/tmp/recovery.age"));
                assert_eq!(config, default_config_path());
            }
            _ => panic!("expected recovery export"),
        }

        let import =
            Cli::try_parse_from(["floria", "keys", "import-recovery", "/tmp/recovery.age"])
                .unwrap();
        match import.command {
            Cmd::Keys {
                command: KeysCmd::ImportRecovery { source, config },
            } => {
                assert_eq!(source, PathBuf::from("/tmp/recovery.age"));
                assert_eq!(config, default_config_path());
            }
            _ => panic!("expected recovery import"),
        }
    }

    #[test]
    fn daemon_instance_lock_refuses_a_second_live_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let first = DaemonInstance::acquire(dir.path()).unwrap();
        assert_eq!(daemon_lock_state(dir.path()).unwrap(), DaemonLockState::Held);

        let error = DaemonInstance::acquire(dir.path()).err().unwrap();
        assert!(error.to_string().contains("already running"));

        drop(first);
        assert_eq!(daemon_lock_state(dir.path()).unwrap(), DaemonLockState::Free);
        DaemonInstance::acquire(dir.path()).unwrap();
    }

    #[test]
    fn exact_mount_distinguishes_a_directory_from_its_containing_volume() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(exact_mount(dir.path()).unwrap(), None);

        let root = exact_mount(Path::new("/")).unwrap().unwrap();
        assert!(!root.source.is_empty());
        assert!(!root.fs_type.is_empty());
    }

    #[test]
    fn macfuse_kernel_backend_requires_a_numbered_device_node() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("macfuse"), b"").unwrap();
        std::fs::write(dir.path().join("macfuse-control"), b"").unwrap();
        assert!(!macfuse_kernel_backend_ready_in(dir.path()));

        std::fs::write(dir.path().join("macfuse0"), b"").unwrap();
        assert!(macfuse_kernel_backend_ready_in(dir.path()));
    }

    #[test]
    fn doctor_accepts_a_missing_or_private_audit_log_and_rejects_public_access() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit log.jsonl");

        validate_existing_audit_log(&audit).unwrap();
        std::fs::write(&audit, b"").unwrap();
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o600)).unwrap();
        validate_existing_audit_log(&audit).unwrap();

        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = validate_existing_audit_log(&audit).unwrap_err().to_string();
        assert!(error.contains("found mode 0644"), "{error}");
        assert!(error.contains("chmod 600 '"), "{error}");
    }

    #[test]
    fn unmount_is_idempotent_and_refuses_foreign_filesystems() {
        let dir = tempfile::tempdir().unwrap();
        cmd_unmount(
            Some(dir.path().to_path_buf()),
            Path::new("/fixture/config-is-not-read.toml"),
        )
        .unwrap();

        let error = cmd_unmount(
            Some(PathBuf::from("/")),
            Path::new("/fixture/config-is-not-read.toml"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("not Floria"));
    }

    #[test]
    fn managed_policy_keeps_surface_and_resource_levels_independent() {
        let audit_id = "00000000-0000-0000-0000-000000000201";
        let biometric_id = "00000000-0000-0000-0000-000000000202";
        let protected_id = "00000000-0000-0000-0000-000000000203";
        let ssh_id = "00000000-0000-0000-0000-000000000204";
        let mut ssh_identity = resource("managed-ssh", ssh_id, Enforcement::Prompt);
        ssh_identity.kind = ResourceKind::SshIdentity;
        ssh_identity.shape = ValueShape::SshIdentity;
        ssh_identity.default_env_key = None;
        ssh_identity.entries = vec![EntrySpec {
            address: "ssh/sha256/fixture-managed-identity".to_string(),
            label: "Managed SSH identity".to_string(),
            key: None,
            sensitive: false,
        }];
        let snapshot = CatalogSnapshot {
            resources: vec![
                resource("audit", audit_id, Enforcement::Allow),
                resource("biometric", biometric_id, Enforcement::TouchId),
                ssh_identity,
            ],
            bindings: vec![
                binding("audit-binding", "audit"),
                binding("bio-binding", "biometric"),
            ],
            surfaces: vec![Surface {
                id: "combined".to_string(),
                environment_id: "fixture-environment".to_string(),
                name: ".env".to_string(),
                kind: SurfaceKind::File(FileBacking::Composed(SurfaceFormat::Dotenv)),
                path: Some(PathBuf::from("/fixture/.env")),
                input: SurfaceInput::Bindings {
                    binding_ids: vec!["audit-binding".to_string(), "bio-binding".to_string()],
                },
                enforcement: Enforcement::Allow,
                position: 0,
            }],
            ..Default::default()
        };
        let records = vec![SecretRecord {
            id: protected_id.parse().unwrap(),
            origin: SecretOrigin::File { source_path: PathBuf::from("/fixture/.pgpass") },
            mode: 0o600,
            size: 1,
            created: "fixture-time".to_string(),
            current_version: 1,
            enforcement: Enforcement::Allow,
            environment_ids: None,
            metadata: Default::default(),
        }];

        let items = managed_policy_items(&snapshot, &records);
        assert!(items.contains(&ManagedPolicyItem {
            object: ManagedObject::Secret { secret_id: audit_id.to_string() },
            enforcement: Enforcement::Allow,
        }));
        assert!(items.contains(&ManagedPolicyItem {
            object: ManagedObject::Secret { secret_id: biometric_id.to_string() },
            enforcement: Enforcement::TouchId,
        }));
        assert!(items.contains(&ManagedPolicyItem {
            object: ManagedObject::Secret { secret_id: protected_id.to_string() },
            enforcement: Enforcement::Allow,
        }));
        assert!(items.contains(&ManagedPolicyItem {
            object: ManagedObject::Surface {
                surface_id: "combined".to_string(),
                item_id: "combined".to_string(),
            },
            enforcement: Enforcement::Allow,
        }));
        assert!(items.contains(&ManagedPolicyItem {
            object: ManagedObject::SshResource {
                resource_id: "managed-ssh".to_string(),
            },
            enforcement: Enforcement::Prompt,
        }));
    }

    #[test]
    fn product_peer_requirement_pins_identifier_and_team() {
        let requirement = product_code_requirement("floria.hola.ac", "A1B2C3D4E5");

        assert_eq!(
            requirement,
            "anchor apple generic and identifier \"floria.hola.ac\" and certificate leaf[subject.OU] = \"A1B2C3D4E5\""
        );
        assert!(validate_team_id("A1B2C3D4E5").is_ok());
        assert!(validate_team_id("attacker").is_err());
    }
}
