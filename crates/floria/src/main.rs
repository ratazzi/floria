use std::ffi::{CStr, CString, OsString};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use floria_catalog::{
    Catalog, CatalogSnapshot, ResourceKind, ResourceSource, Surface,
};
use floria_agent::{ManagedObject, ManagedPolicyItem};
use floria_control::{
    ActiveGrant as ControlActiveGrant, BackupReport as ControlBackupReport, BackupService,
    CatalogObserver, ControlClient, ControlCommand, ControlResult, ControlRuntimeServices,
    ControlServer, ManagedSshConfig, RuntimePolicyController, SshConfigManager, SshIdentity,
    SshIdentityDiscovery,
};
use floria_core::audit::AuditLog;
use floria_core::authz::{Authorizer, PolicyMode, PolicyModeStatus};
use floria_core::config::{Config, ResolvedConfig, StoreKeySource};
use floria_discover::{GitCheckoutMonitor, MonitoredGitProject};
use floria_platform::{CodeSignedPeerVerifier, SocketPeerVerifier};
use floria_store::{
    AgeDirStore, KeychainKeyProvider, SecretId, SecretRecord, SecretStore, SshKeyProvider,
};
use floria_surface::{
    ensure_file_surface_link, file_surface_instances, protected_checkout_links,
    refresh_protected_checkout_links, release_protected_links_for_file_surfaces,
    remove_file_surface_link, validate_secret_bytes, ProtectedCheckoutLink, SurfaceLinkRemoval,
    SurfaceLinkState, SurfaceRegistry,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

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
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Unmount the given mount point.
    Unmount {
        /// Mount point path; defaults to the value from config.
        path: Option<PathBuf>,
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Self-check: macFUSE readiness, mount point, config, and content-source permissions.
    Doctor {
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Protect a regular file in place through the running Floria daemon.
    Protect {
        /// File to protect.
        path: PathBuf,
        #[arg(short, long, default_value = "floria.toml")]
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
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Show the version history of a protected secret.
    History {
        /// Original path of the protected file, or its store id.
        target: String,
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Roll back a protected secret's head to an earlier version (repoints; nothing is deleted).
    Rollback {
        /// Original path of the protected file, or its store id.
        target: String,
        /// Version to make current.
        version: u32,
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// List protected secrets.
    List {
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Query the daemon's catalog control plane.
    Control {
        #[command(subcommand)]
        command: ControlCmd,
        /// Override the derived control socket path.
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Create or verify an encrypted backup of all Floria-managed data.
    Backup {
        #[command(subcommand)]
        command: BackupCmd,
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
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Verify checksums, catalog integrity, references, and every encrypted version.
    Verify {
        /// Existing backup directory.
        backup: PathBuf,
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Restore a verified backup into a new standalone data directory.
    Restore {
        /// Existing backup directory.
        backup: PathBuf,
        /// New standalone data directory. Existing paths are never overwritten.
        destination: PathBuf,
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Activate a standalone restored data directory after taking a safety backup.
    Activate {
        /// Standalone data directory created by `backup restore`.
        restored: PathBuf,
        #[arg(short, long, default_value = "floria.toml")]
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
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Export the active store key into a password-encrypted recovery file.
    ExportRecovery {
        /// New recovery-key file. Existing paths are never overwritten.
        destination: PathBuf,
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
    /// Import a password-encrypted recovery key into an empty Keychain-backed store.
    ImportRecovery {
        /// Recovery-key file created by `keys export-recovery`.
        source: PathBuf,
        #[arg(short, long, default_value = "floria.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ControlCmd {
    /// Check that the daemon control socket and catalog schema are available.
    Ping,
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

    match Cli::parse().command {
        Cmd::Mount { config } => cmd_mount(&config),
        Cmd::Unmount { path, config } => cmd_unmount(path, &config),
        Cmd::Doctor { config } => cmd_doctor(&config),
        Cmd::Protect { path, config } => cmd_protect(&path, &config),
        Cmd::Reveal { target, version, to, config } => cmd_reveal(&target, version, to, &config),
        Cmd::History { target, config } => cmd_history(&target, &config),
        Cmd::Rollback { target, version, config } => cmd_rollback(&target, version, &config),
        Cmd::List { config } => cmd_list(&config),
        Cmd::Control { command, socket, config } => cmd_control(command, socket, &config),
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
    let (keys, source) = store_key_provider(cfg);
    tracing::info!(source, "store key source");
    let store = AgeDirStore::open(cfg.store_root.clone(), keys)
        .with_context(|| format!("opening store at {}", cfg.store_root.display()))?;
    Ok(store)
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
    let catalog = Catalog::open(&catalog_path)
        .with_context(|| format!("opening catalog at {}", catalog_path.display()))?;
    let store = open_store(&cfg)?;
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
    let store = open_store(&cfg)?;
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

fn cmd_keys_import(remove_file: bool, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    if matches!(cfg.store_key_source, StoreKeySource::Keychain)
        || matches!(cfg.store_key_source, StoreKeySource::Auto) && !cfg.store_ssh_key.exists()
    {
        anyhow::bail!("the configured store already reads its key from Keychain");
    }
    let key_path = &cfg.store_ssh_key;
    let decrypted = read_ssh_private_key(key_path)?;
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

fn read_ssh_private_key(key_path: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let data = std::fs::read(key_path)
        .with_context(|| format!("reading ssh private key {}", key_path.display()))?;
    let key = ssh_key::PrivateKey::from_openssh(&data[..])
        .with_context(|| format!("parsing ssh private key {}", key_path.display()))?;
    let key = if key.is_encrypted() {
        let passphrase = std::env::var("FLORIA_KEY_PASSPHRASE").context(
            "the key is passphrase-protected; set FLORIA_KEY_PASSPHRASE for the import",
        )?;
        let passphrase = zeroize::Zeroizing::new(passphrase);
        key.decrypt(passphrase.as_bytes())
            .context("decrypting ssh private key (wrong FLORIA_KEY_PASSPHRASE?)")?
    } else {
        key
    };
    let decrypted = key
        .to_openssh(ssh_key::LineEnding::LF)
        .context("re-encoding decrypted ssh private key")?;
    Ok(zeroize::Zeroizing::new(decrypted.as_bytes().to_vec()))
}

fn cmd_keys_export_recovery(destination: &Path, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    open_store(&cfg)?
        .verify_all()
        .context("verifying that the active key decrypts every store version")?;
    let private_key = match cfg.store_key_source {
        StoreKeySource::Ssh => read_ssh_private_key(&cfg.store_ssh_key)?,
        StoreKeySource::Auto if cfg.store_ssh_key.exists() => {
            read_ssh_private_key(&cfg.store_ssh_key)?
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
    let socket = support_dir(&cfg)?.join("control.sock");
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving the current directory")?
            .join(path)
    };
    let mut client = ControlClient::connect(&socket)
        .with_context(|| format!("connecting to control socket {}", socket.display()))?;
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
            std::fs::write(&dest, &plaintext[..])
                .with_context(|| format!("writing {}", dest.display()))?;
            std::fs::set_permissions(
                &dest,
                std::os::unix::fs::PermissionsExt::from_mode(record.mode),
            )?;
            eprintln!("wrote {} bytes to {}", plaintext.len(), dest.display());
        }
        None => std::io::stdout().write_all(&plaintext[..])?,
    }
    Ok(())
}

fn cmd_history(target: &str, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let store = open_store(&cfg)?;
    let record = resolve_target(&store, target)?;
    println!("{}  {}", record.id, record.display_name());
    for v in store.history(&record.id)? {
        let head = if v.version == record.current_version { " (current)" } else { "" };
        let note = v.note.map(|n| format!("  {n}")).unwrap_or_default();
        println!("  v{}  {} bytes  {}{head}{note}", v.version, v.size, v.created);
    }
    Ok(())
}

fn cmd_rollback(target: &str, version: u32, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let store = open_store(&cfg)?;
    let record = resolve_target(&store, target)?;
    let plaintext = store.get_version(&record.id, version)?;
    validate_catalog_secret_bytes(&cfg, &record.id, &plaintext)?;
    store.set_head(&record.id, version)?;
    println!("{} → head is now v{version}", record.id);
    Ok(())
}

fn validate_catalog_secret_bytes(
    cfg: &ResolvedConfig,
    secret_id: &SecretId,
    bytes: &[u8],
) -> Result<()> {
    let catalog_path = support_dir(cfg)?.join("catalog.sqlite");
    if !catalog_path.exists() {
        return Ok(());
    }
    let catalog = Catalog::open(&catalog_path)
        .with_context(|| format!("opening catalog at {}", catalog_path.display()))?;
    let snapshot = catalog.snapshot().context("loading catalog for secret validation")?;
    validate_secret_bytes(&snapshot, secret_id.as_str(), bytes)
        .with_context(|| format!("validating replacement bytes for secret {secret_id}"))
}

fn cmd_list(config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let store = open_store(&cfg)?;
    let records = store.list()?;
    if records.is_empty() {
        println!("no protected secrets");
        return Ok(());
    }
    for r in records {
        println!(
            "{}  {}  (v{}, {} bytes, mode {:04o}, {})",
            r.id,
            r.display_name(),
            r.current_version,
            r.size,
            r.mode,
            r.created
        );
    }
    Ok(())
}

/// Resolve a reveal target that may be a store id or a source path.
fn resolve_target(store: &AgeDirStore, target: &str) -> Result<SecretRecord> {
    if let Ok(id) = target.parse::<SecretId>() {
        if let Some(r) = store.list()?.into_iter().find(|r| r.id == id) {
            return Ok(r);
        }
    }
    let abs = std::fs::canonicalize(target).unwrap_or_else(|_| {
        std::env::current_dir()
            .map(|d| d.join(target))
            .unwrap_or_else(|_| PathBuf::from(target))
    });
    store
        .get_by_path(&abs)?
        .with_context(|| format!("no protected secret for {target:?}"))
}

fn load(config: &Path) -> Result<ResolvedConfig> {
    Config::load(config).with_context(|| format!("loading config {}", config.display()))
}

fn cmd_mount(config: &Path) -> Result<()> {
    let cfg = load(config)?;
    std::fs::create_dir_all(&cfg.mount_path)
        .with_context(|| format!("creating mount point {}", cfg.mount_path.display()))?;
    let support_dir = support_dir(&cfg)?.to_path_buf();
    let _instance = DaemonInstance::acquire(&support_dir)?;
    initialize_store_key_if_needed(&cfg)?;
    recover_stale_mount(&cfg.mount_path)?;
    let catalog_path = support_dir.join("catalog.sqlite");
    let store = open_store(&cfg)?;
    if catalog_path.exists() {
        if let Some(report) =
            floria_backup::recover_interrupted_activation(&catalog_path, &store)
                .context("recovering an interrupted data restore")?
        {
            tracing::warn!(
                safety_backup = %report.safety_backup.path.display(),
                "finished an interrupted data restore"
            );
        }
    }
    let daemon_executable =
        std::env::current_exe().context("resolving daemon executable for peer policy")?;
    let gui_executable = trusted_gui_executable(&daemon_executable)?;
    let agent_peer_verifier: Arc<dyn SocketPeerVerifier> = Arc::new(
        CodeSignedPeerVerifier::from_executables([&gui_executable])
            .context("building agent socket peer policy")?,
    );
    let control_peer_verifier: Arc<dyn SocketPeerVerifier> = Arc::new(
        CodeSignedPeerVerifier::from_executables([&gui_executable, &daemon_executable])
            .context("building control socket peer policy")?,
    );
    tracing::info!(
        gui = %gui_executable.display(),
        daemon = %daemon_executable.display(),
        "loaded local socket code-signing policy"
    );
    let control_path = support_dir.join("control.sock");
    let catalog = Catalog::open(&catalog_path)
        .with_context(|| format!("opening catalog at {}", catalog_path.display()))?;
    let snapshot = catalog.snapshot().context("loading initial surface registry")?;
    let checkout_monitor = Arc::new(
        GitCheckoutMonitor::start(monitored_git_projects(&snapshot))
            .context("starting Git checkout monitor")?,
    );
    let surface_registry = Arc::new(SurfaceRegistry::from_snapshot(&snapshot));
    let linked_file_surfaces =
        file_surface_instances(&snapshot).context("materializing project checkout links")?;
    let concrete_store = Arc::new(store);
    let backup: Arc<dyn BackupService> =
        Arc::new(DaemonBackupService { store: Arc::clone(&concrete_store) });
    let store: Arc<dyn SecretStore> = concrete_store;
    let records = store.list()?;
    release_protected_links_for_file_surfaces(
        &snapshot,
        &records,
        &linked_file_surfaces,
        &cfg.mount_path,
    )
    .context("transitioning protected worktree links to configured surfaces")?;
    reconcile_file_links(&linked_file_surfaces, &cfg.mount_path);
    let mut linked_protected_files = Vec::new();
    refresh_protected_checkout_links(
        &mut linked_protected_files,
        protected_checkout_links(&snapshot, &records, &cfg.mount_path),
        store.as_ref(),
    )
    .context("materializing protected files in project worktrees")?;
    let agent = floria_agent::SocketAgent::start(&cfg, agent_peer_verifier)
        .context("starting agent socket")?;
    agent.replace_managed_policy(managed_policy_items(&snapshot, &records));
    let audit = Arc::new(AuditLog::open(&cfg.audit_log).context("opening shared audit log")?);
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
    let _control = ControlServer::start_runtime_with_services(
        &control_path,
        catalog.clone(),
        Arc::clone(&store),
        cfg.mount_path.clone(),
        ControlRuntimeServices {
            observer,
            checkout_monitor,
            policy,
            ssh_discovery,
            ssh_config,
            backup,
            audit_log: cfg.audit_log.clone(),
            ssh_runtime_dir,
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
    )
    .context("mount failed")
}

struct AgentPolicyController {
    agent: Arc<floria_agent::SocketAgent>,
}

struct AgentSshIdentityDiscovery;

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
        reconcile_file_links(&next_links, &self.mount_path);
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
            object: ManagedObject::Surface { surface_id: surface.id.clone() },
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
        match remove_file_surface_link(surface, mount_path) {
            Ok(SurfaceLinkRemoval::Removed) => tracing::info!(
                surface = %surface.id,
                path = %surface.path.display(),
                "removed project surface link"
            ),
            Ok(SurfaceLinkRemoval::Missing | SurfaceLinkRemoval::Preserved) => {}
            Err(error) => tracing::warn!(
                surface = %surface.id,
                path = %surface.path.display(),
                %error,
                "removed surface link needs attention"
            ),
        }
    }
}

fn reconcile_file_links(surfaces: &[Surface], mount_path: &Path) {
    for surface in surfaces {
        match ensure_file_surface_link(surface, mount_path) {
            Ok(SurfaceLinkState::Created) => tracing::info!(
                surface = %surface.id,
                path = %surface.path.display(),
                "created project surface link"
            ),
            Ok(SurfaceLinkState::Ready) => tracing::debug!(
                surface = %surface.id,
                path = %surface.path.display(),
                "project surface link is ready"
            ),
            Err(error) => tracing::warn!(
                surface = %surface.id,
                path = %surface.path.display(),
                %error,
                "project surface link needs attention"
            ),
        }
    }
}

fn cmd_control(command: ControlCmd, socket: Option<PathBuf>, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let socket = match socket {
        Some(socket) => socket,
        None => support_dir(&cfg)?.join("control.sock"),
    };
    let mut client = ControlClient::connect(&socket)
        .with_context(|| format!("connecting to control socket {}", socket.display()))?;
    let command = match command {
        ControlCmd::Ping => ControlCommand::Ping,
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
        ControlResult::Pong { schema_version } => {
            println!("daemon ready; catalog schema v{schema_version}");
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
            println!("configured {} as {}", surface.path.display(), surface.id);
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

fn cmd_unmount(path: Option<PathBuf>, config: &Path) -> Result<()> {
    let target = match path {
        Some(p) => p,
        None => load(config)?.mount_path,
    };
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

            match (support_dir(&cfg), exact_mount(&cfg.mount_path)) {
                (Ok(support_dir), Ok(mount)) => {
                    match (daemon_lock_state(support_dir), mount) {
                        (Ok(DaemonLockState::Held), Some(mount)) if mount.is_floria() => {
                            report("daemon lifecycle (running)", true, "");
                        }
                        (Ok(DaemonLockState::Free), None) => {
                            report("daemon lifecycle (not running; mount available)", true, "");
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

    #[test]
    fn protect_has_one_managed_lifecycle_without_legacy_storage_switches() {
        let protect = Cli::try_parse_from(["floria", "protect", "/tmp/.env"]).unwrap();
        match protect.command {
            Cmd::Protect { path, config } => {
                assert_eq!(path, PathBuf::from("/tmp/.env"));
                assert_eq!(config, PathBuf::from("floria.toml"));
            }
            _ => panic!("expected protect"),
        }

        for flag in ["--link", "--remove", "--force"] {
            assert!(Cli::try_parse_from(["floria", "protect", "/tmp/.env", flag]).is_err());
        }
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
                assert_eq!(config, PathBuf::from("floria.toml"));
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
                assert_eq!(config, PathBuf::from("floria.toml"));
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
                assert_eq!(config, PathBuf::from("floria.toml"));
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
                assert_eq!(config, PathBuf::from("floria.toml"));
            }
            _ => panic!("expected backup activate"),
        }
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
                assert_eq!(config, PathBuf::from("floria.toml"));
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
                assert_eq!(config, PathBuf::from("floria.toml"));
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
                path: PathBuf::from("/fixture/.env"),
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
            object: ManagedObject::Surface { surface_id: "combined".to_string() },
            enforcement: Enforcement::Allow,
        }));
        assert!(items.contains(&ManagedPolicyItem {
            object: ManagedObject::SshResource {
                resource_id: "managed-ssh".to_string(),
            },
            enforcement: Enforcement::Prompt,
        }));
    }
}
