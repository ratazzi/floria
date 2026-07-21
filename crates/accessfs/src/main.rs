use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use accessfs_catalog::{Catalog, CatalogSnapshot, Surface, SurfaceKind};
use accessfs_control::{
    CatalogObserver, ControlClient, ControlCommand, ControlResult, ControlServer,
};
use accessfs_core::config::{Config, ResolvedConfig};
use accessfs_store::{AgeDirStore, NewSecret, SecretId, SecretRecord, SecretStore, SshKeyProvider};
use accessfs_surface::{
    ensure_file_surface_link, remove_file_surface_link, SurfaceLinkRemoval, SurfaceLinkState,
    SurfaceRegistry,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// AccessFS: a userspace filesystem that exposes dynamic content as plain local files (macOS/macFUSE).
#[derive(Parser)]
#[command(name = "accessfs", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Mount in the foreground (blocks until unmounted).
    Mount {
        #[arg(short, long, default_value = "accessfs.toml")]
        config: PathBuf,
    },
    /// Unmount the given mount point.
    Unmount {
        /// Mount point path; defaults to the value from config.
        path: Option<PathBuf>,
        #[arg(short, long, default_value = "accessfs.toml")]
        config: PathBuf,
    },
    /// Self-check: macFUSE readiness, mount point, config, and handler permissions.
    Doctor {
        #[arg(short, long, default_value = "accessfs.toml")]
        config: PathBuf,
    },
    /// Encrypt a file into the secret store (age-encrypted, keyed by the store's ssh key).
    Protect {
        /// File to protect.
        path: PathBuf,
        /// Replace the original with a symlink into the mount (`secrets/<id>`); readable once mounted.
        #[arg(long)]
        link: bool,
        /// Delete the plaintext original after a successful encrypt (implied by --link).
        #[arg(long)]
        remove: bool,
        /// If already protected, re-encrypt the current content in place (same id).
        #[arg(long)]
        force: bool,
        #[arg(short, long, default_value = "accessfs.toml")]
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
        #[arg(short, long, default_value = "accessfs.toml")]
        config: PathBuf,
    },
    /// Show the version history of a protected secret.
    History {
        /// Original path of the protected file, or its store id.
        target: String,
        #[arg(short, long, default_value = "accessfs.toml")]
        config: PathBuf,
    },
    /// Roll back a protected secret's head to an earlier version (repoints; nothing is deleted).
    Rollback {
        /// Original path of the protected file, or its store id.
        target: String,
        /// Version to make current.
        version: u32,
        #[arg(short, long, default_value = "accessfs.toml")]
        config: PathBuf,
    },
    /// List protected secrets.
    List {
        #[arg(short, long, default_value = "accessfs.toml")]
        config: PathBuf,
    },
    /// Query the daemon's catalog control plane.
    Control {
        #[command(subcommand)]
        command: ControlCmd,
        /// Override the derived control socket path.
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(short, long, default_value = "accessfs.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ControlCmd {
    /// Check that the daemon control socket and catalog schema are available.
    Ping,
    /// Print the complete metadata catalog as JSON (never secret plaintext).
    Snapshot,
    /// Resolve environment keys and provenance without decrypting values.
    Resolve {
        project_id: String,
        environment_id: String,
    },
    /// Show every binding and surface affected by a resource.
    Usage { resource_id: String },
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
        Cmd::Protect { path, link, remove, force, config } => {
            cmd_protect(&path, link, remove, force, &config)
        }
        Cmd::Reveal { target, version, to, config } => cmd_reveal(&target, version, to, &config),
        Cmd::History { target, config } => cmd_history(&target, &config),
        Cmd::Rollback { target, version, config } => cmd_rollback(&target, version, &config),
        Cmd::List { config } => cmd_list(&config),
        Cmd::Control { command, socket, config } => cmd_control(command, socket, &config),
    }
}

/// Open the secret store from config. The private key passphrase, if any, comes from
/// `FLORIA_KEY_PASSPHRASE` (dev convenience; interactive/Touch ID unlock is a later milestone).
fn open_store(cfg: &ResolvedConfig) -> Result<AgeDirStore> {
    let passphrase = std::env::var("FLORIA_KEY_PASSPHRASE")
        .ok()
        .map(zeroize::Zeroizing::new);
    let keys = Arc::new(SshKeyProvider::new(cfg.store_ssh_key.clone(), passphrase));
    let store = AgeDirStore::open(cfg.store_root.clone(), keys)
        .with_context(|| format!("opening store at {}", cfg.store_root.display()))?;
    Ok(store)
}

fn cmd_protect(path: &Path, link: bool, remove: bool, force: bool, config: &Path) -> Result<()> {
    let cfg = load(config)?;
    let store = open_store(&cfg)?;

    // Refuse a symlink (very likely one we already created into the mount); don't recurse into it.
    let lmeta = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;
    if lmeta.file_type().is_symlink() {
        anyhow::bail!("{} is a symlink (already linked?); refusing to protect it", path.display());
    }
    if !lmeta.is_file() {
        anyhow::bail!("{} is not a regular file", path.display());
    }
    let abs = std::fs::canonicalize(path)
        .with_context(|| format!("resolving {}", path.display()))?;
    let plaintext = zeroize::Zeroizing::new(std::fs::read(&abs)?);
    let mode = (lmeta.mode() & 0o7777) as u32;

    // Import step: reuse the existing entry when already protected, so --link/--remove stay usable.
    let id = match store.get_by_path(&abs)? {
        Some(rec) if force => {
            let v = store.append_version(&rec.id, &plaintext)?;
            println!("updated {} → {} (saved version {v})", abs.display(), rec.id);
            rec.id
        }
        Some(rec) => {
            if rec.size != plaintext.len() as u64 {
                anyhow::bail!(
                    "{} changed since it was protected (id {}); re-run with --force to save a new version",
                    abs.display(),
                    rec.id
                );
            }
            println!("already protected {} → {} (v{})", abs.display(), rec.id, rec.current_version);
            rec.id
        }
        None => {
            let id = store.put(NewSecret::file(abs.clone(), mode), &plaintext)?;
            println!("protected {} → {id}", abs.display());
            println!("  stored at {}/{id}", cfg.store_root.display());
            id
        }
    };

    // Surface step: independent of whether we just imported or reused an existing entry.
    if link {
        let target = cfg
            .mount_path
            .join(accessfs_core::config::SECRETS_DIR)
            .join(id.to_string());
        replace_with_symlink(&abs, &target)?;
        println!("  linked {} → {} (readable once mounted)", abs.display(), target.display());
    } else if remove {
        std::fs::remove_file(&abs)?;
        println!("  removed plaintext original (restore: accessfs reveal {id} --to {})", abs.display());
    } else {
        println!("  original left in place; add --link or --remove to surface it");
    }
    Ok(())
}

/// Atomically replace the file at `at` with a symlink to `target` (symlink a temp sibling, rename over).
fn replace_with_symlink(at: &Path, target: &Path) -> Result<()> {
    let parent = at.parent().unwrap_or_else(|| Path::new("."));
    let name = at.file_name().unwrap_or_default().to_string_lossy();
    let tmp = parent.join(format!(".{name}.floria-tmp"));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)
        .with_context(|| format!("creating symlink {}", tmp.display()))?;
    std::fs::rename(&tmp, at).with_context(|| format!("replacing {}", at.display()))?;
    Ok(())
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
    store.set_head(&record.id, version)?;
    println!("{} → head is now v{version}", record.id);
    Ok(())
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
    let support_dir = support_dir(&cfg)?;
    let catalog_path = support_dir.join("catalog.sqlite");
    let control_path = support_dir.join("control.sock");
    let catalog = Catalog::open(&catalog_path)
        .with_context(|| format!("opening catalog at {}", catalog_path.display()))?;
    let snapshot = catalog.snapshot().context("loading initial surface registry")?;
    let surface_registry = Arc::new(SurfaceRegistry::from_snapshot(&snapshot));
    reconcile_file_links(&snapshot, &cfg.mount_path);
    let observer: Arc<dyn CatalogObserver> = Arc::new(RuntimeCatalogObserver {
        surface_registry: Arc::clone(&surface_registry),
        mount_path: cfg.mount_path.clone(),
    });
    let store: Arc<dyn SecretStore> = Arc::new(open_store(&cfg)?);
    let _control = ControlServer::start_runtime(
        &control_path,
        catalog.clone(),
        Arc::clone(&store),
        observer,
    )
        .with_context(|| format!("starting control socket at {}", control_path.display()))?;
    tracing::info!(socket = %control_path.display(), "control socket listening");
    let agent = accessfs_agent::SocketAgent::start(&cfg).context("starting agent socket")?;
    accessfs_fs::mount(
        cfg,
        agent,
        Some(store),
        Some(catalog),
        Some(surface_registry),
    )
    .context("mount failed")
}

struct RuntimeCatalogObserver {
    surface_registry: Arc<SurfaceRegistry>,
    mount_path: PathBuf,
}

impl CatalogObserver for RuntimeCatalogObserver {
    fn catalog_changed(&self, snapshot: &CatalogSnapshot) {
        let previous = self
            .surface_registry
            .list()
            .into_iter()
            .map(|registered| registered.surface)
            .collect::<Vec<_>>();
        cleanup_removed_file_links(&previous, snapshot, &self.mount_path);
        self.surface_registry.replace(snapshot);
        reconcile_file_links(snapshot, &self.mount_path);
    }
}

fn cleanup_removed_file_links(
    previous: &[Surface],
    snapshot: &CatalogSnapshot,
    mount_path: &Path,
) {
    for surface in previous {
        let still_present = snapshot.surfaces.iter().any(|current| {
            current.id == surface.id
                && current.path == surface.path
                && matches!(current.kind, SurfaceKind::DotenvFile | SurfaceKind::EnvFileDirect)
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

fn reconcile_file_links(snapshot: &CatalogSnapshot, mount_path: &Path) {
    for surface in snapshot
        .surfaces
        .iter()
        .filter(|surface| {
            matches!(surface.kind, SurfaceKind::DotenvFile | SurfaceKind::EnvFileDirect)
        })
    {
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
        ControlCmd::Snapshot => ControlCommand::Snapshot,
        ControlCmd::Resolve { project_id, environment_id } => {
            ControlCommand::ResolveEnvironment { project_id, environment_id }
        }
        ControlCmd::Usage { resource_id } => ControlCommand::ResourceUsage { resource_id },
    };
    match client.request(command)? {
        ControlResult::Pong { schema_version } => {
            println!("daemon ready; catalog schema v{schema_version}");
        }
        ControlResult::Snapshot(snapshot) => {
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
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

fn cmd_unmount(path: Option<PathBuf>, config: &Path) -> Result<()> {
    let target = match path {
        Some(p) => p,
        None => load(config)?.mount_path,
    };
    // Prefer diskutil (cleaner for macFUSE volumes), fall back to umount.
    let ok = run("diskutil", &["unmount", &target.to_string_lossy()])
        || run("umount", &[&target.to_string_lossy()]);
    if ok {
        println!("unmounted {}", target.display());
        Ok(())
    } else {
        anyhow::bail!("failed to unmount {}", target.display())
    }
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

            println!("  resolved {} virtual file(s):", cfg.files.len());
            for f in &cfg.files {
                let kind = match &f.handler {
                    accessfs_core::handler::ContentHandler::Constant(b) => {
                        format!("constant, {} bytes", b.len())
                    }
                    accessfs_core::handler::ContentHandler::Script { argv } => {
                        format!("script `{}`", argv.join(" "))
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
