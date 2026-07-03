use std::path::{Path, PathBuf};
use std::process::Command;

use accessfs_core::config::{Config, ResolvedConfig};
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
    }
}

fn load(config: &Path) -> Result<ResolvedConfig> {
    Config::load(config).with_context(|| format!("loading config {}", config.display()))
}

fn cmd_mount(config: &Path) -> Result<()> {
    let cfg = load(config)?;
    std::fs::create_dir_all(&cfg.mount_path)
        .with_context(|| format!("creating mount point {}", cfg.mount_path.display()))?;
    let agent = accessfs_agent::SocketAgent::start(&cfg).context("starting agent socket")?;
    accessfs_fs::mount(cfg, agent).context("mount failed")
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
