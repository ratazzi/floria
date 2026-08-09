use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, RwLock};
use std::time::{Duration, Instant};

use notify::{RecommendedWatcher, RecursiveMode, Watcher};

use crate::{discover_git_checkouts, GitCheckoutDiscovery};

const EVENT_DEBOUNCE: Duration = Duration::from_millis(400);
const SAFETY_RESCAN: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoredGitProject {
    pub id: String,
    pub root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitoredGitCheckout {
    Ready(GitCheckoutDiscovery),
    Unavailable(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitCheckoutInventory {
    pub revision: u64,
    pub projects: HashMap<String, MonitoredGitCheckout>,
}

/// Keeps a current, in-memory view of Git checkouts.
///
/// Filesystem notifications are only wake-up signals. Every update is rebuilt from Git metadata,
/// and a low-frequency rescan repairs missed or coalesced events.
#[derive(Clone)]
pub struct GitCheckoutMonitor {
    inner: Arc<GitCheckoutMonitorInner>,
}

struct GitCheckoutMonitorInner {
    commands: mpsc::Sender<Command>,
    inventory: Arc<RwLock<GitCheckoutInventory>>,
}

impl Drop for GitCheckoutMonitorInner {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Shutdown);
    }
}

impl GitCheckoutMonitor {
    pub fn start(projects: Vec<MonitoredGitProject>) -> notify::Result<Self> {
        let (commands, receiver) = mpsc::channel();
        let (watch_commands, watch_receiver) = mpsc::channel();
        let event_commands = commands.clone();
        let watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| match event {
                Ok(event) => {
                    let _ = event_commands.send(Command::Filesystem(event.paths));
                }
                Err(error) => {
                    tracing::warn!(%error, "Git checkout filesystem watcher reported an error");
                    let _ = event_commands.send(Command::Refresh);
                }
            })?;
        let watcher_events = commands.clone();
        std::thread::Builder::new()
            .name("floria-git-checkout-watcher".to_string())
            .spawn(move || run_watcher(watcher, watch_receiver, watcher_events))
            .map_err(notify::Error::io)?;
        let inventory = Arc::new(RwLock::new(GitCheckoutInventory::default()));
        let worker_inventory = Arc::clone(&inventory);
        std::thread::Builder::new()
            .name("floria-git-checkout-monitor".to_string())
            .spawn(move || run(receiver, watch_commands, worker_inventory, projects))
            .map_err(notify::Error::io)?;
        Ok(Self {
            inner: Arc::new(GitCheckoutMonitorInner {
                commands,
                inventory,
            }),
        })
    }

    pub fn replace_projects(&self, projects: Vec<MonitoredGitProject>) {
        let _ = self.inner.commands.send(Command::Replace(projects));
    }

    pub fn refresh(&self) {
        let _ = self.inner.commands.send(Command::Refresh);
    }

    pub fn inventory(&self) -> GitCheckoutInventory {
        self.inner
            .inventory
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn discovery(&self, project_id: &str) -> Option<Result<GitCheckoutDiscovery, String>> {
        self.inner
            .inventory
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .projects
            .get(project_id)
            .map(|status| match status {
                MonitoredGitCheckout::Ready(discovery) => Ok(discovery.clone()),
                MonitoredGitCheckout::Unavailable(error) => Err(error.clone()),
            })
    }
}

enum Command {
    Replace(Vec<MonitoredGitProject>),
    Filesystem(Vec<PathBuf>),
    Refresh,
    Shutdown,
}

enum WatchCommand {
    Replace(HashSet<PathBuf>),
    Shutdown,
}

fn run(
    receiver: mpsc::Receiver<Command>,
    watch_commands: mpsc::Sender<WatchCommand>,
    inventory: Arc<RwLock<GitCheckoutInventory>>,
    initial_projects: Vec<MonitoredGitProject>,
) {
    let mut projects = project_map(initial_projects);
    let mut dirty_deadline = Some(Instant::now());
    let mut safety_deadline = Instant::now();

    loop {
        let deadline = dirty_deadline.map_or(safety_deadline, |dirty| dirty.min(safety_deadline));
        let timeout = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(timeout) {
            Ok(Command::Replace(next)) => {
                projects = project_map(next);
                dirty_deadline = Some(Instant::now());
            }
            Ok(Command::Filesystem(paths)) => {
                if filesystem_event_is_relevant(&paths, &projects, &inventory) {
                    dirty_deadline = Some(Instant::now() + EVENT_DEBOUNCE);
                }
            }
            Ok(Command::Refresh) => {
                dirty_deadline = Some(Instant::now());
            }
            Ok(Command::Shutdown) => {
                let _ = watch_commands.send(WatchCommand::Shutdown);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let desired = reconcile(&projects, &inventory);
                let _ = watch_commands.send(WatchCommand::Replace(desired));
                dirty_deadline = None;
                safety_deadline = Instant::now() + SAFETY_RESCAN;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = watch_commands.send(WatchCommand::Shutdown);
                break;
            }
        }
    }
}

fn run_watcher(
    mut watcher: RecommendedWatcher,
    receiver: mpsc::Receiver<WatchCommand>,
    events: mpsc::Sender<Command>,
) {
    let mut watched = HashSet::new();
    while let Ok(command) = receiver.recv() {
        match command {
            WatchCommand::Replace(desired) => {
                if replace_watch_roots(&mut watcher, &mut watched, desired) {
                    // Rebuild after registration so changes made while the native call was
                    // blocked cannot remain invisible until the safety rescan.
                    let _ = events.send(Command::Refresh);
                }
            }
            WatchCommand::Shutdown => break,
        }
    }
}

fn replace_watch_roots(
    watcher: &mut RecommendedWatcher,
    watched: &mut HashSet<PathBuf>,
    desired: HashSet<PathBuf>,
) -> bool {
    if *watched == desired {
        return false;
    }

    for path in watched.difference(&desired) {
        if let Err(error) = watcher.unwatch(path) {
            tracing::debug!(path = %path.display(), %error, "stale Git watch was already absent");
        }
    }
    for path in desired.difference(watched) {
        if let Err(error) = watcher.watch(path, RecursiveMode::Recursive) {
            tracing::warn!(path = %path.display(), %error, "watching Git metadata failed");
        }
    }
    *watched = desired;
    true
}

fn project_map(projects: Vec<MonitoredGitProject>) -> HashMap<String, PathBuf> {
    projects
        .into_iter()
        .map(|project| (project.id, project.root))
        .collect()
}

fn reconcile(
    projects: &HashMap<String, PathBuf>,
    inventory: &RwLock<GitCheckoutInventory>,
) -> HashSet<PathBuf> {
    let next = scan(projects);
    let desired = watch_roots(projects, &next);

    let mut current = inventory
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if current.projects != next {
        current.revision = current.revision.wrapping_add(1);
        current.projects = next;
    }
    desired
}

fn scan(projects: &HashMap<String, PathBuf>) -> HashMap<String, MonitoredGitCheckout> {
    projects
        .iter()
        .map(|(id, root)| {
            let status = match discover_git_checkouts(root) {
                Ok(discovery) => MonitoredGitCheckout::Ready(discovery),
                Err(error) => MonitoredGitCheckout::Unavailable(error.to_string()),
            };
            (id.clone(), status)
        })
        .collect()
}

fn watch_roots(
    _projects: &HashMap<String, PathBuf>,
    discoveries: &HashMap<String, MonitoredGitCheckout>,
) -> HashSet<PathBuf> {
    discoveries
        .values()
        .filter_map(|status| match status {
            MonitoredGitCheckout::Ready(discovery) => Some(discovery.common_dir.clone()),
            MonitoredGitCheckout::Unavailable(_) => None,
        })
        .collect()
}

fn filesystem_event_is_relevant(
    paths: &[PathBuf],
    projects: &HashMap<String, PathBuf>,
    inventory: &RwLock<GitCheckoutInventory>,
) -> bool {
    if paths.is_empty() {
        return true;
    }
    let current = inventory
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    projects.iter().any(|(id, root)| {
        let (watch_root, worktrees) = match current.projects.get(id) {
            Some(MonitoredGitCheckout::Ready(discovery)) => (
                discovery.common_dir.as_path(),
                Some(discovery.common_dir.join("worktrees")),
            ),
            _ => (root.as_path(), None),
        };
        paths.iter().any(|path| {
            path == watch_root
                || worktrees
                    .as_ref()
                    .is_some_and(|worktrees| path.starts_with(worktrees))
                || (worktrees.is_none() && path.starts_with(root.join(".git")))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // macOS serializes initial FSEvents stream registration across watchers in one process.
    // Floria owns one checkout monitor in production, so keep these independent lifecycle
    // tests from manufacturing a multi-monitor startup delay that the product never has.
    static NATIVE_WATCHER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn native_watcher_test_guard() -> std::sync::MutexGuard<'static, ()> {
        NATIVE_WATCHER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn wait_for(
        monitor: &GitCheckoutMonitor,
        predicate: impl Fn(&GitCheckoutInventory) -> bool,
    ) -> GitCheckoutInventory {
        wait_for_with_timeout(monitor, Duration::from_secs(3), predicate)
    }

    fn wait_for_with_timeout(
        monitor: &GitCheckoutMonitor,
        timeout: Duration,
        predicate: impl Fn(&GitCheckoutInventory) -> bool,
    ) -> GitCheckoutInventory {
        let deadline = Instant::now() + timeout;
        loop {
            let inventory = monitor.inventory();
            if predicate(&inventory) {
                return inventory;
            }
            assert!(
                Instant::now() < deadline,
                "checkout monitor did not converge: {inventory:#?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn refresh_rebuilds_inventory_from_git_metadata() {
        let _watcher_guard = native_watcher_test_guard();
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("main");
        std::fs::create_dir_all(primary.join(".git")).unwrap();
        let monitor = GitCheckoutMonitor::start(vec![MonitoredGitProject {
            id: "fixture-project".to_string(),
            root: primary.clone(),
        }])
        .unwrap();
        let initial = wait_for(&monitor, |inventory| inventory.revision > 0);
        assert!(matches!(
            initial.projects.get("fixture-project"),
            Some(MonitoredGitCheckout::Ready(discovery)) if discovery.checkouts.len() == 1
        ));

        let feature = dir.path().join("feature");
        let worktree_git = primary.join(".git/worktrees/feature");
        std::fs::create_dir_all(&worktree_git).unwrap();
        std::fs::create_dir(&feature).unwrap();
        std::fs::write(
            feature.join(".git"),
            format!("gitdir: {}\n", worktree_git.display()),
        )
        .unwrap();
        std::fs::write(worktree_git.join("commondir"), "../..\n").unwrap();
        std::fs::write(
            worktree_git.join("gitdir"),
            format!("{}\n", feature.join(".git").display()),
        )
        .unwrap();
        monitor.refresh();

        let refreshed = wait_for(&monitor, |inventory| inventory.revision > initial.revision);
        assert!(matches!(
            refreshed.projects.get("fixture-project"),
            Some(MonitoredGitCheckout::Ready(discovery)) if discovery.checkouts.len() == 2
        ));
    }

    #[test]
    fn filesystem_event_rebuilds_inventory_without_an_explicit_refresh() {
        let _watcher_guard = native_watcher_test_guard();
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("main");
        std::fs::create_dir_all(primary.join(".git")).unwrap();
        let monitor = GitCheckoutMonitor::start(vec![MonitoredGitProject {
            id: "fixture-project".to_string(),
            root: primary.clone(),
        }])
        .unwrap();
        let initial = wait_for(&monitor, |inventory| inventory.revision > 0);

        let feature = dir.path().join("feature");
        let worktree_git = primary.join(".git/worktrees/feature");
        std::fs::create_dir_all(&worktree_git).unwrap();
        std::fs::create_dir(&feature).unwrap();
        std::fs::write(
            feature.join(".git"),
            format!("gitdir: {}\n", worktree_git.display()),
        )
        .unwrap();
        std::fs::write(worktree_git.join("commondir"), "../..\n").unwrap();
        std::fs::write(
            worktree_git.join("gitdir"),
            format!("{}\n", feature.join(".git").display()),
        )
        .unwrap();

        let refreshed = wait_for_with_timeout(&monitor, Duration::from_secs(15), |inventory| {
            inventory.revision > initial.revision
        });
        assert!(matches!(
            refreshed.projects.get("fixture-project"),
            Some(MonitoredGitCheckout::Ready(discovery)) if discovery.checkouts.len() == 2
        ));
    }

    #[test]
    fn replacing_projects_removes_stale_inventory() {
        let _watcher_guard = native_watcher_test_guard();
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("main");
        std::fs::create_dir_all(primary.join(".git")).unwrap();
        let monitor = GitCheckoutMonitor::start(vec![MonitoredGitProject {
            id: "fixture-project".to_string(),
            root: primary,
        }])
        .unwrap();
        let initial = wait_for(&monitor, |inventory| inventory.revision > 0);
        monitor.replace_projects(vec![]);
        let replaced = wait_for(&monitor, |inventory| inventory.revision > initial.revision);
        assert!(replaced.projects.is_empty());
    }
}
