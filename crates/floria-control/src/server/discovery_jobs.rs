use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use floria_catalog::Catalog;
use floria_discover::{
    discover_many_with_progress, DiscoverError, DiscoveryProgress, DiscoveryScanPhase,
};
use floria_store::SecretStore;

use super::{
    discovery_review_plan, existing_discovery_projects, DiscoveryJobPhase, DiscoveryJobProgress,
    DiscoveryJobState, DiscoveryJobStatus, DispatchError,
};

const MAX_RETAINED_JOBS: usize = 8;

/// Owns the complete asynchronous discovery lifecycle behind one small control-plane seam.
///
/// Jobs retain only redacted review plans. Plaintext discovered values remain inside the worker
/// thread and are dropped before a completed status becomes observable.
pub(super) struct DiscoveryJobManager {
    catalog: Arc<Catalog>,
    store: Arc<dyn SecretStore>,
    mount_path: PathBuf,
    next_id: AtomicU64,
    registry: Mutex<JobRegistry>,
}

#[derive(Default)]
struct JobRegistry {
    jobs: HashMap<String, Arc<DiscoveryJob>>,
    order: VecDeque<String>,
}

struct DiscoveryJob {
    cancel: AtomicBool,
    status: Mutex<DiscoveryJobStatus>,
}

impl DiscoveryJobManager {
    pub(super) fn new(
        catalog: Arc<Catalog>,
        store: Arc<dyn SecretStore>,
        mount_path: PathBuf,
    ) -> Self {
        DiscoveryJobManager {
            catalog,
            store,
            mount_path,
            next_id: AtomicU64::new(1),
            registry: Mutex::new(JobRegistry::default()),
        }
    }

    pub(super) fn start(&self, paths: Vec<PathBuf>) -> Result<DiscoveryJobStatus, String> {
        let id = format!("discover-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let status = DiscoveryJobStatus {
            id: id.clone(),
            state: DiscoveryJobState::Queued,
            progress: DiscoveryJobProgress {
                phase: DiscoveryJobPhase::Starting,
                directories_scanned: 0,
                candidate_files: 0,
                project_candidates: 0,
                files_parsed: 0,
            },
            plan: None,
            error: None,
        };
        let job = Arc::new(DiscoveryJob {
            cancel: AtomicBool::new(false),
            status: Mutex::new(status.clone()),
        });
        {
            let mut registry = self.registry.lock().expect("discovery job registry poisoned");
            prune_terminal_jobs(&mut registry);
            if registry.jobs.len() >= MAX_RETAINED_JOBS {
                return Err("too many discovery jobs are still active".to_string());
            }
            registry.order.push_back(id.clone());
            registry.jobs.insert(id.clone(), Arc::clone(&job));
        }

        let catalog = Arc::clone(&self.catalog);
        let store = Arc::clone(&self.store);
        let mount_path = self.mount_path.clone();
        let worker_job = Arc::clone(&job);
        let worker_id = id.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("floria-discovery".to_string())
            .spawn(move || run_job(worker_id, worker_job, paths, catalog, store, mount_path))
        {
            let mut registry = self.registry.lock().expect("discovery job registry poisoned");
            registry.jobs.remove(&id);
            registry.order.retain(|candidate| candidate != &id);
            return Err(format!("could not start discovery worker: {error}"));
        }
        Ok(status)
    }

    pub(super) fn status(&self, id: &str) -> Result<DiscoveryJobStatus, String> {
        let job = {
            let registry = self.registry.lock().expect("discovery job registry poisoned");
            registry.jobs.get(id).cloned()
        }
        .ok_or_else(|| format!("discovery job not found: {id}"))?;
        let status = job.status.lock().expect("discovery job status poisoned").clone();
        Ok(status)
    }

    pub(super) fn cancel(&self, id: &str) -> Result<DiscoveryJobStatus, String> {
        let job = {
            let registry = self.registry.lock().expect("discovery job registry poisoned");
            registry.jobs.get(id).cloned()
        }
        .ok_or_else(|| format!("discovery job not found: {id}"))?;
        job.cancel.store(true, Ordering::Relaxed);
        let mut status = job.status.lock().expect("discovery job status poisoned");
        if !status.is_terminal() {
            status.state = DiscoveryJobState::Cancelling;
        }
        Ok(status.clone())
    }
}

fn run_job(
    id: String,
    job: Arc<DiscoveryJob>,
    paths: Vec<PathBuf>,
    catalog: Arc<Catalog>,
    store: Arc<dyn SecretStore>,
    mount_path: PathBuf,
) {
    let started = Instant::now();
    tracing::info!(job_id = %id, input_count = paths.len(), "discovery job started");
    update_status(&job, |status| {
        status.state = DiscoveryJobState::Running;
    });
    let discovery = discover_many_with_progress(&paths, |progress| {
        if job.cancel.load(Ordering::Relaxed) {
            return false;
        }
        update_status(&job, |status| {
            status.state = DiscoveryJobState::Running;
            status.progress = job_progress(progress);
        });
        true
    });
    let discovery = match discovery {
        Ok(discovery) => discovery,
        Err(DiscoverError::Cancelled) => {
            finish_cancelled(&job);
            tracing::info!(
                job_id = %id,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "discovery job cancelled"
            );
            return;
        }
        Err(error) => {
            let message = error.to_string();
            finish_failed(&job, message.clone());
            tracing::warn!(
                job_id = %id,
                elapsed_ms = started.elapsed().as_millis() as u64,
                error = %message,
                "discovery job failed"
            );
            return;
        }
    };
    let scan_ms = started.elapsed().as_millis() as u64;
    if job.cancel.load(Ordering::Relaxed) {
        finish_cancelled(&job);
        tracing::info!(
            job_id = %id,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "discovery job cancelled"
        );
        return;
    }

    update_status(&job, |status| {
        status.state = DiscoveryJobState::Running;
        status.progress.phase = DiscoveryJobPhase::Reconciling;
    });
    let result = (|| {
        let projects_started = Instant::now();
        let managed_projects = existing_discovery_projects(&catalog, discovery.projects())?;
        let project_match_ms = projects_started.elapsed().as_millis() as u64;
        if job.cancel.load(Ordering::Relaxed) {
            return Err(DispatchError::Validation("discovery was cancelled".to_string()));
        }
        let plan_started = Instant::now();
        // Preview must never block on Keychain. Apply rescans and performs exact key+value reuse
        // matching inside the trusted daemon before it mutates the catalog.
        let plan = discovery.plan_with_projects(&[], &managed_projects);
        let plan_ms = plan_started.elapsed().as_millis() as u64;
        if job.cancel.load(Ordering::Relaxed) {
            return Err(DispatchError::Validation("discovery was cancelled".to_string()));
        }
        let review_started = Instant::now();
        let review = discovery_review_plan(
            &catalog,
            store.as_ref(),
            Some(&mount_path),
            plan,
        )?;
        let managed_items_ms = review_started.elapsed().as_millis() as u64;
        Ok((
            review,
            project_match_ms,
            plan_ms,
            managed_items_ms,
        ))
    })();
    if job.cancel.load(Ordering::Relaxed) {
        finish_cancelled(&job);
        tracing::info!(
            job_id = %id,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "discovery job cancelled"
        );
        return;
    }
    match result {
        Ok((plan, project_match_ms, plan_ms, managed_items_ms)) => {
            let project_count = plan.projects.len();
            let file_count = plan.summary.files;
            let entry_count = plan.summary.entries;
            update_status(&job, |status| {
                status.state = DiscoveryJobState::Completed;
                status.progress.phase = DiscoveryJobPhase::Complete;
                status.plan = Some(plan);
            });
            tracing::info!(
                job_id = %id,
                elapsed_ms = started.elapsed().as_millis() as u64,
                scan_ms,
                project_match_ms,
                plan_ms,
                managed_items_ms,
                project_count,
                file_count,
                entry_count,
                "discovery job completed"
            );
        }
        Err(error) => {
            let message = error.body().message;
            finish_failed(&job, message.clone());
            tracing::warn!(
                job_id = %id,
                elapsed_ms = started.elapsed().as_millis() as u64,
                error = %message,
                "discovery job failed"
            );
        }
    }
}

fn job_progress(progress: DiscoveryProgress) -> DiscoveryJobProgress {
    DiscoveryJobProgress {
        phase: match progress.phase {
            DiscoveryScanPhase::ProjectCandidates => DiscoveryJobPhase::ProjectCandidates,
            DiscoveryScanPhase::CandidateFiles => DiscoveryJobPhase::CandidateFiles,
            DiscoveryScanPhase::ParsingFiles => DiscoveryJobPhase::ParsingFiles,
        },
        directories_scanned: progress.directories_scanned,
        candidate_files: progress.candidate_files,
        project_candidates: progress.project_candidates,
        files_parsed: progress.files_parsed,
    }
}

fn finish_cancelled(job: &DiscoveryJob) {
    update_status(job, |status| {
        status.state = DiscoveryJobState::Cancelled;
        status.plan = None;
        status.error = None;
    });
}

fn finish_failed(job: &DiscoveryJob, error: String) {
    update_status(job, |status| {
        status.state = DiscoveryJobState::Failed;
        status.plan = None;
        status.error = Some(error);
    });
}

fn update_status(job: &DiscoveryJob, update: impl FnOnce(&mut DiscoveryJobStatus)) {
    let mut status = job.status.lock().expect("discovery job status poisoned");
    update(&mut status);
}

fn prune_terminal_jobs(registry: &mut JobRegistry) {
    while registry.jobs.len() >= MAX_RETAINED_JOBS {
        let Some(position) = registry.order.iter().position(|id| {
            registry.jobs.get(id).is_some_and(|job| {
                job.status
                    .lock()
                    .expect("discovery job status poisoned")
                    .is_terminal()
            })
        }) else {
            return;
        };
        let Some(id) = registry.order.remove(position) else { return };
        registry.jobs.remove(&id);
    }
}
