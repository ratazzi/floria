use std::sync::{Mutex, Weak};

pub trait ManagedMutationObserver: Send + Sync {
    fn managed_mutation_committed(&self);
}

/// Serializes mutations that span the catalog and encrypted store.
///
/// Neither backend can enforce the other's invariants. Holding this gate from validation through
/// commit prevents a catalog schema change and a secret head update from both succeeding against
/// stale views of one another. Control-plane callers also keep the gate through their synchronous
/// runtime refresh, so concurrent connections cannot reinstall an older catalog snapshot.
pub struct ManagedMutationCoordinator {
    gate: Mutex<()>,
    observers: Mutex<Vec<Weak<dyn ManagedMutationObserver>>>,
}

impl Default for ManagedMutationCoordinator {
    fn default() -> Self {
        Self {
            gate: Mutex::new(()),
            observers: Mutex::new(Vec::new()),
        }
    }
}

impl ManagedMutationCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn run<T>(&self, operation: impl FnOnce() -> T) -> T {
        let _guard = self
            .gate
            .lock()
            .expect("managed mutation coordinator poisoned");
        operation()
    }

    /// Run one local mutation and synchronously notify observers after it commits successfully.
    ///
    /// Notifications run before the mutation gate is released, so a durable replication observer
    /// can checkpoint this exact committed state before another local mutation begins. Importers
    /// and replication maintenance must continue using `run()` to avoid export loops.
    pub fn run_committed<T, E>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let _guard = self
            .gate
            .lock()
            .expect("managed mutation coordinator poisoned");
        let result = operation();
        if result.is_ok() {
            self.notify_committed();
        }
        result
    }

    pub fn observe(&self, observer: Weak<dyn ManagedMutationObserver>) {
        self.observers
            .lock()
            .expect("managed mutation observers poisoned")
            .push(observer);
    }

    fn notify_committed(&self) {
        let observers = {
            let mut registered = self
                .observers
                .lock()
                .expect("managed mutation observers poisoned");
            let observers = registered.iter().filter_map(Weak::upgrade).collect::<Vec<_>>();
            registered.retain(|observer| observer.strong_count() > 0);
            observers
        };
        for observer in observers {
            observer.managed_mutation_committed();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    struct CountingObserver(AtomicUsize);

    impl ManagedMutationObserver for CountingObserver {
        fn managed_mutation_committed(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn only_successful_local_commits_notify_observers() {
        let coordinator = ManagedMutationCoordinator::new();
        let observer = Arc::new(CountingObserver(AtomicUsize::new(0)));
        let erased: Arc<dyn ManagedMutationObserver> = observer.clone();
        coordinator.observe(Arc::downgrade(&erased));

        assert_eq!(coordinator.run_committed(|| Ok::<_, ()>(7)), Ok(7));
        assert_eq!(coordinator.run_committed(|| Err::<(), _>("no commit")), Err("no commit"));
        coordinator.run(|| {});

        assert_eq!(observer.0.load(Ordering::Relaxed), 1);
    }
}
