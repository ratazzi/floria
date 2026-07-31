use std::sync::Mutex;

/// Serializes mutations that span the catalog and encrypted store.
///
/// Neither backend can enforce the other's invariants. Holding this gate from validation through
/// commit prevents a catalog schema change and a secret head update from both succeeding against
/// stale views of one another. Control-plane callers also keep the gate through their synchronous
/// runtime refresh, so concurrent connections cannot reinstall an older catalog snapshot.
#[derive(Default)]
pub struct ManagedMutationCoordinator {
    gate: Mutex<()>,
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
}
