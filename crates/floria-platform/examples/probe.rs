//! Probe: print enriched identity (exe + code signature) for the given pids.
//! `cargo run -p floria-platform --example probe -- <pid> [pid...]`

fn main() {
    for arg in std::env::args().skip(1) {
        let Ok(pid) = arg.parse::<i32>() else {
            eprintln!("skip non-pid arg {arg:?}");
            continue;
        };
        let id = floria_platform::enrich(pid, 0, 0);
        println!(
            "pid={pid} exe={:?} bundle={:?} team={:?}",
            id.exe_path.as_deref().map(|p| p.display().to_string()),
            id.bundle_id,
            id.team_id,
        );
    }
}
