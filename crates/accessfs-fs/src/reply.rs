use std::time::{Duration, SystemTime};

use fuser::{FileAttr, FileType};
use fuser::{INodeNo, MountOption};

/// Cache TTL for attr / entry. Set to 1s: getattr has no side effects and is cheap,
/// but not 0 either (to avoid a getattr storm). The attributes themselves stay constant
/// for the mount's lifetime, so watchers won't trigger accidentally.
pub const TTL: Duration = Duration::from_secs(1);

/// Build the `FileAttr` for a virtual file. size/mtime are stable, ensuring it "looks like a regular file".
#[allow(clippy::too_many_arguments)]
pub fn file_attr(
    ino: u64,
    size: u64,
    perm: u16,
    epoch: SystemTime,
    uid: u32,
    gid: u32,
) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size,
        blocks: size.div_ceil(512),
        atime: epoch,
        mtime: epoch,
        ctime: epoch,
        crtime: epoch,
        kind: FileType::RegularFile,
        perm,
        nlink: 1,
        uid,
        gid,
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

/// Build the `FileAttr` for a directory.
pub fn dir_attr(ino: u64, perm: u16, epoch: SystemTime, uid: u32, gid: u32) -> FileAttr {
    FileAttr {
        ino: INodeNo(ino),
        size: 4096,
        blocks: 8,
        atime: epoch,
        mtime: epoch,
        ctime: epoch,
        crtime: epoch,
        kind: FileType::Directory,
        perm,
        nlink: 2,
        uid,
        gid,
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

/// Assemble the macFUSE mount options. Stable attributes and suppression of macOS metadata
/// probe noise. Not mounted RO: store-backed secrets are writable (each save appends a version);
/// everything else rejects write-opens with EROFS in `open()`.
pub fn mount_config(volname: &str) -> fuser::Config {
    let mut config = fuser::Config::default();
    config.mount_options = vec![
        MountOption::NoAtime,
        // The kernel makes permission decisions from getattr's mode/owner; read-only single user is enough.
        MountOption::DefaultPermissions,
        MountOption::FSName("accessfs".to_string()),
        MountOption::Subtype("accessfs".to_string()),
        // The following are macFUSE-specific -o options, passed through via CUSTOM.
        MountOption::CUSTOM("local".to_string()),
        MountOption::CUSTOM(format!("volname={volname}")),
        // Suppress AppleDouble (._*)/.DS_Store and com.apple.* xattr probing.
        MountOption::CUSTOM("noappledouble".to_string()),
        MountOption::CUSTOM("noapplexattr".to_string()),
        // macFUSE can keep one vnode open while any process holds an fd, hiding later processes'
        // POSIX opens from FUSE_OPEN. Disabling readahead, UBC, and vnode caching ensures each
        // reader still reaches FUSE_READ, where process-scoped authorization is enforced.
        MountOption::CUSTOM("nolocalcaches".to_string()),
        // Give slow handlers enough time so the kernel doesn't declare the mount dead.
        MountOption::CUSTOM("daemon_timeout=60".to_string()),
    ];
    // fuser's event loop is single-threaded on macOS (n_threads > 1 is Linux-only), so a
    // slow/blocking open() would freeze the whole mount. We keep the event loop free by
    // running open() work on our own thread pool and replying from there (see lib.rs).
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_disables_macos_local_caches_for_process_scoped_authorization() {
        let config = mount_config("fixture");

        assert!(config
            .mount_options
            .contains(&MountOption::CUSTOM("nolocalcaches".to_string())));
    }
}
