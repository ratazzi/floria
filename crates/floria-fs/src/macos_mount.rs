//! macOS mount bridge for modern macFUSE releases.
//!
//! fuser 0.17 still mounts through libfuse's `fuse_mount_compat25` entry point. macFUSE 5.3
//! no longer provides a working compatibility mount on macOS 26: it can fail without setting
//! errno, or leave `mount_macfuse` waiting and make the next attempt report EEXIST. The current
//! `fuse_mount` API remains supported. This module uses that API only to create the mount and
//! hands a duplicated device fd back to fuser for its protocol and filesystem implementation.

use std::ffi::{c_char, c_int, CString};
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;
use std::ptr;

use fuser::{BackgroundSession, Config, Filesystem, MountOption, Session, SessionACL};

#[repr(C)]
struct FuseArgs {
    argc: c_int,
    argv: *mut *mut c_char,
    allocated: c_int,
}

enum FuseChannel {}

unsafe extern "C" {
    fn fuse_opt_add_arg(args: *mut FuseArgs, arg: *const c_char) -> c_int;
    fn fuse_opt_free_args(args: *mut FuseArgs);
    fn fuse_mount(mountpoint: *const c_char, args: *mut FuseArgs) -> *mut FuseChannel;
    fn fuse_unmount(mountpoint: *const c_char, channel: *mut FuseChannel);
    fn fuse_chan_destroy(channel: *mut FuseChannel);
    fn fuse_chan_fd(channel: *mut FuseChannel) -> c_int;
}

/// A fuser background session paired with the modern libfuse mount object that owns it.
pub(crate) struct MacOsBackgroundSession {
    session: Option<BackgroundSession>,
    mount: Option<ModernMount>,
}

impl MacOsBackgroundSession {
    /// Synchronously unmount, then join fuser after its duplicated device fd receives ENODEV.
    pub(crate) fn unmount_and_join(mut self) -> io::Result<()> {
        if let Some(mut mount) = self.mount.take() {
            mount.unmount()?;
        }
        match self.session.take() {
            Some(session) => session.join(),
            None => Ok(()),
        }
    }
}

impl Drop for MacOsBackgroundSession {
    fn drop(&mut self) {
        if let Some(mut mount) = self.mount.take() {
            let _ = mount.unmount();
        }
    }
}

pub(crate) fn spawn<FS: Filesystem + Send + 'static>(
    filesystem: FS,
    mountpoint: &Path,
    config: &Config,
) -> io::Result<MacOsBackgroundSession> {
    let mount = ModernMount::new(mountpoint, config)?;
    let fd = mount.duplicate_fd()?;
    let session = Session::from_fd(filesystem, fd, config.acl, config.clone())?.spawn()?;
    Ok(MacOsBackgroundSession {
        session: Some(session),
        mount: Some(mount),
    })
}

struct ModernMount {
    mountpoint: CString,
    channel: *mut FuseChannel,
}

impl ModernMount {
    fn new(mountpoint: &Path, config: &Config) -> io::Result<Self> {
        let mountpoint = CString::new(mountpoint.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "mount point contains a NUL byte")
        })?;
        let mut arguments = FuseArguments::new();
        arguments.push_os(std::env::current_exe()?.as_os_str())?;
        for option in &config.mount_options {
            arguments.push("-o")?;
            arguments.push(&option_to_string(option)?)?;
        }
        if let Some(acl) = acl_option(config.acl) {
            arguments.push("-o")?;
            arguments.push(acl)?;
        }

        // SAFETY: mountpoint and every argument are valid C strings for the duration of the
        // call. `FuseArguments` owns libfuse's copied argv and frees it after this call.
        let channel = unsafe { fuse_mount(mountpoint.as_ptr(), &mut arguments.raw) };
        if channel.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error().is_some_and(|code| code != 0) {
                Err(error)
            } else {
                Err(io::Error::other(
                    "macFUSE fuse_mount failed without reporting an OS error",
                ))
            };
        }
        Ok(Self {
            mountpoint,
            channel,
        })
    }

    fn duplicate_fd(&self) -> io::Result<OwnedFd> {
        // SAFETY: a non-null channel returned by fuse_mount remains live until unmount().
        let fd = unsafe { fuse_chan_fd(self.channel) };
        if fd < 0 {
            return Err(io::Error::other("macFUSE returned an invalid channel fd"));
        }
        // Keep libfuse's channel ownership intact while giving fuser an independently owned fd.
        // SAFETY: fcntl is called with a valid fd and the F_DUPFD_CLOEXEC integer argument.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }

    fn unmount(&mut self) -> io::Result<()> {
        if self.channel.is_null() {
            return Ok(());
        }

        // macFUSE's fuse_unmount dispatches an asynchronous Disk Arbitration request on modern
        // macOS. If shutdown follows a just-completed mount, fuser can remain blocked on the
        // duplicated device fd until launchd's ExitTimeOut kills the daemon. The unmount syscall
        // is synchronous and makes every descriptor for this connection observe ENODEV before
        // we join the request loop.
        // SAFETY: mountpoint is the live path used by the successful fuse_mount call.
        let result = unsafe { libc::unmount(self.mountpoint.as_ptr(), 0) };
        let error = io::Error::last_os_error();
        if result != 0 && error.raw_os_error() == Some(libc::EBUSY) {
            // A reader may still hold a vnode when launchd asks the daemon to stop. This is a
            // read-only virtual mount and shutdown must invalidate those old handles. macFUSE 5
            // can reject even unmount(2) with MNT_FORCE here; diskutil is macOS's synchronous
            // Disk Arbitration frontend and reliably completes that supported forced unmount.
            let path = std::ffi::OsStr::from_bytes(self.mountpoint.as_bytes());
            let output = Command::new("/usr/sbin/diskutil")
                .args(["unmount", "force"])
                .arg(path)
                .output()?;
            if !output.status.success() {
                let detail = String::from_utf8_lossy(&output.stderr);
                return Err(io::Error::other(format!(
                    "diskutil forced unmount failed: {}",
                    detail.trim()
                )));
            }
        } else if result != 0 {
            // Preserve macFUSE's best-effort Disk Arbitration fallback for unusual teardown
            // failures. It is asynchronous, so the synchronous error remains authoritative.
            // SAFETY: the channel is still owned by this ModernMount.
            unsafe { fuse_unmount(self.mountpoint.as_ptr(), self.channel) };
            self.channel = ptr::null_mut();
            return Err(error);
        }

        // fuse_mount owns this original channel. fuser reads from an independent duplicated fd,
        // so the channel can be destroyed after the kernel has detached the mount.
        // SAFETY: synchronous unmount completed and this is the channel returned by fuse_mount.
        unsafe { fuse_chan_destroy(self.channel) };
        self.channel = ptr::null_mut();
        Ok(())
    }
}

impl Drop for ModernMount {
    fn drop(&mut self) {
        let _ = self.unmount();
    }
}

struct FuseArguments {
    raw: FuseArgs,
}

impl FuseArguments {
    fn new() -> Self {
        Self {
            raw: FuseArgs {
                argc: 0,
                argv: ptr::null_mut(),
                allocated: 0,
            },
        }
    }

    fn push(&mut self, value: &str) -> io::Result<()> {
        let value = CString::new(value).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "mount option contains a NUL byte")
        })?;
        self.push_c_string(&value)
    }

    fn push_os(&mut self, value: &std::ffi::OsStr) -> io::Result<()> {
        let value = CString::new(value.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "mount argument contains a NUL byte",
            )
        })?;
        self.push_c_string(&value)
    }

    fn push_c_string(&mut self, value: &CString) -> io::Result<()> {
        // SAFETY: fuse_opt_add_arg copies the NUL-terminated argument into an argv owned by raw.
        let result = unsafe { fuse_opt_add_arg(&mut self.raw, value.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::other("macFUSE failed to allocate mount arguments"))
        }
    }
}

impl Drop for FuseArguments {
    fn drop(&mut self) {
        // SAFETY: raw was initialized as FUSE_ARGS_INIT and only mutated by fuse_opt_add_arg.
        unsafe { fuse_opt_free_args(&mut self.raw) };
    }
}

fn acl_option(acl: SessionACL) -> Option<&'static str> {
    match acl {
        SessionACL::All | SessionACL::RootAndOwner => Some("allow_other"),
        SessionACL::Owner => None,
    }
}

fn option_to_string(option: &MountOption) -> io::Result<String> {
    let value = match option {
        MountOption::FSName(value) => format!("fsname={value}"),
        MountOption::Subtype(value) => format!("subtype={value}"),
        MountOption::CUSTOM(value) => value.clone(),
        MountOption::AutoUnmount => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "auto_unmount is not supported by the macOS mount bridge",
            ));
        }
        MountOption::DefaultPermissions => "default_permissions".into(),
        MountOption::Dev => "dev".into(),
        MountOption::NoDev => "nodev".into(),
        MountOption::Suid => "suid".into(),
        MountOption::NoSuid => "nosuid".into(),
        MountOption::RO => "ro".into(),
        MountOption::RW => "rw".into(),
        MountOption::Exec => "exec".into(),
        MountOption::NoExec => "noexec".into(),
        MountOption::Atime => "atime".into(),
        MountOption::NoAtime => "noatime".into(),
        MountOption::DirSync => "dirsync".into(),
        MountOption::Sync => "sync".into(),
        MountOption::Async => "async".into(),
    };
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_floria_mount_options_for_modern_libfuse() {
        assert_eq!(
            option_to_string(&MountOption::FSName("floria".into())).unwrap(),
            "fsname=floria"
        );
        assert_eq!(
            option_to_string(&MountOption::CUSTOM("nolocalcaches".into())).unwrap(),
            "nolocalcaches"
        );
    }
}
