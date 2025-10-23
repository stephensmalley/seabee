// SPDX-License-Identifier: Apache-2.0

use std::{fs, io::ErrorKind, os::unix::fs::PermissionsExt, path::Path};

use libtest_mimic::Failed;
use nix::sys::{ptrace, signal::Signal::SIGCONT};

// try chmod and expect permission denied
pub fn try_chmod(path: &str, expect_success: bool) -> Result<(), Failed> {
    // Try to change permissions
    let result = fs::set_permissions(path, fs::Permissions::from_mode(0o777));

    // check expected result
    match result {
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            if expect_success {
                return Err(format!("try_chmod on {path} expected success, but got {e}").into());
            }
        }
        Ok(_) => {
            if !expect_success {
                return Err(format!("try_chmod on {path} expected fail, but succeeded").into());
            }
        }
        Err(e) => return Err(format!("try_chmod on {path}: unexpected error: {e}").into()),
    }
    Ok(())
}

/// Attempt to write to a file testing that permission is denied
pub fn try_open(path: &Path, file_is_executing: bool, expect_success: bool) -> Result<(), Failed> {
    let open_result = fs::OpenOptions::new()
        .append(true) // open in append mode
        .open(path);

    match open_result {
        Ok(_) => {
            if !expect_success {
                return Err(format!(
                    "try_open on {} expected fail, but succeeded",
                    path.display()
                )
                .into());
            }
        }
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            if expect_success {
                return Err(format!(
                    "try_open on {} expected success, but was denied",
                    path.display()
                )
                .into());
            }
        }
        // we ignore executable file busy since we may get this when function is called on an executable
        Err(e) => {
            if !file_is_executing || e.kind() != ErrorKind::ExecutableFileBusy {
                return Err(
                    format!("try_open on {}: unexpected error: {e}", path.display()).into(),
                );
            }
        }
    }
    Ok(())
}

/// Try to delete a directory and all its contents
pub fn try_create_file(path: &Path, expect_success: bool) -> Result<(), Failed> {
    match std::fs::File::create(path) {
        Ok(_) => {
            if !expect_success {
                return Err(format!(
                    "try_create_file on {} succeeded, but expected failures",
                    path.display()
                )
                .into());
            }
        }
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            if expect_success {
                return Err(format!(
                    "try_create_file on {} failed, but expected success",
                    path.display()
                )
                .into());
            }
        }
        Err(e) => {
            return Err(format!(
                "try_create_file on {}: unexpected error: {e}",
                path.display()
            )
            .into())
        }
    }
    Ok(())
}

/// Try to delete a directory and all its contents
pub fn try_remove_dir_all(path: &str, expect_success: bool) -> Result<(), Failed> {
    match fs::remove_dir_all(path) {
        Ok(_) => {
            if !expect_success {
                return Err(format!(
                    "try_remove_dir on {path} expected failure, but successfully delete files"
                )
                .into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            if expect_success {
                return Err(
                    format!("try_remove_dir on {path} expected success, but was denied").into(),
                );
            }
        }
        Err(e) => return Err(format!("Unexpected error during remove_dir_all: {e}").into()),
    }
    Ok(())
}

/// Attempts to remove a file testing that permission is denied
pub fn try_unlink_file(path: &str, expect_success: bool) -> Result<(), Failed> {
    match fs::remove_file(path) {
        Ok(_) => {
            if !expect_success {
                return Err(format!(
                    "try_unlink_file on {path} expected failure, but successfully deleted file"
                )
                .into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            if expect_success {
                return Err(
                    format!("try_unlink_file on {path} expected success, but was denied").into(),
                );
            }
        }
        Err(e) => return Err(format!("Unexpected error during remove_dir_all: {e}").into()),
    }
    Ok(())
}

/// Attempts to run `kill` with specified arguments and return code
pub fn try_kill(signal: i32, pid: u32, expect_success: bool) -> Result<(), Failed> {
    let res = unsafe { libc::kill(pid as i32, signal) };
    if res == 0 && !expect_success {
        Err(
            format!("Signal {signal:?} should not have succeeded on pid {pid}, return: {res}")
                .into(),
        )
    } else if res != 0 && expect_success {
        Err(format!(
            "Signal {signal:?} should not have failed on pid {pid}: {}",
            std::io::Error::last_os_error()
        )
        .into())
    } else {
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum PtraceOp {
    Attach,
    Seize,
}

/// Attempts Ptrace with the given request on target pid.
/// request could be either ATTACH or SEIZE
pub fn try_ptrace(mode: PtraceOp, target_pid: u32, expect_success: bool) -> Result<(), Failed> {
    // take action
    let pid = nix::unistd::Pid::from_raw(target_pid as i32);
    let result = match mode {
        PtraceOp::Attach => ptrace::attach(pid),
        PtraceOp::Seize => ptrace::seize(pid, nix::sys::ptrace::Options::empty()),
    };

    // check result
    match result {
        Ok(_) => {
            // continue process
            if mode == PtraceOp::Seize {
                ptrace::interrupt(pid)
                    .map_err(|e| format!("failed to interrupt process {pid}: {e}"))?;
            }
            nix::sys::wait::waitpid(pid, None)
                .map_err(|e| format!("failed waitpid on {pid}: {e}"))?;
            ptrace::detach(pid, SIGCONT)
                .map_err(|e| format!("failed to detach and process {pid}: {e}"))?;

            // check if we failed
            if !expect_success {
                return Err(format!("Failed to block ptrace on pid {target_pid}").into());
            }
        }
        Err(e) => {
            if expect_success {
                return Err(format!("Failed to ptrace pid {target_pid}, error: {e:?}").into());
            }
            // check that the correct error was obtained
            if e != nix::Error::EPERM {
                return Err(format!("Ptrace {mode:?} gave unexpected error: {e}").into());
            }
        }
    }

    Ok(())
}
