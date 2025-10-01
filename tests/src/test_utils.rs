// SPDX-License-Identifier: Apache-2.0
use libtest_mimic::Failed;

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

/// Attempts PTRACE_ATTACH on target pid
pub fn try_ptrace_attach(target_pid: u32, expect_success: bool) -> Result<(), Failed> {
    let pid = nix::unistd::Pid::from_raw(target_pid as i32);
    // try attach and then continue
    match nix::sys::ptrace::attach(pid) {
        Ok(_) => {
            nix::sys::wait::waitpid(pid, None)
                .map_err(|e| format!("failed waitpid on {pid}: {e}"))?;
            nix::sys::ptrace::cont(pid, None)
                .map_err(|e| format!("failed to continue process {pid}: {e}"))?;
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
                return Err(format!("Ptrace attach gave unexpected error: {e}").into());
            }
        }
    }
    Ok(())
}
