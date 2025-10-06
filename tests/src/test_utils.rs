// SPDX-License-Identifier: Apache-2.0

use libtest_mimic::Failed;
use nix::sys::{ptrace, signal::Signal::SIGCONT};

use crate::command::TestCommandBuilder;

/// Attempts to remove a file testing that permission is denied
pub fn try_unlink(path: &str, expect_success: bool) -> Result<(), Failed> {
    if expect_success {
        TestCommandBuilder::default()
            .program("rm")
            .args(&[path])
            .expected_rc(0)
            .build()?
            .test()
    } else {
        TestCommandBuilder::default()
            .program("rm")
            .args(&[path])
            .expected_rc(1)
            .expected_stderr("Operation not permitted")
            .build()?
            .test()
    }
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
