use libtest_mimic::Failed;

/// Attempts to run `kill` with specified arguments and return code
pub fn try_kill(signal: i32, pid: u32, expect_success: bool) -> Result<(), Failed> {
    let res = unsafe { libc::kill(pid as i32, signal) };
    if res == 0 && !expect_success {
        Err(format!("Signal {signal:?} should not have succeeded, return: {res}").into())
    } else if res != 0 && expect_success {
        Err(format!(
            "Signal {signal:?} should not have failed: {}",
            std::io::Error::last_os_error()
        )
        .into())
    } else {
        Ok(())
    }
}
