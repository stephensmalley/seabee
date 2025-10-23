// SPDX-License-Identifier: Apache-2.0

/// Module to check the security of signal protections
use libtest_mimic::{Failed, Trial};

use seabee::utils::generate_sigmask;

use crate::{create_test, suite::TestSuite, test_utils};

use super::SeaBeeSecurityTestSuite;

/// Check that a null/0 signal can be sent to the userspace
/// This is commonly used to see if a pid still exists
fn security_signal_send_null() -> Result<(), Failed> {
    test_utils::try_kill(0, unsafe { libc::getpid() as u32 }, true)
}

/// Check that the process survives a SIGKILL
fn security_signal_send_sigkill() -> Result<(), Failed> {
    test_utils::try_kill(libc::SIGKILL, unsafe { libc::getpid() as u32 }, false)
}

/// Check that the sigmask works to block unwanted signals
fn security_signal_check_sigmask() -> Result<(), Failed> {
    let config = SeaBeeSecurityTestSuite::get_custom_state()?;
    let sigmask = generate_sigmask(config.sigint);

    for signal in 1..=libc::SIGRTMAX() {
        // SIGINT is reserved as a 'backdoor' for test purposes
        if signal == libc::SIGINT && config.sigint {
            continue;
        }
        // if the signal is allowed skip it
        if (1 << (signal - 1)) & sigmask != 0 {
            continue;
        }
        test_utils::try_kill(signal, unsafe { libc::getpid() as u32 }, false)?
    }
    Ok(())
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(security_signal_send_null),
        create_test!(security_signal_send_sigkill),
        create_test!(security_signal_check_sigmask),
    ]
}
