// SPDX-License-Identifier: Apache-2.0

/// Module to check the security of ptrace protections
use libtest_mimic::{Failed, Trial};

use crate::{create_test, test_utils};

/// Tests whether a ptrace can be attached to the current process
fn security_ptrace_deny_attach() -> Result<(), Failed> {
    let pid = std::process::id();
    test_utils::try_ptrace(test_utils::PtraceOp::Attach, pid, false)
}

pub fn tests() -> Vec<Trial> {
    vec![create_test!(security_ptrace_deny_attach)]
}
