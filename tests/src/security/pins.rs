// SPDX-License-Identifier: Apache-2.0

/// Module to check the security of pin protections
///
/// # Intentionally not included Tests
///
/// - BPF_LINK_DETACH on our pinned programs returns -EOPNOTSUPP with bpftool.
///
/// # Missing Tests
///
/// - Is `BPF_LINK_UPDATE` dangerous to our links?
/// - prevent `BPF_OBJ_GET` on pins, generally prevent interaction with
///   our pinned programs through the BPF filesystem
use std::path::Path;

use libtest_mimic::{Failed, Trial};

use crate::{command::TestCommandBuilder, create_test, suite::TestSuite};

use super::SeaBeeSecurityTestSuite;

/// Tests that protected BPF pins cannot be deleted
fn security_pin_deny_unlink() -> Result<(), Failed> {
    let state = SeaBeeSecurityTestSuite::get_system_state()?;

    let dir = Path::new(&state.rust_state.pins.dir);
    for path in state.rust_state.pins.pins.keys() {
        let full_path = dir.join(Path::new(&path));
        TestCommandBuilder::default()
            .program("rm")
            .args(&[&full_path.to_string_lossy()])
            .expected_rc(1)
            .expected_stderr("Operation not permitted")
            .build()?
            .test()?;
    }

    Ok(())
}

pub fn tests() -> Vec<Trial> {
    vec![create_test!(security_pin_deny_unlink)]
}
