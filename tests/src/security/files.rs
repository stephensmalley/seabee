// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

/// Module to check the security of file protections
///
/// IMPORTANT: if these tests fail, you may need to delete
/// the `target` folder and recompile since they may corrupt
/// the binary and configs used to do testing.
use libtest_mimic::{Failed, Trial};

use crate::{command::TestCommandBuilder, create_test, suite::TestSuite};

use super::SeaBeeSecurityTestSuite;

/// Attempts to remove a file testing that permission is denied
fn try_unlink(path: &str) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program("rm")
        .args(&[path])
        .expected_rc(1)
        .expected_stderr("Operation not permitted")
        .build()?
        .test()
}

/// Attempt to write to a file testing that permission is denied
fn try_write(path: &str, exe: bool) -> Result<(), Failed> {
    if exe {
        TestCommandBuilder::default()
            .program("bash")
            .args(&["-c", &format!("echo test >> {path}")])
            .expected_stderr("Text file busy")
            .expected_rc(1)
            .build()?
            .test()
    } else {
        TestCommandBuilder::default()
            .program("bash")
            .args(&["-c", &format!("echo test >> {path}")])
            .expected_stderr("Operation not permitted")
            .expected_rc(1)
            .build()?
            .test()
    }
}

/// Tests that protected files cannot be deleted
fn security_file_deny_unlink() -> Result<(), Failed> {
    let config = SeaBeeSecurityTestSuite::get_custom_state()?;

    for file in &config.policy_file.files {
        try_unlink(file)?
    }

    Ok(())
}

/// Tests that protected files cannot be written to
fn security_file_deny_write() -> Result<(), Failed> {
    let config = SeaBeeSecurityTestSuite::get_custom_state()?;

    for file in &config.policy_file.files {
        try_write(file, PathBuf::from(file) == std::env::current_exe()?)?
    }

    Ok(())
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(security_file_deny_unlink),
        create_test!(security_file_deny_write),
    ]
}
