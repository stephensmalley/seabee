// SPDX-License-Identifier: Apache-2.0
use std::{fs, path::PathBuf};

/// Module to check the security of file protections
///
/// IMPORTANT: if these tests fail, you may need to delete
/// the `target` folder and recompile since they may corrupt
/// the binary and configs used to do testing584252
/// .
use libtest_mimic::{Failed, Trial};
use seabee::constants::{self, TEST_PROTECT_DIR};

use crate::{command::TestCommandBuilder, create_test};

//TODO: refactor to include directories
const PROTECTED_FILES: [&str; 3] = [
    constants::CONFIG_PATH,
    constants::SEABEECTL_EXE,
    constants::SERVICE_PATH,
];

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
    for file in PROTECTED_FILES {
        try_unlink(file)?
    }

    Ok(())
}

/// Tests that protected files cannot be written to
fn security_file_deny_write() -> Result<(), Failed> {
    for file in PROTECTED_FILES {
        try_write(file, PathBuf::from(file) == std::env::current_exe()?)?
    }

    Ok(())
}

fn security_protect_directory() -> Result<(), Failed> {
    match fs::remove_dir(TEST_PROTECT_DIR) {
        Ok(_) => Err(format!("{TEST_PROTECT_DIR} was deleted").into()),
        Err(e) => match e.kind() {
            std::io::ErrorKind::PermissionDenied => Ok(()),
            _ => Err(format!("Unexpected error during remove_dir: {e}").into()),
        },
    }
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(security_file_deny_unlink),
        create_test!(security_file_deny_write),
        create_test!(security_protect_directory),
    ]
}
