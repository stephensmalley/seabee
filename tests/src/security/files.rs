// SPDX-License-Identifier: Apache-2.0
use std::{fs, io::ErrorKind, os::unix::fs::PermissionsExt, path::PathBuf};

/// Module to check the security of file protections
///
/// IMPORTANT: if these tests fail, you may need to delete
/// the `target` folder and recompile since they may corrupt
/// the binary and configs used to do testing584252
/// .
use libtest_mimic::{Failed, Trial};
use seabee::constants;

use crate::{command::TestCommandBuilder, create_test, test_utils};

const PROTECTED_FILES: [&str; 3] = [
    constants::CONFIG_PATH,
    constants::SEABEECTL_EXE,
    constants::SERVICE_PATH,
];

fn try_remove_dir_all(path: &str) -> Result<(), Failed> {
    match fs::remove_dir_all(path) {
        Ok(_) => Err(format!("try_remove_dir failed: {} was deleted", { path }).into()),
        Err(e) => match e.kind() {
            std::io::ErrorKind::PermissionDenied => Ok(()),
            _ => Err(format!("Unexpected error during remove_dir_all: {e}").into()),
        },
    }
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

// try chmod and expect permission denied
pub fn try_chmod(path: &str) -> Result<(), Failed> {
    // Try to change permissions
    let result = fs::set_permissions(path, fs::Permissions::from_mode(0o777));

    // We expect a PermissionDenied error
    match result {
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Ok(()),
        Err(e) => Err(format!("try_chmod on {path}: unexpected error : {e}").into()),
        Ok(_) => Err(format!("try_chmod on {path} succeeded").into()),
    }
}

/// Tests that protected files cannot be deleted
fn security_file_deny_unlink() -> Result<(), Failed> {
    for file in PROTECTED_FILES {
        test_utils::try_unlink(file, false)?
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

// Tests that seabee protected directory cannot be removed
fn security_deny_remove_seabee_dir() -> Result<(), Failed> {
    try_remove_dir_all(constants::SEABEE_DIR)
}

// Tests that a single protected subdirectory cannot be removed
fn security_deny_remove_policy_dir() -> Result<(), Failed> {
    try_remove_dir_all(constants::POLICY_DIR)
}

// Tests chmod fails on protected files
// This tests the security_inode_setattr hook
fn security_deny_chmod() -> Result<(), Failed> {
    try_chmod(constants::POLICY_DIR)?;
    try_chmod(constants::CONFIG_PATH)?;
    Ok(())
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(security_file_deny_unlink),
        create_test!(security_file_deny_write),
        create_test!(security_deny_remove_seabee_dir),
        create_test!(security_deny_remove_policy_dir),
        create_test!(security_deny_chmod),
    ]
}
