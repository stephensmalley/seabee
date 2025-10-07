// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

/// Module to check the security of file protections
///
/// IMPORTANT: if these tests fail, you may need to delete
/// the `target` folder and recompile since they may corrupt
/// the binary and configs used to do testing584252
/// .
use libtest_mimic::{Failed, Trial};
use seabee::constants;

use crate::{create_test, test_utils};

const PROTECTED_FILES: [&str; 3] = [
    constants::CONFIG_PATH,
    constants::SEABEECTL_EXE,
    constants::SERVICE_PATH,
];

/// Tests that protected files cannot be deleted
fn security_file_deny_unlink() -> Result<(), Failed> {
    for file in PROTECTED_FILES {
        test_utils::try_unlink_file(file, false)?
    }

    Ok(())
}

/// Tests that protected files cannot be written to
fn security_file_deny_open() -> Result<(), Failed> {
    for file in PROTECTED_FILES {
        test_utils::try_open(
            Path::new(file),
            PathBuf::from(file) == std::env::current_exe()?,
            false,
        )?
    }

    Ok(())
}

// Tests that seabee protected directory cannot be removed
fn security_deny_remove_seabee_dir() -> Result<(), Failed> {
    test_utils::try_remove_dir_all(constants::SEABEE_DIR, false)
}

// Tests that a single protected subdirectory cannot be removed
fn security_deny_remove_policy_dir() -> Result<(), Failed> {
    test_utils::try_remove_dir_all(constants::POLICY_DIR, false)
}

// Tests chmod fails on protected file
// This tests the security_inode_setattr hook
fn security_deny_chmod_file() -> Result<(), Failed> {
    test_utils::try_chmod(constants::CONFIG_PATH, false)
}

// Tests chmod fails on protected directory
// This tests the security_inode_setattr hook
fn security_deny_chmod_dir() -> Result<(), Failed> {
    test_utils::try_chmod(constants::POLICY_DIR, false)
}

// Block untrusted application creating a new file in a protected directory
fn security_deny_create_file() -> Result<(), Failed> {
    let testfile = std::path::Path::new(constants::POLICY_DIR).join("fake-policy");
    test_utils::try_create_file(&testfile, false)
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(security_file_deny_unlink),
        create_test!(security_file_deny_open),
        create_test!(security_deny_remove_seabee_dir),
        create_test!(security_deny_remove_policy_dir),
        create_test!(security_deny_chmod_file),
        create_test!(security_deny_chmod_dir),
        create_test!(security_deny_create_file),
    ]
}
