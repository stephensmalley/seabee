// SPDX-License-Identifier: Apache-2.0

/// Module to check the security of kernel module protections
///
/// The Makefile will compile and install the kernel modules
/// before these tests are run.
use libtest_mimic::{Failed, Trial};

use crate::{command::TestCommandBuilder, create_test};

/// Test the `kernel_read_file` hook by trying to load kernel module
fn security_kmod_deny_kernel_module_from_file() -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program("modprobe")
        .args(&["hello_world_kmod"])
        .expected_rc(1)
        .expected_stderr("Operation not permitted")
        .build()?
        .test()
}

/// Test the kernel_load_data hook by trying to load compressed kernel module
fn security_kmod_deny_kernel_module_from_data_blob() -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program("modprobe")
        .args(&["hello_world_kmod_compressed"])
        .expected_rc(1)
        .expected_stderr("Operation not permitted")
        .build()?
        .test()
}

/// Test the kernel_module_request hook by asking a kernel module to run `request_module()`
fn security_kmod_deny_kernel_module_request() -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program("kmod_test/test_kmod_user")
        .args(&["-r"])
        .expected_rc(0)
        .expected_stdout("DENIED")
        .build()?
        .test()
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(security_kmod_deny_kernel_module_from_file),
        create_test!(security_kmod_deny_kernel_module_from_data_blob),
        create_test!(security_kmod_deny_kernel_module_request),
    ]
}
