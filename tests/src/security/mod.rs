// SPDX-License-Identifier: Apache-2.0
use std::sync::OnceLock;

use libtest_mimic::Trial;

use crate::suite::{TestSuite, TestSystemState};
use seabee::config::Config;

mod files;
mod kmod;
mod maps;
mod pins;
mod ptrace;
mod signal;
mod uprobe;

pub static TEST_SYSTEM_STATE: OnceLock<TestSystemState> = OnceLock::new();
pub static CONFIG: OnceLock<Config> = OnceLock::new();

pub struct SeaBeeSecurityTestSuite;

impl TestSuite for SeaBeeSecurityTestSuite {
    type CustomTestState = Config;

    fn custom_state() -> &'static OnceLock<Self::CustomTestState> {
        &CONFIG
    }

    fn system_state() -> &'static OnceLock<TestSystemState> {
        &TEST_SYSTEM_STATE
    }

    fn tests() -> Vec<Trial> {
        let mut tests = Vec::new();
        tests.extend(files::tests());
        tests.extend(kmod::tests());
        tests.extend(maps::tests());
        tests.extend(pins::tests());
        tests.extend(ptrace::tests());
        tests.extend(signal::tests());
        tests.extend(uprobe::tests());
        tests
    }
}
