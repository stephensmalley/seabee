// SPDX-License-Identifier: Apache-2.0
use std::sync::OnceLock;

use libtest_mimic::Trial;

use crate::suite::TestSystemState;

use super::suite::TestSuite;

mod maps;
mod pins;
mod userspace;

pub static TEST_SYSTEM_STATE: OnceLock<TestSystemState> = OnceLock::new();
pub static UNUSED_CUSTOM_STATE: OnceLock<u32> = OnceLock::new();

pub struct FunctionalTestSuite;

impl TestSuite for FunctionalTestSuite {
    type CustomTestState = u32; // never used

    fn system_state() -> &'static OnceLock<crate::suite::TestSystemState> {
        &TEST_SYSTEM_STATE
    }

    fn custom_state() -> &'static OnceLock<Self::CustomTestState> {
        &UNUSED_CUSTOM_STATE
    }

    fn tests() -> Vec<Trial> {
        let mut tests = Vec::new();
        tests.extend(maps::tests());
        tests.extend(pins::tests());
        tests.extend(userspace::tests());
        tests
    }
}
