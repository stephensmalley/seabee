// SPDX-License-Identifier: Apache-2.0
use std::{path::PathBuf, sync::OnceLock};

use anyhow::Result;
use libbpf_rs::skel::Skel;
use libtest_mimic::{Arguments, Failed, Trial};

use super::state::{linux, rust, BPFState};

/// Convenience macro for creating a [libtest_mimic::Trial] with
/// the stringified name of the test function for use when printing
#[macro_export]
macro_rules! create_test {
    ($func: path) => {
        libtest_mimic::Trial::test(stringify!($func), move || $func())
    };
}

/// Aggregated state after the Rust userspace is loaded from different
/// perspectives that tests can use to determine if the expected output
/// has been met.
#[derive(PartialEq)]
pub struct TestSystemState {
    /// State gathered at runtime from the Rust program
    pub rust_state: BPFState,
    /// State gathered at runtime from Linux (bash, bpftool, etc.)
    pub linux_state: BPFState,
    /// State gathered from static file that is always true
    pub ground_truth: BPFState,
}

impl TestSystemState {
    /// Records the SeaBee state from the Linux and Rust perspectives
    /// and optionally loads the ground truth to be used inside of tests
    pub fn new(skel: &dyn Skel, pin_dir: &PathBuf, ground_truth_path: &str) -> Result<Self> {
        let ground_truth = toml::from_str(&std::fs::read_to_string(ground_truth_path)?)?;
        Ok(Self {
            rust_state: rust::rust_state(skel, pin_dir, &ground_truth)?,
            linux_state: linux::linux_state(skel, pin_dir, &ground_truth)?,
            ground_truth,
        })
    }
}

/// Generic integration testing harness with default implementations for
/// common test lifecycle management
pub trait TestSuite {
    type CustomTestState;

    /// Provides a reference to a static [TestSystemState] needed by individual tests
    /// since [libtest_mimic] does not provide a way to pass state into tests
    fn system_state() -> &'static OnceLock<TestSystemState>;

    /// Provides a reference to a static [Self::CustomTestState] needed by individual tests
    /// since [libtest_mimic] does not provide a way to pass state into tests
    fn custom_state() -> &'static OnceLock<Self::CustomTestState>;

    /// Provides an iterator of tests to pass to the test harness for
    /// different threads to run through.
    fn tests() -> Vec<Trial>;

    /// Provides individual tests an easy way to grab the static [TestSystemState]
    fn get_system_state() -> Result<&'static TestSystemState, Failed> {
        match Self::system_state().get() {
            Some(inner) => Ok(inner),
            None => Err("You must initialize the static first".into()),
        }
    }

    /// Provides individual tests an easy way to grab the static [Self::CustomTestState]
    fn get_custom_state() -> Result<&'static Self::CustomTestState, Failed> {
        match Self::custom_state().get() {
            Some(inner) => Ok(inner),
            None => Err("You must initialize the static first".into()),
        }
    }

    /// Checks whether the runtime state gathered from the Rust program
    /// or from Linux has changed throughout the lifetime of the tests
    fn check_args(final_args: TestSystemState) -> Result<(), Failed> {
        let initial_args = Self::get_system_state()?;
        if initial_args.ground_truth != final_args.ground_truth {
            initial_args.ground_truth.diff(&final_args.ground_truth);
            return Err("ground truth changed during testing".into());
        }
        if initial_args.linux_state != final_args.linux_state {
            initial_args.linux_state.diff(&final_args.linux_state);
            return Err("linux state changed during testing".into());
        }
        if initial_args.rust_state != final_args.rust_state {
            initial_args.rust_state.diff(&final_args.rust_state);
            return Err("rust state changed during testing".into());
        }
        Ok(())
    }

    /// Default test harness lifecycle implementation
    ///
    /// It is responsible for setting up the Rust userspace as well as checking
    /// if all tests completed successfully.
    ///
    /// When this function exits, the SeaBee destructor will execute and
    /// unload all of the eBPF programs load
    fn run_tests(
        args: &Arguments,
        system_state: TestSystemState,
        custom_state: Self::CustomTestState,
    ) -> Result<(), Failed>
    where
        Self::CustomTestState: 'static,
    {
        if Self::system_state().set(system_state).is_err() {
            return Err("Unable to initialize TestSystemState".into());
        }

        if Self::custom_state().set(custom_state).is_err() {
            return Err("Unable to initialize CustomTestState".into());
        }

        let conclusion = libtest_mimic::run(args, Self::tests());

        match conclusion.has_failed() {
            true => Err("At least one test failed".into()),
            false => Ok(()),
        }
    }
}
