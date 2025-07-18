// SPDX-License-Identifier: Apache-2.0

/// Integration test suite for the SeaBee systemd daemon
use anyhow::Result;
use libtest_mimic::{Arguments, Failed};

fn main() -> Result<(), Failed> {
    let args = Arguments::from_args();
    tests::policy::run_policy_tests(&args)?;
    tracing::info!("Successfully completed all tests!");
    Ok(())
}
