// SPDX-License-Identifier: Apache-2.0
use std::mem::MaybeUninit;

use anyhow::Result;

use seabee::{config, utils};

fn main() -> Result<()> {
    // verify system requirements and dependencies
    utils::verify_requirements()?;
    // Get config info
    let config = config::configure()?;
    // Setup control-c handler early before fork() protection is enabled
    let ctrlc_handler = config::setup_ctrlc(config.sigint)?;
    // Setup and load eBPF
    let mut open_obj = MaybeUninit::uninit();
    let seabee = seabee::seabee_init(config, &mut open_obj)?;

    // Run main loop
    seabee::main_loop(seabee, ctrlc_handler)?;

    Ok(())
}
