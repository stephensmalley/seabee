// SPDX-License-Identifier: Apache-2.0
use anyhow::Result;
use clap::Parser;

use seabee::{
    seabeectl_lib::{self, SeaBeeCtlArgs},
    utils,
};

fn main() -> Result<()> {
    utils::ensure_root()?;
    let cli_args = SeaBeeCtlArgs::parse();
    seabeectl_lib::execute_args(cli_args)?;

    Ok(())
}
