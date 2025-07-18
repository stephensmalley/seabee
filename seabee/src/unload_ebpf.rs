// SPDX-License-Identifier: Apache-2.0
use std::{fs, path::Path};
use tracing::{debug, error};

use crate::{constants, utils, SeaBee};

/// Automatic cleanup for [SeaBee] at process exit
///
/// Cleans up by unloading policy and deleting program pins.
impl Drop for SeaBee<'_> {
    fn drop(&mut self) {
        cleanup_return();
        debug!("Exit Drop for SeaBee")
    }
}

pub fn cleanup_return() {
    // shutting down external communications should happen first
    if let Err(e) = utils::remove_if_exists(Path::new(constants::SOCKET_PATH)) {
        error!("error cleaning up socket path: {}", e);
    }

    // remove pin files and pin dir
    if let Err(e) = fs::remove_dir_all(constants::PIN_DIR) {
        error!("error cleaning up pin dir: {}", e);
    }
}
