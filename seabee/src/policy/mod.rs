// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::{collections::HashMap, os::unix::net::UnixListener, path::PathBuf};

use anyhow::{anyhow, Result};

use crate::config::Config;
use crate::constants::SEABEE_ROOT_KEY_PATH;
use crate::crypto;
use policy_file::PolicyFile;

pub mod boot_load;
mod crypto_api;
mod fs_api;
pub mod policy_file;
pub mod runtime_update;

pub const ROOT_KEY_ID: u32 = 0;

#[derive(Debug)]
pub struct SeaBeePolicy {
    /// Maps a policy name to a PolicyFile
    policies: HashMap<String, PolicyFile>,
    /// SeaBee base policy (the policy that protects SeaBee itself)
    pub base_policy: PolicyFile,
    /// The id for the next policy to be assigned. Ensures no two policies have the same id
    next_policy_id: u32,
    /// Listens for connections from seabeectl for user interaction
    listener: Option<UnixListener>,
    /// Is policy verification enabled?
    verify_policy: bool,
    /// Is key verification enabled?
    verify_keys: bool,
    /// A list of verification keys including the root key
    verification_keys: HashMap<u32, crypto::SeaBeeKey>,
    /// The id for the next key to be assigned.
    next_key_id: u32,
}

impl SeaBeePolicy {
    pub fn init(config: &Config) -> Result<Self> {
        let mut verification_keys = HashMap::new();
        let root_key =
            match crypto::SeaBeeKey::new_key(&PathBuf::from(SEABEE_ROOT_KEY_PATH), ROOT_KEY_ID) {
                Ok(key) => key,
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to get root key from {SEABEE_ROOT_KEY_PATH}.\n{e}"
                    ))
                }
            };
        verification_keys.insert(ROOT_KEY_ID, root_key);

        Ok(Self {
            policies: HashMap::default(),
            base_policy: PolicyFile::base(config)?,
            next_policy_id: policy_file::BASE_POLICY_ID + 1,
            verification_keys,
            verify_policy: config.verify_policy,
            verify_keys: config.verify_keys,
            listener: None,
            next_key_id: ROOT_KEY_ID + 1,
        })
    }

    /// returns a policy id that has not yet been used
    /// TODO: inflexible, will need to fit within kernel memory limits
    pub fn get_unused_policy_id(&mut self) -> Result<u32> {
        let unused_id = self.next_policy_id;
        match unused_id.checked_add(1) {
            Some(next_policy_id) => self.next_policy_id = next_policy_id,
            None => {
                return Err(anyhow!(
                    "SeaBee ran out of policy ids! Restart to refresh ids."
                ))
            }
        }
        Ok(unused_id)
    }
}

/// Allows test cases to run correctly with policy turned on (bpftool exec will not be labeled)
pub fn generate_policy_prog_filter(config: &Config, filtered_progs: &mut HashSet<String>) {
    if config.test {
        filtered_progs.insert(String::from("seabee_label_child_process"));
    }
}
