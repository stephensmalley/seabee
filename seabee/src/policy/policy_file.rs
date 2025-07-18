// SPDX-License-Identifier: Apache-2.0
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{config::SecurityLevel, constants, crypto, utils};

const NO_POLICY_ID: u32 = bpf::seabee::NO_POL_ID;
pub const BASE_POLICY_ID: u32 = bpf::seabee::BASE_POLICY_ID;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PolicyConfig {
    /// Select map security level
    pub map_access: SecurityLevel,

    /// Select pin security level
    pub pin_access: SecurityLevel,

    /// Protection level for files
    pub file_write_access: SecurityLevel,
}

/// Use audit as default to prevent unintentional breakage of other programs that use SeaBee
impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            map_access: SecurityLevel::audit,
            pin_access: SecurityLevel::audit,
            file_write_access: SecurityLevel::audit,
        }
    }
}

impl PolicyConfig {
    pub fn to_c_policy_config(&self) -> bpf::seabee::c_policy_config {
        bpf::seabee::c_policy_config {
            file_modification: self.file_write_access as u8,
            map_access: self.map_access as u8,
            pin_removal: self.pin_access as u8,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Uniquely idenfies a policy file and corresponds to name
    #[serde(skip, default = "default_policy_id")]
    pub id: u32,
    // Stores the path to the policy in the seabee policy directory
    #[serde(skip, default)]
    pub seabee_path: PathBuf,
    /// Uniquely identifies a policy file
    pub name: String,
    pub version: u32,
    pub scope: HashSet<String>,
    pub files: HashSet<String>,
    pub config: PolicyConfig,
    #[serde(default)]
    pub digest: crypto::SeaBeeDigest,
    // Identifies the key used to sign this policy
    #[serde(skip)]
    pub key_id: Option<u32>,
}

fn default_policy_id() -> u32 {
    NO_POLICY_ID
}

impl PolicyFile {
    pub fn from_path(path: &PathBuf) -> Result<Self> {
        utils::verify_file_has_ext(path, vec!["yaml", "yml"])?;
        let policy_str = match std::fs::read_to_string(Path::new(path)) {
            Ok(s) => s,
            Err(e) => return Err(anyhow!("error reading '{}' to string: {e}", path.display())),
        };
        Ok(serde_yaml::from_str(&policy_str)?)
    }

    pub fn base() -> Result<Self> {
        let current_exe = std::env::current_exe()?;
        let current_exe_str = current_exe
            .to_str()
            .context("Cannot convert current exe path to string")?;
        Ok(Self {
            id: BASE_POLICY_ID,
            name: String::from("base"),
            files: HashSet::from([
                current_exe_str.to_string(),
                String::from(constants::SERVICE_PATH),
                String::from(constants::CONFIG_PATH),
                String::from(constants::SEABEECTL_EXE),
            ]),
            config: PolicyConfig {
                map_access: SecurityLevel::blocked,
                pin_access: SecurityLevel::blocked,
                file_write_access: SecurityLevel::blocked,
            },
            ..Default::default()
        })
    }

    pub fn display_short(&self) -> String {
        format!(
            "{}({}) scope: {}",
            self.name,
            self.id,
            self.scope.iter().join(", ")
        )
    }
}

impl std::fmt::Display for PolicyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_id_str = match self.key_id {
            Some(id) => id.to_string(),
            None => String::from("None"),
        };
        write!(
            f,
            "{}: {}\n  signed by key id: {}\n  version: {}\n  scope: {}\n  files: {}\n  config:\n    maps: {}\n    pins: {}\n    files: {}",
            self.id, self.name, key_id_str, self.version, self.scope.iter().join(", "), self.files.iter().join(", "), self.config.map_access, self.config.pin_access, self.config.file_write_access,
        )
    }
}

impl PartialEq for PolicyFile {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

/// Minimum amount of information needed to remove a policy.
/// Also the format of a signed yaml request to remove a policy.
#[derive(Serialize, Deserialize)]
pub struct RemovePolicyYaml {
    pub name: String,
    pub version: u32,
}

impl RemovePolicyYaml {
    pub fn from_path(path: &PathBuf) -> Result<Self> {
        utils::verify_file_has_ext(path, vec!["yaml", "yml"])?;
        let request_str = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => return Err(anyhow!("error reading '{}' to string: {e}", path.display())),
        };
        Ok(serde_yaml::from_str(&request_str)?)
    }
}
