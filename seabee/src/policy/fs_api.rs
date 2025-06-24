// SPDX-License-Identifier: Apache-2.0
use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

use super::policy_file::PolicyFile;
use crate::{
    constants::{self, KEYLIST_PATH},
    crypto::{SeaBeeDigest, SeaBeeKey},
};

/// Used to distinguish between keys and policies
#[derive(Debug)]
pub enum FileType {
    Key,
    Policy,
}

/// Minimal information about a key saved to the filesystem
#[derive(Serialize, Deserialize, Debug)]
pub struct SavedKey {
    pub path: PathBuf,
    pub sig_digest: SeaBeeDigest,
}

impl From<&SeaBeeKey> for crate::policy::fs_api::SavedKey {
    fn from(value: &SeaBeeKey) -> Self {
        Self {
            path: value.seabee_path.clone(),
            sig_digest: value.sig_digest.clone(),
        }
    }
}

impl super::SeaBeePolicy {
    pub fn export_keys(&self) -> Result<()> {
        let mut keylist: Vec<SavedKey> = Vec::new();
        for key in self.verification_keys.values() {
            if key.id != super::ROOT_KEY_ID {
                keylist.push(key.into());
            }
        }

        let yaml = serde_yaml::to_string(&keylist)?;
        if let Err(e) = fs::write(KEYLIST_PATH, yaml) {
            return Err(anyhow!("Error writing keylist to '{KEYLIST_PATH}'\n{e}"));
        }

        Ok(())
    }
}

pub fn import_keys() -> Result<Vec<SavedKey>> {
    match fs::read_to_string(KEYLIST_PATH) {
        Ok(yaml) => Ok(serde_yaml::from_str(&yaml)?),
        Err(e) => {
            info!("Warning: No keys added. Error reading from keylist: '{KEYLIST_PATH}'\n{e}");
            Ok(Vec::new())
        }
    }
}

/// Generates a [PolicyFile] from a yaml file. Does not do signature validation
pub fn generate_policy_from_yaml(yaml_path: &PathBuf) -> Result<PolicyFile> {
    // get policy
    let mut new_policy = PolicyFile::from_path(yaml_path)?;

    // validate files
    for file in &new_policy.files {
        if !Path::new(file).exists() {
            return Err(anyhow!("File {file} does not exist. Create the file or use 'seabeectl update' to protect the file after it is created."));
        }
    }

    // set filesystem path
    new_policy.seabee_path = get_seabee_path(yaml_path, &FileType::Policy)?;

    Ok(new_policy)
}

// Remove a policy or key file from disk and the corresponding signature
pub fn delete_seabee_file_and_sig(file_path: &PathBuf, file_type: &FileType) -> Result<()> {
    if let Err(e) = fs::remove_file(file_path) {
        return Err(anyhow!(
            "failed to {file_type:?} file at '{}'\n{e}",
            file_path.display()
        ));
    }
    let sig_path = get_sig_path(file_path, file_type)?;
    if let Err(e) = fs::remove_file(&sig_path) {
        return Err(anyhow!(
            "failed to remove {file_type:?} file signature at '{}'\n{e}",
            sig_path.display()
        ));
    };
    Ok(())
}

/// Save a policy or key to disk and its signature
/// If signature is none, then no signature is saved to disk
pub fn save_seabee_file_and_sig(
    file_path: &PathBuf,
    file_type: &FileType,
    sig_path: &Option<PathBuf>,
) -> Result<()> {
    // get paths
    let new_path = get_seabee_path(file_path, file_type)?;
    let new_sig_path = get_sig_path(file_path, file_type)?;

    // save file if it doesn't already exist
    // make sure that source and dest for copy are different
    if *file_path != new_path {
        if let Err(e) = fs::copy(file_path, &new_path) {
            return Err(anyhow!(
                "add_new_policy_from_yaml: failed to copy from {} to {}. Got error: {e}",
                file_path.display(),
                new_path.display(),
            ));
        }
    }
    // save the signature if there is one
    // make sure that source and dest for copy are different
    if let Some(sig_path) = sig_path {
        if *sig_path != new_sig_path {
            if let Err(e) = fs::copy(sig_path, &new_sig_path) {
                return Err(anyhow!(
                    "add_new_policy_from_yaml: failed to copy from {} to {}. Got error: {e}",
                    sig_path.display(),
                    new_sig_path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Return a path where the input document will be stored on disk.
///
/// * `input_path` - the path of a file passed in to SeaBee
/// * `input_type` - whether the path is to a policy or key
pub fn get_seabee_path(input_path: &Path, input_type: &FileType) -> Result<PathBuf> {
    let dir = match input_type {
        FileType::Policy => constants::POLICY_DIR,
        FileType::Key => constants::KEY_DIR,
    };

    // get the new file path
    match input_path.file_name() {
        Some(name) => Ok(Path::new(dir).join(name)),
        None => Err(anyhow!(
            "get_seabee_path: invalid file name for path '{}'",
            input_path.display()
        )),
    }
}

/// Gets the path to the signature file for a policy on disk
pub fn get_sig_path(file_path: &Path, file_type: &FileType) -> Result<PathBuf> {
    // This function should not be refactored into get_seabee_path() function because
    // boot time load requires deriving the signature path from the file path

    let dir = match file_type {
        FileType::Policy => constants::POL_SIGNATURE_DIR,
        FileType::Key => constants::KEY_SIGNATURE_DIR,
    };

    let mut sig_path = match file_path.file_name() {
        Some(name) => Path::new(dir).join(name),
        None => {
            return Err(anyhow!(
                "get_sig_path: invalid file name for path '{}'",
                file_path.display()
            ))
        }
    };
    sig_path.set_extension("sign");
    Ok(sig_path)
}
