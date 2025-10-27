// SPDX-License-Identifier: Apache-2.0
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use tracing::warn;

use crate::crypto::{self, SeaBeeDigest};

impl super::SeaBeePolicy {
    /// returns a new key id that does not yet exist
    pub fn get_next_key_id(&mut self) -> Result<u32> {
        let unused_id = self.next_key_id;
        match unused_id.checked_add(1) {
            Some(key_id) => self.next_key_id = key_id,
            None => {
                return Err(anyhow!(
                    "SeaBee ran out of key ids! Restart to refresh ids."
                ))
            }
        }
        Ok(unused_id)
    }

    // Verify a new policy and set new_policy.key_id
    // O(n) where n is the number of keys
    pub fn verify_new_policy(
        &self,
        new_policy: &mut super::policy_file::PolicyFile,
        input_path: &Path,
        sig_path: &Option<PathBuf>,
    ) -> Result<()> {
        // fail if no signature
        if sig_path.is_none() {
            return self.interpret_verify_error(anyhow!(
                "Verification failure for file '{}': no signature given",
                input_path.display()
            ));
        }

        // verify signature, digest comes from policy file
        if let Some(key) = self.verification_keys.values().find(|key| {
            self.verify_signature(input_path, sig_path, &None, Some(key.id))
                .is_ok()
        }) {
            new_policy.key_id = Some(key.id)
        } else {
            return self.interpret_verify_error(anyhow!(
                "failed to verify signature for policy at '{}' and sig '{:?}'",
                input_path.display(),
                sig_path
            ));
        }

        Ok(())
    }

    /// wrapper around [crypto::verify_file_signature]
    ///
    /// This function will run even when verification is disabled, it will
    /// return Ok(()) and print a warning on verification failure
    pub fn verify_signature(
        &self,
        obj_path: &Path,
        sig_path: &Option<PathBuf>,
        custom_digest: &Option<SeaBeeDigest>,
        key_id: Option<u32>,
    ) -> Result<()> {
        // Error if no signature or key
        let sig_path = match sig_path {
            Some(path) => path,
            None => {
                return self.interpret_verify_error(anyhow!(
                    "Verification failure for file '{}': no signature given",
                    obj_path.display()
                ))
            }
        };
        let key_id = match key_id {
            Some(path) => path,
            None => {
                return self.interpret_verify_error(anyhow!(
                    "Verification failure for file '{}': no key id given",
                    obj_path.display()
                ))
            }
        };

        // Get verification result
        let digest = crypto::get_digest_algorithm(obj_path, custom_digest)?;
        let key = match self.verification_keys.get(&key_id) {
            Some(key) => key,
            None => {
                return self.interpret_verify_error(anyhow!(
                    "Key id '{}' did not exist for verifying object '{}'",
                    key_id,
                    obj_path.display()
                ))
            }
        };
        let verify_result = crypto::verify_file_signature(obj_path, sig_path, digest, key);

        // Check for errors
        let error = match verify_result {
            Ok(success) => {
                if success {
                    return Ok(());
                } else {
                    anyhow!(
                        "Verification failure\nfile: '{}'\nsig: '{}'\ndigest: '{}'",
                        obj_path.display(),
                        sig_path.display(),
                        digest.type_().short_name()?,
                    )
                }
            }
            Err(e) => anyhow!(
                "Error during signature verification\nfile: '{}'\nsig: '{}'\n{e}",
                obj_path.display(),
                sig_path.display(),
            ),
        };

        self.interpret_verify_error(error)
    }

    fn interpret_verify_error(&self, error: anyhow::Error) -> Result<()> {
        if self.verify_policy {
            return Err(error);
        } else {
            warn!("Verification Disabled, got result: \n{error}");
        }
        Ok(())
    }
}
