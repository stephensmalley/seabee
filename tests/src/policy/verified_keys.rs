// SPDX-License-Identifier: Apache-2.0

use libtest_mimic::{Failed, Trial};

use super::shared::{self, Expected, ECDSA_PUB, ECDSA_PUB_ROOT_SIG, RSA_PUB, RSA_PUB_ROOT_SIG};
use crate::{create_test, policy::daemon_status};

pub fn add_ecdsa_key() -> Result<(), Failed> {
    shared::add_key_signed(ECDSA_PUB, ECDSA_PUB_ROOT_SIG, Expected::Success)?;
    shared::list_keys(2)
}

pub fn add_rsa_key() -> Result<(), Failed> {
    shared::add_key_signed(RSA_PUB, RSA_PUB_ROOT_SIG, Expected::Success)?;
    shared::list_keys(3)
}

pub fn remove_ecdsa_key() -> Result<(), Failed> {
    shared::remove_key_signed(ECDSA_PUB, ECDSA_PUB_ROOT_SIG, Expected::Success)?;
    shared::list_keys(2)
}

pub fn remove_rsa_key() -> Result<(), Failed> {
    shared::remove_key_signed(RSA_PUB, RSA_PUB_ROOT_SIG, Expected::Success)?;
    shared::list_keys(1)
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(daemon_status::daemon_status),
        create_test!(shared::no_starting_keys_policies),
        create_test!(add_ecdsa_key),
        create_test!(add_rsa_key),
        create_test!(remove_ecdsa_key),
        create_test!(remove_rsa_key),
    ]
}
