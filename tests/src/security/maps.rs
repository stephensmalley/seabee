// SPDX-License-Identifier: Apache-2.0

/// Module to check the security of map protections
///
/// # Deliberately not included tests
///
/// 1. It is believed that malicious eBPF programs may only interact with
///    an eBPF map that is defined in their source code or *maybe* through
///    a file descriptor that is passed to it.
///    Since such a file descriptor must come from Linux userspace,
///    we do not consider malicious eBPF programs a threat to our eBPF maps.
/// 2. Our maps are not pinned to the BPF filesystem, so we do not consider
///    interactions with it or pins (see security/pins.rs)
/// 3. Tests that interact with `libbpf` or the `bpf` syscall directly.
///    While the most complete way to write these test cases would be to write
///    tests that directly try each `bpf` syscall command or libbpf wrapper,
///    we've decided that running bpftool suffices for our tests.
use std::path::Path;

use libtest_mimic::{Failed, Trial};

use crate::{command::TestCommandBuilder, create_test, suite::TestSuite};

use super::SeaBeeSecurityTestSuite;

fn try_bpftool(args: &[&str]) -> Result<(), Failed> {
    TestCommandBuilder::default()
        .program("bpftool")
        .args(args)
        .expected_rc(255)
        .expected_stderr("Operation not permitted")
        .build()?
        .test()
}

/// Tests that protected maps cannot be dumped
fn security_map_deny_dump() -> Result<(), Failed> {
    let state = SeaBeeSecurityTestSuite::get_system_state()?;
    for map in state.rust_state.maps.values() {
        try_bpftool(&["map", "dump", "id", &map.id.to_string()])?;
    }
    Ok(())
}

/// Tests that protected maps cannot be updated
fn security_map_deny_update() -> Result<(), Failed> {
    let state = SeaBeeSecurityTestSuite::get_system_state()?;

    for map in state.rust_state.maps.values() {
        let id = map.id.to_string();
        // dummy key that is likely to not be in the map
        let key: Vec<&str> = (0..map.bytes_key).map(|_| "11").collect();
        // dummy value
        let value: Vec<&str> = (0..map.bytes_value).map(|_| "11").collect();
        let mut args = vec!["map", "update", "id", &id, "key"];
        args.extend(key);
        args.push("value");
        args.extend(value);
        try_bpftool(&args)?;
    }
    Ok(())
}

/// Tests that an entry within a protected map cannot be deleted
fn security_map_deny_delete() -> Result<(), Failed> {
    let state = SeaBeeSecurityTestSuite::get_system_state()?;

    for map in state.rust_state.maps.values() {
        // Only test if there is an entry in the map
        if let Some(key) = map.data.keys().next() {
            let id = map.id.to_string();
            let mut args = vec!["map", "update", "id", &id, "key"];
            let key_str: Vec<String> = key.iter().map(|char| char.to_string()).collect();
            for key in &key_str {
                args.push(key)
            }
            try_bpftool(&args)?;
        }
    }
    Ok(())
}

/// Tests that protected maps cannot be pinned
fn security_map_deny_pin() -> Result<(), Failed> {
    let state = SeaBeeSecurityTestSuite::get_system_state()?;

    for (map_name, map) in &state.rust_state.maps {
        let id = map.id.to_string();
        let pin = Path::new(&state.rust_state.pins.dir)
            .join(map_name)
            .to_string_lossy()
            .to_string();
        try_bpftool(&["map", "pin", "id", &id, &pin])?;
    }
    Ok(())
}

/// Tests that protected maps cannot be frozen
fn security_map_deny_freeze() -> Result<(), Failed> {
    let state = SeaBeeSecurityTestSuite::get_system_state()?;

    for map in state.rust_state.maps.values() {
        try_bpftool(&["map", "freeze", "id", &map.id.to_string()])?;
    }
    Ok(())
}

pub fn tests() -> Vec<Trial> {
    vec![
        create_test!(security_map_deny_dump),
        create_test!(security_map_deny_update),
        create_test!(security_map_deny_delete),
        create_test!(security_map_deny_pin),
        create_test!(security_map_deny_freeze),
    ]
}
