// SPDX-License-Identifier: Apache-2.0
use std::collections::HashSet;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{skel::Skel, Link, MapCore, MapHandle, ProgramMut};
use tracing::trace;

type InodeNumber = u64;

pub struct PinnedLink {
    pub link: Link,
    pub inode: InodeNumber,
}

/// Attach and pin all programs for a skeleton
pub fn attach_pin_programs(
    skel: &mut dyn Skel,
    pin_dir: &Path,
    prog_name_filter: HashSet<String>,
) -> Result<Vec<PinnedLink>> {
    // Attach & pin
    let mut pinned_links: Vec<PinnedLink> = Vec::new();

    for prog in skel.object_mut().progs_mut() {
        let prog_name = prog
            .name()
            .to_str()
            .context("Bad program name")?
            .to_string();
        if !prog_name_filter.contains(prog_name.as_str()) {
            pinned_links.push(attach_pin(prog, &prog_name, pin_dir)?);
        }
    }
    Ok(pinned_links)
}

/// Attach and pin all programs
pub fn attach_pin(prog: ProgramMut, prog_name: &str, pin_dir: &Path) -> Result<PinnedLink> {
    let pin_path = pin_dir.join(prog_name);

    // Attach program
    // Note: Some eBPF programs (XDP) require an argument.
    //       These program types will fail to attach with this implementation.
    let mut link = prog
        .attach()
        .context(format!("Failed to attach {prog_name}"))?;

    // Pin program
    link.pin(&pin_path)
        .context(format!("Failed to pin {prog_name}"))?;

    trace!(
        "Attached program {} and pinned to path {}",
        prog_name,
        pin_path.to_string_lossy()
    );

    // Save link and inode info
    let pin_path_inode = nix::sys::stat::stat(&pin_path)?.st_ino;

    Ok(PinnedLink {
        link,
        inode: pin_path_inode,
    })
}

/// Helper function to get a named map from a skeleton or return an Err
pub fn get_map(name: &str, skel: &dyn Skel) -> Result<MapHandle> {
    for map in skel.object().maps() {
        if name == map.name() {
            return Ok(MapHandle::try_from(&map)?);
        }
    }
    Err(anyhow!("{name} map not found in skeleton"))
}

/// Helper function to get a named program from a skeleton or return an Err
pub fn get_prog<'a>(name: &str, skel: &'a mut dyn Skel) -> Result<ProgramMut<'a>> {
    for prog in skel.object_mut().progs_mut() {
        if prog.name() == name {
            return Ok(prog);
        }
    }
    Err(anyhow!("{name} program not found in skeleton"))
}
