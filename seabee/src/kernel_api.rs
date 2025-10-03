// SPDX-License-Identifier: Apache-2.0
use std::{
    fs,
    mem::MaybeUninit,
    os::fd::AsFd,
    path::{Path, PathBuf},
    process,
};

use anyhow::{anyhow, Context, Result};
use libbpf_rs::{
    query,
    skel::{OpenSkel, Skel, SkelBuilder},
    Map, MapCore, OpenObject,
};
use tracing::{debug, trace};
use zerocopy::IntoBytes;

use bpf::kernel_api::{label_file, label_maps, label_task};
use bpf::{common::PinnedLink, seabee::PATH_MAX};

use crate::{
    constants,
    policy::policy_file::{self, PolicyFile, BASE_POLICY_ID},
    utils, SeaBee, SeaBeeMapHandles,
};

/// Updates the ebpf "policy_map" with an id and a config. This can
/// be either an existing id or a new a id.
pub fn update_kernel_policy_map(
    maps: &SeaBeeMapHandles,
    id: u32,
    config: &policy_file::PolicyConfig,
) -> Result<()> {
    let config = config.to_c_policy_config();
    if let Err(e) =
        maps.policy_map
            .update(id.as_bytes(), config.as_bytes(), libbpf_rs::MapFlags::ANY)
    {
        return Err(anyhow!(
            "Error: update_kernel_policy_map: possibly exceeded max policies: {}\n error: '{}'",
            constants::SEABEE_MAX_POLICIES,
            e
        ));
    }
    trace!("Completed update_kernel_policy_map for id: {id}\n{config:?}");
    Ok(())
}

/// removes a policy from the kernel based on an id.
///
/// This removes the policy from the policy map so there will no longer
/// be a policy associated with the given policy id. Objects still labeled with this id
/// will be treated as if they have no policy id.
pub fn remove_kernel_policy(maps: &SeaBeeMapHandles, policy_id: u32) -> Result<()> {
    debug!("remove kernel policy: {}", policy_id);
    maps.policy_map.delete(policy_id.as_bytes())?;

    // inode and task local storage labels will persist,
    //   but will not be associated with a policy, so they won't be affected
    // map protections will be removed when maps are deallocated
    Ok(())
}

// Add a path to the scope corresponding to an id
pub fn add_path_to_scope(maps: &SeaBeeMapHandles, path: &Path, id: u32) -> Result<()> {
    let key = utils::str_to_bytes(
        path.to_str()
            .context(format!("failed to covert {} to string", path.display()))?,
        PATH_MAX.try_into()?,
    )?;

    if let Err(e) =
        maps.path_to_pol_id
            .update(key.as_slice(), id.as_bytes(), libbpf_rs::MapFlags::ANY)
    {
        return Err(anyhow!(
            "Error: add_path_to_scope: possibly exceeded max policy scopes: {}\n error: '{e}'",
            constants::SEABEE_MAX_POLICY_SCOPES,
        ));
    }
    debug!("added path {} to scope for policy {}", path.display(), id);
    Ok(())
}

/// Label all files for a policy with a given id
pub fn label_files_for_policy(policy: &PolicyFile, sb_maps: &SeaBeeMapHandles) -> Result<()> {
    debug!("label_files_for_policy id: {}", policy.id);
    let mut open_object = MaybeUninit::uninit();
    let skel = load_label_file_skel(&mut open_object, sb_maps)?;

    // label files
    for path in &policy.files {
        utils::walk_with(path, |entry| {
            if entry.path().is_file() || entry.path().is_dir() {
                trigger_inode_labeling(&skel.maps.filename_to_policy_id, path, policy.id).map_err(
                    |e| {
                        anyhow!(
                            "label_files_for_policy {}: failed to label {}\n{e}",
                            policy.id,
                            path.display()
                        )
                    },
                )?;
            } else {
                println!("{} is not a file and was skipped", entry.path().display());
            }
            Ok(())
        })?;

        // } else if path.is_dir() {
        //     for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
        //         let entry_path = entry.path();
        //         if entry_path.is_file() {
        //             trigger_inode_labeling(&skel.maps.filename_to_policy_id, entry_path, policy.id)
        //                 .map_err(|e| {
        //                     anyhow!(
        //                         "label_files_for_policy {}: failed to label {}\n{e}",
        //                         policy.id,
        //                         entry_path.display()
        //                     )
        //                 })?;
        //         }
        //     }
        //     // label_directory_recurse(&path, &skel.maps.filename_to_policy_id, policy.id)?;
        // } else {
        //     //TODO: should this be error? what if we skip and warn instead?
        //     return Err(anyhow!(
        //         "label_files_for_policy {}: failed to label {}: neither a file or a directory",
        //         policy.id,
        //         path.display()
        //     ));
        // }
    }

    Ok(())
}

/// Label a given file with a given id
pub fn label_file_with_id(sb_maps: &SeaBeeMapHandles, path: &Path, id: u32) -> Result<()> {
    debug!("Labeling file {} with id: {id}", path.display());
    let mut open_object = MaybeUninit::uninit();
    let skel = load_label_file_skel(&mut open_object, sb_maps)?;
    if let Err(e) = trigger_inode_labeling(&skel.maps.filename_to_policy_id, path, id) {
        return Err(anyhow!(
            "label_file_with_id failed on {}: {e}",
            path.display()
        ));
    }

    Ok(())
}

/// Unlabel a given file
pub fn unlabel_file(sb_maps: &SeaBeeMapHandles, file: &PathBuf) -> Result<()> {
    debug!("unlabel file {}", file.display());
    let mut open_object = MaybeUninit::uninit();
    let skel = load_label_file_skel(&mut open_object, sb_maps)?;
    trigger_inode_labeling(
        &skel.maps.filename_to_policy_id,
        Path::new(file),
        bpf::seabee::NO_POL_ID,
    )?;

    Ok(())
}

pub fn label_pins(
    pins: &Vec<PinnedLink>,
    policy_id: u32,
    sb_maps: &SeaBeeMapHandles,
) -> Result<()> {
    debug!("Labeling pins...");
    let mut open_object = MaybeUninit::uninit();
    let skel = load_label_file_skel(&mut open_object, sb_maps)?;

    for pin in pins {
        match pin.link.pin_path() {
            Some(path) => {
                trigger_inode_labeling(&skel.maps.filename_to_policy_id, &path, policy_id)?
            }
            None => {
                return Err(anyhow!("link was not pinned!"));
            }
        }
    }
    Ok(())
}

/// Adds access protections for every map in a skeleton
pub fn label_maps_for_skel(
    skel: &dyn Skel,
    policy_id: u32,
    sb_maps: &SeaBeeMapHandles,
) -> Result<()> {
    debug!("Labeling maps...");

    // Setup
    let num_maps = skel.object().maps().count();
    let mut open_object = MaybeUninit::uninit();
    let label_skel = load_label_maps_skel(&mut open_object, sb_maps, num_maps)?;
    for map in skel.object().maps() {
        let key = map.info()?.info.id;
        label_skel.maps.map_id_to_pol_id.update(
            key.as_bytes(),
            policy_id.as_bytes(),
            libbpf_rs::MapFlags::ANY,
        )?;
    }

    // Trigger eBPF via 'bpf_map_get_fd_by_id'
    // This will trigger for every map on the system, but only the SeaBee maps will be labeled
    for _map in query::MapInfoIter::default() {
        continue;
    }

    Ok(())
}

// should only be called after load_label_file_skel(), this triggers
// loaded eBPF programs which actually execute the file labeling
fn trigger_inode_labeling(map: &Map, path: &Path, policy_id: u32) -> Result<()> {
    // Update map with filename
    let file_name = path.file_name().context(format!(
        "trigger_file_labeling: file_name() failed on {}",
        path.display()
    ))?;
    let key = crate::utils::str_to_bytes(
        file_name.to_str().context(format!(
            "trigger_file_labeling: to_str() failed on {}",
            path.display()
        ))?,
        128,
    )?;
    map.update(
        key.as_slice(),
        policy_id.as_bytes(),
        libbpf_rs::MapFlags::ANY,
    )?;

    // trigger 'seabee_label_file' eBPF program in 'label_file.bpf.c' using stat.
    // After successfully labeling the file, a permission denied is returned.
    // We don't actually care about the result of stat.
    // The denial simply indicates we successfully triggered our program.
    match nix::sys::stat::stat(path) {
        Ok(_) => Err(anyhow!(
            "trigger_file_labeling: stat returned unexpected allow for {}",
            path.display()
        )),
        Err(e) => {
            if e == nix::errno::Errno::EPERM {
                Ok(())
            } else {
                Err(anyhow!("trigger_file_labeling: failed stat: {e}"))
            }
        }
    }?;

    // Reset map
    map.delete(key.as_slice())?;
    Ok(())
}

/// Updates task storage for associated pid with the given policy id
pub fn label_seabee_process(sb: &SeaBee) -> Result<()> {
    debug!("Labeling seabee process with id: {BASE_POLICY_ID}");
    let mut open_object = MaybeUninit::uninit();
    let _skel = load_label_task_skel(&mut open_object, sb, BASE_POLICY_ID)?;

    // signal each thread in task
    for entry in fs::read_dir("/proc/self/task")? {
        if let Some(name) = entry?.file_name().to_str() {
            let tid = name.parse::<u32>().map_err(|e| {
                anyhow!("label_seabee_process: failed to convert {name} to u32: {e}")
            })?;
            let tgid = process::id();

            // signal thread and catch error
            let result =
                unsafe { libc::syscall(libc::SYS_tgkill, tgid as i32, tid as i32, libc::SIGCONT) };
            if result != 0 {
                return Err(anyhow!(
                    "libc::kill returned error: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }

    Ok(())
}

fn load_label_file_skel<'a>(
    open_object: &'a mut MaybeUninit<OpenObject>,
    sb_maps: &SeaBeeMapHandles,
) -> Result<label_file::LabelFileSkel<'a>> {
    let mut open_skel = label_file::LabelFileSkelBuilder::default().open(open_object)?;

    open_skel
        .maps
        .inode_storage
        .reuse_fd(sb_maps.inode_storage.as_fd())?;
    open_skel
        .maps
        .log_ringbuf
        .reuse_fd(sb_maps.log_ringbuf.as_fd())?;
    open_skel
        .maps
        .policy_map
        .reuse_fd(sb_maps.policy_map.as_fd())?;
    open_skel.maps.bss_data.user_pid = process::id();
    open_skel.maps.bss_data.log_level = *bpf::logging::LOG_LEVEL.get().unwrap() as u32;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    debug!("Label file skel was attached");

    Ok(skel)
}

fn load_label_task_skel<'a>(
    open_object: &'a mut MaybeUninit<OpenObject>,
    sb: &SeaBee,
    policy_id: u32,
) -> Result<label_task::LabelTaskSkel<'a>> {
    let mut open_skel = label_task::LabelTaskSkelBuilder::default().open(open_object)?;
    open_skel
        .maps
        .task_storage
        .reuse_fd(sb.maps.task_storage.as_fd())?;
    open_skel
        .maps
        .log_ringbuf
        .reuse_fd(sb.maps.log_ringbuf.as_fd())?;
    open_skel
        .maps
        .policy_map
        .reuse_fd(sb.maps.policy_map.as_fd())?;
    open_skel.maps.bss_data.user_pid = process::id();
    open_skel.maps.bss_data.policy_id = policy_id;
    open_skel.maps.bss_data.log_level = *bpf::logging::LOG_LEVEL.get().unwrap() as u32;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    debug!("Label task skel was attached");

    Ok(skel)
}

fn load_label_maps_skel<'a>(
    open_object: &'a mut MaybeUninit<OpenObject>,
    sb_maps: &SeaBeeMapHandles,
    num_maps: usize,
) -> Result<label_maps::LabelMapsSkel<'a>> {
    let mut open_skel = label_maps::LabelMapsSkelBuilder::default().open(open_object)?;
    open_skel.maps.bss_data.log_level = *bpf::logging::LOG_LEVEL.get().unwrap() as u32;
    open_skel
        .maps
        .map_to_pol_id
        .reuse_fd(sb_maps.map_to_pol_id.as_fd())?;
    open_skel
        .maps
        .log_ringbuf
        .reuse_fd(sb_maps.log_ringbuf.as_fd())?;
    open_skel
        .maps
        .map_id_to_pol_id
        .set_max_entries(num_maps.try_into()?)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    debug!("Label maps skel was attached");

    Ok(skel)
}
