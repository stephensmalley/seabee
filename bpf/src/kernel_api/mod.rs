// SPDX-License-Identifier: Apache-2.0

// error if two skels in the same module
pub mod label_file {
    include!(concat!(env!("OUT_DIR"), "/label_file.skel.rs"));
}
pub mod label_task {
    include!(concat!(env!("OUT_DIR"), "/label_task.skel.rs"));
}
pub mod label_maps {
    include!(concat!(env!("OUT_DIR"), "/label_maps.skel.rs"));
}
