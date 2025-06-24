// SPDX-License-Identifier: Apache-2.0
include!(concat!(env!("OUT_DIR"), "/shared_rust_types.rs"));
/// Kernel version v5.14 is the oldest we officially support as that is RHEL 9
pub mod seabee_5_14_0 {
    include!(concat!(env!("OUT_DIR"), "/seabee.skel.rs"));
}
pub mod seabee_6_1_0 {
    include!(concat!(env!("OUT_DIR"), "/seabee_6_1_0.skel.rs"));
}
pub mod seabee_6_9_0 {
    include!(concat!(env!("OUT_DIR"), "/seabee_6_9_0.skel.rs"));
}
