// SPDX-License-Identifier: Apache-2.0
pub mod write_user {
    include!(concat!(env!("OUT_DIR"), "/write_user.skel.rs"));
}

pub mod test_tool {
    include!(concat!(env!("OUT_DIR"), "/test_tool.skel.rs"));

    pub fn rb_callback(data: &[u8]) -> i32 {
        let count = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
        let file = crate::logging::char_array_to_str(&data[4..]);
        println!("file num {count}: '{file}'");
        0
    }
}
