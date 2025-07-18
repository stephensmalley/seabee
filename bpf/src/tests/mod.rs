// SPDX-License-Identifier: Apache-2.0
pub mod write_user {
    include!(concat!(env!("OUT_DIR"), "/write_user.skel.rs"));
}

pub mod test_tool {
    include!(concat!(env!("OUT_DIR"), "/test_tool.skel.rs"));

    pub fn rb_callback(data: &[u8]) -> i32 {
        let msg = crate::logging::char_array_to_str(data);
        println!("file open: '{msg}'");
        0
    }
}
