// SPDX-License-Identifier: Apache-2.0

use std::io::Write;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use bpf::tests::test_tool::*;
use tests::policy::test_constants;

fn main() -> Result<()> {
    // create file, TEST_DIR must already exist
    let mut file = std::fs::File::create(test_constants::TEST_TOOL_FILE)?;
    file.write_all(b"Hello, World!")?;

    // load ebpf skel
    let skel_builder = TestToolSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let skel = open_skel.load()?;
    let mut link = skel.progs.test_seabee.attach()?;
    link.pin(test_constants::TEST_TOOL_PIN_PATH)?;

    // stop loop with ctrlc
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    // setup ringbuffer
    let mut rbb = libbpf_rs::RingBufferBuilder::new();
    rbb.add(&skel.maps.ringbuf, rb_callback)?;
    let ringbuf = rbb.build()?;

    while running.load(Ordering::SeqCst) {
        if let Err(e) = ringbuf.poll(std::time::Duration::from_millis(10)) {
            if e.kind() == libbpf_rs::ErrorKind::Interrupted {
                continue;
            } else {
                return Err(e.into());
            }
        }
    }

    std::fs::remove_file(test_constants::TEST_TOOL_PIN_PATH)?;
    std::fs::remove_dir_all(test_constants::TEST_TOOL_DIR)?;

    Ok(())
}
