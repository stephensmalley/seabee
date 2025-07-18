// SPDX-License-Identifier: Apache-2.0
use std::mem::MaybeUninit;
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use bpf::tests::test_tool::*;

const PIN_PATH: &str = "/sys/fs/bpf/test_tool_pin";

fn main() -> Result<()> {
    // load ebpf skel
    let skel_builder = TestToolSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let skel = open_skel.load()?;
    let mut link = skel.progs.test_seabee.attach()?;
    link.pin(PIN_PATH)?;

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

    std::fs::remove_file(PIN_PATH)?;

    Ok(())
}
