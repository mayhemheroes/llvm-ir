#![no_main]
use libfuzzer_sys::fuzz_target;
use llvm_ir::Module;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;

fuzz_target!(|data: &[u8]| {
    // bitcode header is 5 u32s
    if data.len() < 5 * 4 {
        return;
    }

    let mfd = match memfd::MemfdOptions::default().create("fuzz-file") {
        Ok(m) => m,
        Err(_) => return,
    };

    let fd = mfd.as_raw_fd();
    let filepath = format!("/proc/self/fd/{fd}");

    let mut file = mfd.into_file();
    if file.write_all(data).is_err() {
        println!("could not write to memfd file!");
        return;
    }

    if file.seek(SeekFrom::Start(0)).is_err() {
        println!("failed to seek!");
        return;
    }

    let _ = Module::from_bc_path(&filepath);

    drop(file);
});
