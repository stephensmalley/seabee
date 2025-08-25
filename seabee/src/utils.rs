// SPDX-License-Identifier: Apache-2.0
use std::{
    fs::{self, File},
    io::{ErrorKind, Read},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use nix::sys::signal::Signal;
use tracing::{error, trace};

use crate::cli::SecurityLevel;

/// Ensure the system has all requirements for running ebpf security
pub fn verify_requirements() -> Result<()> {
    ensure_root()?;
    verify_bpf_lsm_enabled()?;
    Ok(())
}

fn verify_bpf_lsm_enabled() -> Result<()> {
    let lsm_string = std::fs::read_to_string("/sys/kernel/security/lsm")?;
    if !lsm_string.contains("bpf") {
        Err(anyhow!("BPF LSM is not enabled!\nTry adding \"bpf\" to \"lsm=\" on the kernel command line.\nAlso confirm your kernel config uses CONFIG_BPF_LSM."))
    } else {
        Ok(())
    }
}

/// Check if the process is running with uid 0
pub fn ensure_root() -> Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        Err(anyhow!("You must run as root!"))
    } else {
        Ok(())
    }
}

/// Error if file does not have extensions in list of expected_ext
pub fn verify_file_has_ext(file: &Path, expected_ext: Vec<&str>) -> Result<()> {
    if let Some(file_ext) = file.extension() {
        for ext in &expected_ext {
            if file_ext == *ext {
                return Ok(());
            }
        }
    }
    Err(anyhow!(
        "file {} did not have an expected extension: {:?}",
        file.display(),
        expected_ext
    ))
}

pub fn file_to_bytes(file: &dyn AsRef<Path>) -> Result<Vec<u8>> {
    let mut file_bytes = Vec::new();
    let mut open_file = File::open(file)
        .map_err(|e| anyhow!("Failed to open file {:?}\n{e}", file.as_ref().display()))?;
    open_file
        .read_to_end(&mut file_bytes)
        .map_err(|e| anyhow!("failed to read file {}\n{e}", file.as_ref().display()))?;
    Ok(file_bytes)
}

pub fn str_to_abs_path_str(path: &str) -> Result<String> {
    match std::path::absolute(path)?.to_str() {
        Some(abs_path) => Ok(abs_path.to_owned()),
        None => Err(anyhow!("failed to convert '{path}' to String")),
    }
}

pub fn str_to_abs_pathbuf(path: &str) -> Result<PathBuf> {
    Ok(std::path::absolute(path)?)
}

/// Converts a path to a u8 vector with a requested max size
pub fn str_to_bytes(string: &str, max_size: usize) -> Result<Vec<u8>> {
    let mut bpf_c_path = vec![0; max_size];
    fill_buff_with_str(&mut bpf_c_path, max_size, string)?;

    Ok(bpf_c_path)
}

pub fn fill_buff_with_str(buf: &mut [u8], buf_size: usize, string: &str) -> Result<()> {
    // string.len() does not include a null terminator, hence >=
    if string.len() >= buf_size {
        return Err(anyhow!(
            "fill buf_with_str: string '{string}' is longer than {buf_size} bytes"
        ));
    }

    buf[..string.len()].clone_from_slice(string.as_bytes());

    Ok(())
}

/// Generates a [mask](https://en.wikipedia.org/wiki/Mask_(computing))
/// of allowed signals
pub const fn generate_sigmask(sigint: SecurityLevel) -> u64 {
    let mut sigmask: u64 = 0;
    // These signals are those that do not terminate a process by default
    sigmask |= 1 << (Signal::SIGCHLD as u64 - 1);
    sigmask |= 1 << (Signal::SIGCONT as u64 - 1);
    sigmask |= 1 << (Signal::SIGURG as u64 - 1);
    sigmask |= 1 << (Signal::SIGWINCH as u64 - 1);

    if is_sigint_allowed(sigint) {
        sigmask |= 1 << (Signal::SIGINT as u64 - 1);
    }
    sigmask
}

pub const fn is_sigint_allowed(sigint: SecurityLevel) -> bool {
    matches!(sigint, SecurityLevel::allow | SecurityLevel::audit)
}

pub fn create_dir_if_not_exists(dir: &str) -> Result<()> {
    if let Err(e) = fs::create_dir_all(dir) {
        if e.kind() != ErrorKind::AlreadyExists {
            return Err(anyhow!("failed to create dir '{}'\n{}", dir, e));
        }
    }
    Ok(())
}

/// try to open a file for reading, but create the file if it does not exist
///
/// Why open or create for all files we protect?
/// 1. if file exists, protect it
/// 2. if file does not exist,create it to prevent an adversary from creating it
/// 3. if file exists, we should not delete it when the program exits
/// 4. if file does not exist, there is no harm in not deleting it
pub fn open_or_create(path: &str) -> Result<()> {
    trace!("try open {path}");
    // try open file
    match File::open(path) {
        Ok(_) => Ok(()),
        // try to create file if it doesn't exist
        Err(e) => match e.kind() {
            ErrorKind::NotFound => {
                if let Err(e) = File::create(path) {
                    error!("open_or_create: create failed for {path}");
                    return Err(e.into());
                };
                if let Err(e) = File::open(path) {
                    error!("open_or_create: create failed for {path}");
                    return Err(e.into());
                };
                Ok(())
            }
            _ => {
                error!("open_or_create: File::open failed for {path}");
                Err(e.into())
            }
        },
    }
}

pub fn remove_if_exists(path: &Path) -> Result<()> {
    let result = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    if let Err(e) = result {
        match e.kind() {
            ErrorKind::NotFound => return Ok(()),
            _ => return Err(anyhow!("Failed to remove {}\n{e}", path.display())),
        }
    };

    Ok(())
}
