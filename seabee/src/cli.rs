// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use serde::Deserialize;

use crate::policy::policy_file::PolicyConfig;
use bpf::logging::{EventType, LogLevel};

/// The default arguments
impl Default for Args {
    fn default() -> Self {
        Self {
            // Do not specify a config file
            config: None,
            // Log Level Info
            log_level: Some(LogLevelArg::info),
            // Enable map protection
            map_modification: Some(SecurityLevel::blocked),
            // Enable pin protection
            pin_modification: Some(SecurityLevel::blocked),
            // sigint is not allowed
            sigint: Some(SecurityLevel::blocked),
            // kernel modules are allowed
            kmod: Some(SecurityLevel::audit),
            // daemon modification is not allowed
            daemon_modification: Some(SecurityLevel::blocked),
            // ptrace is not allowed
            ptrace: Some(SecurityLevel::blocked),
            // nothing is excluded
            exclude: Vec::new(),
            // digital signature verification is enabled
            verify_policy: Some(true),
            // by default anyone can add a key to SeaBee
            verify_keys: Some(false),
        }
    }
}

/// Get config info from CLI arguments
pub fn args_from_cli() -> Result<Args> {
    let cli_args = Args::parse();
    // Get args from file or use Args::default() which is a blank config (None for all options)
    let mut file_args = if cli_args.config.is_some() {
        args_from_file(cli_args.config.as_ref().unwrap())?
    } else {
        Args::default()
    };
    file_args.apply(cli_args);
    Ok(file_args)
}

/// Get config info from a config file
///
/// <div class="warning">This funciton does not check if the file exists</div>
pub fn args_from_file(config_path: &str) -> Result<Args> {
    let config_str = std::fs::read_to_string(config_path)?;
    let args: Args = toml::from_str(&config_str)?;
    Ok(args)
}

/// User specified arguments in the CLI and config files.
///
/// Used by [clap::Parser] and [toml::from_str].
///
/// Every type **must** be an [Option] in order for the additive nature of
/// the [configure] function to work.
///
/// For CLAP documentation refer to <https://docs.rs/clap/>
#[derive(Parser, Clone, Debug, PartialEq, Deserialize)]
#[command(version, about = None, long_about = None)] // allows -v version command
#[serde(deny_unknown_fields)]
pub struct Args {
    /// Absolute or relative path to a config file
    #[arg(short, long)]
    config: Option<String>,

    /// Select the granularity of logs
    #[arg(short, long)]
    log_level: Option<LogLevelArg>,

    /// Select map security level
    #[arg(short, long)]
    map_modification: Option<SecurityLevel>,

    /// Select pin security level
    #[arg(short, long)]
    pin_modification: Option<SecurityLevel>,

    /// Is `kill -SIGINT <pid>` allowed to kill userspace process?
    #[arg(short, long)]
    sigint: Option<SecurityLevel>,

    /// Are kernel modules allowed to be loaded?
    #[arg(long)]
    kmod: Option<SecurityLevel>,

    /// Protection level for modification of daemon service, config, and executable files
    #[arg(short, long)]
    daemon_modification: Option<SecurityLevel>,

    /// Whether or not ptrace can be used on seabee. Use this option to run seabee under GDB.
    /// Note that PTRACE_ATTACH will cause seabee to exit gracefully while PTRACE_SEIZE will allow
    /// seabee to continue running.
    #[arg(short('t'), long)]
    ptrace: Option<SecurityLevel>,

    // A list of LogTypes to exclude from output
    #[arg(short, long, value_delimiter = ' ', num_args = 0..)]
    exclude: Vec<LogTypeCLI>,

    /// Whether or not digital signature verification for policy updates is enabled. This option is enabled
    /// by default and disabling it eliminates all security benefits SeaBee provides. Only for debugging.
    #[arg(short, long)]
    verify_policy: Option<bool>,

    /// Whether or not digital signature verification for new keys is enabled. This option is
    /// disabled by default. Enabling allows an administrator to authorize who can create SeaBee
    /// policies by controlling who can add keys.
    #[arg(long)]
    verify_keys: Option<bool>,
}

impl Args {
    /// Update an [Args] struct with values from another [Args]
    ///
    /// **Update this when [Args] or Config are updated**
    pub fn apply(&mut self, other: Args) {
        if other.log_level.is_some() {
            self.log_level = other.log_level;
        }
        if other.map_modification.is_some() {
            self.map_modification = other.map_modification;
        }
        if other.pin_modification.is_some() {
            self.pin_modification = other.pin_modification;
        }
        if other.sigint.is_some() {
            self.sigint = other.sigint;
        }
        if other.daemon_modification.is_some() {
            self.daemon_modification = other.daemon_modification;
        }
        if other.kmod.is_some() {
            self.kmod = other.kmod;
        }
        if other.ptrace.is_some() {
            self.ptrace = other.ptrace;
        }
        for log in other.exclude {
            if !self.exclude.contains(&log) {
                self.exclude.push(log);
            }
        }
        if other.verify_policy.is_some() {
            self.verify_policy = other.verify_policy;
        }
        if other.verify_keys.is_some() {
            self.verify_keys = other.verify_keys;
        }
    }
}

impl From<Args> for crate::config::Config {
    fn from(value: Args) -> Self {
        // Should not panic since every field must have been initialized with a value from DEFAULT_ARGS
        let mut config = Self {
            log_level: value.log_level.unwrap().into(),
            sigint: value.sigint.unwrap(),
            kmod: value.kmod.unwrap(),
            ptrace: value.ptrace.unwrap(),
            log_filter: {
                let mut filter = HashSet::new();
                for log_type in &value.exclude {
                    for event_type in log_type.to_event_types() {
                        filter.insert(event_type);
                    }
                }
                filter
            },
            verify_policy: value.verify_policy.unwrap(),
            verify_keys: value.verify_keys.unwrap(),
            ..Default::default()
        };
        config.policy_file.config = value.clone().into();
        config
    }
}

impl From<Args> for PolicyConfig {
    fn from(value: Args) -> Self {
        Self {
            map_access: value.map_modification.unwrap(),
            pin_access: value.pin_modification.unwrap(),
            file_write_access: value.daemon_modification.unwrap(),
        }
    }
}

/// The level of protection desired
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    serde::Deserialize,
    serde::Serialize,
    PartialEq,
    clap::ValueEnum,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
    zerocopy::Immutable,
    strum_macros::FromRepr,
)]
#[repr(C)]
pub enum SecurityLevel {
    /// No protection
    allow = 1,
    /// No protection but audit
    audit = 2,
    /// Full protection and audit
    #[default]
    blocked = 3,
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::allow => write!(f, "allow"),
            Self::audit => write!(f, "audit"),
            Self::blocked => write!(f, "blocked"),
        }
    }
}

/// The least severe log type to output
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, ValueEnum)]
enum LogLevelArg {
    off,
    error,
    warn,
    #[default]
    info,
    debug,
    trace,
}

impl From<LogLevelArg> for LogLevel {
    fn from(level: LogLevelArg) -> Self {
        LogLevel::from_repr(level as u32).expect("Bad log level conversion")
    }
}

// Used to generate CLI for log filtering
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, ValueEnum)]
pub enum LogTypeCLI {
    File,
    Unmount,
    Map,
    Signal,
    Kmod,
    Ptrace,
    BpfWriteUser,
}

impl LogTypeCLI {
    /// converts a LogTypeCli to a vec of EventType
    ///
    /// Not every EventType is covered by a LogTypeCli
    fn to_event_types(&self) -> Vec<EventType> {
        match self {
            LogTypeCLI::File => vec![
                EventType::EVENT_TYPE_FILE_OPEN,
                EventType::EVENT_TYPE_INODE_UNLINK,
            ],
            LogTypeCLI::Unmount => vec![EventType::EVENT_TYPE_SB_UMOUNT],
            LogTypeCLI::Map => vec![EventType::EVENT_TYPE_BPF_MAP],
            LogTypeCLI::Signal => vec![EventType::EVENT_TYPE_TASK_KILL],
            LogTypeCLI::Kmod => vec![
                EventType::EVENT_TYPE_KERNEL_LOAD_DATA,
                EventType::EVENT_TYPE_KERNEL_READ_FILE,
                EventType::EVENT_TYPE_KERNEL_MODULE_REQUEST,
            ],
            LogTypeCLI::Ptrace => vec![EventType::EVENT_TYPE_PTRACE_ACCESS_CHECK],
            LogTypeCLI::BpfWriteUser => vec![EventType::EVENT_TYPE_BPF_WRITE_USER],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_config_option() {
        let bad_config_str = "bad_option = bad";
        let args: Result<Args, toml::de::Error> = toml::from_str(bad_config_str);
        assert!(args.is_err());
    }
}
