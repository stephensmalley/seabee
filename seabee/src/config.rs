// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::fs;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};

use anyhow::Result;
use tracing_subscriber::prelude::*;

use bpf::logging::{EventType, LogLevel};

pub use crate::cli::SecurityLevel;
use crate::cli::{args_from_cli, args_from_file, Args};
use crate::policy::policy_file::PolicyConfig;
use crate::{constants::*, utils};
use tracing::{trace, warn};

static LOGGING: Once = Once::new();

/// Processes configuration information in the order specified below.
///
/// 1. Initialize from default arguments.
/// 1. Apply args from [CONFIG_PATH] (if present on disk).
/// 1. Apply `--config` CLI arguments (if present).
/// 1. Apply all other CLI arguments (if present).
pub fn configure() -> Result<Config> {
    // Gather the config info using the default trace dispatcher
    let default = tracing_subscriber::fmt().with_target(false).finish();
    let config = tracing::subscriber::with_default(default, || -> Result<Config> {
        let mut base_args = Args::default();
        init_paths()?;
        base_args.apply(args_from_file(CONFIG_PATH)?);
        base_args.apply(args_from_cli()?);
        Ok(base_args.into())
    })?;

    configure_logging(config.log_level)?;

    if !config.verify_policy {
        warn!("Verification of policy updates is disabled. This configuration makes it trivial to defeat all security properties that SeaBee provides.")
    }

    Ok(config)
}

pub fn configure_logging(log_level: LogLevel) -> Result<()> {
    // Set the global tracing dispatcher with the log level specified in the config
    let filter =
        tracing_subscriber::filter::LevelFilter::from_str(&(log_level as usize).to_string())?;
    LOGGING.call_once(|| {
        let registry = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .without_time()
                .with_filter(filter),
        );
        match tracing_journald::layer() {
            Ok(layer) => registry.with(layer).init(),
            Err(_) => tracing::error!("Unable to connect to journald"),
        };
    });

    Ok(())
}

pub fn init_paths() -> Result<()> {
    trace!("create pin path");
    fs::create_dir_all(PIN_DIR)?;
    // These folders are used to store key and signature data.
    // They do not get cleaned up because we need to save policies and keys
    // through a reboot. We should not error if they exist when we start up.
    trace!("create seabee directories");
    utils::create_dir_if_not_exists(SEABEE_DIR)?;
    utils::create_dir_if_not_exists(POLICY_DIR)?;
    utils::create_dir_if_not_exists(POL_SIGNATURE_DIR)?;
    utils::create_dir_if_not_exists(KEY_DIR)?;
    utils::create_dir_if_not_exists(KEY_SIGNATURE_DIR)?;
    // These files are part of the SeaBee base policy
    trace!("create config and service path");
    utils::open_or_create(CONFIG_PATH)?;
    utils::open_or_create(SERVICE_PATH)?;
    trace!("finished creating paths");
    Ok(())
}

/// Parser-complete configuration
///
/// Make sure all updates are reflected in [Args] and its functions
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub log_level: LogLevel,
    pub sigint: SecurityLevel,
    pub kmod: SecurityLevel,
    pub ptrace: SecurityLevel,
    pub policy_config: PolicyConfig,
    pub log_filter: HashSet<EventType>,
    // will only be true during test cases
    pub test: bool,
    // is signature verification for policies enabled?
    pub verify_policy: bool,
    // is signature verification for new keys enabled?
    pub verify_keys: bool,
}

impl Default for Config {
    fn default() -> Self {
        // The default config is intended to be a secure, but usable configuration
        Self {
            log_level: LogLevel::LOG_LEVEL_INFO,
            sigint: SecurityLevel::block,
            kmod: SecurityLevel::audit,
            ptrace: SecurityLevel::block,
            policy_config: Default::default(),
            test: false,
            log_filter: HashSet::new(),
            verify_policy: true,
            verify_keys: false,
        }
    }
}

/// sets up ctrl+c handler based on whether or not SIGINT is allowed
pub fn setup_ctrlc(sigint: SecurityLevel) -> Result<Arc<AtomicBool>> {
    let running = Arc::new(AtomicBool::new(true));
    if crate::utils::is_sigint_allowed(sigint) {
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })?;
    }
    Ok(running)
}
