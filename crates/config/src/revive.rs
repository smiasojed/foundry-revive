use crate::{Config, SolcReq};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
/// File contains info related to revive config
/// There is missing functionality such as
/// Converting between Foundry settings to Revive settings
/// The requirements for what needs to happen here still need
/// to be worked out this is initial work
/// This here will be part of the larger config so
/// Whenever we want to get any config related to revive
/// We can `config.revive.[anything related to revive]`
/// e.g `config.revive.settings` or `config.revive.revive_compile`

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Revive Config
pub struct ReviveConfig {
    /// The revive bin
    pub revive: Option<SolcReq>,
    /// The solc path that will be used by revive
    pub solc_path: Option<PathBuf>,
    /// Enable compilation using revive
    pub revive_compile: bool,
}

impl Default for ReviveConfig {
    fn default() -> Self {
        Self {
            revive: Default::default(),
            solc_path: Default::default(),
            revive_compile: Default::default(),
        }
    }
}

impl ReviveConfig {
    pub fn new(&self, config: Config) -> Self {
        Self {
            revive: config.revive.revive,
            solc_path: config.revive.solc_path,
            revive_compile: config.revive.revive_compile,
        }
    }
}
