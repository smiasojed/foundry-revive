use crate::{Config, SolcReq};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
/// Revive Config
pub struct ReviveConfig {
    /// The revive bin
    pub revive: Option<SolcReq>,
    /// The solc path that will be used by revive
    pub solc_path: Option<PathBuf>,
    /// Enable compilation using revive
    pub revive_compile: bool,
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
