use super::policy::{PolicyManager, SessionPolicy, SystemPolicy, session_default};
use crate::features::feature::{Feature, TYPE_POLICY_MANAGER};

#[derive(Default, Clone, Debug)]
pub struct DefaultManager;

impl DefaultManager {
    pub fn new() -> Self { Self }
}

impl Feature for DefaultManager {
    fn feature_type(&self) -> &'static str { TYPE_POLICY_MANAGER }
}

impl PolicyManager for DefaultManager {
    fn for_level(&self, _level: u32) -> SessionPolicy { session_default() }
    fn for_system(&self) -> SystemPolicy { SystemPolicy::default() }
}

pub fn default_policy() -> SessionPolicy { session_default() }
