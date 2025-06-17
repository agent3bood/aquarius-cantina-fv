pub mod fee_collector_rules;
pub mod fees_collector_mutant_0_verified;
pub mod fees_collector_mutant_1_verified;
pub mod fees_collector_mutant_2_verified;
pub mod access_control_set_role_verified;
pub mod util;

use access_control::access::AccessControl;

#[cfg(feature = "certora")]
pub(crate) static mut ACCESS_CONTROL: Option<AccessControl> = None;