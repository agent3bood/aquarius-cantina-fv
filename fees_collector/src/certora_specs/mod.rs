pub mod fee_collector_rules;
pub mod fees_collector_mutant_0_verified;
pub mod fees_collector_mutant_1_verified;
pub mod fees_collector_mutant_2_verified;
pub mod access_control_set_role_address_verified;
pub mod access_control_set_role_addresses_verified;
pub mod access_control_transfer_ownership_rules;
pub mod access_control_role_symbol_rules;
pub mod access_control_authorization_simple_rules;
pub mod access_control_emergency_mode_rules;
pub mod access_control_storage_edge_cases_rules;
pub mod fees_collector_comprehensive_rules;
pub mod util;

use access_control::access::AccessControl;

#[cfg(feature = "certora")]
pub(crate) static mut ACCESS_CONTROL: Option<AccessControl> = None;