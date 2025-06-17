use soroban_sdk::Env;

use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::clog;
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;

use crate::certora_specs::util::is_role;
pub use crate::contract::FeesCollector;
use access_control::role::Role;

use upgrade::interface::UpgradeableContract;

/**
 * Rule to verify that get_emergency_mode returns the actual emergency mode state
 * This rule should fail on the mutant where get_emergency_mode always returns false
 * We test that after setting emergency mode to true, the getter returns true
 */
#[rule]
pub fn get_emergency_mode_returns_actual_value_when_true(e: Env) {
    let emergency_admin = nondet_address();
    
    cvlr_assume!(is_role(&emergency_admin, &Role::EmergencyAdmin));
    
    clog!(cvlr_soroban::Addr(&emergency_admin));
    
    // Set emergency mode to true
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin, true);
    
    // Get emergency mode should return true
    let emergency_mode = FeesCollector::get_emergency_mode(e);
    
    cvlr_assert!(emergency_mode);
}

#[rule]
pub fn get_emergency_mode_returns_actual_value_when_false(e: Env) {
    let emergency_admin = nondet_address();
    
    cvlr_assume!(is_role(&emergency_admin, &Role::EmergencyAdmin));
    
    clog!(cvlr_soroban::Addr(&emergency_admin));
    
    // Set emergency mode to false
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin, false);
    
    // Get emergency mode should return false
    let emergency_mode = FeesCollector::get_emergency_mode(e);
    
    cvlr_assert!(!emergency_mode);
}