use soroban_sdk::{Env, BytesN};

use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::clog;
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;

use crate::certora_specs::util::is_role;
pub use crate::contract::FeesCollector;
use access_control::role::Role;

use upgrade::interface::UpgradeableContract;

/**
 * Rule to verify that only admin can commit upgrade
 * This rule should fail on the mutant where the admin check is commented out
 */
#[rule]
pub fn only_admin_can_commit_upgrade(e: Env) {
    let caller = nondet_address();
    let new_wasm_hash: BytesN<32> = BytesN::from_array(&e, &[0u8; 32]);
    
    // Assume the caller is not an admin
    cvlr_assume!(!is_role(&caller, &Role::Admin));
    
    // Log the caller address for debugging
    clog!(cvlr_soroban::Addr(&caller));
    
    // Try to commit upgrade as non-admin
    FeesCollector::commit_upgrade(e, caller, new_wasm_hash);
    
    // Should not reach this point - the function should panic
    cvlr_assert!(false);
}

/**
 * Rule to verify that admin can successfully commit upgrade
 * This rule should pass on both the original and mutant contract
 */
#[rule]
pub fn admin_can_commit_upgrade(e: Env) {
    let admin = nondet_address();
    let new_wasm_hash: BytesN<32> = BytesN::from_array(&e, &[0u8; 32]);
    
    // Assume the caller is an admin
    cvlr_assume!(is_role(&admin, &Role::Admin));
    
    // Log the admin address for debugging
    clog!(cvlr_soroban::Addr(&admin));
    
    // Admin should be able to commit upgrade
    FeesCollector::commit_upgrade(e, admin, new_wasm_hash);
    
    // Should reach this point successfully
    cvlr_assert!(true);
}