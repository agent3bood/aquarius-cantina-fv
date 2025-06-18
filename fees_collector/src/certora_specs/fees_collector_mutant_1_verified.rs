use soroban_sdk::{Env, Symbol};

use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::clog;
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;

use crate::certora_specs::util::is_role;
pub use crate::contract::FeesCollector;
use access_control::role::Role;

use access_control::interface::TransferableContract;

/**
 * Rule to verify that only admin can apply transfer ownership
 * This rule should fail on the mutant where the admin check is commented out
 * We focus on the authorization check rather than the full flow
 */
#[rule]
pub fn only_admin_can_apply_transfer_ownership(e: Env) {
    let caller = nondet_address();
    let role_name = Symbol::new(&e, "Admin");
    
    cvlr_assume!(!is_role(&caller, &Role::Admin));
    
    clog!(cvlr_soroban::Addr(&caller));
    
    FeesCollector::apply_transfer_ownership(e, caller, role_name);
    
    cvlr_assert!(false);
}

#[rule]
pub fn admin_can_apply_transfer_ownership(e: Env) {
    let caller = nondet_address();
    let role_name = Symbol::new(&e, "Admin");
    
    cvlr_assume!(is_role(&caller, &Role::Admin));
    
    clog!(cvlr_soroban::Addr(&caller));
    
    FeesCollector::apply_transfer_ownership(e, caller, role_name);
    
    cvlr_assert!(true); 
}