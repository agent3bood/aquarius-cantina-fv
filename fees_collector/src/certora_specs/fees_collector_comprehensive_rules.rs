use soroban_sdk::{BytesN, Env, Symbol};

use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;

use crate::certora_specs::util::{get_role_address, is_role};
pub use crate::contract::FeesCollector;
use access_control::role::{Role, SymbolRepresentation};

use crate::interface::AdminInterface;
use access_control::interface::TransferableContract;
use upgrade::interface::UpgradeableContract;

// ========= ACCESS CONTROL ENFORCEMENT RULES =========

#[rule]
pub fn only_admin_can_commit_upgrade_rule(e: Env) {
    let admin = nondet_address();
    let non_admin = nondet_address();
    let wasm_hash: BytesN<32> = BytesN::from_array(&e, &[0u8; 32]);

    // Assume non_admin does not have admin role
    cvlr_assume!(!is_role(&non_admin, &Role::Admin));
    cvlr_assume!(admin != non_admin);

    // Set admin role first
    FeesCollector::init_admin(e.clone(), admin.clone());

    // Non-admin trying to commit upgrade should fail
    FeesCollector::commit_upgrade(e, non_admin, wasm_hash);
    cvlr_assert!(false); // Should not reach here
}

#[rule]
pub fn only_admin_can_apply_upgrade(e: Env) {
    let admin = nondet_address();
    let non_admin = nondet_address();

    cvlr_assume!(!is_role(&non_admin, &Role::Admin));
    cvlr_assume!(admin != non_admin);

    FeesCollector::init_admin(e.clone(), admin.clone());

    // Non-admin trying to apply upgrade should fail
    FeesCollector::apply_upgrade(e, non_admin);
    cvlr_assert!(false); // Should not reach here
}

#[rule]
pub fn only_admin_can_revert_upgrade(e: Env) {
    let admin = nondet_address();
    let non_admin = nondet_address();

    cvlr_assume!(!is_role(&non_admin, &Role::Admin));
    cvlr_assume!(admin != non_admin);

    FeesCollector::init_admin(e.clone(), admin.clone());

    // Non-admin trying to revert upgrade should fail
    FeesCollector::revert_upgrade(e, non_admin);
    cvlr_assert!(false); // Should not reach here
}

#[rule]
pub fn only_emergency_admin_can_set_emergency_mode(e: Env) {
    let admin = nondet_address();
    let emergency_admin = nondet_address();
    let non_emergency_admin = nondet_address();
    let value: bool = cvlr::nondet();

    cvlr_assume!(!is_role(&non_emergency_admin, &Role::EmergencyAdmin));
    cvlr_assume!(admin != non_emergency_admin);
    cvlr_assume!(emergency_admin != non_emergency_admin);

    FeesCollector::init_admin(e.clone(), admin.clone());

    // Non-emergency-admin trying to set emergency mode should fail
    FeesCollector::set_emergency_mode(e, non_emergency_admin, value);
    cvlr_assert!(false); // Should not reach here
}

#[rule]
pub fn only_admin_can_commit_transfer_ownership(e: Env) {
    let admin = nondet_address();
    let non_admin = nondet_address();
    let role_name = Role::Admin.as_symbol(&e);
    let new_address = nondet_address();

    cvlr_assume!(!is_role(&non_admin, &Role::Admin));
    cvlr_assume!(admin != non_admin);

    FeesCollector::init_admin(e.clone(), admin.clone());

    // Non-admin trying to commit transfer ownership should fail
    FeesCollector::commit_transfer_ownership(e, non_admin, role_name, new_address);
    cvlr_assert!(false); // Should not reach here
}

#[rule]
pub fn only_admin_can_apply_transfer_ownership_rule(e: Env) {
    let admin = nondet_address();
    let non_admin = nondet_address();
    let role_name: Symbol = Role::Admin.as_symbol(&e);

    cvlr_assume!(!is_role(&non_admin, &Role::Admin));
    cvlr_assume!(admin != non_admin);

    FeesCollector::init_admin(e.clone(), admin.clone());

    // Non-admin trying to apply transfer ownership should fail
    // This catches contract_1 mutation where admin check is commented out
    FeesCollector::apply_transfer_ownership(e, non_admin, role_name);
    cvlr_assert!(false); // Should not reach here
}

#[rule]
pub fn only_admin_can_revert_transfer_ownership(e: Env) {
    let admin = nondet_address();
    let non_admin = nondet_address();
    let role_name: Symbol = Role::Admin.as_symbol(&e);

    cvlr_assume!(!is_role(&non_admin, &Role::Admin));
    cvlr_assume!(admin != non_admin);

    FeesCollector::init_admin(e.clone(), admin.clone());

    // Non-admin trying to revert transfer ownership should fail
    FeesCollector::revert_transfer_ownership(e, non_admin, role_name);
    cvlr_assert!(false); // Should not reach here
}

// ========= STATE CONSISTENCY RULES =========

#[rule]
pub fn emergency_mode_reflects_actual_state(e: Env) {
    let admin = nondet_address();
    let emergency_admin = nondet_address();

    FeesCollector::init_admin(e.clone(), admin.clone());

    // Assume emergency_admin has the emergency admin role
    cvlr_assume!(is_role(&emergency_admin, &Role::EmergencyAdmin));

    // Set emergency mode to true
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin.clone(), true);

    // get_emergency_mode should return true, not always false
    // This catches contract_2 mutation where get_emergency_mode always returns false
    let mode = FeesCollector::get_emergency_mode(e.clone());
    cvlr_assert!(mode == true);

    // Set emergency mode to false
    FeesCollector::set_emergency_mode(e.clone(), emergency_admin, false);

    // get_emergency_mode should return false
    let mode2 = FeesCollector::get_emergency_mode(e);
    cvlr_assert!(mode2 == false);
}

#[rule]
pub fn admin_role_consistent_after_init(e: Env) {
    let admin_address = nondet_address();

    FeesCollector::init_admin(e, admin_address.clone());

    // After init, the admin address should be consistent
    let stored_admin = get_role_address();
    cvlr_assert!(stored_admin == admin_address);
    cvlr_assert!(is_role(&admin_address, &Role::Admin));
}

#[rule]
pub fn admin_init_only_once(e: Env) {
    let first_admin = nondet_address();
    let second_admin = nondet_address();

    cvlr_assume!(first_admin != second_admin);

    // First initialization should succeed
    FeesCollector::init_admin(e.clone(), first_admin);

    // Second initialization should fail
    FeesCollector::init_admin(e, second_admin);
    cvlr_assert!(false); // Should not reach here
}
