use soroban_sdk::{Env, Symbol};

use cvlr::asserts::{cvlr_assert, cvlr_assume};
use cvlr::nondet;
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;

// use crate::constants::ADMIN_ACTIONS_DELAY;
use crate::dummy_contract::DummyContract;
use crate::interface::TransferableContract;

// Helper functions to get role symbols
fn admin_symbol(e: &Env) -> Symbol {
    Symbol::new(e, "Admin")
}

fn emergency_admin_symbol(e: &Env) -> Symbol {
    Symbol::new(e, "EmergencyAdmin")
}

fn rewards_admin_symbol(e: &Env) -> Symbol {
    Symbol::new(e, "RewardsAdmin")
}

fn operations_admin_symbol(e: &Env) -> Symbol {
    Symbol::new(e, "OperationsAdmin")
}

fn pause_admin_symbol(e: &Env) -> Symbol {
    Symbol::new(e, "PauseAdmin")
}

fn emergency_pause_admin_symbol(e: &Env) -> Symbol {
    Symbol::new(e, "EmergencyPauseAdmin")
}

/**
 * High-level Access Control Invariants
 */

#[rule]
pub fn admin_initialization_integrity(e: Env) {
    let admin_address = nondet_address();
    
    DummyContract::init_admin(e.clone(), admin_address.clone());
    
    let stored_admin = DummyContract::get_role(e.clone(), admin_symbol(&e));
    cvlr_assert!(stored_admin == admin_address);
}

#[rule]
pub fn role_assignment_consistency(e: Env) {
    let admin = nondet_address();
    let user = nondet_address();
    let role_symbol = rewards_admin_symbol(&e);
    
    DummyContract::init_admin(e.clone(), admin.clone());
    DummyContract::set_role(e.clone(), admin.clone(), role_symbol.clone(), user.clone());
    
    let has_role = DummyContract::has_role(e.clone(), user.clone(), role_symbol);
    cvlr_assert!(has_role);
}

#[rule]
pub fn role_assignment_authorization_invariant(e: Env) {
    let admin = nondet_address();
    let non_admin = nondet_address();
    let target = nondet_address();
    
    cvlr_assume!(admin != non_admin);
    
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Non-admin attempts role assignment - must fail
    DummyContract::set_role(e.clone(), non_admin, rewards_admin_symbol(&e), target);
    
    cvlr_assert!(false);
}

#[rule]
pub fn single_role_holder_invariant(e: Env) {
    let admin = nondet_address();
    let user1 = nondet_address();
    let user2 = nondet_address();
    let role_symbol = operations_admin_symbol(&e);
    
    cvlr_assume!(user1 != user2);
    
    DummyContract::init_admin(e.clone(), admin.clone());
    DummyContract::set_role(e.clone(), admin.clone(), role_symbol.clone(), user1.clone());
    DummyContract::set_role(e.clone(), admin.clone(), role_symbol.clone(), user2.clone());
    
    // Role assignment is exclusive - only latest holder should have role
    let user2_has_role = DummyContract::has_role(e.clone(), user2, role_symbol.clone());
    let user1_has_role = DummyContract::has_role(e.clone(), user1, role_symbol);
    
    cvlr_assert!(user2_has_role && !user1_has_role);
}

/**
 * Emergency Mode Security Invariants
 */

#[rule]
pub fn emergency_mode_access_control_invariant(e: Env) {
    let admin = nondet_address();
    let emergency_admin = nondet_address();
    let unauthorized_user = nondet_address();
    let mode: bool = nondet();
    
    cvlr_assume!(admin != emergency_admin);
    cvlr_assume!(admin != unauthorized_user);
    cvlr_assume!(emergency_admin != unauthorized_user);
    
    DummyContract::init_admin(e.clone(), admin.clone());
    DummyContract::set_role(e.clone(), admin, emergency_admin_symbol(&e), emergency_admin.clone());
    
    // Unauthorized access to emergency mode must fail
    DummyContract::set_emergency_mode(e, unauthorized_user, mode);
    
    cvlr_assert!(false);
}

#[rule]
pub fn emergency_mode_state_consistency(e: Env) {
    let admin = nondet_address();
    let emergency_admin = nondet_address();
    
    DummyContract::init_admin(e.clone(), admin.clone());
    DummyContract::set_role(e.clone(), admin, emergency_admin_symbol(&e), emergency_admin.clone());
    
    let initial_mode = DummyContract::get_emergency_mode(e.clone());
    
    // State transition must be deterministic
    DummyContract::set_emergency_mode(e.clone(), emergency_admin.clone(), !initial_mode);
    let toggled_mode = DummyContract::get_emergency_mode(e.clone());
    cvlr_assert!(toggled_mode == !initial_mode);
    
    // State restoration must be reliable
    DummyContract::set_emergency_mode(e.clone(), emergency_admin, initial_mode);
    let restored_mode = DummyContract::get_emergency_mode(e);
    cvlr_assert!(restored_mode == initial_mode);
}

/**
 * Ownership Transfer Security Invariants
 */

#[rule]
pub fn ownership_transfer_authorization_invariant(e: Env) {
    let admin = nondet_address();
    let unauthorized_user = nondet_address();
    let new_admin = nondet_address();
    
    cvlr_assume!(admin != unauthorized_user);
    
    DummyContract::init_admin(e.clone(), admin);
    
    // Unauthorized ownership transfer must fail
    DummyContract::commit_transfer_ownership(e.clone(), unauthorized_user, admin_symbol(&e), new_admin);
    
    cvlr_assert!(false);
}

#[rule]
pub fn ownership_transfer_delay_security_invariant(e: Env) {
    let admin = nondet_address();
    let new_admin = nondet_address();
    
    cvlr_assume!(admin != new_admin);
    
    DummyContract::init_admin(e.clone(), admin.clone());
    DummyContract::commit_transfer_ownership(e.clone(), admin.clone(), admin_symbol(&e), new_admin.clone());
    
    // Future address must be correctly set
    let future_addr = DummyContract::get_future_address(e.clone(), admin_symbol(&e));
    cvlr_assert!(future_addr == new_admin);
    
    // Immediate application must fail (enforces delay)
    DummyContract::apply_transfer_ownership(e.clone(), admin, admin_symbol(&e));
    
    cvlr_assert!(false);
}

#[rule]
pub fn ownership_transfer_revert_integrity_invariant(e: Env) {
    let admin = nondet_address();
    let new_admin = nondet_address();
    
    DummyContract::init_admin(e.clone(), admin.clone());
    DummyContract::commit_transfer_ownership(e.clone(), admin.clone(), admin_symbol(&e), new_admin.clone());
    
    // Transfer commitment must be verifiable
    let future_addr = DummyContract::get_future_address(e.clone(), admin_symbol(&e));
    cvlr_assert!(future_addr == new_admin);
    
    // Revert must restore original state
    DummyContract::revert_transfer_ownership(e.clone(), admin.clone(), admin_symbol(&e));
    let current_admin = DummyContract::get_role(e.clone(), admin_symbol(&e));
    cvlr_assert!(current_admin == admin);
}

/**
 * Function-Level Access Control Invariants
 */

#[rule]
pub fn rewards_function_authorization_invariant(e: Env) {
    let admin = nondet_address();
    let rewards_admin = nondet_address();
    let unauthorized_user = nondet_address();
    
    cvlr_assume!(admin != rewards_admin);
    cvlr_assume!(admin != unauthorized_user);
    cvlr_assume!(rewards_admin != unauthorized_user);
    
    DummyContract::init_admin(e.clone(), admin.clone());
    DummyContract::set_role(e.clone(), admin.clone(), rewards_admin_symbol(&e), rewards_admin.clone());
    
    // Verify authorized access works
    let admin_success = DummyContract::rewards_admin_function(e.clone(), admin);
    let rewards_admin_success = DummyContract::rewards_admin_function(e.clone(), rewards_admin);
    cvlr_assert!(admin_success && rewards_admin_success);
    
    // Unauthorized access must fail
    DummyContract::rewards_admin_function(e, unauthorized_user);
    cvlr_assert!(false);
}

#[rule]
pub fn operations_function_role_separation_invariant(e: Env) {
    let admin = nondet_address();
    let ops_admin = nondet_address();
    let rewards_admin = nondet_address();
    
    cvlr_assume!(admin != ops_admin);
    cvlr_assume!(admin != rewards_admin);
    cvlr_assume!(ops_admin != rewards_admin);
    
    DummyContract::init_admin(e.clone(), admin.clone());
    DummyContract::set_role(e.clone(), admin.clone(), operations_admin_symbol(&e), ops_admin.clone());
    DummyContract::set_role(e.clone(), admin.clone(), rewards_admin_symbol(&e), rewards_admin.clone());
    
    // Verify proper role separation
    let admin_access = DummyContract::operations_admin_function(e.clone(), admin);
    let ops_admin_access = DummyContract::operations_admin_function(e.clone(), ops_admin);
    cvlr_assert!(admin_access && ops_admin_access);
    
    // Cross-role access must fail
    DummyContract::operations_admin_function(e, rewards_admin);
    cvlr_assert!(false);
}

/**
 * System-Wide State Consistency Invariants
 */

#[rule]
pub fn multi_role_assignment_persistence_invariant(e: Env) {
    let admin = nondet_address();
    let multi_role_user = nondet_address();
    
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Assign multiple distinct roles to same user
    DummyContract::set_role(e.clone(), admin.clone(), rewards_admin_symbol(&e), multi_role_user.clone());
    DummyContract::set_role(e.clone(), admin.clone(), operations_admin_symbol(&e), multi_role_user.clone());
    DummyContract::set_role(e.clone(), admin.clone(), pause_admin_symbol(&e), multi_role_user.clone());
    
    // All role assignments must persist correctly
    let has_rewards = DummyContract::has_role(e.clone(), multi_role_user.clone(), rewards_admin_symbol(&e));
    let has_ops = DummyContract::has_role(e.clone(), multi_role_user.clone(), operations_admin_symbol(&e));
    let has_pause = DummyContract::has_role(e.clone(), multi_role_user, pause_admin_symbol(&e));
    
    cvlr_assert!(has_rewards && has_ops && has_pause);
}

#[rule]
pub fn admin_role_immutability_invariant(e: Env) {
    let admin = nondet_address();
    
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Admin role must be consistently maintained
    let has_admin_role = DummyContract::has_role(e.clone(), admin.clone(), admin_symbol(&e));
    let stored_admin = DummyContract::get_role(e.clone(), admin_symbol(&e));
    
    cvlr_assert!(has_admin_role && stored_admin == admin);
}