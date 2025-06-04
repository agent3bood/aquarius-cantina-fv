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
 * Core Access Control Rules
 */

#[rule]
pub fn init_admin_sets_admin(e: Env) {
    let admin_address = nondet_address();
    
    DummyContract::init_admin(e.clone(), admin_address.clone());
    
    let stored_admin = DummyContract::get_role(e.clone(), admin_symbol(&e));
    cvlr_assert!(stored_admin == admin_address);
}

#[rule]
pub fn address_has_role_consistency(e: Env) {
    let admin = nondet_address();
    let user = nondet_address();
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Admin sets a rewards admin
    DummyContract::set_role(e.clone(), admin.clone(), rewards_admin_symbol(&e), user.clone());
    
    // Check role consistency
    let has_role = DummyContract::has_role(e.clone(), user.clone(), rewards_admin_symbol(&e));
    cvlr_assert!(has_role);
}

#[rule]
pub fn only_admin_can_set_roles(e: Env) {
    let admin = nondet_address();
    let non_admin = nondet_address();
    let target = nondet_address();
    
    cvlr_assume!(admin != non_admin);
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Non-admin tries to set a role - should panic
    DummyContract::set_role(e.clone(), non_admin, rewards_admin_symbol(&e), target);
    
    // Should not reach here
    cvlr_assert!(false);
}

#[rule]
pub fn role_exclusivity(e: Env) {
    let admin = nondet_address();
    let user1 = nondet_address();
    let user2 = nondet_address();
    
    cvlr_assume!(user1 != user2);
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Set user1 as operations admin
    DummyContract::set_role(e.clone(), admin.clone(), operations_admin_symbol(&e), user1.clone());
    
    // Set user2 as operations admin (overwrites user1)
    DummyContract::set_role(e.clone(), admin.clone(), operations_admin_symbol(&e), user2.clone());
    
    // Verify user2 has role and user1 doesn't
    let user2_has_role = DummyContract::has_role(e.clone(), user2, operations_admin_symbol(&e));
    let user1_has_role = DummyContract::has_role(e.clone(), user1, operations_admin_symbol(&e));
    
    cvlr_assert!(user2_has_role);
    cvlr_assert!(!user1_has_role);
}

/**
 * Emergency Mode Rules
 */

#[rule]
pub fn only_emergency_admin_sets_emergency_mode(e: Env) {
    let admin = nondet_address();
    let emergency_admin = nondet_address();
    let regular_user = nondet_address();
    let mode: bool = nondet();
    
    cvlr_assume!(admin != emergency_admin);
    cvlr_assume!(admin != regular_user);
    cvlr_assume!(emergency_admin != regular_user);
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Admin sets emergency admin
    DummyContract::set_role(e.clone(), admin, emergency_admin_symbol(&e), emergency_admin.clone());
    
    // Regular user tries to set emergency mode - should panic
    DummyContract::set_emergency_mode(e, regular_user, mode);
    
    // Should not reach here
    cvlr_assert!(false);
}

#[rule]
pub fn emergency_mode_toggle(e: Env) {
    let admin = nondet_address();
    let emergency_admin = nondet_address();
    
    // Initialize admin and emergency admin
    DummyContract::init_admin(e.clone(), admin.clone());
    DummyContract::set_role(e.clone(), admin, emergency_admin_symbol(&e), emergency_admin.clone());
    
    // Get initial state
    let initial_mode = DummyContract::get_emergency_mode(e.clone());
    
    // Toggle mode
    DummyContract::set_emergency_mode(e.clone(), emergency_admin.clone(), !initial_mode);
    
    // Verify toggle worked
    let new_mode = DummyContract::get_emergency_mode(e.clone());
    cvlr_assert!(new_mode == !initial_mode);
    
    // Toggle back
    DummyContract::set_emergency_mode(e.clone(), emergency_admin, initial_mode);
    
    // Verify toggle back worked
    let final_mode = DummyContract::get_emergency_mode(e);
    cvlr_assert!(final_mode == initial_mode);
}

/**
 * Transfer Ownership Rules
 */

#[rule]
pub fn transfer_ownership_requires_admin(e: Env) {
    let admin = nondet_address();
    let non_admin = nondet_address();
    let new_admin = nondet_address();
    
    cvlr_assume!(admin != non_admin);
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin);
    
    // Non-admin tries to commit transfer - should panic
    DummyContract::commit_transfer_ownership(e.clone(), non_admin, admin_symbol(&e), new_admin);
    
    // Should not reach here
    cvlr_assert!(false);
}

#[rule]
pub fn transfer_ownership_delay_enforced(e: Env) {
    let admin = nondet_address();
    let new_admin = nondet_address();
    let current_time: u64 = nondet();
    
    cvlr_assume!(admin != new_admin);
    cvlr_assume!(current_time > 0);
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Commit transfer
    DummyContract::commit_transfer_ownership(e.clone(), admin.clone(), admin_symbol(&e), new_admin.clone());
    
    // Get future address
    let future_addr = DummyContract::get_future_address(e.clone(), admin_symbol(&e));
    cvlr_assert!(future_addr == new_admin);
    
    // Try to apply immediately - should fail
    DummyContract::apply_transfer_ownership(e.clone(), admin, admin_symbol(&e));
    
    // Should not reach here (due to delay requirement)
    cvlr_assert!(false);
}

#[rule]
pub fn transfer_ownership_revert_works(e: Env) {
    let admin = nondet_address();
    let new_admin = nondet_address();
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Commit transfer
    DummyContract::commit_transfer_ownership(e.clone(), admin.clone(), admin_symbol(&e), new_admin.clone());
    
    // Verify future address is set
    let future_addr = DummyContract::get_future_address(e.clone(), admin_symbol(&e));
    cvlr_assert!(future_addr == new_admin);
    
    // Revert transfer
    DummyContract::revert_transfer_ownership(e.clone(), admin.clone(), admin_symbol(&e));
    
    // Verify admin is still the original
    let current_admin = DummyContract::get_role(e.clone(), admin_symbol(&e));
    cvlr_assert!(current_admin == admin);
}

/**
 * Protected Function Rules
 */

#[rule]
pub fn rewards_admin_function_access_control(e: Env) {
    let admin = nondet_address();
    let rewards_admin = nondet_address();
    let regular_user = nondet_address();
    
    cvlr_assume!(admin != rewards_admin);
    cvlr_assume!(admin != regular_user);
    cvlr_assume!(rewards_admin != regular_user);
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Set rewards admin
    DummyContract::set_role(e.clone(), admin.clone(), rewards_admin_symbol(&e), rewards_admin.clone());
    
    // Admin can call rewards function
    let admin_result = DummyContract::rewards_admin_function(e.clone(), admin);
    cvlr_assert!(admin_result);
    
    // Rewards admin can call rewards function
    let rewards_result = DummyContract::rewards_admin_function(e.clone(), rewards_admin);
    cvlr_assert!(rewards_result);
    
    // Regular user cannot call rewards function
    DummyContract::rewards_admin_function(e, regular_user);
    
    // Should not reach here
    cvlr_assert!(false);
}

#[rule]
pub fn operations_admin_function_access_control(e: Env) {
    let admin = nondet_address();
    let ops_admin = nondet_address();
    let rewards_admin = nondet_address();
    
    cvlr_assume!(admin != ops_admin);
    cvlr_assume!(admin != rewards_admin);
    cvlr_assume!(ops_admin != rewards_admin);
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Set operations admin and rewards admin
    DummyContract::set_role(e.clone(), admin.clone(), operations_admin_symbol(&e), ops_admin.clone());
    DummyContract::set_role(e.clone(), admin.clone(), rewards_admin_symbol(&e), rewards_admin.clone());
    
    // Admin can call operations function
    let admin_result = DummyContract::operations_admin_function(e.clone(), admin);
    cvlr_assert!(admin_result);
    
    // Operations admin can call operations function
    let ops_result = DummyContract::operations_admin_function(e.clone(), ops_admin);
    cvlr_assert!(ops_result);
    
    // Rewards admin cannot call operations function
    DummyContract::operations_admin_function(e, rewards_admin);
    
    // Should not reach here
    cvlr_assert!(false);
}

/**
 * State Consistency Rules
 */

#[rule]
pub fn role_persistence(e: Env) {
    let admin = nondet_address();
    let user = nondet_address();
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Set multiple roles
    DummyContract::set_role(e.clone(), admin.clone(), rewards_admin_symbol(&e), user.clone());
    DummyContract::set_role(e.clone(), admin.clone(), operations_admin_symbol(&e), user.clone());
    DummyContract::set_role(e.clone(), admin.clone(), pause_admin_symbol(&e), user.clone());
    
    // Verify all roles are set correctly
    let has_rewards = DummyContract::has_role(e.clone(), user.clone(), rewards_admin_symbol(&e));
    let has_ops = DummyContract::has_role(e.clone(), user.clone(), operations_admin_symbol(&e));
    let has_pause = DummyContract::has_role(e.clone(), user, pause_admin_symbol(&e));
    
    cvlr_assert!(has_rewards);
    cvlr_assert!(has_ops);
    cvlr_assert!(has_pause);
}

#[rule]
pub fn admin_always_has_admin_role(e: Env) {
    let admin = nondet_address();
    
    // Initialize admin
    DummyContract::init_admin(e.clone(), admin.clone());
    
    // Verify admin has admin role
    let has_admin_role = DummyContract::has_role(e.clone(), admin.clone(), admin_symbol(&e));
    cvlr_assert!(has_admin_role);
    
    // Get stored admin
    let stored_admin = DummyContract::get_role(e.clone(), admin_symbol(&e));
    cvlr_assert!(stored_admin == admin);
}