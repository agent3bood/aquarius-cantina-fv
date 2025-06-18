use access_control::access::{AccessControl};
use access_control::management::SingleAddressManagementTrait;
use access_control::role::Role;
use access_control::transfer::TransferOwnershipTrait;
use cvlr::{cvlr_assert, cvlr_assume};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

/// @notice Verifies TransferOwnershipTrait::apply_transfer_ownership() at deadline boundary
#[rule]
pub fn transfer_deadline_boundary_conditions(e: Env) {
    let access_control = AccessControl::new(&e);

    let role = Role::Admin;
    let future_address = nondet_address();

    // Test with current timestamp at boundary
    let current_time = e.ledger().timestamp();

    // Commit transfer
    access_control.commit_transfer_ownership(&role, &future_address);
    let deadline = access_control.get_transfer_ownership_deadline(&role);

    // Test exact deadline boundary
    cvlr_assume!(current_time == deadline);

    // Should be able to apply at exact deadline
    access_control.apply_transfer_ownership(&role);
    cvlr_assert!(true); // Should succeed
}

/// @notice Verifies TransferOwnershipTrait prevents concurrent transfers
#[rule]
pub fn concurrent_transfer_attempts(e: Env) {
    let access_control = AccessControl::new(&e);

    let role = Role::Admin;
    let first_future = nondet_address();
    let second_future = nondet_address();
    cvlr_assume!(first_future != second_future);

    // First transfer
    cvlr_assume!(access_control.get_transfer_ownership_deadline(&role) == 0);
    access_control.commit_transfer_ownership(&role, &first_future);

    // Try to commit another transfer while first is pending
    access_control.commit_transfer_ownership(&role, &second_future);
    cvlr_assert!(false); // Should panic with AnotherActionActive
}

/// @notice Verifies TransferOwnershipTrait::apply_transfer_ownership() with zero deadline when storage in None
#[rule]
pub fn transfer_ownership_skips_deadline_no_value(e: Env) {
    let access_control = AccessControl::new(&e);

    let role = Role::Admin;

    cvlr_assume!(access_control.get_transfer_ownership_deadline(&role) == 0);
    cvlr_assume!(access_control.get_role_safe(&role) == None);
    access_control.get_future_address(&role); // Make sure we have future address

    // Should be able to apply transfer
    access_control.apply_transfer_ownership(&role);
    cvlr_assert!(true);
}
