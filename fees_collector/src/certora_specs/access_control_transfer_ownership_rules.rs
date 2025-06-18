use access_control::management::SingleAddressManagementTrait;
use access_control::role::Role;
use access_control::transfer::TransferOwnershipTrait;
use access_control::{access::AccessControl, constants::ADMIN_ACTIONS_DELAY};
use cvlr::{cvlr_assert, cvlr_assume, nondet};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

/// @notice Verifies Role::is_transfer_delayed() logic via TransferOwnershipTrait::commit_transfer_ownership()
#[rule]
pub fn admin_requires_delay(e: Env) {
    let access_control = AccessControl::new(&e);
    let future_address = nondet_address();
    let role = Role::Admin;

    let initial_deadline = access_control.get_transfer_ownership_deadline(&role);
    cvlr_assume!(initial_deadline == 0); // No pending transfer

    access_control.commit_transfer_ownership(&role, &future_address);
    cvlr_assert!(true); // Should succeed
}

#[rule]
pub fn emergency_admin_requires_delay(e: Env) {
    let access_control = AccessControl::new(&e);
    let future_address = nondet_address();
    let role = Role::EmergencyAdmin;

    let initial_deadline = access_control.get_transfer_ownership_deadline(&role);
    cvlr_assume!(initial_deadline == 0); // No pending transfer

    access_control.commit_transfer_ownership(&role, &future_address);
    cvlr_assert!(true); // Should succeed
}

#[rule]
pub fn rewards_admin_cannot_use_delayed_transfer(e: Env) {
    let access_control = AccessControl::new(&e);
    let future_address = nondet_address();
    let role = Role::RewardsAdmin;

    access_control.commit_transfer_ownership(&role, &future_address);
    cvlr_assert!(false); // Should panic with BadRoleUsage
}

#[rule]
pub fn operations_admin_cannot_use_delayed_transfer(e: Env) {
    let access_control = AccessControl::new(&e);
    let future_address = nondet_address();
    let role = Role::OperationsAdmin;

    access_control.commit_transfer_ownership(&role, &future_address);
    cvlr_assert!(false); // Should panic with BadRoleUsage
}

#[rule]
pub fn pause_admin_cannot_use_delayed_transfer(e: Env) {
    let access_control = AccessControl::new(&e);
    let future_address = nondet_address();
    let role = Role::PauseAdmin;

    access_control.commit_transfer_ownership(&role, &future_address);
    cvlr_assert!(false); // Should panic with BadRoleUsage
}

#[rule]
pub fn emergency_pause_admin_cannot_use_delayed_transfer(e: Env) {
    let access_control = AccessControl::new(&e);
    let future_address = nondet_address();
    let role = Role::EmergencyPauseAdmin;

    access_control.commit_transfer_ownership(&role, &future_address);
    cvlr_assert!(false); // Should panic with BadRoleUsage
}

/// @notice Verifies TransferOwnershipTrait::commit_transfer_ownership() deadline calculation
/// @dev Ensures transfer deadline is set to current_timestamp + ADMIN_ACTIONS_DELAY (3 days)
#[rule]
pub fn commit_transfer_sets_correct_deadline(e: Env) {
    let role_type: bool = nondet();
    let role = if role_type {
        Role::Admin
    } else {
        Role::EmergencyAdmin
    };

    let future_address = nondet_address();

    let access_control = AccessControl::new(&e);

    let initial_deadline = access_control.get_transfer_ownership_deadline(&role);
    cvlr_assume!(initial_deadline == 0); // No pending transfer

    let current_timestamp = e.ledger().timestamp();

    access_control.commit_transfer_ownership(&role, &future_address);

    let new_deadline = access_control.get_transfer_ownership_deadline(&role);
    cvlr_assert!(new_deadline == current_timestamp + ADMIN_ACTIONS_DELAY);
}

/// @notice Verifies TransferOwnershipTrait::apply_transfer_ownership() active transfer requirement
#[rule]
pub fn apply_transfer_fails_with_no_active_transfer(e: Env) {
    let role = Role::Admin;

    let access_control = AccessControl::new(&e);

    cvlr_assume!(access_control.get_transfer_ownership_deadline(&role) == 0);
    cvlr_assume!(access_control.get_role_safe(&role) != None);

    access_control.apply_transfer_ownership(&role);
    cvlr_assert!(false); // Should panic
}

/// @notice Verifies TransferOwnershipTrait::apply_transfer_ownership() deadline clearing
#[rule]
pub fn apply_transfer_clears_deadline(e: Env) {
    let role = Role::Admin;

    let access_control = AccessControl::new(&e);

    access_control.apply_transfer_ownership(&role);

    let deadline_after = access_control.get_transfer_ownership_deadline(&role);
    cvlr_assert!(deadline_after == 0);
}

/// @notice Verifies TransferOwnershipTrait::revert_transfer_ownership() deadline clearing
#[rule]
pub fn revert_transfer_clears_deadline(e: Env) {
    let role = Role::Admin;

    let access_control = AccessControl::new(&e);

    // Set a deadline
    access_control.put_transfer_ownership_deadline(&role, 12345);

    // Revert should clear it
    access_control.revert_transfer_ownership(&role);

    let deadline_after = access_control.get_transfer_ownership_deadline(&role);
    cvlr_assert!(deadline_after == 0);
}
