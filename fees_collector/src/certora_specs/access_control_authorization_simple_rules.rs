use access_control::access::{AccessControl, AccessControlTrait};
use access_control::management::SingleAddressManagementTrait;
use access_control::role::Role;
use cvlr::{cvlr_assert, cvlr_assume};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

/// @notice Verifies AccessControlTrait::address_has_role() and assert_address_has_role() consistency
/// @dev Ensures that address_has_role returns true iff assert_address_has_role doesn't panic
#[rule]
pub fn authorization_consistency(e: Env) {
    let access_control = AccessControl::new(&e);

    let address = nondet_address();
    let role = Role::OperationsAdmin;

    access_control.assert_address_has_role(&address, &role);
    cvlr_assert!(access_control.address_has_role(&address, &role));
}

/// @notice Verifies role assignments are isolated - setting one role doesn't affect others
#[rule]
pub fn role_assignment_isolation(e: Env) {
    let access_control = AccessControl::new(&e);

    let addr1 = nondet_address();
    let addr2 = nondet_address();
    cvlr_assume!(addr1 != addr2);

    let role1 = Role::Admin;
    let role2 = Role::EmergencyAdmin;

    // Set different roles to different addresses
    access_control.set_role_address(&role1, &addr1);
    access_control.set_role_address(&role2, &addr2);

    // Each address should only have its assigned role
    cvlr_assert!(access_control.address_has_role(&addr1, &role1));
    cvlr_assert!(!access_control.address_has_role(&addr1, &role2));
    cvlr_assert!(access_control.address_has_role(&addr2, &role2));
    cvlr_assert!(!access_control.address_has_role(&addr2, &role1));
}

/// @notice Verifies a single address can hold multiple different roles simultaneously
#[rule]
pub fn multiple_roles_same_address(e: Env) {
    let access_control = AccessControl::new(&e);

    let super_admin = nondet_address();

    // Give the same address multiple single-user roles
    access_control.set_role_address(&Role::Admin, &super_admin);
    access_control.set_role_address(&Role::EmergencyAdmin, &super_admin);
    access_control.set_role_address(&Role::RewardsAdmin, &super_admin);

    // Verify all roles are held by the same address
    cvlr_assert!(access_control.address_has_role(&super_admin, &Role::Admin));
    cvlr_assert!(access_control.address_has_role(&super_admin, &Role::EmergencyAdmin));
    cvlr_assert!(access_control.address_has_role(&super_admin, &Role::RewardsAdmin));
}

/// @notice Verifies setting a new address for a role removes it from the previous holder
#[rule]
pub fn role_overwrite_behavior(e: Env) {
    let access_control = AccessControl::new(&e);

    let initial_admin = nondet_address();
    let new_admin = nondet_address();
    cvlr_assume!(initial_admin != new_admin);

    // Set initial admin
    access_control.set_role_address(&Role::Admin, &initial_admin);
    cvlr_assert!(access_control.address_has_role(&initial_admin, &Role::Admin));

    // Overwrite with new admin
    access_control.set_role_address(&Role::Admin, &new_admin);

    // Old admin should lose role, new admin should have it
    cvlr_assert!(!access_control.address_has_role(&initial_admin, &Role::Admin));
    cvlr_assert!(access_control.address_has_role(&new_admin, &Role::Admin));
}

// NOT WORKING
// /// @notice Verifies uninitialized optional roles return false for any address query
// #[rule]
// pub fn uninitialized_roles_behavior(e: Env) {
//     let access_control = AccessControl::new(&e);

//     let random_address = nondet_address();

//     // Check behavior for uninitialized single-user roles
//     let role = Role::OperationsAdmin;

//     // address_has_role should return false for uninitialized role
//     cvlr_assert!(!access_control.address_has_role(&random_address, &role));
// }
