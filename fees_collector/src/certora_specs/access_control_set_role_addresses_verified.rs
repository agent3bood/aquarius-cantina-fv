use access_control::access::AccessControlTrait;
use access_control::management::MultipleAddressesManagementTrait;
use access_control::{access::AccessControl, role::Role};
use cvlr::{clog, cvlr_assert, cvlr_assume};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Env, Vec};

/**
 * set_role_addresses (multi-user roles)
 */
#[rule]
pub fn set_emergency_pause_admin_addresses_only_affects_emergency_pause_admin_role(e: Env) {
    let address1 = nondet_address();
    let address2 = nondet_address();
    clog!(cvlr_soroban::Addr(&address1));
    clog!(cvlr_soroban::Addr(&address2));
    let access = AccessControl::new(&e);

    let mut addresses = Vec::new(&e);
    addresses.push_back(address1.clone());
    addresses.push_back(address2.clone());
    cvlr_assume!(address1 != address2);

    let has_admin_before = access.address_has_role(&address1, &Role::Admin);
    let has_emergency_admin_before = access.address_has_role(&address1, &Role::EmergencyAdmin);
    let has_rewards_admin_before = access.address_has_role(&address1, &Role::RewardsAdmin);
    let has_operations_admin_before = access.address_has_role(&address1, &Role::OperationsAdmin);
    let has_pause_admin_before = access.address_has_role(&address1, &Role::PauseAdmin);
    let has_emergency_pause_admin_before_address1 =
        access.address_has_role(&address1, &Role::EmergencyPauseAdmin);
    let has_emergency_pause_admin_before_address2 =
        access.address_has_role(&address2, &Role::EmergencyPauseAdmin);

    clog!(
        has_admin_before,
        has_emergency_admin_before,
        has_rewards_admin_before,
        has_operations_admin_before,
        has_pause_admin_before,
        has_emergency_pause_admin_before_address1,
        has_emergency_pause_admin_before_address2
    );

    cvlr_assume!(!has_emergency_pause_admin_before_address1);
    cvlr_assume!(!has_emergency_pause_admin_before_address2);
    access.set_role_addresses(&Role::EmergencyPauseAdmin, &addresses);

    let has_admin_after = access.address_has_role(&address1, &Role::Admin);
    let has_emergency_admin_after = access.address_has_role(&address1, &Role::EmergencyAdmin);
    let has_rewards_admin_after = access.address_has_role(&address1, &Role::RewardsAdmin);
    let has_operations_admin_after = access.address_has_role(&address1, &Role::OperationsAdmin);
    let has_pause_admin_after = access.address_has_role(&address1, &Role::PauseAdmin);
    let has_emergency_pause_admin_after_address1 =
        access.address_has_role(&address1, &Role::EmergencyPauseAdmin);
    let has_emergency_pause_admin_after_address2 =
        access.address_has_role(&address2, &Role::EmergencyPauseAdmin);

    clog!(
        has_admin_after,
        has_emergency_admin_after,
        has_rewards_admin_after,
        has_operations_admin_after,
        has_pause_admin_after,
        has_emergency_pause_admin_after_address1,
        has_emergency_pause_admin_after_address2
    );

    cvlr_assert!(has_emergency_pause_admin_after_address1);
    cvlr_assert!(has_emergency_pause_admin_after_address2);
    cvlr_assert!(has_admin_before == has_admin_after);
    cvlr_assert!(has_emergency_admin_before == has_emergency_admin_after);
    cvlr_assert!(has_rewards_admin_before == has_rewards_admin_after);
    cvlr_assert!(has_operations_admin_before == has_operations_admin_after);
    cvlr_assert!(has_pause_admin_before == has_pause_admin_after);
}

#[rule]
pub fn set_role_addresses_only_accepts_multi_user_roles(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    let access = AccessControl::new(&e);

    let mut addresses = Vec::new(&e);
    addresses.push_back(address);

    access.set_role_addresses(&Role::Admin, &addresses);
    cvlr_assert!(false);
}
