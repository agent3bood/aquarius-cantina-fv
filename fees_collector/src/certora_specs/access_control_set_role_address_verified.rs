use access_control::access::AccessControlTrait;
use access_control::management::SingleAddressManagementTrait;
use access_control::{access::AccessControl, role::Role};
use cvlr::{clog, cvlr_assert, cvlr_assume};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Env};

/**
 * set_role_address
 */

#[rule]
pub fn set_admin_role_only_affects_admin_role(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    let access = AccessControl::new(&e);

    let has_admin_before = access.address_has_role(&address, &Role::Admin);
    let has_emergency_admin_before = access.address_has_role(&address, &Role::EmergencyAdmin);
    let has_rewards_admin_before = access.address_has_role(&address, &Role::RewardsAdmin);
    let has_operations_admin_before = access.address_has_role(&address, &Role::OperationsAdmin);
    let has_pause_admin_before = access.address_has_role(&address, &Role::PauseAdmin);

    clog!(
        has_admin_before,
        has_emergency_admin_before,
        has_rewards_admin_before,
        has_operations_admin_before,
        has_pause_admin_before
    );

    cvlr_assume!(!has_admin_before);
    access.set_role_address(&Role::Admin, &address);

    let has_admin_after = access.address_has_role(&address, &Role::Admin);
    let has_emergency_admin_after = access.address_has_role(&address, &Role::EmergencyAdmin);
    let has_rewards_admin_after = access.address_has_role(&address, &Role::RewardsAdmin);
    let has_operations_admin_after = access.address_has_role(&address, &Role::OperationsAdmin);
    let has_pause_admin_after = access.address_has_role(&address, &Role::PauseAdmin);

    clog!(
        has_admin_after,
        has_emergency_admin_after,
        has_rewards_admin_after,
        has_operations_admin_after,
        has_pause_admin_after
    );

    cvlr_assert!(has_admin_after);
    cvlr_assert!(has_emergency_admin_before == has_emergency_admin_after);
    cvlr_assert!(has_rewards_admin_before == has_rewards_admin_after);
    cvlr_assert!(has_operations_admin_before == has_operations_admin_after);
    cvlr_assert!(has_pause_admin_before == has_pause_admin_after);
}

#[rule]
pub fn set_emergency_admin_role_only_affects_emergency_admin_role(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    let access = AccessControl::new(&e);

    let has_admin_before = access.address_has_role(&address, &Role::Admin);
    let has_emergency_admin_before = access.address_has_role(&address, &Role::EmergencyAdmin);
    let has_rewards_admin_before = access.address_has_role(&address, &Role::RewardsAdmin);
    let has_operations_admin_before = access.address_has_role(&address, &Role::OperationsAdmin);
    let has_pause_admin_before = access.address_has_role(&address, &Role::PauseAdmin);

    clog!(
        has_admin_before,
        has_emergency_admin_before,
        has_rewards_admin_before,
        has_operations_admin_before,
        has_pause_admin_before
    );

    cvlr_assume!(!has_emergency_admin_before);
    access.set_role_address(&Role::EmergencyAdmin, &address);

    let has_admin_after = access.address_has_role(&address, &Role::Admin);
    let has_emergency_admin_after = access.address_has_role(&address, &Role::EmergencyAdmin);
    let has_rewards_admin_after = access.address_has_role(&address, &Role::RewardsAdmin);
    let has_operations_admin_after = access.address_has_role(&address, &Role::OperationsAdmin);
    let has_pause_admin_after = access.address_has_role(&address, &Role::PauseAdmin);

    clog!(
        has_admin_after,
        has_emergency_admin_after,
        has_rewards_admin_after,
        has_operations_admin_after,
        has_pause_admin_after
    );

    cvlr_assert!(has_emergency_admin_after);
    cvlr_assert!(has_admin_before == has_admin_after);
    cvlr_assert!(has_rewards_admin_before == has_rewards_admin_after);
    cvlr_assert!(has_operations_admin_before == has_operations_admin_after);
    cvlr_assert!(has_pause_admin_before == has_pause_admin_after);
}

#[rule]
pub fn set_rewards_admin_role_only_affects_rewards_admin_role(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    let access = AccessControl::new(&e);

    let has_admin_before = access.address_has_role(&address, &Role::Admin);
    let has_emergency_admin_before = access.address_has_role(&address, &Role::EmergencyAdmin);
    let has_rewards_admin_before = access.address_has_role(&address, &Role::RewardsAdmin);
    let has_operations_admin_before = access.address_has_role(&address, &Role::OperationsAdmin);
    let has_pause_admin_before = access.address_has_role(&address, &Role::PauseAdmin);

    clog!(
        has_admin_before,
        has_emergency_admin_before,
        has_rewards_admin_before,
        has_operations_admin_before,
        has_pause_admin_before
    );

    cvlr_assume!(!has_rewards_admin_before);
    access.set_role_address(&Role::RewardsAdmin, &address);

    let has_admin_after = access.address_has_role(&address, &Role::Admin);
    let has_emergency_admin_after = access.address_has_role(&address, &Role::EmergencyAdmin);
    let has_rewards_admin_after = access.address_has_role(&address, &Role::RewardsAdmin);
    let has_operations_admin_after = access.address_has_role(&address, &Role::OperationsAdmin);
    let has_pause_admin_after = access.address_has_role(&address, &Role::PauseAdmin);

    clog!(
        has_admin_after,
        has_emergency_admin_after,
        has_rewards_admin_after,
        has_operations_admin_after,
        has_pause_admin_after
    );

    cvlr_assert!(has_rewards_admin_after);
    cvlr_assert!(has_admin_before == has_admin_after);
    cvlr_assert!(has_emergency_admin_before == has_emergency_admin_after);
    cvlr_assert!(has_operations_admin_before == has_operations_admin_after);
    cvlr_assert!(has_pause_admin_before == has_pause_admin_after);
}

#[rule]
pub fn set_operations_admin_role_only_affects_operations_admin_role(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    let access = AccessControl::new(&e);

    let has_admin_before = access.address_has_role(&address, &Role::Admin);
    let has_emergency_admin_before = access.address_has_role(&address, &Role::EmergencyAdmin);
    let has_rewards_admin_before = access.address_has_role(&address, &Role::RewardsAdmin);
    let has_operations_admin_before = access.address_has_role(&address, &Role::OperationsAdmin);
    let has_pause_admin_before = access.address_has_role(&address, &Role::PauseAdmin);

    clog!(
        has_admin_before,
        has_emergency_admin_before,
        has_rewards_admin_before,
        has_operations_admin_before,
        has_pause_admin_before
    );

    cvlr_assume!(!has_operations_admin_before);
    access.set_role_address(&Role::OperationsAdmin, &address);

    let has_admin_after = access.address_has_role(&address, &Role::Admin);
    let has_emergency_admin_after = access.address_has_role(&address, &Role::EmergencyAdmin);
    let has_rewards_admin_after = access.address_has_role(&address, &Role::RewardsAdmin);
    let has_operations_admin_after = access.address_has_role(&address, &Role::OperationsAdmin);
    let has_pause_admin_after = access.address_has_role(&address, &Role::PauseAdmin);

    clog!(
        has_admin_after,
        has_emergency_admin_after,
        has_rewards_admin_after,
        has_operations_admin_after,
        has_pause_admin_after
    );

    cvlr_assert!(has_operations_admin_after);
    cvlr_assert!(has_admin_before == has_admin_after);
    cvlr_assert!(has_emergency_admin_before == has_emergency_admin_after);
    cvlr_assert!(has_rewards_admin_before == has_rewards_admin_after);
    cvlr_assert!(has_pause_admin_before == has_pause_admin_after);
}

#[rule]
pub fn set_pause_admin_role_only_affects_pause_admin_role(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    let access = AccessControl::new(&e);

    let has_admin_before = access.address_has_role(&address, &Role::Admin);
    let has_emergency_admin_before = access.address_has_role(&address, &Role::EmergencyAdmin);
    let has_rewards_admin_before = access.address_has_role(&address, &Role::RewardsAdmin);
    let has_operations_admin_before = access.address_has_role(&address, &Role::OperationsAdmin);
    let has_pause_admin_before = access.address_has_role(&address, &Role::PauseAdmin);

    clog!(
        has_admin_before,
        has_emergency_admin_before,
        has_rewards_admin_before,
        has_operations_admin_before,
        has_pause_admin_before
    );

    cvlr_assume!(!has_pause_admin_before);
    access.set_role_address(&Role::PauseAdmin, &address);

    let has_admin_after = access.address_has_role(&address, &Role::Admin);
    let has_emergency_admin_after = access.address_has_role(&address, &Role::EmergencyAdmin);
    let has_rewards_admin_after = access.address_has_role(&address, &Role::RewardsAdmin);
    let has_operations_admin_after = access.address_has_role(&address, &Role::OperationsAdmin);
    let has_pause_admin_after = access.address_has_role(&address, &Role::PauseAdmin);

    clog!(
        has_admin_after,
        has_emergency_admin_after,
        has_rewards_admin_after,
        has_operations_admin_after,
        has_pause_admin_after
    );

    cvlr_assert!(has_pause_admin_after);
    cvlr_assert!(has_admin_before == has_admin_after);
    cvlr_assert!(has_emergency_admin_before == has_emergency_admin_after);
    cvlr_assert!(has_rewards_admin_before == has_rewards_admin_after);
    cvlr_assert!(has_operations_admin_before == has_operations_admin_after);
}

#[rule]
pub fn set_role_address_only_accept_single_role_user(e: Env) {
    let address = nondet_address();
    clog!(cvlr_soroban::Addr(&address));
    let access = AccessControl::new(&e);
    access.set_role_address(&Role::EmergencyPauseAdmin, &address);
    cvlr_assert!(false);
}
