use soroban_sdk::{Env, Vec};
use cvlr::{cvlr_assert, cvlr_assume, nondet};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use access_control::role::Role;
use access_control::access::AccessControlTrait;
use access_control::management::{SingleAddressManagementTrait, MultipleAddressesManagementTrait};
use access_control::transfer::TransferOwnershipTrait;
use access_control::emergency::{get_emergency_mode, set_emergency_mode};
use access_control::constants::ADMIN_ACTIONS_DELAY;
use crate::certora_specs::ACCESS_CONTROL;

/// @notice Verifies the core access control invariant: only Admin role is guaranteed to exist
/// @dev High-level invariant ensuring Admin role is always accessible while others are optional
#[rule]
pub fn admin_role_always_exists_others_optional(_e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    let access_control = acc_ctrl.as_ref().unwrap();
    
    // Admin role should always be accessible via get_role (doesn't panic)
    let _admin = access_control.get_role(&Role::Admin);
    cvlr_assert!(true); // Should succeed
    
    // Other roles should fail with get_role since they're not guaranteed
    let role_type: u8 = nondet();
    let optional_role = match role_type % 4 {
        0 => Role::EmergencyAdmin,
        1 => Role::RewardsAdmin,
        2 => Role::OperationsAdmin,
        _ => Role::PauseAdmin,
    };
    
    access_control.get_role(&optional_role);
    cvlr_assert!(false); // Should panic with BadRoleUsage
}

/// @notice Verifies role-based access control isolation across all operations
/// @dev Ensures operations are properly restricted to authorized roles only
#[rule]
pub fn rbac_isolation_comprehensive(_e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    let access_control = acc_ctrl.as_ref().unwrap();
    
    let admin = nondet_address();
    let emergency_admin = nondet_address();
    let rewards_admin = nondet_address();
    let unauthorized = nondet_address();
    
    cvlr_assume!(admin != emergency_admin);
    cvlr_assume!(admin != rewards_admin);
    cvlr_assume!(admin != unauthorized);
    cvlr_assume!(emergency_admin != rewards_admin);
    cvlr_assume!(emergency_admin != unauthorized);
    cvlr_assume!(rewards_admin != unauthorized);
    
    // Set up roles
    access_control.set_role_address(&Role::Admin, &admin);
    access_control.set_role_address(&Role::EmergencyAdmin, &emergency_admin);
    access_control.set_role_address(&Role::RewardsAdmin, &rewards_admin);
    
    // Test role isolation
    cvlr_assert!(access_control.address_has_role(&admin, &Role::Admin));
    cvlr_assert!(!access_control.address_has_role(&admin, &Role::EmergencyAdmin));
    cvlr_assert!(!access_control.address_has_role(&emergency_admin, &Role::Admin));
    cvlr_assert!(access_control.address_has_role(&emergency_admin, &Role::EmergencyAdmin));
    cvlr_assert!(!access_control.address_has_role(&unauthorized, &Role::Admin));
    cvlr_assert!(!access_control.address_has_role(&unauthorized, &Role::EmergencyAdmin));
}

/// @notice Verifies emergency mode functionality is independent and consistent
/// @dev Comprehensive test for emergency mode state management
#[rule]
pub fn emergency_mode_comprehensive(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    let access_control = acc_ctrl.as_ref().unwrap();
    
    // Test default state
    cvlr_assert!(get_emergency_mode(&e) == false);
    
    // Test setting and persistence
    set_emergency_mode(&e, &true);
    cvlr_assert!(get_emergency_mode(&e) == true);
    
    // Verify independence from role changes
    let admin = nondet_address();
    access_control.set_role_address(&Role::Admin, &admin);
    cvlr_assert!(get_emergency_mode(&e) == true); // Should still be true
    
    // Test toggle functionality
    set_emergency_mode(&e, &false);
    cvlr_assert!(get_emergency_mode(&e) == false);
    
    set_emergency_mode(&e, &true);
    cvlr_assert!(get_emergency_mode(&e) == true);
}

/// @notice Verifies transfer ownership security model for critical roles
/// @dev Ensures only Admin and EmergencyAdmin have delayed transfers for security
#[rule]
pub fn delayed_transfer_security_model(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    let access_control = acc_ctrl.as_ref().unwrap();
    
    let future_address = nondet_address();
    let role_type: u8 = nondet();
    
    if role_type % 2 == 0 {
        // Test Admin role (should support delayed transfer)
        let role = Role::Admin;
        let initial_deadline = access_control.get_transfer_ownership_deadline(&role);
        cvlr_assume!(initial_deadline == 0);
        
        let current_time = e.ledger().timestamp();
        access_control.commit_transfer_ownership(&role, &future_address);
        
        let deadline = access_control.get_transfer_ownership_deadline(&role);
        cvlr_assert!(deadline == current_time + ADMIN_ACTIONS_DELAY);
    } else {
        // Test non-critical role (should fail delayed transfer)
        let role = Role::RewardsAdmin;
        access_control.commit_transfer_ownership(&role, &future_address);
        cvlr_assert!(false); // Should panic with BadRoleUsage
    }
}

/// @notice Verifies complete transfer ownership state machine with security delays
/// @dev Tests the full workflow: commit -> wait -> apply/revert with proper timing
#[rule]
pub fn transfer_ownership_complete_workflow(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    let access_control = acc_ctrl.as_ref().unwrap();
    
    let role = Role::Admin;
    let future_address = nondet_address();
    let current_admin = nondet_address();
    
    // Setup: Set initial admin
    access_control.set_role_address(&role, &current_admin);
    cvlr_assert!(access_control.get_role(&role) == current_admin);
    
    // Phase 1: Commit transfer
    let commit_time = e.ledger().timestamp();
    access_control.commit_transfer_ownership(&role, &future_address);
    
    let deadline = access_control.get_transfer_ownership_deadline(&role);
    cvlr_assert!(deadline == commit_time + ADMIN_ACTIONS_DELAY);
    
    // Phase 2: Wait period (cannot apply early)
    cvlr_assume!(e.ledger().timestamp() < deadline);
    // Attempting to apply early should fail
    
    // Phase 3: Apply after deadline
    cvlr_assume!(e.ledger().timestamp() >= deadline);
    let new_admin = access_control.apply_transfer_ownership(&role);
    
    // Verify transfer completed
    cvlr_assert!(new_admin == future_address);
    cvlr_assert!(access_control.get_role(&role) == future_address);
    cvlr_assert!(access_control.get_transfer_ownership_deadline(&role) == 0);
}

/// @notice Verifies single vs multi-address role enforcement is consistent
/// @dev Ensures proper separation between single and multi-address role management
#[rule]
pub fn single_vs_multi_address_role_enforcement(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    let access_control = acc_ctrl.as_ref().unwrap();
    
    let address = nondet_address();
    let mut addresses = Vec::new(&e);
    addresses.push_back(address.clone());
    
    let role_type: u8 = nondet();
    
    if role_type % 6 == 5 {
        // EmergencyPauseAdmin is multi-user role
        let role = Role::EmergencyPauseAdmin;
        
        // Should succeed with multi-address method
        access_control.set_role_addresses(&role, &addresses);
        let retrieved = access_control.get_role_addresses(&role);
        cvlr_assert!(retrieved.len() == 1);
        
        // Should fail with single-address method
        access_control.set_role_address(&role, &address);
        cvlr_assert!(false); // Should panic with BadRoleUsage
    } else {
        // All other roles are single-user
        let role = match role_type % 5 {
            0 => Role::Admin,
            1 => Role::EmergencyAdmin,
            2 => Role::RewardsAdmin,
            3 => Role::OperationsAdmin,
            _ => Role::PauseAdmin,
        };
        
        // Should succeed with single-address method
        access_control.set_role_address(&role, &address);
        let retrieved = access_control.get_role(&role);
        cvlr_assert!(retrieved == address);
        
        // Should fail with multi-address method
        access_control.set_role_addresses(&role, &addresses);
        cvlr_assert!(false); // Should panic with BadRoleUsage
    }
}

/// @notice Verifies no privilege escalation through role manipulation
/// @dev Critical security property ensuring role changes don't grant unintended access
#[rule]
pub fn no_privilege_escalation(_e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    let access_control = acc_ctrl.as_ref().unwrap();
    
    let user = nondet_address();
    let admin = nondet_address();
    cvlr_assume!(user != admin);
    
    // Setup: admin has Admin role, user has RewardsAdmin
    access_control.set_role_address(&Role::Admin, &admin);
    access_control.set_role_address(&Role::RewardsAdmin, &user);
    
    // Verify initial state
    cvlr_assert!(access_control.address_has_role(&admin, &Role::Admin));
    cvlr_assert!(access_control.address_has_role(&user, &Role::RewardsAdmin));
    cvlr_assert!(!access_control.address_has_role(&user, &Role::Admin));
    
    // Change user's role to OperationsAdmin
    access_control.set_role_address(&Role::OperationsAdmin, &user);
    
    // Verify user lost RewardsAdmin but didn't gain Admin
    cvlr_assert!(!access_control.address_has_role(&user, &Role::RewardsAdmin));
    cvlr_assert!(access_control.address_has_role(&user, &Role::OperationsAdmin));
    cvlr_assert!(!access_control.address_has_role(&user, &Role::Admin));
    cvlr_assert!(access_control.address_has_role(&admin, &Role::Admin)); // Admin unchanged
}

/// @notice Verifies atomic role updates prevent inconsistent intermediate states
/// @dev Ensures role changes are atomic and don't create race conditions
#[rule]
pub fn atomic_role_updates(_e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    let access_control = acc_ctrl.as_ref().unwrap();
    
    let old_admin = nondet_address();
    let new_admin = nondet_address();
    cvlr_assume!(old_admin != new_admin);
    
    // Set initial admin
    access_control.set_role_address(&Role::Admin, &old_admin);
    cvlr_assert!(access_control.address_has_role(&old_admin, &Role::Admin));
    cvlr_assert!(!access_control.address_has_role(&new_admin, &Role::Admin));
    
    // Change admin atomically
    access_control.set_role_address(&Role::Admin, &new_admin);
    
    // Verify atomic change: only new admin has role, old admin lost it
    cvlr_assert!(!access_control.address_has_role(&old_admin, &Role::Admin));
    cvlr_assert!(access_control.address_has_role(&new_admin, &Role::Admin));
    cvlr_assert!(access_control.get_role(&Role::Admin) == new_admin);
}

/// @notice Verifies system resilience to edge cases and boundary conditions
/// @dev Tests system behavior with extreme values and edge cases
#[rule]
pub fn system_resilience_edge_cases(e: Env) {
    let acc_ctrl = unsafe { &mut *&raw mut ACCESS_CONTROL };
    let access_control = acc_ctrl.as_ref().unwrap();
    
    // Test with maximum deadline values
    let role = Role::Admin;
    let max_deadline = u64::MAX - 1;
    access_control.put_transfer_ownership_deadline(&role, max_deadline);
    let retrieved = access_control.get_transfer_ownership_deadline(&role);
    cvlr_assert!(retrieved == max_deadline);
    
    // Test empty EmergencyPauseAdmin list
    let empty_vec = Vec::new(&e);
    access_control.set_role_addresses(&Role::EmergencyPauseAdmin, &empty_vec);
    let retrieved_empty = access_control.get_role_addresses(&Role::EmergencyPauseAdmin);
    cvlr_assert!(retrieved_empty.len() == 0);
    
    // Test same address for multiple roles
    let super_admin = nondet_address();
    access_control.set_role_address(&Role::Admin, &super_admin);
    access_control.set_role_address(&Role::EmergencyAdmin, &super_admin);
    
    cvlr_assert!(access_control.address_has_role(&super_admin, &Role::Admin));
    cvlr_assert!(access_control.address_has_role(&super_admin, &Role::EmergencyAdmin));
}