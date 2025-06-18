use access_control::role::{Role, SymbolRepresentation};
use cvlr::cvlr_assert;
use cvlr_soroban_derive::rule;
use soroban_sdk::{Env, Symbol};

/// @notice Verifies Admin role symbol bidirectional conversion
#[rule]
pub fn admin_role_symbol_conversion(e: Env) {
    let original_role = Role::Admin;
    let symbol = original_role.as_symbol(&e);
    let converted_back = Role::from_symbol(&e, symbol.clone());
    let converted_symbol = converted_back.as_symbol(&e);
    cvlr_assert!(symbol == converted_symbol);
}

/// @notice Verifies EmergencyAdmin role symbol bidirectional conversion
#[rule]
pub fn emergency_admin_role_symbol_conversion(e: Env) {
    let original_role = Role::EmergencyAdmin;
    let symbol = original_role.as_symbol(&e);
    let converted_back = Role::from_symbol(&e, symbol.clone());
    let converted_symbol = converted_back.as_symbol(&e);
    cvlr_assert!(symbol == converted_symbol);
}

/// @notice Verifies RewardsAdmin role symbol bidirectional conversion
#[rule]
pub fn rewards_admin_role_symbol_conversion(e: Env) {
    let original_role = Role::RewardsAdmin;
    let symbol = original_role.as_symbol(&e);
    let converted_back = Role::from_symbol(&e, symbol.clone());
    let converted_symbol = converted_back.as_symbol(&e);
    cvlr_assert!(symbol == converted_symbol);
}

/// @notice Verifies OperationsAdmin role symbol bidirectional conversion
#[rule]
pub fn operations_admin_role_symbol_conversion(e: Env) {
    let original_role = Role::OperationsAdmin;
    let symbol = original_role.as_symbol(&e);
    let converted_back = Role::from_symbol(&e, symbol.clone());
    let converted_symbol = converted_back.as_symbol(&e);
    cvlr_assert!(symbol == converted_symbol);
}

/// @notice Verifies PauseAdmin role symbol bidirectional conversion
#[rule]
pub fn pause_admin_role_symbol_conversion(e: Env) {
    let original_role = Role::PauseAdmin;
    let symbol = original_role.as_symbol(&e);
    let converted_back = Role::from_symbol(&e, symbol.clone());
    let converted_symbol = converted_back.as_symbol(&e);
    cvlr_assert!(symbol == converted_symbol);
}

/// @notice Verifies EmergencyPauseAdmin role symbol bidirectional conversion
#[rule]
pub fn emergency_pause_admin_role_symbol_conversion(e: Env) {
    let original_role = Role::EmergencyPauseAdmin;
    let symbol = original_role.as_symbol(&e);
    let converted_back = Role::from_symbol(&e, symbol.clone());
    let converted_symbol = converted_back.as_symbol(&e);
    cvlr_assert!(symbol == converted_symbol);
}

/// @notice Verifies SymbolRepresentation::from_symbol() error handling
/// @dev Ensures invalid role symbols trigger BadRoleUsage panic
#[rule]
pub fn invalid_role_symbol_panics(e: Env) {
    let invalid_symbol = Symbol::new(&e, "InvalidRole");
    Role::from_symbol(&e, invalid_symbol);
    cvlr_assert!(false); // Should panic with BadRoleUsage
}
