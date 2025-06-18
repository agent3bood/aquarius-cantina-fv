use access_control::emergency::{get_emergency_mode, set_emergency_mode};
use cvlr::{clog, cvlr_assert, nondet};
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;

// @notice Verifies get_emergency_mode() consistency with set_emergency_mode()
#[rule]
pub fn emergency_mode_setter_getter(e: Env) {
    let value: bool = cvlr::nondet();

    clog!(value);

    set_emergency_mode(&e, &value);

    let retrieved_value = get_emergency_mode(&e);

    clog!(retrieved_value);

    // Assert that the getter returns the same value that was set
    cvlr_assert!(retrieved_value == value);
}

/// @notice Verifies emergency mode toggle functionality
/// @dev Ensures emergency mode can be toggled between true and false states
#[rule]
pub fn emergency_mode_toggle_sequence(e: Env) {
    let initial_state = get_emergency_mode(&e);

    // Toggle the state
    set_emergency_mode(&e, &!initial_state);
    cvlr_assert!(get_emergency_mode(&e) == !initial_state);

    // Toggle back
    set_emergency_mode(&e, &initial_state);
    cvlr_assert!(get_emergency_mode(&e) == initial_state);
}

/// @notice Verifies emergency::set_emergency_mode() idempotency
/// @dev Ensures setting the same value multiple times has no side effects
#[rule]
pub fn emergency_mode_idempotent_operations(e: Env) {
    let value: bool = nondet();

    // Set the same value multiple times
    set_emergency_mode(&e, &value);
    let first_get = get_emergency_mode(&e);

    set_emergency_mode(&e, &value);
    let second_get = get_emergency_mode(&e);

    set_emergency_mode(&e, &value);
    let third_get = get_emergency_mode(&e);

    // All gets should return the same value
    cvlr_assert!(first_get == value);
    cvlr_assert!(second_get == value);
    cvlr_assert!(third_get == value);
}
