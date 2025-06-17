use cvlr::{clog, cvlr_assert};
use cvlr_soroban::nondet_address;
use cvlr_soroban_derive::rule;
use soroban_sdk::Env;
use upgrade::interface::UpgradeableContract;

use crate::FeesCollector;

#[rule]
pub fn emergency_mode_setter_getter(e: Env) {
    let emergency_admin = nondet_address();
    let value: bool = cvlr::nondet();

    clog!(value);

    FeesCollector::set_emergency_mode(e.clone(), emergency_admin, value);

    let retrieved_value = FeesCollector::get_emergency_mode(e.clone());

    clog!(retrieved_value);

    // Assert that the getter returns the same value that was set
    cvlr_assert!(retrieved_value == value);
}
