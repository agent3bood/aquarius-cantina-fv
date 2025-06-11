use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

use crate::access::{AccessControl, AccessControlTrait};
use crate::emergency;
use crate::interface::TransferableContract;
use crate::management::{MultipleAddressesManagementTrait, SingleAddressManagementTrait};
use crate::role::{Role, SymbolRepresentation};
use crate::transfer::TransferOwnershipTrait;

#[contract]
pub struct DummyContract;

#[contractimpl]
impl DummyContract {
    /// Initialize the contract with an admin
    pub fn init_admin(e: Env, admin: Address) {
        let access_control = AccessControl::new(&e);
        access_control.set_role_address(&Role::Admin, &admin);
    }

    /// Set a role for an address (admin only)
    pub fn set_role(e: Env, admin: Address, role_symbol: Symbol, address: Address) {
        let access_control = AccessControl::new(&e);
        // Check admin permission
        access_control.assert_address_has_role(&admin, &Role::Admin);
        
        let role = Role::from_symbol(&e, role_symbol);
        access_control.set_role_address(&role, &address);
    }

    /// Set multiple addresses for a role (admin only)
    pub fn set_role_addresses(e: Env, admin: Address, role_symbol: Symbol, addresses: Vec<Address>) {
        let access_control = AccessControl::new(&e);
        // Check admin permission
        access_control.assert_address_has_role(&admin, &Role::Admin);
        
        let role = Role::from_symbol(&e, role_symbol);
        access_control.set_role_addresses(&role, &addresses);
    }

    /// Get role address
    pub fn get_role(e: Env, role_symbol: Symbol) -> Address {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_symbol);
        access_control.get_role(&role)
    }

    /// Get role addresses for multi-address roles
    pub fn get_role_addresses(e: Env, role_symbol: Symbol) -> Vec<Address> {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_symbol);
        access_control.get_role_addresses(&role)
    }

    /// Check if address has role
    pub fn has_role(e: Env, address: Address, role_symbol: Symbol) -> bool {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_symbol);
        access_control.address_has_role(&address, &role)
    }

    /// Set emergency mode (emergency admin only)
    pub fn set_emergency_mode(e: Env, admin: Address, value: bool) {
        let access_control = AccessControl::new(&e);
        // Check emergency admin permission
        access_control.assert_address_has_role(&admin, &Role::EmergencyAdmin);
        
        emergency::set_emergency_mode(&e, &value);
    }

    /// Get emergency mode
    pub fn get_emergency_mode(e: Env) -> bool {
        emergency::get_emergency_mode(&e)
    }

    /// Protected function - only rewards admin or owner
    pub fn rewards_admin_function(e: Env, caller: Address) -> bool {
        let access_control = AccessControl::new(&e);
        if access_control.address_has_role(&caller, &Role::Admin) || 
           access_control.address_has_role(&caller, &Role::RewardsAdmin) {
            true
        } else {
            panic!("Unauthorized")
        }
    }

    /// Protected function - only operations admin or owner
    pub fn operations_admin_function(e: Env, caller: Address) -> bool {
        let access_control = AccessControl::new(&e);
        if access_control.address_has_role(&caller, &Role::Admin) || 
           access_control.address_has_role(&caller, &Role::OperationsAdmin) {
            true
        } else {
            panic!("Unauthorized")
        }
    }
}

#[contractimpl]
impl TransferableContract for DummyContract {
    fn commit_transfer_ownership(e: Env, admin: Address, role_name: Symbol, new_address: Address) {
        let access_control = AccessControl::new(&e);
        // Verify admin has permission
        access_control.assert_address_has_role(&admin, &Role::Admin);
        
        let role = Role::from_symbol(&e, role_name);
        access_control.commit_transfer_ownership(&role, &new_address);
    }

    fn apply_transfer_ownership(e: Env, admin: Address, role_name: Symbol) {
        let access_control = AccessControl::new(&e);
        // Verify admin has permission
        access_control.assert_address_has_role(&admin, &Role::Admin);
        
        let role = Role::from_symbol(&e, role_name);
        access_control.apply_transfer_ownership(&role);
    }

    fn revert_transfer_ownership(e: Env, admin: Address, role_name: Symbol) {
        let access_control = AccessControl::new(&e);
        // Verify admin has permission
        access_control.assert_address_has_role(&admin, &Role::Admin);
        
        let role = Role::from_symbol(&e, role_name);
        access_control.revert_transfer_ownership(&role);
    }

    fn get_future_address(e: Env, role_name: Symbol) -> Address {
        let access_control = AccessControl::new(&e);
        let role = Role::from_symbol(&e, role_name);
        access_control.get_future_address(&role)
    }
}