#[cfg(test)]
mod tests {
    extern crate std;
    use crate::access::{AccessControl, AccessControlTrait};
    use crate::management::MultipleAddressesManagementTrait;
    use crate::role::Role;
    use soroban_sdk::testutils::{Address as AddressTestUtils, Ledger};
    use soroban_sdk::{contract, contractimpl, Address, Env, String, Vec};

    // Create a dummy contract wrapper for testing
    #[contract]
    pub struct AccessControlTestContract;

    #[contractimpl]
    impl AccessControlTestContract {
        pub fn set_addresses(env: Env, addresses: Vec<Address>) {
            let access = AccessControl::new(&env);
            access.set_role_addresses(&Role::EmergencyPauseAdmin, &addresses);
        }
        
        pub fn get_addresses(env: Env) -> Vec<Address> {
            let access = AccessControl::new(&env);
            access.get_role_addresses(&Role::EmergencyPauseAdmin)
            
        }
    }

    #[test]
    fn test_emergency_pause_admin_addresses_single_address_version() {
        let e = Env::default();
        e.mock_all_auths();

        let address1 = <soroban_sdk::Address as AddressTestUtils>::generate(&e);
        let address2 = <soroban_sdk::Address as AddressTestUtils>::generate(&e);
        let mut addresses = Vec::new(&e);
        addresses.push_back(address1.clone());
        addresses.push_back(address1.clone());
        addresses.push_back(address2.clone());

        let contract_id = e.register_contract(None, AccessControlTestContract);
        let client = AccessControlTestContractClient::new(&e, &contract_id);
        client.set_addresses(&addresses);

        let result = client.get_addresses();
        std::println!("Found {} addresses:", result.len());
        for (i, addr) in result.iter().enumerate() {
            std::println!("  Address {}: {:?}", i + 1, addr);
        }
        assert_eq!(result.len(), 3);
    }
}
