use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use did_contract::contract::{sv::mt::CodeId as DidContractCodeId, DidContract};

use crate::contract::sv::mt::{CodeId, EscrowContractProxy};

#[test]
fn test_remove_admin() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 60000)
        .call(&owner)
        .unwrap();

    let admin1 = "admin1".into_addr();

    // First, add an admin to remove later
    escrow_contract
        .add_admin(admin1.to_string())
        .call(&owner)
        .expect("error adding admin1");

    // Remove the admin
    let res = escrow_contract
        .remove_admin(admin1.to_string())
        .call(&owner)
        .expect("error removing admin");

    // Validate the response attributes and events
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-remove_admin");
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "executor");
    assert_eq!(res.events[1].attributes[1].value, owner.to_string());
    assert_eq!(res.events[1].attributes[2].key, "removed_admin");
    assert_eq!(res.events[1].attributes[2].value, admin1.to_string());

    // Test removing a non-existing admin
    let non_admin = "non_admin".into_addr();
    let res = escrow_contract
        .remove_admin(non_admin.to_string())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Admin not found", res.err().unwrap().to_string());

    // Test unauthorized removal attempt
    let unauthorized_user = "unauthorized".into_addr();
    let another_admin = "admin2".into_addr();

    // Add a second admin to test unauthorized removal
    escrow_contract
        .add_admin(another_admin.to_string())
        .call(&owner)
        .expect("error adding admin2");

    let res = escrow_contract
        .remove_admin(another_admin.to_string())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}


#[test]
fn test_remove_admin_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 10000)
        .call(&owner)
        .unwrap();

    let admin1 = "admin1".into_addr();

    // Add an admin to remove later
    escrow_contract
        .add_admin(admin1.to_string())
        .call(&owner)
        .expect("error adding admin");

    // Remove the admin
    let res = escrow_contract
        .remove_admin(admin1.to_string())
        .call(&owner)
        .expect("error removing admin");

    // Validate the response attributes and events
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-remove_admin");
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "executor");
    assert_eq!(res.events[1].attributes[1].value, owner.to_string());
    assert_eq!(res.events[1].attributes[2].key, "removed_admin");
    assert_eq!(res.events[1].attributes[2].value, admin1.to_string());
}

#[test]
fn test_remove_admin_non_existent() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 10000)
        .call(&owner)
        .unwrap();

    let non_existent_admin = "non_existent_admin".into_addr();

    // Attempt to remove a non-existent admin
    let res = escrow_contract
        .remove_admin(non_existent_admin.to_string())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Admin not found", res.err().unwrap().to_string());
}

#[test]
fn test_remove_admin_unauthorized() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 10000)
        .call(&owner)
        .unwrap();

    let admin1 = "admin1".into_addr();
    let unauthorized_user = "unauthorized".into_addr();

    // Add an admin to remove later
    escrow_contract
        .add_admin(admin1.to_string())
        .call(&owner)
        .expect("error adding admin");

    // Attempt to remove the admin by an unauthorized user
    let res = escrow_contract
        .remove_admin(admin1.to_string())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}


#[test]
fn test_cannot_remove_last_admin() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);
    
    let only_admin = "only_admin".into_addr();
    let auth_address = "cw721_address".into_addr();

    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&only_admin).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![only_admin.clone()], did_contract.contract_addr, 10000)
        .call(&only_admin)
        .unwrap();

    let res = escrow_contract
        .remove_admin(only_admin.to_string())
        .call(&only_admin);

    assert!(res.is_err(), "Expected error when removing last admin");
    assert_eq!(
        "At least one contract admin is required",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_remove_same_admin_twice() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);
    
    let admin = "only_admin".into_addr();
    let auth_address = "cw721_address".into_addr();

    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&admin).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![admin.clone()], did_contract.contract_addr, 10000)
        .call(&admin)
        .unwrap();

    let admin_to_remove = "admin2".into_addr();
    escrow_contract
        .add_admin(admin_to_remove.to_string())
        .call(&admin)
        .expect("failed to add admin");

    // First removal should succeed
    escrow_contract
        .remove_admin(admin_to_remove.to_string())
        .call(&admin)
        .expect("first removal failed");

    // Second removal should fail
    let result = escrow_contract
        .remove_admin(admin_to_remove.to_string())
        .call(&admin);

    assert!(result.is_err(), "Expected error on second removal");
    assert_eq!("Admin not found", result.unwrap_err().to_string());
}

#[test]
fn test_remove_admin_invalid_format() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 10000)
        .call(&owner)
        .unwrap();

    let invalid_admin = "invalid_admin_format"; // Invalid format (not a valid address)

    // Attempt to remove an admin with an invalid format
    let res = escrow_contract.remove_admin(invalid_admin.to_string()).call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Invalid admin address: Generic error: Error decoding bech32",
        res.err().unwrap().to_string()
    );
}