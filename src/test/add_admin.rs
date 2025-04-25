use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use did_contract::contract::{
    sv::mt::CodeId as DidContractCodeId, DidContract,
};

use crate::contract::sv::mt::{CodeId, EscrowContractProxy};

#[test]
fn test_add_admin() {
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

    let res = escrow_contract
        .add_admin(admin1.to_string())
        .call(&owner)
        .expect("error adding admin");

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-add_admin");
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "executor");
    assert_eq!(res.events[1].attributes[1].value, owner.to_string());
    assert_eq!(res.events[1].attributes[2].key, "new_admin");
    assert_eq!(res.events[1].attributes[2].value, admin1.to_string());

    let non_admin1 = "non_admin".into_addr();
    let admin2 = "admin2".into_addr();
    let res = escrow_contract
        .add_admin(admin2.to_string())
        .call(&non_admin1);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());

    let admin3 = "admin3".into_addr();

    escrow_contract
        .add_admin(admin3.to_string())
        .call(&admin1)
        .expect("error adding admin3");
}

#[test]
fn test_add_admin_success() {
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

    // Add a new admin
    let res = escrow_contract
        .add_admin(admin1.to_string())
        .call(&owner)
        .expect("error adding admin");

    // Validate the response attributes and events
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-add_admin");
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "executor");
    assert_eq!(res.events[1].attributes[1].value, owner.to_string());
    assert_eq!(res.events[1].attributes[2].key, "new_admin");
    assert_eq!(res.events[1].attributes[2].value, admin1.to_string());
}

#[test]
fn test_add_admin_duplicate() {
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

    // Add the admin for the first time
    escrow_contract
        .add_admin(admin1.to_string())
        .call(&owner)
        .expect("error adding admin");

    // Attempt to add the same admin again
    let res = escrow_contract.add_admin(admin1.to_string()).call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Admin already exists",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_add_admin_unauthorized() {
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

    // Attempt to add an admin by an unauthorized user
    let res = escrow_contract.add_admin(admin1.to_string()).call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_add_admin_invalid_format() {
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

    // Attempt to add an admin with an invalid format
    let res = escrow_contract.add_admin(invalid_admin.to_string()).call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Invalid admin address: Generic error: Error decoding bech32",
        res.err().unwrap().to_string()
    );
}