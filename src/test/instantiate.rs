use core::time;

use crate::contract::sv::mt::{CodeId, EscrowContractProxy};
use cosmwasm_std::Addr;
use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

#[test]
fn test_instantiate_success() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let admin1 = "admin1".into_addr();
    let admin2 = "admin2".into_addr();
    let did_contract1 = "nft_contract1".into_addr();

    let contract = code_id
        .instantiate(
            vec![admin1.clone(), admin2.clone()],
            did_contract1.clone(),
            1000,
        )
        .call(&admin1)
        .expect("instantiate should succeed");

    let admins = contract.get_admins().expect("get_admins failed");
    assert_eq!(admins.len(), 2);
    assert!(admins.contains(&admin1));
    assert!(admins.contains(&admin2));

    let nft_contracts = contract
        .get_did_contract()
        .expect("get_did_contract failed");
    assert_eq!(nft_contracts, did_contract1);

    let lt = contract
        .get_load_timeout()
        .expect("get_did_contract failed");
    assert_eq!(lt, time::Duration::from_millis(1000));
}

#[test]
fn test_instantiate_no_admins_should_fail() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let did_contract1 = "nft_contract1".into_addr();
    let admin1 = "admin1".into_addr();

    let contract_result = code_id
        .instantiate(vec![], did_contract1.clone(), 1000)
        .call(&admin1);
    assert!(contract_result.is_err());
    assert_eq!(
        contract_result.unwrap_err().to_string(),
        "At least one contract admin is required"
    );
}


#[test]
fn test_instantiate_with_duplicate_admins_should_fail() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let admin = "admin".into_addr();
    let did_contract1 = "nft_contract1".into_addr();


    let contract_result = code_id
        .instantiate(vec![admin.clone(), admin.clone()], did_contract1.clone(), 1000)
        .call(&admin);
    assert!(contract_result.is_err());
    assert_eq!(
        contract_result.unwrap_err().to_string(),
        format!("Duplicated admin: {}", admin)
    );
}

#[test]
fn test_instantiate_with_invalid_admin_address_should_fail() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let invalid_admin = Addr::unchecked("invalid_admin_address");
    let did_contract1 = "nft_contract1".into_addr();

    let contract_result = code_id
        .instantiate(vec![invalid_admin.clone()], did_contract1.clone(), 1000)
        .call(&invalid_admin);
    assert!(contract_result.is_err());
    assert_eq!(
        contract_result.unwrap_err().to_string(),
        "Invalid admin address: Generic error: Error decoding bech32"
    );
}


#[test]
fn test_instantiate_with_invalid_did_conract_address_should_fail() {
    let app = App::default();
    let code_id = CodeId::store_code(&app);

    let admin = "admin".into_addr();
    let invalid_did_contract = Addr::unchecked("invalid_did_contract");

    let contract_result = code_id
        .instantiate(vec![admin.clone()], invalid_did_contract.clone(), 1000)
        .call(&admin);
    assert!(contract_result.is_err());
    assert_eq!(
        contract_result.unwrap_err().to_string(),
        "Invalid address: Generic error: Error decoding bech32"
    );
}
