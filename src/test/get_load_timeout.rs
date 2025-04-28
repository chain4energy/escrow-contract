use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use crate::contract::{sv::mt::{CodeId, EscrowContractProxy}, EscrowContract};

#[test]
fn test_get_load_timeout_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let did_contract_address = "did_contract".into_addr();
    let load_timeout = 60000; // 60 seconds in milliseconds

    let escrow_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, EscrowContract> =
        escrow_code_id
            .instantiate(vec![owner.clone()], did_contract_address.clone(), load_timeout, 5*24*3600*1000)
            .call(&owner)
            .unwrap();

    // Query the load timeout
    let queried_load_timeout = escrow_contract.get_load_timeout().unwrap();

    // Validate the queried load timeout
    assert_eq!(queried_load_timeout.as_secs(), load_timeout / 1000);
}

#[test]
fn test_get_load_timeout_not_set() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let did_contract_address = "did_contract".into_addr();

    // Instantiate the contract without setting a load timeout
    let escrow_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, EscrowContract> =
        escrow_code_id
            .instantiate(vec![owner.clone()], did_contract_address.clone(), 0, 5*24*3600*1000)
            .call(&owner)
            .unwrap();

    // Query the load timeout
    let queried_load_timeout = escrow_contract.get_load_timeout().unwrap();

    // Validate that the load timeout is zero
    assert_eq!(queried_load_timeout.as_secs(), 0);
}