use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use crate::contract::{sv::mt::{CodeId, EscrowContractProxy}, EscrowContract};

#[test]
fn test_get_did_contract_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    // let _did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let did_contract_address = "did_contract".into_addr();

    let escrow_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, EscrowContract> =
        escrow_code_id
            .instantiate(vec![owner.clone()], did_contract_address.clone(), 10000, 5*24*3600*1000)
            .call(&owner)
            .unwrap();

    // Query the DID contract address
    let queried_did_contract = escrow_contract.get_did_contract().unwrap();

    // Validate the queried DID contract address
    assert_eq!(queried_did_contract, did_contract_address);
}
