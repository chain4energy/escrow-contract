use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use did_contract::contract::{sv::mt::CodeId as DidContractCodeId, DidContract};

use crate::contract::sv::mt::{CodeId, EscrowContractProxy};

#[test]
fn test_get_admins_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let admin1 = "admin1".into_addr();
    let admin2 = "admin2".into_addr();

    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone(), admin1.clone(), admin2.clone()], did_contract.contract_addr, 10000, 5*24*3600*1000)
        .call(&owner)
        .unwrap();

    // Query the list of admins
    let admins = escrow_contract.get_admins().unwrap();

    // Validate the list of admins
    assert_eq!(admins.len(), 3);
    assert!(admins.contains(&owner));
    assert!(admins.contains(&admin1));
    assert!(admins.contains(&admin2));
}
