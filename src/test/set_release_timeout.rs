use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use crate::contract::sv::mt::{CodeId, EscrowContractProxy};

#[test]
fn test_set_release_timeout_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate the contract
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], "did_contract".into_addr(), 60000, 5 * 24 * 3600 * 1000)
        .call(&owner)
        .unwrap();

    // Set a new load timeout
    let new_timeout = 120000; // 120 seconds in milliseconds
    let res = escrow_contract
        .set_release_timeout(new_timeout)
        .call(&owner)
        .expect("error setting load timeout");

    // Validate the response events
    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-set_release_timeout");
    assert_eq!(res.events[1].attributes.len(), 2);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "timeout");
    assert_eq!(res.events[1].attributes[1].value, new_timeout.to_string());

    // Query the load timeout to verify the update
    let timeout = escrow_contract
        .get_release_timeout()
        .expect("error querying load timeout");
    assert_eq!(timeout.as_millis(), new_timeout as u128);
}

#[test]
fn test_set_release_timeout_unauthorized() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);

    let owner = "owner".into_addr();
    let unauthorized_user = "unauthorized_user".into_addr();

    // Instantiate the contract
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], "did_contract".into_addr(), 60000, 5 * 24 * 3600 * 1000)
        .call(&owner)
        .unwrap();

    // Attempt to set a new load timeout by an unauthorized user
    let new_timeout = 120000; // 120 seconds in milliseconds
    let res = escrow_contract.set_release_timeout(new_timeout).call(&unauthorized_user);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}