use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use crate::contract::sv::mt::{CodeId, EscrowContractProxy};
use did_contract::{
    contract::{
        sv::mt::CodeId as DidContractCodeId,
        DidContract,
    },
    state::Controller,
};

#[test]
fn test_remove_operator() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 60000, 5*24*3600*1000)
        .call(&owner)
        .unwrap();

    // Add an operator to remove later
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Remove the operator successfully
    let res = escrow_contract
        .remove_operator(operator_id.clone())
        .call(&owner)
        .expect("error removing operator");

    // Validate the response attributes and events
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    // Attempt to remove the same operator again, expecting an error
    let res = escrow_contract
        .remove_operator(operator_id.clone())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator does not exist", res.err().unwrap().to_string());

    // Test unauthorized removal attempt
    let unauthorized_user = "unauthorized_user".into_addr();
    let operator_id2 = "operator2".to_string();

    // Add a second operator
    escrow_contract
        .create_operator(operator_id2.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator2");

    // Unauthorized user tries to remove operator
    let res = escrow_contract
        .remove_operator(operator_id2.clone())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_remove_operator_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 60000, 5*24*3600*1000)
        .call(&owner)
        .unwrap();

    // Add an operator to remove later
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Remove the operator successfully
    let res = escrow_contract
        .remove_operator(operator_id.clone())
        .call(&owner)
        .expect("error removing operator");

    // Validate the response attributes and events
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
}

#[test]
fn test_remove_operator_not_found() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 60000, 5*24*3600*1000)
        .call(&owner)
        .unwrap();

    // Attempt to remove a non-existent operator
    let res = escrow_contract
        .remove_operator("non_existent_operator".to_string())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator does not exist", res.err().unwrap().to_string());
}

#[test]
fn test_remove_operator_unauthorized() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 60000, 5*24*3600*1000)
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to remove the operator by an unauthorized user
    let unauthorized_user = "unauthorized_user".into_addr();
    let res = escrow_contract
        .remove_operator(operator_id.clone())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_remove_operator_with_event_verification() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 60000, 5*24*3600*1000)
        .call(&owner)
        .unwrap();

    // Add an operator to remove later
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Remove the operator
    let res = escrow_contract
        .remove_operator(operator_id.clone())
        .call(&owner)
        .expect("error removing operator");

    // Validate the response events
    assert_eq!(res.events.len(), 2);

    // Verify the "execute" event
    let execute_event = &res.events[0];
    assert_eq!(execute_event.ty, "execute");
    assert_eq!(execute_event.attributes[0].key, "_contract_address");
    assert_eq!(
        execute_event.attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    // Verify the "remove_operator" event
    let remove_operator_event = &res.events[1];
    // assert_eq!(remove_operator_event.ty, "wasm-create_operator");
    // assert_eq!(remove_operator_event.attributes[0].key, "_contract_address");
    // assert_eq!(
    //     remove_operator_event.attributes[0].value,
    //     escrow_contract.contract_addr.to_string()
    // );

    assert_eq!(remove_operator_event.ty, "wasm-remove_operator");
    assert_eq!(remove_operator_event.attributes[0].key, "_contract_address");
    assert_eq!(
        remove_operator_event.attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(remove_operator_event.attributes[1].key, "operator_id");
    assert_eq!(remove_operator_event.attributes[1].value, operator_id);
}
