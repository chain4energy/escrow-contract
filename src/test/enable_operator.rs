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
fn test_enable_operator() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr, 60000)
        .call(&owner)
        .unwrap();

    // Add an operator and disable it first
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    escrow_contract
        .disable_operator(operator_id.clone())
        .call(&owner)
        .expect("error disabling operator");

    let operator = escrow_contract
        .get_escrow_operator(operator_id.clone())
        .expect("error querying operator");
    assert_eq!(operator.enabled, false);

    // Enable the operator
    let res = escrow_contract
        .enable_operator(operator_id.clone())
        .call(&owner)
        .expect("error enabling operator");

    // Validate the response attributes and events
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    // assert_eq!(res.events[1].ty, "wasm");
    // assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    // assert_eq!(res.events[1].attributes[0].value, escrow_contract.contract_addr.to_string());
    // assert_eq!(res.events[1].attributes[1].key, "action");
    // assert_eq!(res.events[1].attributes[1].value, "enable_operator");
    // assert_eq!(res.events[1].attributes[2].key, "operator_id");
    // assert_eq!(res.events[1].attributes[2].value, operator_id);
    // assert_eq!(res.events[1].attributes[3].key, "enabled");
    // assert_eq!(res.events[1].attributes[3].value, "true");

    // Verify the operator is actually enabled
    let operator = escrow_contract
        .get_escrow_operator(operator_id.clone())
        .expect("error querying operator");
    assert_eq!(operator.enabled, true);

    // Attempt to enable a non-existent operator, expecting an error
    let non_existent_operator = "non_existent_operator".to_string();
    let res = escrow_contract
        .enable_operator(non_existent_operator)
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator does not exist", res.err().unwrap().to_string());

    // Test unauthorized enable attempt
    let unauthorized_user = "unauthorized_user".into_addr();
    let res = escrow_contract
        .enable_operator(operator_id.clone())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_enable_operator_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr.clone(), 60000)
        .call(&owner)
        .unwrap();

    // Add an operator and disable it first
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    escrow_contract
        .disable_operator(operator_id.clone())
        .call(&owner)
        .expect("error disabling operator");

    let operator = escrow_contract
        .get_escrow_operator(operator_id.clone())
        .expect("error querying operator");
    assert_eq!(operator.enabled, false);

    // Enable the operator
    let res = escrow_contract
        .enable_operator(operator_id.clone())
        .call(&owner)
        .expect("error enabling operator");

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

    // Verify the "enable_operator" event
    let enable_event = &res.events[1];
    assert_eq!(enable_event.ty, "wasm-enable_operator");
    assert_eq!(enable_event.attributes[0].key, "_contract_address");
    assert_eq!(
        enable_event.attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(enable_event.attributes[1].key, "operator_id");
    assert_eq!(enable_event.attributes[1].value, operator_id);

    // Verify the operator is actually enabled
    let operator = escrow_contract
        .get_escrow_operator(operator_id.clone())
        .expect("error querying operator");
    assert_eq!(operator.enabled, true);
}

#[test]
fn test_enable_operator_not_found() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr.clone(), 60000)
        .call(&owner)
        .unwrap();

    // Attempt to enable a non-existent operator
    let res = escrow_contract
        .enable_operator("non_existent_operator".to_string())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator does not exist", res.err().unwrap().to_string());
}

#[test]
fn test_enable_operator_unauthorized() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr.clone(), 60000)
        .call(&owner)
        .unwrap();

    // Add an operator and disable it first
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    escrow_contract
        .disable_operator(operator_id.clone())
        .call(&owner)
        .expect("error disabling operator");

    // Attempt to enable the operator by an unauthorized user
    let unauthorized_user = "unauthorized_user".into_addr();
    let res = escrow_contract
        .enable_operator(operator_id.clone())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}