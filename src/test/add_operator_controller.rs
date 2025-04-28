use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use crate::contract::sv::mt::{CodeId, EscrowContractProxy};
use did_contract::{
    contract::{
        sv::mt::{CodeId as DidContractCodeId, DidContractProxy},
        DidContract,
    },
    state::{Controller, Did, DidDocument, DID_PREFIX},
};

#[test]
fn test_add_operator_controller() {
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

    // Add a new controller to the operator
    let new_controller: Controller = "controller2".into_addr().to_string().into();

    let res = escrow_contract
        .add_operator_controller(operator_id.clone(), new_controller.clone())
        .call(&owner)
        .expect("error adding operator controller");

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
    // assert_eq!(res.events[1].attributes[1].value, "add_operator_controller");
    // assert_eq!(res.events[1].attributes[2].key, "operator_id");
    // assert_eq!(res.events[1].attributes[2].value, operator_id);
    // assert_eq!(res.events[1].attributes[3].key, "controller_id");
    // assert_eq!(res.events[1].attributes[3].value, new_controller.id.to_string());

    // Verify the operator has the new controller added
    let operator = escrow_contract
        .get_escrow_operator(operator_id.clone())
        .expect("error querying operator");

    assert!(operator.controller.iter().any(|c| *c == new_controller));

    // Attempt to add a controller to a non-existent operator
    let non_existent_operator = "non_existent_operator".to_string();
    let res = escrow_contract
        .add_operator_controller(non_existent_operator, new_controller.clone())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator does not exist", res.err().unwrap().to_string());

    // Test unauthorized addition of controller
    let unauthorized_user = "unauthorized_user".into_addr();
    let res = escrow_contract
        .add_operator_controller(operator_id.clone(), new_controller.clone())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_add_operator_controller_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(
            vec![owner.clone()],
            did_contract.contract_addr.clone(),
            60000, 5*24*3600*1000,
            
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Add a new controller to the operator
    let new_controller: Controller = "controller2".into_addr().to_string().into();

    let res = escrow_contract
        .add_operator_controller(operator_id.clone(), new_controller.clone())
        .call(&owner)
        .expect("error adding operator controller");

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

    // Verify the "add_operator_controller" event
    let add_controller_event = &res.events[1];
    assert_eq!(add_controller_event.ty, "wasm-add_operator_controller");
    assert_eq!(add_controller_event.attributes[0].key, "_contract_address");
    assert_eq!(
        add_controller_event.attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(add_controller_event.attributes[1].key, "operator_id");
    assert_eq!(add_controller_event.attributes[1].value, operator_id);
    assert_eq!(add_controller_event.attributes[2].key, "controller");
    assert_eq!(
        add_controller_event.attributes[2].value,
        new_controller.to_string()
    );

    // Verify the operator has the new controller added
    let operator = escrow_contract
        .get_escrow_operator(operator_id.clone())
        .unwrap();
    assert!(operator.controller.contains(&new_controller));
}

#[test]
fn test_add_operator_controller_duplicate() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(
            vec![owner.clone()],
            did_contract.contract_addr.clone(),
            60000, 5*24*3600*1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to add the same controller again
    let res = escrow_contract
        .add_operator_controller(operator_id.clone(), controller1.clone())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        format!("Duplicated controller: {}", controller1.to_string()),
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_add_operator_controller_unauthorized() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(
            vec![owner.clone()],
            did_contract.contract_addr.clone(),
            60000, 5*24*3600*1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to add a controller by an unauthorized user
    let unauthorized_user = "unauthorized_user".into_addr();
    let new_controller: Controller = "controller2".into_addr().to_string().into();
    let res = escrow_contract
        .add_operator_controller(operator_id.clone(), new_controller.clone())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_add_operator_controller_nonexistent_operator() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(
            vec![owner.clone()],
            did_contract.contract_addr.clone(),
            60000, 5*24*3600*1000,
        )
        .call(&owner)
        .unwrap();

    // Attempt to add a controller to a non-existent operator
    let non_existent_operator = "non_existent_operator".to_string();
    let new_controller: Controller = "controller2".into_addr().to_string().into();
    let res = escrow_contract
        .add_operator_controller(non_existent_operator.clone(), new_controller.clone())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator does not exist", res.err().unwrap().to_string());
}

#[test]
fn test_add_operator_controller_with_did_controller() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr.clone(), 60000, 5*24*3600*1000)
        .call(&owner)
        .unwrap();

    // Add an operator

    let did = format!("{}controler", DID_PREFIX);
    let controller1: Controller = did.clone().into();

    let new_did_doc = DidDocument {
        id: Did::new(&did),
        controller: vec![owner.to_string().into()],
        service: vec![],
    };

    did_contract
    .create_did_document(new_did_doc.clone())
    .call(&owner)
    .expect("error adding controller");

    let did_controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Add a DID controller to the operator
    let res = escrow_contract
        .add_operator_controller(operator_id.clone(), did_controller.clone())
        .call(&owner)
        .expect("error adding DID controller");

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

    // Verify the "add_operator_controller" event
    let add_controller_event = &res.events[1];
    assert_eq!(add_controller_event.ty, "wasm-add_operator_controller");
    assert_eq!(add_controller_event.attributes[0].key, "_contract_address");
    assert_eq!(
        add_controller_event.attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(add_controller_event.attributes[1].key, "operator_id");
    assert_eq!(add_controller_event.attributes[1].value, operator_id);
    assert_eq!(add_controller_event.attributes[2].key, "controller");
    assert_eq!(
        add_controller_event.attributes[2].value,
        did_controller.to_string()
    );

    // Verify the operator has the DID controller added
    let operator = escrow_contract
        .get_escrow_operator(operator_id.clone())
        .unwrap();
    assert!(operator.controller.contains(&did_controller));
}

#[test]
fn test_add_operator_controller_with_nonexistent_did_controller() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr.clone(), 60000, 5*24*3600*1000)
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to add a non-existent DID controller to the operator
    let nonexistent_did = format!("{}nonexistent", DID_PREFIX);
    let nonexistent_controller: Controller = nonexistent_did.clone().into();

    let res = escrow_contract
        .add_operator_controller(operator_id.clone(), nonexistent_controller.clone())
        .call(&owner);

    // Validate the error response
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Controller does not exist",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_add_operator_controller_with_invalid_format() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(vec![owner.clone()], did_contract.contract_addr.clone(), 60000, 5*24*3600*1000)
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to add a controller with an invalid format
    let invalid_controller: Controller = "invalid_controller_format".to_string().into();

    let res = escrow_contract
        .add_operator_controller(operator_id.clone(), invalid_controller.clone())
        .call(&owner);

    // Validate the error response
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Controller format error: invalid_controller_format",
        res.err().unwrap().to_string()
    );
}