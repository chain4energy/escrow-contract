use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use crate::contract::sv::mt::{CodeId, EscrowContractProxy};
use did_contract::{
    contract::{sv::mt::{CodeId as DidContractCodeId, DidContractProxy}, DidContract},
    state::{Controller, Did, DidDocument, DID_PREFIX},
};

#[test]
fn test_create_operator() {
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

    // Test creating a valid operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let controller2: Controller = "controller2".into_addr().to_string().into();

    let res = escrow_contract
        .create_operator(
            "operator1".to_string(),
            vec![controller1.clone(), controller2.clone()],
        )
        .call(&owner)
        .expect("error creating operator");

    // Validate the response
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
    // assert_eq!(res.events[1].attributes[1].value, "create_operator");

    // Test trying to overwrite an existing operator
    let res = escrow_contract
        .create_operator("operator1".to_string(), vec![controller1.clone()])
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator already exists", res.err().unwrap().to_string());

    // Test invalid controller (assuming we have some validation that fails in Controller.ensure_valid)
    let invalid_controller: Controller = "invalid_controller".into(); // Assume this controller fails validation
    let res = escrow_contract
        .create_operator("operator2".to_string(), vec![invalid_controller.clone()])
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Controller format error: invalid_controller",
        res.err().unwrap().to_string()
    );

    // Test unauthorized creation attempt
    let unauthorized_user = "unauthorized_user".into_addr();
    let res = escrow_contract
        .create_operator("operator3".to_string(), vec![controller1.clone()])
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_create_operator_success() {
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

    // Test creating a valid operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let controller2: Controller = "controller2".into_addr().to_string().into();

    let res = escrow_contract
        .create_operator(
            "operator1".to_string(),
            vec![controller1.clone(), controller2.clone()],
        )
        .call(&owner)
        .expect("error creating operator");

    // Validate the response
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    // Query the operator to validate it was created
    let operator = escrow_contract
        .get_escrow_operator("operator1".to_string())
        .unwrap();
    assert_eq!(operator.id, "operator1");
    assert!(operator.controller.contains(&controller1));
    assert!(operator.controller.contains(&controller2));
    assert!(operator.enabled);
}

#[test]
fn test_create_operator_with_did_controller_success() {
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

    let did = format!("{}controler", DID_PREFIX);
    let controller: Controller = did.clone().into();

    let new_did_doc = DidDocument {
        id: Did::new(&did),
        controller: vec![owner.to_string().into()],
        service: vec![],
    };

    did_contract
        .create_did_document(new_did_doc.clone())
        .call(&owner)
        .expect("error adding controller");

    // Test creating a valid operator

    let res = escrow_contract
        .create_operator("operator1".to_string(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Validate the response
    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    // Query the operator to validate it was created
    let operator = escrow_contract
        .get_escrow_operator("operator1".to_string())
        .unwrap();
    assert_eq!(operator.id, "operator1");
    assert!(operator.controller.contains(&controller));
    assert!(operator.enabled);
}

#[test]
fn test_create_operator_duplicate() {
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

    let controller1: Controller = "controller1".into_addr().to_string().into();

    // Create the operator
    escrow_contract
        .create_operator("operator1".to_string(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to create the same operator again
    let res = escrow_contract
        .create_operator("operator1".to_string(), vec![controller1.clone()])
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator already exists", res.err().unwrap().to_string());
}

#[test]
fn test_create_operator_invalid_controller() {
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

    // Test invalid controller
    let invalid_controller: Controller = "invalid_controller".into(); // Assume this controller fails validation
    let res = escrow_contract
        .create_operator("operator2".to_string(), vec![invalid_controller.clone()])
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Controller format error: invalid_controller",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_create_operator_unauthorized() {
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

    let controller1: Controller = "controller1".into_addr().to_string().into();

    // Test unauthorized creation attempt
    let unauthorized_user = "unauthorized_user".into_addr();
    let res = escrow_contract
        .create_operator("operator3".to_string(), vec![controller1.clone()])
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_create_operator_no_controllers() {
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

    // Test creating an operator with no controllers
    let res = escrow_contract
        .create_operator("operator4".to_string(), vec![])
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "At least one controller is required",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_create_operator_controller_does_not_exist() {
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
            60000,
        )
        .call(&owner)
        .unwrap();

    // Test creating an operator with a non-existent DID controller
    let non_existent_did = format!("{}address", DID_PREFIX);
    let non_existent_controller: Controller = non_existent_did.clone().into();
    let res = escrow_contract
        .create_operator(
            "operator5".to_string(),
            vec![non_existent_controller.clone()],
        )
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Controller does not exist", res.err().unwrap().to_string());
}

#[test]
fn test_create_operator_with_event_verification() {
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

    // Test creating an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let controller2: Controller = "controller2".into_addr().to_string().into();

    let res = escrow_contract
        .create_operator(
            "operator1".to_string(),
            vec![controller1.clone(), controller2.clone()],
        )
        .call(&owner)
        .expect("error creating operator");

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

    // Verify the "create_operator" event
    let create_operator_event = &res.events[1];
    assert_eq!(create_operator_event.ty, "wasm-create_operator");
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(create_operator_event.attributes[1].key, "operator_id");
    assert_eq!(create_operator_event.attributes[1].value, "operator1");
    assert_eq!(create_operator_event.attributes[2].key, "controllers");
    assert_eq!(
        create_operator_event.attributes[2].value,
        format!("{},{}", controller1.to_string(), controller2.to_string())
    );

    // Query the operator to validate it was created
    let operator = escrow_contract
        .get_escrow_operator("operator1".to_string())
        .unwrap();
    assert_eq!(operator.id, "operator1");
    assert!(operator.controller.contains(&controller1));
    assert!(operator.controller.contains(&controller2));
    assert!(operator.enabled);
}

#[test]
fn test_create_operator_with_duplicated_controllers() {
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

    // Test creating an operator with duplicated controllers
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let duplicated_controller: Controller = "controller1".into_addr().to_string().into();

    let res = escrow_contract
        .create_operator(
            "operator_with_duplicates".to_string(),
            vec![controller1.clone(), duplicated_controller.clone()],
        )
        .call(&owner);

    // Validate the error response
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        format!("Duplicated controller: {}", controller1.to_string()),
        res.err().unwrap().to_string()
    );
}