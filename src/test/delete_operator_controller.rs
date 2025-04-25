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
fn test_delete_operator_controller() {
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

    // Add an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let controller2: Controller = "controller2".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(
            operator_id.clone(),
            vec![controller1.clone(), controller2.clone()],
        )
        .call(&owner)
        .expect("error creating operator");

    // Delete an existing controller from the operator
    let res = escrow_contract
        .delete_operator_controller(operator_id.clone(), controller2.clone())
        .call(&owner)
        .expect("error deleting operator controller");

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
    // assert_eq!(res.events[1].attributes[1].value, "delete_operator_controller");
    // assert_eq!(res.events[1].attributes[2].key, "operator_id");
    // assert_eq!(res.events[1].attributes[2].value, operator_id);
    // assert_eq!(res.events[1].attributes[3].key, "controller_id");
    // assert_eq!(res.events[1].attributes[3].value, controller2.id.to_string());

    // Verify that the controller has been removed
    let operator = escrow_contract
        .get_escrow_operator(operator_id.clone())
        .expect("error querying operator");

    assert!(!operator.controller.iter().any(|c| *c == controller2));

    // Attempt to delete a non-existent controller from the operator
    let non_existent_controller: Controller =
        "non_existent_controller".into_addr().to_string().into();
    let res = escrow_contract
        .delete_operator_controller(operator_id.clone(), non_existent_controller)
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Did document controller not exist",
        res.err().unwrap().to_string()
    );

    // Test unauthorized controller removal attempt
    let unauthorized_user = "unauthorized_user".into_addr();
    let res = escrow_contract
        .delete_operator_controller(operator_id.clone(), controller1.clone())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_delete_operator_controller_success() {
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

    // Add an operator with multiple controllers
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let controller2: Controller = "controller2".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone(), controller2.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Delete an existing controller from the operator
    let res = escrow_contract
        .delete_operator_controller(operator_id.clone(), controller2.clone())
        .call(&owner)
        .expect("error deleting operator controller");

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

    // Verify the "delete_operator_controller" event
    let delete_event = &res.events[1];
    assert_eq!(delete_event.ty, "wasm-delete_operator_controller");
    assert_eq!(delete_event.attributes[0].key, "_contract_address");
    assert_eq!(
        delete_event.attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(delete_event.attributes[1].key, "operator_id");
    assert_eq!(delete_event.attributes[1].value, operator_id);
    assert_eq!(delete_event.attributes[2].key, "controller");
    assert_eq!(delete_event.attributes[2].value, controller2.to_string());

    // Verify that the controller has been removed
    let operator = escrow_contract
        .get_escrow_operator(operator_id.clone())
        .expect("error querying operator");
    assert!(!operator.controller.contains(&controller2));
}

#[test]
fn test_delete_operator_controller_nonexistent_controller() {
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

    // Add an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to delete a non-existent controller
    let non_existent_controller: Controller = "non_existent_controller".into_addr().to_string().into();
    let res = escrow_contract
        .delete_operator_controller(operator_id.clone(), non_existent_controller.clone())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Did document controller not exist",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_delete_operator_controller_unauthorized() {
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

    // Add an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to delete a controller by an unauthorized user
    let unauthorized_user = "unauthorized_user".into_addr();
    let res = escrow_contract
        .delete_operator_controller(operator_id.clone(), controller1.clone())
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_delete_operator_controller_last_controller() {
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

    // Add an operator with a single controller
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to delete the last controller
    let res = escrow_contract
        .delete_operator_controller(operator_id.clone(), controller1.clone())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "At least one controller is required",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_delete_operator_controller_with_invalid_format() {
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

    // Add an operator
    let controller1: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller1.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to delete a controller with an invalid format
    let invalid_controller: Controller = "invalid_controller_format".to_string().into();

    let res = escrow_contract
        .delete_operator_controller(operator_id.clone(), invalid_controller.clone())
        .call(&owner);

    // Validate the error response
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Controller format error: invalid_controller_format",
        res.err().unwrap().to_string()
    );
}