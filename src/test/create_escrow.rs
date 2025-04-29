use cosmwasm_std::{Coin, Coins};
use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use did_contract::{
    contract::{sv::mt::CodeId as DidContractCodeId, DidContract},
    state::Controller,
};

use crate::{
    contract::sv::mt::{CodeId, EscrowContractProxy},
    state::{CoinsExt, Escrow, EscrowState},
};

#[test]
fn test_create_escrow_by_admin_success() {
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
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Create an escrow
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver.clone(),
            expected_coins.clone(),
        )
        .call(&owner)
        .expect("error creating escrow");

    // Validate the response events
    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_create");
    assert_eq!(res.events[1].attributes.len(), 5);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");
    assert_eq!(res.events[1].attributes[2].key, "operator_id");
    assert_eq!(res.events[1].attributes[2].value, operator_id);
    assert_eq!(res.events[1].attributes[3].key, "receiver");
    assert_eq!(res.events[1].attributes[3].value, receiver);
    assert_eq!(res.events[1].attributes[4].key, "expected_coins");
    let dedupl_expected_coins = Coins::deduplicated_coins(expected_coins.clone()).unwrap();
    assert_eq!(
        res.events[1].attributes[4].value,
        dedupl_expected_coins.to_string()
    );

    // Verify the escrow is created
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");
    assert_eq!(escrow.id, "escrow1");
    assert_eq!(escrow.operator_id, operator_id);
    assert_eq!(escrow.receiver, receiver);
    assert_eq!(escrow.expected_coins, expected_coins);
    assert_eq!(escrow.state, EscrowState::Loading);

    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id,
            expected_coins: expected_coins.clone(),
            loaded_coins: None,
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: vec![],
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: vec![],
            state: EscrowState::Loading,
            lock_timestamp: None,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    )
}

#[test]
fn test_create_escrow_by_operator_success() {
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
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller_addr = "controller1".into_addr();
    let controller: Controller = controller_addr.to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Create an escrow
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver.clone(),
            expected_coins.clone(),
        )
        .call(&controller_addr)
        .expect("error creating escrow");

    // Validate the response events
    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_create");
    assert_eq!(res.events[1].attributes.len(), 5);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");
    assert_eq!(res.events[1].attributes[2].key, "operator_id");
    assert_eq!(res.events[1].attributes[2].value, operator_id);
    assert_eq!(res.events[1].attributes[3].key, "receiver");
    assert_eq!(res.events[1].attributes[3].value, receiver);
    assert_eq!(res.events[1].attributes[4].key, "expected_coins");
    let dedupl_expected_coins = Coins::deduplicated_coins(expected_coins.clone()).unwrap();
    assert_eq!(
        res.events[1].attributes[4].value,
        dedupl_expected_coins.to_string()
    );

    // Verify the escrow is created
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");
    assert_eq!(escrow.id, "escrow1");
    assert_eq!(escrow.operator_id, operator_id);
    assert_eq!(escrow.receiver, receiver);
    assert_eq!(escrow.expected_coins, expected_coins);
    assert_eq!(escrow.state, EscrowState::Loading);

    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id,
            expected_coins: expected_coins.clone(),
            loaded_coins: None,
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: vec![],
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: vec![],
            state: EscrowState::Loading,
            lock_timestamp: None,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    )
}

#[test]
fn test_create_escrow_operator_not_found() {
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
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Attempt to create an escrow with a non-existent operator
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            "non_existent_operator".to_string(),
            receiver,
            expected_coins,
        )
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator does not exist", res.err().unwrap().to_string());
}

#[test]
fn test_create_escrow_invalid_receiver() {
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
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to create an escrow with an invalid receiver
    let invalid_receiver: Controller = "invalid_receiver".to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id,
            invalid_receiver,
            expected_coins,
        )
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Controller format error: invalid_receiver",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_create_escrow_duplicate_id() {
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
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Create an escrow
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver.clone(),
            expected_coins.clone(),
        )
        .call(&owner)
        .expect("error creating escrow");

    // Attempt to create another escrow with the same ID
    let res = escrow_contract
        .create_escrow("escrow1".to_string(), operator_id, receiver, expected_coins)
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Escrow already exists", res.err().unwrap().to_string());
}

#[test]
fn test_create_escrow_with_disabled_operator() {
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
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Disable the operator
    escrow_contract
        .disable_operator(operator_id.clone())
        .call(&owner)
        .expect("error disabling operator");

    // Attempt to create an escrow with the disabled operator
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver,
            expected_coins,
        )
        .call(&owner);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        format!("Escrow operator disabled: {}", operator_id),
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_create_escrow_unauthorized() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let unauthorized_user = "unauthorized_user".into_addr();

    // Instantiate contracts
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(
            vec![owner.clone()],
            did_contract.contract_addr.clone(),
            60000,
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to create an escrow with an unauthorized user
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver,
            expected_coins,
        )
        .call(&unauthorized_user);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_create_escrow_no_coins() {
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
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to create an escrow with no coins
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let no_coins = vec![];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver,
            no_coins,
        )
        .call(&owner);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("No coins", res.err().unwrap().to_string());
}

#[test]
fn test_create_escrow_with_zero_value_coins() {
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
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to create an escrow with coins that have zero value
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let zero_value_coins = vec![Coin::new(0u128, "uc4e")];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver,
            zero_value_coins,
        )
        .call(&owner);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("No coins", res.err().unwrap().to_string());
}

#[test]
fn test_create_escrow_with_duplicated_coins() {
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
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Add an operator
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Attempt to create an escrow with duplicated coins
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let duplicated_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(1000u128, "uc4e")];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver.clone(),
            duplicated_coins.clone(),
        )
        .call(&owner)
        .expect("error creating escrow");

    // Validate the response events
    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_create");
    assert_eq!(res.events[1].attributes.len(), 5);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");
    assert_eq!(res.events[1].attributes[2].key, "operator_id");
    assert_eq!(res.events[1].attributes[2].value, operator_id);
    assert_eq!(res.events[1].attributes[3].key, "receiver");
    assert_eq!(res.events[1].attributes[3].value, receiver);
    assert_eq!(res.events[1].attributes[4].key, "expected_coins");
    let dedupl_expected_coins = Coins::deduplicated_coins(duplicated_coins.clone()).unwrap();
    assert_eq!(
        res.events[1].attributes[4].value,
        dedupl_expected_coins.to_string()
    );

    // Verify the escrow is created
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");
    assert_eq!(escrow.id, "escrow1");
    assert_eq!(escrow.operator_id, operator_id);
    assert_eq!(escrow.receiver, receiver);
    assert_eq!(escrow.expected_coins, dedupl_expected_coins.into_vec());
    assert_eq!(escrow.state, EscrowState::Loading);
}

#[test]
fn test_create_escrow_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> =
        did_code_id.instantiate().call(&owner).unwrap();
    let escrow_contract = escrow_code_id
        .instantiate(
            vec![owner.clone()],
            did_contract.contract_addr,
            60000,
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    let op_controller_addr = "operatr_controller".into_addr();

    let op_controller: Controller = op_controller_addr.to_string().into();

    escrow_contract
        .create_operator("operator1".to_string(), vec![op_controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    let coin = Coin {
        denom: "uatom".to_string(),
        amount: 1000u128.into(),
    };

    let receiver: Controller = "controller1".into_addr().to_string().into();
    let expected_coins = vec![coin];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            "operator1".to_string(),
            receiver.clone(),
            expected_coins.clone(),
            // receiver_share,
        )
        .call(&op_controller_addr)
        .expect("error creating escrow");

    // Verify escrow creation success attributes
    assert_eq!(res.events[0].ty, "execute");
    // assert_eq!(res.events[1].ty, "wasm");
    // assert_eq!(res.events[1].attributes[1].key, "action");
    // assert_eq!(res.events[1].attributes[1].value, "create_escrow");

    // // Query to verify the escrow has been created correctly
    // let escrow = escrow_contract.escrows().query("escrow1").expect("query error");
    // assert_eq!(escrow.expected_coins[0].denom, "uatom");
    // assert_eq!(escrow.expected_coins[0].amount, Uint128::new(1000));
    // assert_eq!(escrow.receiver_share, Decimal::percent(50));
    // assert_eq!(escrow.state, EscrowState::Loading);

    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("getting escrow error");
    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: "operator1".to_string(),
            expected_coins: expected_coins.clone(),
            loaded_coins: None,
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: vec![],
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: vec![],
            state: EscrowState::Loading,
            lock_timestamp: None,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    )
}

#[test]
fn test_create_escrow_operator_does_not_exist() {
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
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    // Attempt to create an escrow with a non-existent operator
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    let res = escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            "non_existent_operator".to_string(),
            receiver,
            expected_coins,
        )
        .call(&owner);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator does not exist", res.err().unwrap().to_string());
}

#[test]
fn create_escrow_no_operator() {
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
            did_contract.contract_addr,
            60000,
            5 * 24 * 3600 * 1000,
        )
        .call(&owner)
        .unwrap();

    let operator = "operator-1";
    let escrow = "escrow-1";
    let receiver = "receiver-1".into_addr().to_string();
    let expected_coins = vec![Coin::new(123u64, "uc4e")];
    // let share = Decimal::from_str("0.34").expect("error parsing decimale");
    let result = escrow_contract
        .create_escrow(
            escrow.to_string(),
            operator.to_string(),
            receiver.into(),
            expected_coins,
        )
        .call(&owner);
    assert!(result.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator does not exist", result.err().unwrap().to_string());
}
