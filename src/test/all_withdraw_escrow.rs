use cosmwasm_std::Coin;
use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use did_contract::{
    contract::{sv::mt::CodeId as DidContractCodeId, DidContract},
    state::Controller,
};

use crate::{
    contract::sv::mt::{CodeId, EscrowContractProxy},
    state::{Escrow, EscrowState, LoadedCoins},
};

#[test]
fn test_withdraw_wrong_state() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let loader = "loader".into_addr();

    let loader_coin = Coin {
        denom: "uc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin.clone()],
                },
            ))
            .expect("error minting coins");
    }

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

    // Add an operator and create an escrow
    let controller_addr = "controller1".into_addr();
    let controller: Controller = controller_addr.to_string().into();
    let operator_id = "operator1".to_string();
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver.clone(),
            expected_coins.clone(),
        )
        .call(&controller_addr)
        .expect("error creating escrow");

    // Withdraw by the loader
    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Escrow wrong state: expected released, but got loading",
        res.err().unwrap().to_string()
    );

    // Load the escrow
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Withdraw by the loader
    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Escrow wrong state: expected released, but got locked",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_withdraw_unauthorized() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let loader = "loader".into_addr();

    let loader_coin = Coin {
        denom: "uc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin.clone()],
                },
            ))
            .expect("error minting coins");
    }

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

    // Add an operator and create an escrow
    let controller_addr = "controller1".into_addr();
    let controller: Controller = controller_addr.to_string().into();
    let operator_id = "operator1".to_string();
    let receiver: Controller = "receiver1".into_addr().to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver.clone(),
            expected_coins.clone(),
        )
        .call(&controller_addr)
        .expect("error creating escrow");

    // Load the escrow
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![];
    let operator_fee = vec![];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Withdraw by the loader
    let unauth = "unauth".into_addr();

    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&unauth);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_withdraw_all_at_once_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let loader = "loader".into_addr();

    let loader_coin = Coin {
        denom: "uc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin.clone()],
                },
            ))
            .expect("error minting coins");
    }

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

    // Add an operator and create an escrow
    // let controller_addr = "controller1".into_addr();
    let controller: Controller = loader.to_string().into();
    let operator_id = "operator1".to_string();
    let receiver: Controller = loader.to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver.clone(),
            expected_coins.clone(),
        )
        .call(&loader)
        .expect("error creating escrow");

    // Load the escrow
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(500u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&loader)
        .expect("error releasing escrow");

    // Withdraw by the loader
    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader)
        .expect("error withdrawing by loader");

    // Validate the response events
    assert_eq!(res.events.len(), 7);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_withdraw_loader");
    assert_eq!(res.events[1].attributes.len(), 3);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");
    assert_eq!(res.events[1].attributes[2].key, "amount");
    assert_eq!(res.events[1].attributes[2].value, "500uc4e");

    assert_eq!(res.events[2].ty, "wasm-escrow_withdraw_receiver");
    assert_eq!(res.events[2].attributes.len(), 3);
    assert_eq!(res.events[2].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[2].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[2].attributes[1].key, "escrow_id");
    assert_eq!(res.events[2].attributes[1].value, "escrow1");
    assert_eq!(res.events[2].attributes[2].key, "amount");
    assert_eq!(res.events[2].attributes[2].value, "400uc4e");

    assert_eq!(res.events[3].ty, "wasm-escrow_withdraw_operator");
    assert_eq!(res.events[3].attributes.len(), 3);
    assert_eq!(res.events[3].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[3].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[3].attributes[1].key, "escrow_id");
    assert_eq!(res.events[3].attributes[1].value, "escrow1");
    assert_eq!(res.events[3].attributes[2].key, "amount");
    assert_eq!(res.events[3].attributes[2].value, "100uc4e");

    assert_eq!(res.events[4].ty, "transfer");
    assert_eq!(res.events[4].attributes.len(), 3);
    assert_eq!(res.events[4].attributes[0].key, "recipient");
    assert_eq!(res.events[4].attributes[0].value, receiver.to_string(),);
    assert_eq!(res.events[4].attributes[1].key, "sender");
    assert_eq!(
        res.events[4].attributes[1].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[4].attributes[2].key, "amount");
    assert_eq!(res.events[4].attributes[2].value, "500uc4e".to_string());

    assert_eq!(res.events[5].ty, "transfer");
    assert_eq!(res.events[5].attributes.len(), 3);
    assert_eq!(res.events[5].attributes[0].key, "recipient");
    assert_eq!(res.events[5].attributes[0].value, receiver.to_string(),);
    assert_eq!(res.events[5].attributes[1].key, "sender");
    assert_eq!(
        res.events[5].attributes[1].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[5].attributes[2].key, "amount");
    assert_eq!(res.events[5].attributes[2].value, "400uc4e".to_string());

    assert_eq!(res.events[6].ty, "transfer");
    assert_eq!(res.events[6].attributes.len(), 3);
    assert_eq!(res.events[6].attributes[0].key, "recipient");
    assert_eq!(res.events[6].attributes[0].value, receiver.to_string(),);
    assert_eq!(res.events[6].attributes[1].key, "sender");
    assert_eq!(
        res.events[6].attributes[1].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[6].attributes[2].key, "amount");
    assert_eq!(res.events[6].attributes[2].value, "100uc4e".to_string());

    // Verify the escrow state
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");
    assert_eq!(escrow.state, EscrowState::Closed);

    // Verify the escrow is updated
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");

    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id,
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                coins: expected_coins.clone(),
                loader: loader,
            }),
            operator_claimed: true,
            receiver: receiver,
            receiver_claimed: true,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: true,
            used_coins: used_coins.clone(),
            state: EscrowState::Closed,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    )
}

#[test]
fn test_withdraw_all_sequence() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let loader = "loader".into_addr();

    let loader_coin = Coin {
        denom: "uc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin.clone()],
                },
            ))
            .expect("error minting coins");
    }

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

    // Add an operator and create an escrow
    let controller_addr = "controller1".into_addr();
    let controller: Controller = controller_addr.to_string().into();
    let operator_id = "operator1".to_string();
    let receiver_addr = "receiver1".into_addr();
    let receiver: Controller = receiver_addr.to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver.clone(),
            expected_coins.clone(),
        )
        .call(&controller_addr)
        .expect("error creating escrow");

    // Load the escrow
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(500u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Withdraw by the loader
    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&receiver_addr)
        .expect("error withdrawing by loader");

    // Validate the response events
    assert_eq!(res.events.len(), 3);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_withdraw_receiver");
    assert_eq!(res.events[1].attributes.len(), 3);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");
    assert_eq!(res.events[1].attributes[2].key, "amount");
    assert_eq!(res.events[1].attributes[2].value, "400uc4e");

    assert_eq!(res.events[2].ty, "transfer");
    assert_eq!(res.events[2].attributes.len(), 3);
    assert_eq!(res.events[2].attributes[0].key, "recipient");
    assert_eq!(res.events[2].attributes[0].value, receiver.to_string(),);
    assert_eq!(res.events[2].attributes[1].key, "sender");
    assert_eq!(
        res.events[2].attributes[1].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[2].attributes[2].key, "amount");
    assert_eq!(res.events[2].attributes[2].value, "400uc4e".to_string());

    // Verify the escrow state
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");
    assert!(escrow.receiver_claimed);
    assert_eq!(escrow.state, EscrowState::Released);

    // Verify the escrow is updated
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");

    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id.clone(),
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                coins: expected_coins.clone(),
                loader: loader.clone(),
            }),
            operator_claimed: false,
            receiver: receiver.clone(),
            receiver_claimed: true,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: used_coins.clone(),
            state: EscrowState::Released,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    );

    // Withdraw by the loader
    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader)
        .expect("error withdrawing by loader");

    // Validate the response events
    assert_eq!(res.events.len(), 3);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_withdraw_loader");
    assert_eq!(res.events[1].attributes.len(), 3);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");
    assert_eq!(res.events[1].attributes[2].key, "amount");
    assert_eq!(res.events[1].attributes[2].value, "500uc4e");

    assert_eq!(res.events[2].ty, "transfer");
    assert_eq!(res.events[2].attributes.len(), 3);
    assert_eq!(res.events[2].attributes[0].key, "recipient");
    assert_eq!(res.events[2].attributes[0].value, loader.to_string(),);
    assert_eq!(res.events[2].attributes[1].key, "sender");
    assert_eq!(
        res.events[2].attributes[1].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[2].attributes[2].key, "amount");
    assert_eq!(res.events[2].attributes[2].value, "500uc4e".to_string());

    // Verify the escrow state
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");
    assert!(escrow.loader_claimed);
    assert_eq!(escrow.state, EscrowState::Released);

    // Verify the escrow is updated
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");

    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id.clone(),
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                coins: expected_coins.clone(),
                loader: loader.clone(),
            }),
            operator_claimed: false,
            receiver: receiver.clone(),
            receiver_claimed: true,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: true,
            used_coins: used_coins.clone(),
            state: EscrowState::Released,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    );

    // Withdraw by the operator
    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&controller_addr)
        .expect("error withdrawing by loader");

    // Validate the response events
    assert_eq!(res.events.len(), 3);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_withdraw_operator");
    assert_eq!(res.events[1].attributes.len(), 3);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");
    assert_eq!(res.events[1].attributes[2].key, "amount");
    assert_eq!(res.events[1].attributes[2].value, "100uc4e");

    assert_eq!(res.events[2].ty, "transfer");
    assert_eq!(res.events[2].attributes.len(), 3);
    assert_eq!(res.events[2].attributes[0].key, "recipient");
    assert_eq!(
        res.events[2].attributes[0].value,
        controller_addr.to_string(),
    );
    assert_eq!(res.events[2].attributes[1].key, "sender");
    assert_eq!(
        res.events[2].attributes[1].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[2].attributes[2].key, "amount");
    assert_eq!(res.events[2].attributes[2].value, "100uc4e".to_string());

    // Verify the escrow state
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");
    assert!(escrow.operator_claimed);
    assert_eq!(escrow.state, EscrowState::Closed);

    // Verify the escrow is updated
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");

    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id,
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                coins: expected_coins.clone(),
                loader: loader,
            }),
            operator_claimed: true,
            receiver: receiver,
            receiver_claimed: true,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: true,
            used_coins: used_coins.clone(),
            state: EscrowState::Closed,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    )
}

#[test]
fn test_withdraw_all_already_withdrawn() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let loader = "loader".into_addr();

    let loader_coin = Coin {
        denom: "uc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin.clone()],
                },
            ))
            .expect("error minting coins");
    }

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

    // Add an operator and create an escrow
    let controller_addr = "controller1".into_addr();
    let controller: Controller = controller_addr.to_string().into();
    let operator_id = "operator1".to_string();
    let receiver_addr = "receiver1".into_addr();
    let receiver: Controller = receiver_addr.to_string().into();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            operator_id.clone(),
            receiver.clone(),
            expected_coins.clone(),
        )
        .call(&controller_addr)
        .expect("error creating escrow");

    // Load the escrow
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(500u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Withdraw by the receiver
    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&receiver_addr)
        .expect("error withdrawing by loader");

    // Withdraw by the loader
    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader)
        .expect("error withdrawing by loader");

    // Withdraw by the operator
    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&controller_addr)
        .expect("error withdrawing by loader");

    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader);
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Escrow already withdrawn", res.err().unwrap().to_string());

    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&receiver_addr);
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Escrow already withdrawn", res.err().unwrap().to_string());

    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&controller_addr);
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Escrow already withdrawn", res.err().unwrap().to_string());
}

#[test]
fn test_withdraw() {
    let app: App<cw_multi_test::App> = App::default();

    let loader = "loader".into_addr();
    let loader_coin = Coin {
        denom: "uatom".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
    }
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

    let receiver_addr = "controller1".into_addr();
    let receiver: Controller = receiver_addr.to_string().into();
    let coin = Coin {
        denom: "uatom".to_string(),
        amount: 1000u128.into(),
    };

    let expected_coins = vec![coin.clone()];
    escrow_contract
        .create_escrow(
            "escrow1".to_string(),
            "operator1".to_string(),
            receiver.clone(),
            expected_coins.clone(),
            // Decimal::percent(50),
        )
        .call(&op_controller_addr)
        .expect("error creating escrow");

    // Attempt to load
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("load_escrow error");

    let contract_coin = app
        .querier()
        .query_balance(&escrow_contract.contract_addr, &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(coin, contract_coin);

    // Attempt to release coins
    let rel_coin = Coin {
        denom: "uatom".to_string(),
        amount: 500u128.into(),
    };

    let operator_fee = Coin {
        denom: "uatom".to_string(),
        amount: 250u128.into(),
    };

    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            vec![rel_coin.clone()],
            vec![operator_fee.clone()],
        )
        .call(&op_controller_addr)
        .expect("load_escrow error");

    let contract_coin = app
        .querier()
        .query_balance(&escrow_contract.contract_addr, &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(coin, contract_coin);
    let contract_coin = app
        .querier()
        .query_balance(&loader, &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 9000u128.into()
        },
        contract_coin
    );

    let contract_coin = app
        .querier()
        .query_balance(receiver.to_string(), &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 0u128.into()
        },
        contract_coin
    );

    let contract_coin = app
        .querier()
        .query_balance(op_controller.to_string(), &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 0u128.into()
        },
        contract_coin
    );

    // ---- Withdraw loader --

    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader)
        .expect("withdraw loader error");

    let contract_coin = app
        .querier()
        .query_balance(&escrow_contract.contract_addr, &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 500u128.into()
        },
        contract_coin
    );
    let contract_coin = app
        .querier()
        .query_balance(&loader, &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 9500u128.into()
        },
        contract_coin
    );

    let contract_coin = app
        .querier()
        .query_balance(receiver.to_string(), &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 0u128.into()
        },
        contract_coin
    );

    let contract_coin = app
        .querier()
        .query_balance(op_controller.to_string(), &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 0u128.into()
        },
        contract_coin
    );

    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("getting escrow error");
    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: "operator1".to_string(),
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                loader: loader.clone(),
                coins: expected_coins.clone()
            }),
            operator_claimed: false,
            receiver: receiver.clone(),
            receiver_claimed: false,
            operator_fee: vec![operator_fee.clone()],
            // receiver_share: Decimal::percent(50),
            loader_claimed: true,
            used_coins: vec![rel_coin.clone()],
            state: EscrowState::Released,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp,
        },
        escrow
    );

    // ---- Withdraw oparator --

    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&op_controller_addr)
        .expect("withdraw loader error");

    let contract_coin = app
        .querier()
        .query_balance(&escrow_contract.contract_addr, &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 250u128.into()
        },
        contract_coin
    );
    let contract_coin = app
        .querier()
        .query_balance(&loader, &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 9500u128.into()
        },
        contract_coin
    );

    let contract_coin = app
        .querier()
        .query_balance(receiver.to_string(), &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 0u128.into()
        },
        contract_coin
    );

    let contract_coin = app
        .querier()
        .query_balance(op_controller.to_string(), &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 250u128.into()
        },
        contract_coin
    );

    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("getting escrow error");
    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: "operator1".to_string(),
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                loader: loader.clone(),
                coins: expected_coins.clone()
            }),
            operator_claimed: true,
            receiver: receiver.clone(),
            receiver_claimed: false,
            operator_fee: vec![operator_fee.clone()],
            // receiver_share: Decimal::percent(50),
            loader_claimed: true,
            used_coins: vec![rel_coin.clone()],
            state: EscrowState::Released,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    );

    // ---- Withdraw receiver --

    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&receiver_addr)
        .expect("withdraw loader error");

    let contract_coin = app
        .querier()
        .query_balance(&escrow_contract.contract_addr, &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 0u128.into()
        },
        contract_coin
    );
    let contract_coin = app
        .querier()
        .query_balance(&loader, &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 9500u128.into()
        },
        contract_coin
    );

    let contract_coin = app
        .querier()
        .query_balance(receiver.to_string(), &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 250u128.into()
        },
        contract_coin
    );

    let contract_coin = app
        .querier()
        .query_balance(op_controller.to_string(), &coin.denom)
        .expect("error taking cntract coins");
    assert_eq!(
        Coin {
            denom: "uatom".to_string(),
            amount: 250u128.into()
        },
        contract_coin
    );

    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("getting escrow error");
    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: "operator1".to_string(),
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                loader: loader,
                coins: expected_coins.clone()
            }),
            operator_claimed: true,
            receiver: receiver.clone(),
            receiver_claimed: true,
            operator_fee: vec![operator_fee],
            // receiver_share: Decimal::percent(50),
            loader_claimed: true,
            used_coins: vec![rel_coin.clone()],
            state: EscrowState::Closed,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    );
}
