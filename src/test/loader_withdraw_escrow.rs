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
fn test_withdraw_loader_success() {
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
            operator_id: operator_id,
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                coins: expected_coins.clone(),
                loader: loader.to_string(),
            }),
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: true,
            used_coins: used_coins.clone(),
            state: EscrowState::Released,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    )
}

#[test]
fn test_withdraw_loader_success_many_denoms() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let loader = "loader".into_addr();

    let loader_coin = Coin {
        denom: "uc4e".to_string(),
        amount: 10000u128.into(),
    };
    let loader_coin2 = Coin {
        denom: "zc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin.clone(), loader_coin2.clone()],
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
    let expected_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(1000u128, "zc4e")];

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
    let used_coins = vec![Coin::new(500u128, "uc4e") ,Coin::new(500u128, "zc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e"),Coin::new(100u128, "zc4e")];
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
    assert_eq!(res.events[1].attributes[2].value, "500uc4e,500zc4e");

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
    assert_eq!(res.events[2].attributes[2].value, "500uc4e,500zc4e".to_string());

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
            operator_id: operator_id,
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                coins: expected_coins.clone(),
                loader: loader.to_string(),
            }),
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: true,
            used_coins: used_coins.clone(),
            state: EscrowState::Released,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    )
}


#[test]
fn test_withdraw_loader_by_admin_success() {
    let app = App::default();
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let admin = "admin".into_addr();
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
            vec![admin.clone()],
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
        .call(&admin)
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
        .call(&admin)
        .expect("error withdrawing by admin");

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
            operator_id: operator_id,
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                coins: expected_coins.clone(),
                loader: loader.to_string(),
            }),
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: true,
            used_coins: used_coins.clone(),
            state: EscrowState::Released,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    )
}

#[test]
fn test_withdraw_loader_success_already_withdrawn() {
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
    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader)
        .expect("error withdrawing by loader");

    let res = escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader);
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Escrow already withdrawn", res.err().unwrap().to_string());
}

#[test]
fn test_withdraw_loader_success_all_used() {
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
    let used_coins = vec![Coin::new(1000u128, "uc4e")];
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
        .call(&loader);
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Escrow already withdrawn", res.err().unwrap().to_string());
}
