use cosmwasm_std::{BlockInfo, Coin, Coins, Timestamp};
use cw_multi_test::IntoAddr;
use sylvia::multitest::App;

use did_contract::{
    contract::{sv::mt::CodeId as DidContractCodeId, DidContract},
    state::Controller,
};

use crate::{
    contract::sv::mt::{CodeId, EscrowContractProxy},
    state::{CoinsExt, Escrow, EscrowState, LoadedCoins},
};

#[test]
fn test_release_escrow_success_by_admin() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&owner)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

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
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_by_operator_none_consumed() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![];
    let operator_fee = vec![];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

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
            operator_claimed: true,
            receiver: receiver,
            receiver_claimed: true,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: used_coins.clone(),
            state: EscrowState::Released,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_by_operator_all_consumed() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

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
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_by_operator_all_consumed_used_only() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

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
            operator_claimed: true,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: true,
            used_coins: used_coins.clone(),
            state: EscrowState::Released,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_by_operator_all_consumed_fee_only() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![Coin::new(1000u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

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
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_by_operator_partial_consumed() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(800u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

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
            loader_claimed: false,
            used_coins: used_coins.clone(),
            state: EscrowState::Released,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_by_operator_partial_consumed_used_only() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(800u128, "uc4e")];
    let operator_fee = vec![];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

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
            operator_claimed: true,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: used_coins.clone(),
            state: EscrowState::Released,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_by_operator_partial_consumed_fee_only() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(800u128, "uc4e")];
    let operator_fee = vec![Coin::new(800u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

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
            loader_claimed: false,
            used_coins: used_coins.clone(),
            state: EscrowState::Released,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

// ---

#[test]
fn test_release_escrow_success_by_operator_all_consumed_many_denoms() {
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
        denom: "mc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin, loader_coin2],
                },
            ))
            .expect("error sudo");
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
    let expected_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(1000u128, "mc4e")];

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(1000u128, "mc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e"), Coin::new(300u128, "mc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

    // Verify the escrow is updated
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");

    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id,
            expected_coins: vec![expected_coins[1].clone(), expected_coins[0].clone()],
            loaded_coins: Some(LoadedCoins {
                coins: vec![expected_coins[1].clone(), expected_coins[0].clone()],
                loader: loader.to_string(),
            }),
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: vec![operator_fee[1].clone(), operator_fee[0].clone()],
            // receiver_share: receiver_share,
            loader_claimed: true,
            used_coins: vec![used_coins[1].clone(), used_coins[0].clone()],
            state: EscrowState::Released,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_by_operator_all_consumed_many_denoms_only_fee_or_used_per_denom() {
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
        denom: "mc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin, loader_coin2],
                },
            ))
            .expect("error sudo");
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
    let expected_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(1000u128, "mc4e")];

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(1000u128, "mc4e")];
    let operator_fee = vec![Coin::new(1000u128, "mc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

    // Verify the escrow is updated
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");

    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id,
            expected_coins: vec![expected_coins[1].clone(), expected_coins[0].clone()],
            loaded_coins: Some(LoadedCoins {
                coins: vec![expected_coins[1].clone(), expected_coins[0].clone()],
                loader: loader.to_string(),
            }),
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: operator_fee.clone(),
            // receiver_share: receiver_share,
            loader_claimed: true,
            used_coins: vec![used_coins[1].clone(), used_coins[0].clone()],
            state: EscrowState::Released,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_by_operator_partially_consumed_many_denoms() {
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
        denom: "mc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin, loader_coin2],
                },
            ))
            .expect("error sudo");
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
    let expected_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(1000u128, "mc4e")];

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(900u128, "uc4e"), Coin::new(600u128, "mc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e"), Coin::new(300u128, "mc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

    // Verify the escrow is updated
    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("error querying escrow");

    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id,
            expected_coins: vec![expected_coins[1].clone(), expected_coins[0].clone()],
            loaded_coins: Some(LoadedCoins {
                coins: vec![expected_coins[1].clone(), expected_coins[0].clone()],
                loader: loader.to_string(),
            }),
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            operator_fee: vec![operator_fee[1].clone(), operator_fee[0].clone()],
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: vec![used_coins[1].clone(), used_coins[0].clone()],
            state: EscrowState::Released,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_not_found() {
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

    // Attempt to release a non-existent escrow
    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow("non_existent_escrow".to_string(), used_coins, operator_fee)
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Escrow not found: non_existent_escrow",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_release_escrow_invalid_state() {
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

    // Attempt to release the escrow without loading it
    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow("escrow1".to_string(), used_coins, operator_fee)
        .call(&controller_addr);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Escrow wrong state: expected locked, but got loading",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_release_escrow_unauthorized() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Attempt to release the escrow by an unauthorized user
    let unauthorized_user = "unauthorized_user".into_addr();

    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow("escrow1".to_string(), used_coins, operator_fee)
        .call(&unauthorized_user);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_release_escrow_success_by_disabled_operator() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Disable the operator
    escrow_contract
        .disable_operator(operator_id.clone())
        .call(&owner)
        .expect("error disabling operator");

    // Release the escrow
    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

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
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_by_non_existent_operator() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Disable the operator
    escrow_contract
        .remove_operator(operator_id.clone())
        .call(&owner)
        .expect("error disabling operator");

    // Release the escrow
    let used_coins = vec![Coin::new(900u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Unauthorized", res.err().unwrap().to_string());
}

#[test]
fn test_release_escrow_success_by_admin_when_operator_not_exists() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Remove the operator
    escrow_contract
        .remove_operator(operator_id.clone())
        .call(&owner)
        .expect("error removing operator");

    // Release the escrow
    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&owner)
        .expect("error releasing escrow");

    // Validate the response events

    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_release");
    assert_eq!(res.events[1].attributes.len(), 4);
    assert_eq!(res.events[1].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[1].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );
    assert_eq!(res.events[1].attributes[1].key, "escrow_id");
    assert_eq!(res.events[1].attributes[1].value, "escrow1");

    assert_eq!(res.events[1].attributes[2].key, "used_coins");
    assert_eq!(
        res.events[1].attributes[2].value,
        Coins::deduplicated_coins(used_coins.clone())
            .unwrap()
            .to_string()
    );
    assert_eq!(res.events[1].attributes[3].key, "operator_fee");
    assert_eq!(
        res.events[1].attributes[3].value,
        Coins::deduplicated_coins(operator_fee.clone())
            .unwrap()
            .to_string()
    );

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
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_release_timeout() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow

    let ts3 = ts2.plus_seconds(5 * 24 * 3600 * 1000);
    app.set_block(BlockInfo {
        height: 130,
        time: ts3,
        chain_id: "c4e-1".to_string(),
    });

    let used_coins = vec![Coin::new(900u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Escrow has expired: escrow releasing",
        res.err().unwrap().to_string()
    );

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
            operator_fee: vec![],
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: vec![],
            state: EscrowState::FailedReleaseTimeout,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_release_escrow_success_by_operator_unknown_denom_used_coins() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(900u128, "zc4e")];
    let operator_fee = vec![];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Coins not match: used coins are more than expected: expected 1000uc4e, got 900zc4e",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_release_escrow_success_by_operator_unknown_denom_fee_coins() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(900u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "zc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Coins not match: operator fee coins are more than used: expected 900uc4e, got 100zc4e",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_release_escrow_success_by_operator_known_denom_too_much() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(1001u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Coins not match: used coins are more than expected: expected 1000uc4e, got 1001uc4e",
        res.err().unwrap().to_string()
    );
}


#[test]
fn test_release_escrow_success_by_operator_known_denom_fee_too_much() {
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
                    amount: vec![loader_coin],
                },
            ))
            .expect("error sudo");
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

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(100u128, "uc4e")];
    let operator_fee = vec![Coin::new(101u128, "uc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Coins not match: operator fee coins are more than used: expected 100uc4e, got 101uc4e",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_release_escrow_success_by_operator_many_denoms_too_much() {
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
        denom: "mc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin, loader_coin2],
                },
            ))
            .expect("error sudo");
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
    let expected_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(1000u128, "mc4e")];

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(900u128, "uc4e"), Coin::new(1001u128, "mc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e"), Coin::new(300u128, "mc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Coins not match: used coins are more than expected: expected 1000mc4e,1000uc4e, got 1001mc4e,900uc4e",
        res.err().unwrap().to_string()
    );
}


#[test]
fn test_release_escrow_success_by_operator_many_denoms_fee_too_much() {
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
        denom: "mc4e".to_string(),
        amount: 10000u128.into(),
    };
    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin, loader_coin2],
                },
            ))
            .expect("error sudo");
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
    let expected_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(1000u128, "mc4e")];

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });

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
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Release the escrow
    let used_coins = vec![Coin::new(900u128, "uc4e"), Coin::new(1000u128, "mc4e")];
    let operator_fee = vec![Coin::new(901u128, "uc4e"), Coin::new(300u128, "mc4e")];
    let res = escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&controller_addr);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Coins not match: operator fee coins are more than used: expected 1000mc4e,900uc4e, got 300mc4e,901uc4e",
        res.err().unwrap().to_string()
    );
}


#[test]
fn test_release() {
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

    let receiver: Controller = "controller1".into_addr().to_string().into();
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

    let escrow = escrow_contract
        .get_escrow("escrow1".to_string())
        .expect("getting escrow error");
    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: "operator1".to_string(),
            expected_coins: expected_coins.clone(),
            loaded_coins: Some(LoadedCoins {
                loader: loader.to_string(),
                coins: expected_coins.clone()
            }),
            operator_claimed: false,
            receiver: receiver.clone(),
            receiver_claimed: false,
            operator_fee: vec![operator_fee],
            // receiver_share: Decimal::percent(50),
            loader_claimed: false,
            used_coins: vec![rel_coin.clone()],
            state: EscrowState::Released,
            lock_timestamp: escrow.lock_timestamp,
            create_timestamp: escrow.create_timestamp
        },
        escrow
    );

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
}