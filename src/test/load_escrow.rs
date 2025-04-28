use core::time;

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
fn test_load_escrow_success() {
    let app = App::default();
    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });
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
        let a = app_mut
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
        )
        .call(&owner)
        .unwrap();

    // Add an operator and create an escrow
    let controller: Controller = "controller1".into_addr().to_string().into();
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
        .call(&owner)
        .expect("error creating escrow");
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });
    // Load the escrow
    let res = escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Validate the response events
    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_load");
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
    assert_eq!(res.events[1].attributes[3].key, "loader");
    assert_eq!(res.events[1].attributes[3].value, loader.to_string());
    assert_eq!(res.events[1].attributes[4].key, "coins");
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
    assert_eq!(escrow.state, EscrowState::Locked);

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
            state: EscrowState::Locked,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}


#[test]
fn test_load_escrow_success_many_denoms() {
    let app = App::default();
    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let loader = "loader".into_addr();

    let expected_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(1000u128, "mc4e")];

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
        let a = app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: vec![loader_coin.clone(), loader_coin2.clone()],
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
        )
        .call(&owner)
        .unwrap();

    // Add an operator and create an escrow
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();
    let receiver: Controller = "receiver1".into_addr().to_string().into();

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
        .call(&owner)
        .expect("error creating escrow");
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });
    // Load the escrow
    let res = escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Validate the response events
    assert_eq!(res.events.len(), 2);

    assert_eq!(res.events[0].ty, "execute");
    assert_eq!(res.events[0].attributes[0].key, "_contract_address");
    assert_eq!(
        res.events[0].attributes[0].value,
        escrow_contract.contract_addr.to_string()
    );

    assert_eq!(res.events[1].ty, "wasm-escrow_load");
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
    assert_eq!(res.events[1].attributes[3].key, "loader");
    assert_eq!(res.events[1].attributes[3].value, loader.to_string());
    assert_eq!(res.events[1].attributes[4].key, "coins");
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
    assert_eq!(escrow.expected_coins.len(), expected_coins.len());
    
    assert_eq!(escrow.expected_coins, vec![expected_coins[1].clone(), expected_coins[0].clone()]);  
    assert_eq!(escrow.state, EscrowState::Locked);

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
            operator_fee: vec![],
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: vec![],
            state: EscrowState::Locked,
            lock_timestamp: Some(ts2),
            create_timestamp: ts1
        },
        escrow
    )
}

#[test]
fn test_load_escrow_not_found() {
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

    // Attempt to load a non-existent escrow
    let res = escrow_contract
        .load_escrow("non_existent_escrow".to_string())
        .call(&owner);

    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Escrow not found: non_existent_escrow",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_load_escrow_operator_does_not_exist() {
    let app = App::default();
    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });
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
        let a = app_mut
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
        )
        .call(&owner)
        .unwrap();

    // Add an operator and create an escrow
    let controller: Controller = "controller1".into_addr().to_string().into();
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
        .call(&owner)
        .expect("error creating escrow");
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    escrow_contract
        .remove_operator(operator_id.clone())
        .call(&owner)
        .expect("error creating operator");

    // Load the escrow
    let res = escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Operator does not exist", res.err().unwrap().to_string());
}

#[test]
fn test_load_escrow_invalid_state() {
    let app = App::default();
    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });
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
        let a = app_mut
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
        )
        .call(&owner)
        .unwrap();

    // Add an operator and create an escrow
    let controller: Controller = "controller1".into_addr().to_string().into();
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
        .call(&owner)
        .expect("error creating escrow");
    let ts2: Timestamp = Timestamp::from_seconds(12364);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });
    // Load the escrow
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader)
        .expect("error loading escrow");

    let res = escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader);
    // Attempt to load the escrow
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Escrow wrong state: expected loading, but got locked",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_load_escrow_operator_disabled() {
    let app = App::default();
    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });
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
        )
        .call(&owner)
        .unwrap();

    // Add an operator and create an escrow
    let controller: Controller = "controller1".into_addr().to_string().into();
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
        .call(&owner)
        .expect("error creating escrow");

    // Disable the operator
    escrow_contract
        .disable_operator(operator_id.clone())
        .call(&owner)
        .expect("error disabling operator");

    // Attempt to load the escrow
    let res = escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        format!("Escrow operator disabled: {}", operator_id),
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_load_escrow_timeout_exceeded() {
    let app = App::default();
    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });
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
        )
        .call(&owner)
        .unwrap();

    // Add an operator and create an escrow
    let controller: Controller = "controller1".into_addr().to_string().into();
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
        .call(&owner)
        .expect("error creating escrow");

    // Simulate time passing beyond the loading timeout
    let ts2: Timestamp = Timestamp::from_seconds(12400); // Exceeds the timeout

    let ts2 = ts1.plus_seconds(60);
    app.set_block(BlockInfo {
        height: 13,
        time: ts2.clone(),
        chain_id: "c4e-1".to_string(),
    });

    // Attempt to load the escrow
    let res = escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(expected_coins.as_slice())
        .call(&loader);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!("Escrow has expired", res.err().unwrap().to_string());
}

#[test]
fn test_load_escrow_insufficient_funds() {
    let app = App::default();
    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let loader = "loader".into_addr();
    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: expected_coins.clone(),
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
        )
        .call(&owner)
        .unwrap();

    // Add an operator and create an escrow
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();
    let receiver: Controller = "receiver1".into_addr().to_string().into();

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
        .call(&owner)
        .expect("error creating escrow");

    let loader_coins = vec![Coin::new(999u128, "uc4e")];

    // Attempt to load the escrow with insufficient funds
    let res = escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(loader_coins.as_slice())
        .call(&loader);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Coins not match: expected 1000uc4e != got 999uc4e",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_load_escrow_wrong_denom_funds() {
    let app = App::default();
    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let loader = "loader".into_addr();
    let loader_account_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(10000u128, "mc4e")];

    let expected_coins = vec![Coin::new(1000u128, "uc4e")];

    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: loader_account_coins,
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
        )
        .call(&owner)
        .unwrap();

    // Add an operator and create an escrow
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();
    let receiver: Controller = "receiver1".into_addr().to_string().into();

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
        .call(&owner)
        .expect("error creating escrow");

    let loader_coins = vec![Coin::new(10000u128, "mc4e")];

    // Attempt to load the escrow with insufficient funds
    let res = escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(loader_coins.as_slice())
        .call(&loader);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Coins not match: expected 1000uc4e != got 10000mc4e",
        res.err().unwrap().to_string()
    );
}

#[test]
fn test_load_escrow_wrong_many_denomoms_funds() {
    let app = App::default();
    let ts1: Timestamp = Timestamp::from_seconds(12324);
    app.set_block(BlockInfo {
        height: 1,
        time: ts1.clone(),
        chain_id: "c4e-1".to_string(),
    });
    let escrow_code_id = CodeId::store_code(&app);
    let did_code_id = DidContractCodeId::store_code(&app);

    let owner = "owner".into_addr();
    let loader = "loader".into_addr();
    let loader_account_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(10000u128, "nc4e")];

    let expected_coins = vec![Coin::new(1000u128, "uc4e"), Coin::new(10000u128, "mc4e")];

    {
        let mut app_mut = app.app_mut();
        app_mut
            .sudo(cw_multi_test::SudoMsg::Bank(
                cw_multi_test::BankSudo::Mint {
                    to_address: loader.to_string(),
                    amount: loader_account_coins.clone(),
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
        )
        .call(&owner)
        .unwrap();

    // Add an operator and create an escrow
    let controller: Controller = "controller1".into_addr().to_string().into();
    let operator_id = "operator1".to_string();
    let receiver: Controller = "receiver1".into_addr().to_string().into();

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
        .call(&owner)
        .expect("error creating escrow");

    // Attempt to load the escrow with insufficient funds
    let res = escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(loader_account_coins.as_slice())
        .call(&loader);

    // Verify the error
    assert!(res.is_err(), "Expected Err, but got an Ok");
    assert_eq!(
        "Coins not match: expected 10000mc4e,1000uc4e != got 10000nc4e,1000uc4e",
        res.err().unwrap().to_string()
    );
}
