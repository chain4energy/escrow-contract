use cosmwasm_std::{BlockInfo, Coin};
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
fn test_indexes_after_create() {
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

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id.clone(),
            expected_coins: expected_coins.clone(),
            loaded_coins: None,
            operator_claimed: false,
            receiver: receiver.clone(),
            receiver_claimed: false,
            operator_fee: vec![],
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: vec![],
            state: EscrowState::Loading,
            lock_timestamp: None,
            create_timestamp: escrow.create_timestamp
        },
        escrow,
    );

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    assert_eq!(
        Escrow {
            id: "escrow1".to_string(),
            operator_id: operator_id.clone(),
            expected_coins: expected_coins.clone(),
            loaded_coins: None,
            operator_claimed: false,
            receiver: receiver.clone(),
            receiver_claimed: false,
            operator_fee: vec![],
            // receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: vec![],
            state: EscrowState::Loading,
            lock_timestamp: None,
            create_timestamp: escrow.create_timestamp
        },
        escrow,
    );

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);
}

#[test]
fn test_indexes_after_load() {
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

    let coin = Coin {
        denom: "uc4e".to_string(),
        amount: 1000u128.into(),
    };
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("error loading escrow");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
        }),
        operator_claimed: false,
        receiver: receiver.clone(),
        receiver_claimed: false,
        operator_fee: vec![],
        // receiver_share: receiver_share,
        loader_claimed: false,
        used_coins: vec![],
        state: EscrowState::Locked,
        lock_timestamp: escrow.lock_timestamp,
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);
}

#[test]
fn test_indexes_after_release_timeout_withdraw() {
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

    let coin = Coin {
        denom: "uc4e".to_string(),
        amount: 1000u128.into(),
    };
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("error loading escrow");

    let ts2 = app.block_info().time.plus_seconds(5 * 24 * 3600);
    app.set_block(BlockInfo {
        height: 100,
        time: ts2,
        chain_id: "test-chain".to_string(),
    });

    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader)
        .expect("error withdrawing by loader");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
        }),
        operator_claimed: false,
        receiver: receiver.clone(),
        receiver_claimed: false,
        operator_fee: vec![],
        // receiver_share: receiver_share,
        loader_claimed: false,
        used_coins: vec![],
        state: EscrowState::FailedReleaseTimeoutWithdrawned,
        lock_timestamp: escrow.lock_timestamp,
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);
}

#[test]
fn test_indexes_after_release_partial_used() {
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

    let coin = Coin {
        denom: "uc4e".to_string(),
        amount: 1000u128.into(),
    };
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("error loading escrow");

    let ts2 = app.block_info().time.plus_seconds(100);
    app.set_block(BlockInfo {
        height: 100,
        time: ts2,
        chain_id: "test-chain".to_string(),
    });

    let used_coins = vec![Coin::new(800u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&owner)
        .expect("error releasing escrow");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
        }),
        operator_claimed: false,
        receiver: receiver.clone(),
        receiver_claimed: false,
        operator_fee: operator_fee.clone(),
        // receiver_share: receiver_share,
        loader_claimed: false,
        used_coins: used_coins.clone(),
        state: EscrowState::Released,
        lock_timestamp: escrow.lock_timestamp,
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);
}

#[test]
fn test_indexes_after_release_partial_used_all_fee() {
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

    let coin = Coin {
        denom: "uc4e".to_string(),
        amount: 1000u128.into(),
    };
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("error loading escrow");

    let ts2 = app.block_info().time.plus_seconds(100);
    app.set_block(BlockInfo {
        height: 100,
        time: ts2,
        chain_id: "test-chain".to_string(),
    });

    let used_coins = vec![Coin::new(800u128, "uc4e")];
    let operator_fee = vec![Coin::new(800u128, "uc4e")];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&owner)
        .expect("error releasing escrow");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
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
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);
}

#[test]
fn test_indexes_after_release_partial_used_no_fee() {
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

    let coin = Coin {
        denom: "uc4e".to_string(),
        amount: 1000u128.into(),
    };
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("error loading escrow");

    let ts2 = app.block_info().time.plus_seconds(100);
    app.set_block(BlockInfo {
        height: 100,
        time: ts2,
        chain_id: "test-chain".to_string(),
    });

    let used_coins = vec![Coin::new(800u128, "uc4e")];
    let operator_fee = vec![];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&owner)
        .expect("error releasing escrow");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
        }),
        operator_claimed: true,
        receiver: receiver.clone(),
        receiver_claimed: false,
        operator_fee: operator_fee.clone(),
        // receiver_share: receiver_share,
        loader_claimed: false,
        used_coins: used_coins.clone(),
        state: EscrowState::Released,
        lock_timestamp: escrow.lock_timestamp,
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);
}

#[test]
fn test_indexes_after_release_none_used() {
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

    let coin = Coin {
        denom: "uc4e".to_string(),
        amount: 1000u128.into(),
    };
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("error loading escrow");

    let ts2 = app.block_info().time.plus_seconds(100);
    app.set_block(BlockInfo {
        height: 100,
        time: ts2,
        chain_id: "test-chain".to_string(),
    });

    let used_coins = vec![];
    let operator_fee = vec![];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&owner)
        .expect("error releasing escrow");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
        }),
        operator_claimed: true,
        receiver: receiver.clone(),
        receiver_claimed: true,
        operator_fee: operator_fee.clone(),
        // receiver_share: receiver_share,
        loader_claimed: false,
        used_coins: used_coins.clone(),
        state: EscrowState::Released,
        lock_timestamp: escrow.lock_timestamp,
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);
}

#[test]
fn test_indexes_after_release_all_used_with_fee() {
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

    let coin = Coin {
        denom: "uc4e".to_string(),
        amount: 1000u128.into(),
    };
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("error loading escrow");

    let ts2 = app.block_info().time.plus_seconds(100);
    app.set_block(BlockInfo {
        height: 100,
        time: ts2,
        chain_id: "test-chain".to_string(),
    });

    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&owner)
        .expect("error releasing escrow");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
        }),
        operator_claimed: false,
        receiver: receiver.clone(),
        receiver_claimed: false,
        operator_fee: operator_fee.clone(),
        // receiver_share: receiver_share,
        loader_claimed: true,
        used_coins: used_coins.clone(),
        state: EscrowState::Released,
        lock_timestamp: escrow.lock_timestamp,
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);
}

#[test]
fn test_indexes_after_release_all_used_no_fee() {
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

    let coin = Coin {
        denom: "uc4e".to_string(),
        amount: 1000u128.into(),
    };
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("error loading escrow");

    let ts2 = app.block_info().time.plus_seconds(100);
    app.set_block(BlockInfo {
        height: 100,
        time: ts2,
        chain_id: "test-chain".to_string(),
    });

    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&owner)
        .expect("error releasing escrow");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
        }),
        operator_claimed: true,
        receiver: receiver.clone(),
        receiver_claimed: false,
        operator_fee: operator_fee.clone(),
        // receiver_share: receiver_share,
        loader_claimed: true,
        used_coins: used_coins.clone(),
        state: EscrowState::Released,
        lock_timestamp: escrow.lock_timestamp,
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);
}

#[test]
fn test_indexes_after_release_all_used_all_fee() {
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

    let coin = Coin {
        denom: "uc4e".to_string(),
        amount: 1000u128.into(),
    };
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("error loading escrow");

    let ts2 = app.block_info().time.plus_seconds(100);
    app.set_block(BlockInfo {
        height: 100,
        time: ts2,
        chain_id: "test-chain".to_string(),
    });

    let used_coins = vec![Coin::new(1000u128, "uc4e")];
    let operator_fee = vec![Coin::new(1000u128, "uc4e")];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&owner)
        .expect("error releasing escrow");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
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
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);
}

#[test]
fn test_indexes_after_withdraws() {
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

    // Add an operator
    let controller_addr = "controller1".into_addr();
    let controller: Controller = controller_addr.to_string().into();
    let operator_id = "operator1".to_string();

    escrow_contract
        .create_operator(operator_id.clone(), vec![controller.clone()])
        .call(&owner)
        .expect("error creating operator");

    // Create an escrow
    let receiver_addr = "receiver1".into_addr();

    let receiver: Controller = receiver_addr.to_string().into();
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

    let coin = Coin {
        denom: "uc4e".to_string(),
        amount: 1000u128.into(),
    };
    escrow_contract
        .load_escrow("escrow1".to_string())
        .with_funds(vec![coin.clone()].as_slice())
        .call(&loader)
        .expect("error loading escrow");

    let ts2 = app.block_info().time.plus_seconds(100);
    app.set_block(BlockInfo {
        height: 100,
        time: ts2,
        chain_id: "test-chain".to_string(),
    });

    let used_coins = vec![Coin::new(800u128, "uc4e")];
    let operator_fee = vec![Coin::new(100u128, "uc4e")];
    escrow_contract
        .release_escrow(
            "escrow1".to_string(),
            used_coins.clone(),
            operator_fee.clone(),
        )
        .call(&owner)
        .expect("error releasing escrow");

    // ---------------- loader withdraw
    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&loader)
        .expect("error withdrawing by loader");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
        }),
        operator_claimed: false,
        receiver: receiver.clone(),
        receiver_claimed: false,
        operator_fee: operator_fee.clone(),
        // receiver_share: receiver_share,
        loader_claimed: true,
        used_coins: used_coins.clone(),
        state: EscrowState::Released,
        lock_timestamp: escrow.lock_timestamp,
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    // ---------------- receiver withdraw
    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&receiver_addr)
        .expect("error withdrawing by loader");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
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
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    // ---------------- operator withdraw
    escrow_contract
        .withdraw("escrow1".to_string())
        .call(&controller_addr)
        .expect("error withdrawing by loader");

    // Verify the escrow is created
    let escrows = escrow_contract
        .get_escrows_by_operator(operator_id.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    let escrow = escrows[0].1.clone();
    let expected_escrow = Escrow {
        id: "escrow1".to_string(),
        operator_id: operator_id.clone(),
        expected_coins: expected_coins.clone(),
        loaded_coins: Some(LoadedCoins {
            loader: loader.clone(),
            coins: expected_coins.clone(),
        }),
        operator_claimed: true,
        receiver: receiver.clone(),
        receiver_claimed: true,
        operator_fee: operator_fee.clone(),
        // receiver_share: receiver_share,
        loader_claimed: true,
        used_coins: used_coins.clone(),
        state: EscrowState::Closed,
        lock_timestamp: escrow.lock_timestamp,
        create_timestamp: escrow.create_timestamp,
    };
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_operator("wrong_operator".to_string(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    //---------------------

    let escrows = escrow_contract
        .get_escrows_by_receiver(receiver.clone(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_escrows_by_receiver("wrong_receiver".to_string().into(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 1);
    assert_eq!(expected_escrow.clone(), escrow,);

    let escrows = escrow_contract
        .get_loaded_escrows_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_loader("loader".into_addr(), None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_operator(operator_id, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);

    let escrows = escrow_contract
        .get_escrows_to_withdraw_by_receiver(receiver, None, None)
        .expect("error querying escrow");

    assert_eq!(escrows.len(), 0);
}
