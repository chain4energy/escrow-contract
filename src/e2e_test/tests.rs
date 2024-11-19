
use std::collections::HashMap;

use cosmrs::{crypto::secp256k1::SigningKey, proto::cosmos::bank::v1beta1::QueryBalanceResponse};
use cosmwasm_std::{Coin, Decimal};
use serde_json::json;
use serial_test::serial;
use e2e_test_suite::{derive_private_key_from_mnemonic, error::CosmError, ContractInit, ADDR_PREFIX};

use crate::state::{Escrow, EscrowState, LoadedCoins};

// use crate::state::DidDocument;

const CONTRACT_CREATOR_MNEMONIC: &str = "harbor flee number sibling doll recycle brisk mask blanket orphan initial maze race flash limb sound wing ramp proud battle feature ceiling feel miss";
const HD_PATH: &str = "m/44'/118'/0'/0/0";

const ESCROW_CONTRACT_NAME: &str = "escrow";
// const CONTRACT_PATH: &str = "./artifacts/escrow_contract.wasm";
const ESCROW_CONTRACT_PATH: &str = "./target/wasm32-unknown-unknown/release/escrow_contract.wasm";

const DID_CONTRACT_NAME: &str = "did";
// const DID_CONTRACT_PATH: &str = "./../did/artifacts/did_contract.wasm";
const DID_CONTRACT_PATH: &str = "./../did/target/wasm32-unknown-unknown/release/did_contract.wasm";


#[test]
#[serial]
fn test_add_admin() {
    init_suite();

    println!("RUN create_did_document");
    let context = e2e_test_suite::get_context();
    
    let (key, address) = create_key_and_address();

    let wrong_admin_key = derive_private_key_from_mnemonic("dinosaur sound goddess cradle brush you mammal prize little bike surround actor frost edit off debris print correct knee photo fluid game mad same",    HD_PATH).expect("create key error");

    let escrow_contract_address = context.get_contracts_info().get(ESCROW_CONTRACT_NAME).expect("no contacr info").contract_address.clone();

    // ---- wrong admin

    let add_admin_msg = super::super::contract::sv::ExecMsg::AddAdmin { new_admin: "c4e13pq6693n69hfznt33u8d6zkszpy5nq4ucj0f5s".to_string() };
    
    let msg = json!(add_admin_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&wrong_admin_key, &escrow_contract_address, &msg, vec![]);
    let err = result.err().unwrap();
    if let CosmError::TxBroadcastError(_, tx_result, _, _) = err {
        assert_eq!("failed to execute message; message index: 0: Unauthorized: execute wasm contract failed" , tx_result.log);

    } else {
        panic!("not TxBroadcastError");
    }
    // assert_eq!("Tx Bradcast Error", result.err().unwrap().to_string());
    // --- success
    let add_admin_msg = super::super::contract::sv::ExecMsg::AddAdmin { new_admin: "c4e13pq6693n69hfznt33u8d6zkszpy5nq4ucj0f5s".to_string() };
    
    let msg = json!(add_admin_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");
        
}


#[test]
#[serial]
fn test_create_operator() {
    init_suite();

    println!("RUN create_did_document");
    let context = e2e_test_suite::get_context();
    
    let (key, address) = create_key_and_address();

    let (operator_key, operator_address) = create_key_and_address_from_mnemonic("dinosaur sound goddess cradle brush you mammal prize little bike surround actor frost edit off debris print correct knee photo fluid game mad same");

    let escrow_contract_address = context.get_contracts_info().get(ESCROW_CONTRACT_NAME).expect("no contacr info").contract_address.clone();

    let operator_id = "operator-1";
    let exec_msg = super::super::contract::sv::ExecMsg::CreateOperator { operator_id: operator_id.into(), controllers: vec![operator_address.into()] };
    
    let msg = json!(exec_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    let exec_msg = super::super::contract::sv::ExecMsg::RemoveOperator { operator_id: operator_id.into() };
    
    let msg = json!(exec_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");
        
}


#[test]
#[serial]
fn test_full_escrow_process() {
    init_suite();

    const DENOM: &str = "uc4e";


    println!("RUN create_did_document");
    let context = e2e_test_suite::get_context();
    
    let (contract_admin_key, contract_admin_address) = create_key_and_address();

    let (operator_key, operator_address) = create_key_and_address_from_mnemonic("dinosaur sound goddess cradle brush you mammal prize little bike surround actor frost edit off debris print correct knee photo fluid game mad same");
    let (loader_key, loader_address) = create_key_and_address_from_mnemonic("ocean cotton ahead twist size nose stuff name donkey glad matter favorite frown syrup hard expect genuine word media another crush logic enlist practice");
    let (receiver_key, receiver_address) = create_key_and_address_from_mnemonic("average early sad ocean pole party lift panda grab admit bridge drip wrist ridge input clock hip list draft document consider power input priority");

    let escrow_contract_address = context.get_contracts_info().get(ESCROW_CONTRACT_NAME).expect("no contract info").contract_address.clone();

    let admin_balance = context.get_chain_client().query.bank().balance(&contract_admin_address, DENOM).expect("admin balance error").balance.expect("no admin balance").amount;
    // assert_eq!(QueryBalanceResponse {balance: Some(e2e_test_suite::Coin { denom: DENOM.to_string(), amount: "209999954900".into() })}, admin_balance);
    let admin_balance =  admin_balance.parse::<u128>().expect("parse error");

    let operator_balance = context.get_chain_client().query.bank().balance(&operator_address, DENOM).expect("operator balance error").balance.expect("no operator balance").amount;
    // assert_eq!(QueryBalanceResponse {balance: Some(e2e_test_suite::Coin { denom: DENOM.to_string(), amount: "210000000000".into() })}, operator_balance);
    let operator_balance =  operator_balance.parse::<u128>().expect("parse error");

    let loader_balance = context.get_chain_client().query.bank().balance(&loader_address, DENOM).expect("loader balance error").balance.expect("no loader balance").amount;
    // assert_eq!(QueryBalanceResponse {balance: Some(e2e_test_suite::Coin { denom: DENOM.to_string(), amount: "210000000000".into() })}, loader_balance);
    let loader_balance =  loader_balance.parse::<u128>().expect("parse error");

    let receiver_balance = context.get_chain_client().query.bank().balance(&receiver_address, DENOM).expect("receiver balance error").balance.expect("no receiver balance").amount;
    // assert_eq!(QueryBalanceResponse {balance: Some(e2e_test_suite::Coin { denom: DENOM.to_string(), amount: "210000000000".into() })}, receiver_balance);
    let receiver_balance =  receiver_balance.parse::<u128>().expect("parse error");

    let contract_balance = context.get_chain_client().query.bank().balance(&escrow_contract_address, DENOM).expect("contract balance error").balance.expect("no contract balance").amount;
    // assert_eq!(QueryBalanceResponse {balance: Some(e2e_test_suite::Coin { denom: DENOM.to_string(), amount: "0".into() })}, contract_balance);
    let contract_balance =  contract_balance.parse::<u128>().expect("parse error");


    // ------ create operator
    let operator_id = "operator-2";
    let exec_msg = super::super::contract::sv::ExecMsg::CreateOperator { operator_id: operator_id.into(), controllers: vec![operator_address.clone().into()] };
    
    let msg = json!(exec_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&contract_admin_key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    // ------ create escrow
    let escrow_id = "escrow-1";

    let expected_coins = Coin{
        denom: "uc4e".to_string(),
        amount: 1000u128.into()
    };
    // let receiver_share = Decimal::percent(50);

    let exec_msg = super::super::contract::sv::ExecMsg::CreateEscrow { escrow_id: escrow_id.into(), operator_id: operator_id.into(), receiver: receiver_address.clone().into(), expected_coins: vec![expected_coins.clone()] };
    let msg = json!(exec_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&operator_key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    let query_msg = super::super::contract::sv::QueryMsg::GetEscrow { escrow_id: escrow_id.into() };
    let msg = json!(query_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().query.wasm().contract(&escrow_contract_address, &msg);
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Escrow: {resp}");
    let expected_escrow = Escrow {
        id: escrow_id.to_string(),
        operator_id: operator_id.to_string(),
        expected_coins: vec![expected_coins.clone()],
        loaded_coins: None,
        operator_claimed: false,
        receiver: receiver_address.clone().into(),
        receiver_claimed: false,
        operator_fee: vec![],
        // receiver_share: receiver_share,
        loader_claimed: false,
        used_coins: vec![],
        state: EscrowState::Loading,
        lock_timestamp: None
    };
    let escrow: Escrow = serde_json::from_slice(&result.data).expect("CreateEscrow respnse deserialization error");
    
    assert_eq!(expected_escrow.clone(), escrow);

    let new_admin_balance = context.get_chain_client().query.bank().balance(&contract_admin_address, DENOM).expect("admin balance error").balance.expect("no admin balance").amount;
    let new_admin_balance =  new_admin_balance.parse::<u128>().expect("parse error");
    assert_eq!(admin_balance, new_admin_balance);

    let new_operator_balance = context.get_chain_client().query.bank().balance(&operator_address, DENOM).expect("operator balance error").balance.expect("no operator balance").amount;
    let new_operator_balance =  new_operator_balance.parse::<u128>().expect("parse error");
    assert_eq!(operator_balance, new_operator_balance);

    let new_loader_balance = context.get_chain_client().query.bank().balance(&loader_address, DENOM).expect("loader balance error").balance.expect("no loader balance").amount;
    let new_loader_balance =  new_loader_balance.parse::<u128>().expect("parse error");
    assert_eq!(loader_balance, new_loader_balance);

    let new_receiver_balance = context.get_chain_client().query.bank().balance(&receiver_address, DENOM).expect("receiver balance error").balance.expect("no receiver balance").amount;
    let new_receiver_balance =  new_receiver_balance.parse::<u128>().expect("parse error");
    assert_eq!(receiver_balance, new_receiver_balance);

    let new_contract_balance = context.get_chain_client().query.bank().balance(&escrow_contract_address, DENOM).expect("contract balance error").balance.expect("no contract balance").amount;
    let new_contract_balance =  new_contract_balance.parse::<u128>().expect("parse error");
    assert_eq!(contract_balance, new_contract_balance);

    // ------ load escrow

    let exec_msg = super::super::contract::sv::ExecMsg::LoadEscrow { escrow_id: escrow_id.into() } ;
    let msg = json!(exec_msg).to_string();
    println!("Message: {msg}");

    let loader_coin = e2e_test_suite::Coin {
        denom: expected_coins.denom.clone(),
        amount: expected_coins.amount.to_string()
    };

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&loader_key, &escrow_contract_address, &msg, vec![loader_coin.clone()]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    // let query_msg = super::super::contract::sv::QueryMsg::GetEscrow { escrow_id: escrow_id.into() };
    let msg = json!(query_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().query.wasm().contract(&escrow_contract_address, &msg);
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Escrow: {resp}");


    let escrow: Escrow = serde_json::from_slice(&result.data).expect("CreateEscrow respnse deserialization error");
    let expected_escrow = Escrow {
        loaded_coins: Some(LoadedCoins {
            loader: loader_address.to_string(),
            coins: vec![expected_coins.clone()]
        }),
        state: EscrowState::Locked,
        lock_timestamp: escrow.lock_timestamp,
        ..expected_escrow
        
    };

    assert_eq!(expected_escrow.clone(), escrow);

    let new_admin_balance = context.get_chain_client().query.bank().balance(&contract_admin_address, DENOM).expect("admin balance error").balance.expect("no admin balance").amount;
    let new_admin_balance =  new_admin_balance.parse::<u128>().expect("parse error");
    assert_eq!(admin_balance, new_admin_balance);

    let new_operator_balance = context.get_chain_client().query.bank().balance(&operator_address, DENOM).expect("operator balance error").balance.expect("no operator balance").amount;
    let new_operator_balance =  new_operator_balance.parse::<u128>().expect("parse error");
    assert_eq!(operator_balance, new_operator_balance);

    let new_loader_balance = context.get_chain_client().query.bank().balance(&loader_address, DENOM).expect("loader balance error").balance.expect("no loader balance").amount;
    let new_loader_balance =  new_loader_balance.parse::<u128>().expect("parse error");
    let loader_balance = loader_balance-1000;
    assert_eq!(loader_balance, new_loader_balance);

    let new_receiver_balance = context.get_chain_client().query.bank().balance(&receiver_address, DENOM).expect("receiver balance error").balance.expect("no receiver balance").amount;
    let new_receiver_balance =  new_receiver_balance.parse::<u128>().expect("parse error");
    assert_eq!(receiver_balance, new_receiver_balance);

    let new_contract_balance = context.get_chain_client().query.bank().balance(&escrow_contract_address, DENOM).expect("contract balance error").balance.expect("no contract balance").amount;
    let new_contract_balance =  new_contract_balance.parse::<u128>().expect("parse error");
    let contract_balance = contract_balance+1000;
    assert_eq!(contract_balance, new_contract_balance);

    // ------ release escrow

    let rel_coin = Coin{
        denom: DENOM.to_string(),
        amount: 500u128.into()
    };

    let operator_fee = Coin{
        denom: DENOM.to_string(),
        amount: 250u128.into()
    };

    let exec_msg = super::super::contract::sv::ExecMsg::ReleaseEscrow { escrow_id: escrow_id.into(), used_coins: vec![rel_coin.clone()], operator_fee: vec![operator_fee] };
    let msg = json!(exec_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&operator_key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    // let query_msg = super::super::contract::sv::QueryMsg::GetEscrow { escrow_id: escrow_id.into() };
    let msg = json!(query_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().query.wasm().contract(&escrow_contract_address, &msg);
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Escrow: {resp}");


    let escrow: Escrow = serde_json::from_slice(&result.data).expect("CreateEscrow respnse deserialization error");
    let expected_escrow = Escrow {
        state: EscrowState::Released,
        used_coins: vec![rel_coin],
        ..expected_escrow
        
    };

    assert_eq!(expected_escrow.clone(), escrow);

    let new_admin_balance = context.get_chain_client().query.bank().balance(&contract_admin_address, DENOM).expect("admin balance error").balance.expect("no admin balance").amount;
    let new_admin_balance =  new_admin_balance.parse::<u128>().expect("parse error");
    assert_eq!(admin_balance, new_admin_balance);
    println!("new_admin_balance: {new_admin_balance}");

    let new_operator_balance = context.get_chain_client().query.bank().balance(&operator_address, DENOM).expect("operator balance error").balance.expect("no operator balance").amount;
    let new_operator_balance =  new_operator_balance.parse::<u128>().expect("parse error");
    assert_eq!(operator_balance, new_operator_balance);
    println!("new_operator_balance: {new_operator_balance}");

    let new_loader_balance = context.get_chain_client().query.bank().balance(&loader_address, DENOM).expect("loader balance error").balance.expect("no loader balance").amount;
    let new_loader_balance =  new_loader_balance.parse::<u128>().expect("parse error");
    // let loader_balance = loader_balance-1000;
    assert_eq!(loader_balance, new_loader_balance);
    println!("new_loader_balance: {new_loader_balance}");

    let new_receiver_balance = context.get_chain_client().query.bank().balance(&receiver_address, DENOM).expect("receiver balance error").balance.expect("no receiver balance").amount;
    let new_receiver_balance =  new_receiver_balance.parse::<u128>().expect("parse error");
    assert_eq!(receiver_balance, new_receiver_balance);
    println!("new_receiver_balance: {new_receiver_balance}");

    let new_contract_balance = context.get_chain_client().query.bank().balance(&escrow_contract_address, DENOM).expect("contract balance error").balance.expect("no contract balance").amount;
    let new_contract_balance =  new_contract_balance.parse::<u128>().expect("parse error");
    // let contract_balance = contract_balance+1000;
    assert_eq!(contract_balance, new_contract_balance);
    println!("new_contract_balance: {new_contract_balance}");

    // ------ withdraw loader escrow

    let exec_msg = super::super::contract::sv::ExecMsg::Withdraw { escrow_id: escrow_id.into() };
    let msg = json!(exec_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&loader_key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    // let query_msg = super::super::contract::sv::QueryMsg::GetEscrow { escrow_id: escrow_id.into() };
    let msg = json!(query_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().query.wasm().contract(&escrow_contract_address, &msg);
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Escrow: {resp}");


    let escrow: Escrow = serde_json::from_slice(&result.data).expect("CreateEscrow respnse deserialization error");
    let expected_escrow = Escrow {
        loader_claimed: true,
        ..expected_escrow
        
    };

    assert_eq!(expected_escrow.clone(), escrow);

    let new_admin_balance = context.get_chain_client().query.bank().balance(&contract_admin_address, DENOM).expect("admin balance error").balance.expect("no admin balance").amount;
    let new_admin_balance =  new_admin_balance.parse::<u128>().expect("parse error");
    assert_eq!(admin_balance, new_admin_balance);

    let new_operator_balance = context.get_chain_client().query.bank().balance(&operator_address, DENOM).expect("operator balance error").balance.expect("no operator balance").amount;
    let new_operator_balance =  new_operator_balance.parse::<u128>().expect("parse error");
    assert_eq!(operator_balance, new_operator_balance);

    let new_loader_balance = context.get_chain_client().query.bank().balance(&loader_address, DENOM).expect("loader balance error").balance.expect("no loader balance").amount;
    let new_loader_balance =  new_loader_balance.parse::<u128>().expect("parse error");
    let loader_balance = loader_balance+500;
    assert_eq!(loader_balance, new_loader_balance);

    let new_receiver_balance = context.get_chain_client().query.bank().balance(&receiver_address, DENOM).expect("receiver balance error").balance.expect("no receiver balance").amount;
    let new_receiver_balance =  new_receiver_balance.parse::<u128>().expect("parse error");
    assert_eq!(receiver_balance, new_receiver_balance);

    let new_contract_balance = context.get_chain_client().query.bank().balance(&escrow_contract_address, DENOM).expect("contract balance error").balance.expect("no contract balance").amount;
    let new_contract_balance =  new_contract_balance.parse::<u128>().expect("parse error");
    let contract_balance = contract_balance-500;
    assert_eq!(contract_balance, new_contract_balance);

    // ------ withdraw receiver escrow

    let exec_msg = super::super::contract::sv::ExecMsg::Withdraw { escrow_id: escrow_id.into() };
    let msg = json!(exec_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&receiver_key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    // let query_msg = super::super::contract::sv::QueryMsg::GetEscrow { escrow_id: escrow_id.into() };
    let msg = json!(query_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().query.wasm().contract(&escrow_contract_address, &msg);
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Escrow: {resp}");


    let escrow: Escrow = serde_json::from_slice(&result.data).expect("CreateEscrow respnse deserialization error");
    let expected_escrow = Escrow {
        receiver_claimed: true,
        ..expected_escrow
        
    };

    assert_eq!(expected_escrow.clone(), escrow);

    let new_admin_balance = context.get_chain_client().query.bank().balance(&contract_admin_address, DENOM).expect("admin balance error").balance.expect("no admin balance").amount;
    let new_admin_balance =  new_admin_balance.parse::<u128>().expect("parse error");
    assert_eq!(admin_balance, new_admin_balance);

    let new_operator_balance = context.get_chain_client().query.bank().balance(&operator_address, DENOM).expect("operator balance error").balance.expect("no operator balance").amount;
    let new_operator_balance =  new_operator_balance.parse::<u128>().expect("parse error");
    assert_eq!(operator_balance, new_operator_balance);

    let new_loader_balance = context.get_chain_client().query.bank().balance(&loader_address, DENOM).expect("loader balance error").balance.expect("no loader balance").amount;
    let new_loader_balance =  new_loader_balance.parse::<u128>().expect("parse error");
    // let loader_balance = loader_balance+500;
    assert_eq!(loader_balance, new_loader_balance);

    let new_receiver_balance = context.get_chain_client().query.bank().balance(&receiver_address, DENOM).expect("receiver balance error").balance.expect("no receiver balance").amount;
    let new_receiver_balance =  new_receiver_balance.parse::<u128>().expect("parse error");
    let receiver_balance = receiver_balance+250;
    assert_eq!(receiver_balance, new_receiver_balance);

    let new_contract_balance = context.get_chain_client().query.bank().balance(&escrow_contract_address, DENOM).expect("contract balance error").balance.expect("no contract balance").amount;
    let new_contract_balance =  new_contract_balance.parse::<u128>().expect("parse error");
    let contract_balance = contract_balance-250;
    assert_eq!(contract_balance, new_contract_balance);

    // ------ withdraw operator escrow

    let exec_msg = super::super::contract::sv::ExecMsg::Withdraw { escrow_id: escrow_id.into() };
    let msg = json!(exec_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&operator_key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");

    // let query_msg = super::super::contract::sv::QueryMsg::GetEscrow { escrow_id: escrow_id.into() };
    let msg = json!(query_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().query.wasm().contract(&escrow_contract_address, &msg);
    assert!(result.is_ok(), "Expected Ok, but got an Err");
    let result = result.unwrap();
    let resp = String::from_utf8(result.clone().data).expect("Invalid UTF-8 sequence");
    println!("Escrow: {resp}");


    let escrow: Escrow = serde_json::from_slice(&result.data).expect("CreateEscrow respnse deserialization error");
    let expected_escrow = Escrow {
        operator_claimed: true,
        state: EscrowState::Closed,
        ..expected_escrow
        
    };

    assert_eq!(expected_escrow.clone(), escrow);

    let new_admin_balance = context.get_chain_client().query.bank().balance(&contract_admin_address, DENOM).expect("admin balance error").balance.expect("no admin balance").amount;
    let new_admin_balance =  new_admin_balance.parse::<u128>().expect("parse error");
    assert_eq!(admin_balance, new_admin_balance);

    let new_operator_balance = context.get_chain_client().query.bank().balance(&operator_address, DENOM).expect("operator balance error").balance.expect("no operator balance").amount;
    let new_operator_balance =  new_operator_balance.parse::<u128>().expect("parse error");
    let operator_balance = operator_balance+250;
    assert_eq!(operator_balance, new_operator_balance);

    let new_loader_balance = context.get_chain_client().query.bank().balance(&loader_address, DENOM).expect("loader balance error").balance.expect("no loader balance").amount;
    let new_loader_balance =  new_loader_balance.parse::<u128>().expect("parse error");
    // let loader_balance = loader_balance+500;
    assert_eq!(loader_balance, new_loader_balance);

    let new_receiver_balance = context.get_chain_client().query.bank().balance(&receiver_address, DENOM).expect("receiver balance error").balance.expect("no receiver balance").amount;
    let new_receiver_balance =  new_receiver_balance.parse::<u128>().expect("parse error");
    // let receiver_balance = receiver_balance+250;
    assert_eq!(receiver_balance, new_receiver_balance);

    let new_contract_balance = context.get_chain_client().query.bank().balance(&escrow_contract_address, DENOM).expect("contract balance error").balance.expect("no contract balance").amount;
    let new_contract_balance =  new_contract_balance.parse::<u128>().expect("parse error");
    let contract_balance = contract_balance-250;
    assert_eq!(contract_balance, new_contract_balance);

    // ------ remove operator
    let exec_msg = super::super::contract::sv::ExecMsg::RemoveOperator { operator_id: operator_id.into() };
    
    let msg = json!(exec_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&contract_admin_key, &escrow_contract_address, &msg, vec![]);
    assert!(result.is_ok(), "Expected Ok, but got an Err");
        
}

#[test]
#[serial]
fn my_test_2() {
    init_suite();
    println!("RUN TEST 2")
}

#[test]
#[serial]
fn my_test_3() {
    init_suite();
    // setup_context();
    println!("RUN TEST 3");
}

#[test]
fn my_test_4() {

    println!(r#"{{"admins": ["{}"], "did_contract": "{}"}}"#, 34, "DDDDDDDD");
}

fn init_suite() {
    let mut contracts: HashMap<String, ContractInit> = HashMap::new();
    contracts.insert(DID_CONTRACT_NAME.into(), ContractInit { contract_path: DID_CONTRACT_PATH.to_string(), json_ncoded_init_args: "{}".to_string(), label: "did_contract".to_string() });
    e2e_test_suite::init_suite(CONTRACT_CREATOR_MNEMONIC, HD_PATH, &contracts, "c4e-chain-e2e-test:v1.4.3", "escrow-contract", "escrow");
    let (owner_key, owner_addr) = create_key_and_address();

    let mut did_contract_address: String;
    {
        let context = e2e_test_suite::get_context();
        did_contract_address = context.get_contracts_info().get(DID_CONTRACT_NAME).expect("no did contract info").contract_address.clone();
    }

    e2e_test_suite::add_contract(CONTRACT_CREATOR_MNEMONIC, HD_PATH, ESCROW_CONTRACT_NAME, 
        ContractInit {
            contract_path: ESCROW_CONTRACT_PATH.to_string(), 
            json_ncoded_init_args: format!(r#"{{"admins": ["{}"], "did_contract": "{}"}}"#, &owner_addr, did_contract_address), 
            label: "escrow_contract".to_string()
        }
    );
    let context: std::sync::RwLockReadGuard<'_, e2e_test_suite::TestSuiteContextInternal> = e2e_test_suite::get_context();

    
}

fn create_key_and_address() -> (SigningKey, String){
    create_key_and_address_from_mnemonic(CONTRACT_CREATOR_MNEMONIC)
}

fn create_key_and_address_from_mnemonic(mnemonic: &str) -> (SigningKey, String){
    let key = derive_private_key_from_mnemonic(mnemonic,    HD_PATH).expect("create key error");
    let address = key.public_key().account_id(ADDR_PREFIX).expect("cannot create address").to_string();
    (key, address)
}
