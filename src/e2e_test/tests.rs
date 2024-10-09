
use std::collections::HashMap;

use cosmrs::crypto::secp256k1::SigningKey;
use cw_multi_test::IntoAddr;
use serde_json::json;
use serial_test::serial;
use e2e_test_suite::{derive_private_key_from_mnemonic, ContractInit, ADDR_PREFIX};

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
fn create_did_document() {
    init_suite();
    // setup_context();
    println!("RUN create_did_document");

    // let context =  e2e_test_suite::CONTEXT.get().expect("Docker controller is not initialized");
    let context = e2e_test_suite::get_context();
    
    let (key, address) = create_key_and_address();

    // let wrong_admin = "wrong_admin".into_addr();
    let wrong_admin_key = derive_private_key_from_mnemonic("dinosaur sound goddess cradle brush you mammal prize little bike surround actor frost edit off debris print correct knee photo fluid game mad same",    HD_PATH).expect("create key error");

    // // let msg = r#"{
    // //     "create_did_document": {
    // //         "did_doc": {
    // //             "id": "did:example:1234567890",
    // //             "controller": ["did:user:1234567890"],
    // //             "service": [
    // //                 {
    // //                     "id": "did:service:1234567890",
    // //                     "type": "type",
    // //                     "service_endpoint": "http://chargera.io"
    // //                 }
    // //             ]
    // //         }
    // //     }
    // // }"#;

    // let did = "did:example:000432";

    // let did_doc = DidDocument { 
    //     id: crate::state::Did::new(did), 
    //     controller: vec![crate::state::Did::new("did:user:000131")], 
    //     service: vec![crate::state::Service{
    //         id: crate::state::Did::new("did:service:000131"),
    //         a_type: "Chargera".to_string(),
    //         service_endpoint: "http://chargera.io".to_string()
    //     }],
    //  };

    let escrow_contract_address = context.get_contracts_info().get(ESCROW_CONTRACT_NAME).expect("no contacr info").contract_address.clone();
    println!("XXXXXXXXXXXXX: {:?}", &escrow_contract_address);

    let add_admin_msg = super::super::contract::sv::ExecMsg::AddAdmin { new_admin: "c4e13pq6693n69hfznt33u8d6zkszpy5nq4ucj0f5s".to_string() };
    
    let msg = json!(add_admin_msg).to_string();
    println!("Message: {msg}");

    let result = context.get_chain_client().tx.wasm().execute_contract_msg(&key, &escrow_contract_address, &msg, vec![]);
    
    if result.is_err() {
        assert_eq!("Generic error: Querier contract error: Did document not found", result.err().unwrap().to_string());
    } else {
        assert!(result.is_ok(), "Expected Ok, but got an Err");
        
    }
    // let query_msg = super::super::contract::sv::QueryMsg::GetDidDocument { did: did.to_string() };
    // let query = json!(query_msg).to_string();
    // println!("Query: {query}");
    // let result = context.chain.query.contract(&context.contract_address, &query);
    // assert!(result.is_ok(), "Expected Ok, but got an Err");
    // let result = result.unwrap();

    // let resp = String::from_utf8(result.data).expect("parse result error");
    // println!("Resposne: {resp}");
    // let resp_did_doc: DidDocument= serde_json::from_str(&resp).expect("desrializing did doc error");
    // assert_eq!(did_doc.clone(), resp_did_doc);


    // }
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
    println!(r#"GGGGGGGGGGGGG: {{"admins": ["{}"], "did_contract": "{}"}}"#, &owner_addr, did_contract_address);

    e2e_test_suite::add_contract(CONTRACT_CREATOR_MNEMONIC, HD_PATH, ESCROW_CONTRACT_NAME, 
        ContractInit {
            contract_path: ESCROW_CONTRACT_PATH.to_string(), 
            json_ncoded_init_args: format!(r#"{{"admins": ["{}"], "did_contract": "{}"}}"#, &owner_addr, did_contract_address), 
            label: "escrow_contract".to_string()
        }
    );
    let context: std::sync::RwLockReadGuard<'_, e2e_test_suite::TestSuiteContextInternal> = e2e_test_suite::get_context();
    println!("WWWWWWWWWWWWWWWWWW: {:?}", context.get_contracts_info());

    
}

fn create_key_and_address() -> (SigningKey, String){
    let key = derive_private_key_from_mnemonic(CONTRACT_CREATOR_MNEMONIC,    HD_PATH).expect("create key error");
    let address = key.public_key().account_id(ADDR_PREFIX).expect("cannot create address").to_string();
    (key, address)
}
