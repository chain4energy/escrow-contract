
// use cosmrs::crypto::secp256k1::SigningKey;
// use serde_json::json;
// use serial_test::serial;
// use e2e_test_suite::{ADDR_PREFIX, derive_private_key_from_mnemonic};

// use crate::state::DidDocument;

// const MENMONIC: &str = "harbor flee number sibling doll recycle brisk mask blanket orphan initial maze race flash limb sound wing ramp proud battle feature ceiling feel miss";
// const HD_PATH: &str = "m/44'/118'/0'/0/0";

// const CONTRACT_PATH: &str = "./artifacts/did_contract.wasm";

// #[test]
// #[serial]
// fn create_did_document() {
//     init_suite();
//     // setup_context();
//     println!("RUN create_did_document");

//     let context =  e2e_test_suite::CONTEXT.get().expect("Docker controller is not initialized");
//     let context = context.lock().expect("Failed to lock Docker controller");
    
//     let (key, address) = create_key_and_address();

//     // let msg = r#"{
//     //     "create_did_document": {
//     //         "did_doc": {
//     //             "id": "did:example:1234567890",
//     //             "controller": ["did:user:1234567890"],
//     //             "service": [
//     //                 {
//     //                     "id": "did:service:1234567890",
//     //                     "type": "type",
//     //                     "service_endpoint": "http://chargera.io"
//     //                 }
//     //             ]
//     //         }
//     //     }
//     // }"#;

//     let did = "did:example:000432";

//     let did_doc = DidDocument { 
//         id: crate::state::Did::new(did), 
//         controller: vec![crate::state::Did::new("did:user:000131")], 
//         service: vec![crate::state::Service{
//             id: crate::state::Did::new("did:service:000131"),
//             a_type: "Chargera".to_string(),
//             service_endpoint: "http://chargera.io".to_string()
//         }],
//      };

//     let create_msg = super::super::contract::sv::ExecMsg::CreateDidDocument { 
//         did_doc: did_doc.clone()
//     };
    
//     let msg = json!(create_msg).to_string();
//     println!("Message: {msg}");

//     let result = context.chain.tx.execute_contract_msg(&address, &context.contract_address, &msg, vec![], &key);
    
//     if result.is_err() {
//         assert_eq!("Generic error: Querier contract error: Did document not found", result.err().unwrap().to_string());
//     } else {
//         assert!(result.is_ok(), "Expected Ok, but got an Err");
        
//     }
//     let query_msg = super::super::contract::sv::QueryMsg::GetDidDocument { did: did.to_string() };
//     let query = json!(query_msg).to_string();
//     println!("Query: {query}");
//     let result = context.chain.query.contract(&context.contract_address, &query);
//     assert!(result.is_ok(), "Expected Ok, but got an Err");
//     let result = result.unwrap();

//     let resp = String::from_utf8(result.data).expect("parse result error");
//     println!("Resposne: {resp}");
//     let resp_did_doc: DidDocument= serde_json::from_str(&resp).expect("desrializing did doc error");
//     assert_eq!(did_doc.clone(), resp_did_doc);


//     // }
// }

// #[test]
// #[serial]
// fn my_test_2() {
//     init_suite();
//     println!("RUN TEST 2")
// }

// #[test]
// #[serial]
// fn my_test_3() {
//     init_suite();
//     // setup_context();
//     println!("RUN TEST 3");
// }

// fn init_suite() {
//     e2e_test_suite::init_suite(MENMONIC, HD_PATH, CONTRACT_PATH, "c4e-chain-e2e-test:v1.4.3", "did-contract", "did");
// }

// fn create_key_and_address() -> (SigningKey, String){
//     let key = derive_private_key_from_mnemonic(MENMONIC,    HD_PATH).expect("create key error");
//     let address = key.public_key().account_id(ADDR_PREFIX).expect("cannot create address").to_string();
//     (key, address)
// }
