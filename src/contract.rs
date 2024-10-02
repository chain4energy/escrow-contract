use cosmwasm_std::{coins, Addr, Coin, Decimal, Order, Response, StdError, StdResult};
use cw_storage_plus::{Bound, Map, MultiIndex};
use sylvia::{contract, entry_points};
use sylvia::types::{InstantiateCtx, QueryCtx, ExecCtx};
use crate::error::ContractError;
use crate::state::{escrows, Escrow, EscrowOperator, EscrowState};
use did_contract::contract::DidContract;
use did_contract::state::DidDocument;
use did_contract::contract::sv::Querier;
use sylvia::types::Remote;

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
pub struct EscrowContract {
    pub(crate) operators: Map<String, EscrowOperator>,
    // pub(crate) escrows: escrows()
}

#[entry_points]
#[contract]
#[sv::error(ContractError)]
impl EscrowContract {
    pub const fn new() -> Self {
        Self {
            operators: Map::new("operators"),
        }
    }

    #[sv::msg(instantiate)]
    pub fn instantiate(&self, _ctx: InstantiateCtx) -> StdResult<Response> {
        Ok(Response::default())
    }

    #[sv::msg(query)]
    pub fn get_did(&self, ctx: QueryCtx, addr: Addr, did: String) -> Result<DidDocument, ContractError> {

        let result = Remote::<DidContract>::new(addr).querier(&ctx.deps.querier)
                .get_did_document(did);
        match result {
            Ok(r) => Ok(r),
            Err(e) => Err(ContractError::EscrowError(e)),
        }        
    }

    #[sv::msg(query)]
    pub fn get_escrow_operator(&self, ctx: QueryCtx, operator_id: String) -> Result<EscrowOperator, ContractError> {

        let result = self.operators.load(ctx.deps.storage, operator_id);
        match result {
            Ok(did_document) => Ok(did_document),
            Err(e) => match e {
                StdError::NotFound{ .. } => Err(ContractError::EscrowOperatorNotFound(e)),
                _ => Err(ContractError::EscrowOperatorError(e)),
            },
        }
    }

    #[sv::msg(query)]
    pub fn get_escrow(&self, ctx: QueryCtx, escrow_id: String) -> Result<Escrow, ContractError> {

        let result = escrows().load(ctx.deps.storage, escrow_id.as_str());
        match result {
            Ok(did_document) => Ok(did_document),
            Err(e) => match e {
                StdError::NotFound{ .. } => Err(ContractError::EscrowNotFound(e)),
                _ => Err(ContractError::EscrowError(e)),
            },
        }
    }

    #[sv::msg(query)]
    pub fn get_escrow_by_operator(&self, ctx: QueryCtx, operator_id: String, limit: Option<usize>, start_after: Option<String>) -> Result<Vec<(String, Escrow)>, ContractError> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let start = start_after.map(Bound::exclusive);

        let res: Result<Vec<_>, _> = escrows()
        .idx
        .operator
        .prefix(operator_id)
        .range(ctx.deps.storage, start, None, Order::Ascending)
        .take(limit)
        .collect();

        match res {
            Ok(did_document) => Ok(did_document),
            Err(e) => match e {
                StdError::NotFound{ .. } => Err(ContractError::EscrowOperatorNotFound(e)),
                _ => Err(ContractError::EscrowOperatorError(e)),
            },
        }

    }

    #[sv::msg(exec)]
    pub fn create_operator(&self, ctx: ExecCtx, operator_id: String) -> Result<Response, ContractError> {
        if self.operators.has(ctx.deps.storage, operator_id.to_string()) {
            return Err(ContractError::OperatorAlreadyExists);
        }

        let escrow: EscrowOperator = EscrowOperator {
            id: operator_id,
            controller: vec![]

        };
        let r = self.operators.save(ctx.deps.storage, escrow.id.clone(), &escrow);
        match r {
            Ok(_) => Ok(Response::default()),
            Err(e) => Err(ContractError::EscrowOperatorError(e))
        }
    }

    #[sv::msg(exec)]
    pub fn create_escrow(&self, ctx: ExecCtx, escrow_id: String, operator_id: String, receiver: String, expected_coins: Vec<Coin>, receiver_share: Decimal) -> Result<Response, ContractError> {
        let escrows = escrows();

        if !self.operators.has(ctx.deps.storage, operator_id.to_string()) {
            return Err(ContractError::OperatorNotExists);
        }

        if escrows.has(ctx.deps.storage, escrow_id.as_str()) {
            return Err(ContractError::EscrowAlreadyExists);
        }

        // TODO check if operator is signer

        // TODO validate receiver_share <0, 1>

        let escrow = Escrow {
            id: escrow_id,
            operator_id: operator_id,
            expected_coins: expected_coins.clone(),
            loaded_coins: None,
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            receiver_share: receiver_share,
            used_coins: vec![],
            state: EscrowState::Loading,
        };
        let r = escrows.save(ctx.deps.storage, &escrow.id.as_str(), &escrow);
        match r {
            Ok(_) => Ok(Response::default()),
            Err(e) => Err(ContractError::EscrowOperatorError(e))
        }
    }

    // #[sv::msg(exec)]
    // pub fn update_did_document(&self, ctx: ExecCtx, new_did_doc: DidDocument) -> Result<Response, ContractError> {
    //     let did_doc = self.did_docs.load(ctx.deps.storage, new_did_doc.id.to_string());
    //     let did_doc = match did_doc {
    //         Ok(did_document) => did_document,
    //         Err(e) => return match e {
    //             StdError::NotFound{ .. } => Err(ContractError::EscrowOperatorNotFound(e)),
    //             _ => Err(ContractError::EscrowOperatorError(e)),
    //         },
    //     };
    //     let sender = ctx.info.sender.to_string(); // Get sender's address as a string
    //     let sender = Did::new_address(sender.as_str());
    //     if !did_doc.has_controller(&sender) {
    //         return Err(ContractError::DidDocumentWrongOwner);
    //     }

    //     let r = self.did_docs.save(ctx.deps.storage, new_did_doc.id.to_string(), &new_did_doc);
    //     match r {
    //         Ok(_) => Ok(Response::default()),
    //         Err(e) => Err(ContractError::EscrowOperatorError(e))
    //     }
    // }

    // #[sv::msg(exec)]
    // pub fn add_controller(&self, ctx: ExecCtx, did: String, controller: Did) -> Result<Response, ContractError> {
    //     let did_doc = self.did_docs.load(ctx.deps.storage, did);
    //     let mut did_doc = match did_doc {
    //         Ok(did_document) => did_document,
    //         Err(e) => return match e {
    //             StdError::NotFound{ .. } => Err(ContractError::EscrowOperatorNotFound(e)),
    //             _ => Err(ContractError::EscrowOperatorError(e)),
    //         },
    //     };
    //     let sender = ctx.info.sender.to_string(); // Get sender's address as a string
    //     let sender = Did::new_address(sender.as_str());
    //     if !did_doc.has_controller(&sender) {
    //         return Err(ContractError::DidDocumentWrongOwner);
    //     }

    //     if did_doc.has_controller(&controller) {
    //         return Err(ContractError::DidDocumentControllerAlreadyExists);
    //     }

    //     did_doc.controller.push(controller);

    //     let r = self.did_docs.save(ctx.deps.storage, did_doc.id.to_string(), &did_doc);
    //     match r {
    //         Ok(_) => Ok(Response::default()),
    //         Err(e) => Err(ContractError::EscrowOperatorError(e))
    //     }
    // }

    // #[sv::msg(exec)]
    // pub fn delete_controller(&self, ctx: ExecCtx, did: String, controller: Did) -> Result<Response, ContractError> {
    //     let did_doc = self.did_docs.load(ctx.deps.storage, did);
    //     let mut did_doc = match did_doc {
    //         Ok(did_document) => did_document,
    //         Err(e) => return match e {
    //             StdError::NotFound{ .. } => Err(ContractError::EscrowOperatorNotFound(e)),
    //             _ => Err(ContractError::EscrowOperatorError(e)),
    //         },
    //     };
    //     let sender = ctx.info.sender.to_string(); // Get sender's address as a string
    //     let sender = Did::new_address(sender.as_str());
    //     if !did_doc.has_controller(&sender) {
    //         return Err(ContractError::DidDocumentWrongOwner);
    //     }

    //     if !did_doc.has_controller(&controller) {
    //         return Err(ContractError::DidDocumentControllerNotExists);
    //     }

    //     did_doc.controller.retain(|s| *s != controller);

    //     let r = self.did_docs.save(ctx.deps.storage, did_doc.id.to_string(), &did_doc);
    //     match r {
    //         Ok(_) => Ok(Response::default()),
    //         Err(e) => Err(ContractError::EscrowOperatorError(e))
    //     }
    // }

    // pub fn add_service(&self, ctx: ExecCtx, did: String, service: Service) -> Result<Response, ContractError> {
    //     let did_doc = self.did_docs.load(ctx.deps.storage, did);
    //     let mut did_doc = match did_doc {
    //         Ok(did_document) => did_document,
    //         Err(e) => return match e {
    //             StdError::NotFound{ .. } => Err(ContractError::EscrowOperatorNotFound(e)),
    //             _ => Err(ContractError::EscrowOperatorError(e)),
    //         },
    //     };
    //     let sender = ctx.info.sender.to_string(); // Get sender's address as a string
    //     let sender = Did::new_address(sender.as_str());
    //     if !did_doc.has_controller(&sender) {
    //         return Err(ContractError::DidDocumentWrongOwner);
    //     }

    //     if did_doc.has_service(&service.id) {
    //         return Err(ContractError::DidDocumentServiceAlreadyExists);
    //     }

    //     did_doc.service.push(service);

    //     let r = self.did_docs.save(ctx.deps.storage, did_doc.id.to_string(), &did_doc);
    //     match r {
    //         Ok(_) => Ok(Response::default()),
    //         Err(e) => Err(ContractError::EscrowOperatorError(e))
    //     }
    // }

    // pub fn delete_service(&self, ctx: ExecCtx, did: String, service_did: Did) -> Result<Response, ContractError> {
    //     let did_doc = self.did_docs.load(ctx.deps.storage, did);
    //     let mut did_doc = match did_doc {
    //         Ok(did_document) => did_document,
    //         Err(e) => return match e {
    //             StdError::NotFound{ .. } => Err(ContractError::EscrowOperatorNotFound(e)),
    //             _ => Err(ContractError::EscrowOperatorError(e)),
    //         },
    //     };
    //     let sender = ctx.info.sender.to_string(); // Get sender's address as a string
    //     let sender = Did::new_address(sender.as_str());
    //     if !did_doc.has_controller(&sender) {
    //         return Err(ContractError::DidDocumentWrongOwner);
    //     }

    //     if !did_doc.has_service(&service_did) {
    //         return Err(ContractError::DidDocumentServiceNotExists);
    //     }

    //     did_doc.service.retain(|s| s.id != service_did);

    //     let r = self.did_docs.save(ctx.deps.storage, did_doc.id.to_string(), &did_doc);
    //     match r {
    //         Ok(_) => Ok(Response::default()),
    //         Err(e) => Err(ContractError::EscrowOperatorError(e))
    //     }
    // }

    // #[sv::msg(exec)]
    // pub fn delete_did_document(&self, ctx: ExecCtx, did: String) -> Result<Response, ContractError> {
    //      // Load the DID document from storage
    //     let did_doc = self.did_docs.load(ctx.deps.storage, (&did).clone());
    //     let did_doc = match did_doc {
    //         Ok(did_document) => did_document,
    //         Err(e) => return match e {
    //             StdError::NotFound{ .. } => Err(ContractError::EscrowOperatorNotFound(e)),
    //             _ => Err(ContractError::EscrowOperatorError(e)),
    //         },
    //     };

    //     // Ensure the sender is the controller
    //     let sender = ctx.info.sender.to_string(); // Get sender's address as a string
    //     let sender = Did::new_address(sender.as_str());
        
    //     if did_doc.has_controller(&sender) {
    //         // If sender is the controller, remove the DID document
    //         self.did_docs.remove(ctx.deps.storage, did);
    //         Ok(Response::default()) // TODO add some informations
    //     } else {
    //         // Return an error if the sender is not the controller
    //         Err(ContractError::DidDocumentWrongOwner)
    //     }
    // }
    
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cosmwasm_std::{Coin, Decimal};
    use sylvia::cw_multi_test::IntoAddr;
    use sylvia::multitest::App;

    use crate::{contract::sv::mt::{CodeId, EscrowContractProxy}, state::{Escrow, EscrowOperator, EscrowState}/* , state::{Did, DidDocument, Service}*/};

    use did_contract::contract::{sv::mt::CodeId as DidContractCodeId, sv::mt::DidContractProxy, DidContract};
    use did_contract::state::{DidDocument, Did, Service};
    
    // #[test]
    // fn get_document_not_found() {
    //     let app = App::default();
    //     let code_id = CodeId::store_code(&app);
    
    //     let owner = "owner".into_addr();
    
    //     let contract = code_id.instantiate().call(&owner).unwrap();
    
    //     let did = "did";
    //     let no_did = contract.get_did_document(did.to_string());
    //     assert!(no_did.is_err(), "Expected Err, but got an Ok");
    //     assert_eq!("Generic error: Querier contract error: Did document not found", no_did.err().unwrap().to_string());
    // }

    // #[test]
    // fn create_and_get_document() {
    //     let app = App::default();
    //     let code_id = CodeId::store_code(&app);
    
    //     let owner = "owner".into_addr();
    
    //     let contract = code_id.instantiate().call(&owner).unwrap();
    
    //     // let did_owner = "did_owner";
    //     let did = "new_did";
    //     let new_did_doc = DidDocument{
    //         id: Did::new(did),
    //         controller: vec![Did::new(owner.as_str())],
    //         service: vec![Service{
    //             a_type: "".to_string(),
    //             id: Did::new("dfdsfs"),
    //             service_endpoint: "dfdsfs".to_string()
    //         }]
    //     };
    //     let result = contract.create_did_document(new_did_doc.clone()).call(&owner);
    //     assert!(result.is_ok(), "Expected Ok, but got an Err");

    //     let did_document = contract.get_did_document(did.to_string()).unwrap();
    //     assert_eq!(new_did_doc.clone(), did_document.clone());
    // }

    #[test]
    fn get_did_not_found_TEMPORARY() {
        let app = App::default();
        let owner = "owner".into_addr();

        let escrow_code_id = CodeId::store_code(&app);
        let escrow_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, crate::contract::EscrowContract> = escrow_code_id.instantiate().call(&owner).unwrap();
    
        let did_code_id = DidContractCodeId::store_code(&app);
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        
        let did = "did";
        let no_did = escrow_contract.get_did(did_contract.contract_addr, did.to_string());
        assert!(no_did.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Generic error: Querier contract error: Escrow error", no_did.err().unwrap().to_string());
    }

    #[test]
    fn create_and_get_document_TEMPORARY() {
        let app = App::default();
        let owner = "owner".into_addr();

        let escrow_code_id = CodeId::store_code(&app);
        let escrow_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, crate::contract::EscrowContract> = escrow_code_id.instantiate().call(&owner).unwrap();
    
        let did_code_id = DidContractCodeId::store_code(&app);
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        
        let did = "new_did";
        let new_did_doc = DidDocument{
            id: Did::new(did),
            controller: vec![Did::new(owner.as_str())],
            service: vec![Service{
                a_type: "".to_string(),
                id: Did::new("dfdsfs"),
                service_endpoint: "dfdsfs".to_string()
            }]
        };
        let result = did_contract.create_did_document(new_did_doc.clone()).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let did_document = escrow_contract.get_did(did_contract.contract_addr, did.to_string()).unwrap();
        assert_eq!(new_did_doc.clone(), did_document.clone());
    }

    #[test]
    fn get_operator_not_found() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
    
        let owner = "owner".into_addr();
    
        let contract = code_id.instantiate().call(&owner).unwrap();
    
        let operator = "operator-1";
        let no_did = contract.get_escrow_operator(operator.to_string());
        assert!(no_did.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Generic error: Querier contract error: Escrow operator not found", no_did.err().unwrap().to_string());
    }

    #[test]
    fn create_and_get_operator() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
    
        let owner = "owner".into_addr();
    
        let contract = code_id.instantiate().call(&owner).unwrap();
    
        let operator = "operator-1";
        let result = contract.create_operator(operator.to_string()).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow_operator = contract.get_escrow_operator(operator.to_string()).unwrap();
        assert_eq!(EscrowOperator{
            id: operator.to_string(),
            controller: vec![]
        }, escrow_operator.clone());
    }

    #[test]
    fn get_escrow_not_found() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
    
        let owner = "owner".into_addr();
    
        let contract = code_id.instantiate().call(&owner).unwrap();
    
        let escrow = "escrow-1";
        let no_did = contract.get_escrow(escrow.to_string());
        assert!(no_did.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Generic error: Querier contract error: Escrow not found", no_did.err().unwrap().to_string());
    }

    #[test]
    fn get_escrow_by_operator_empty() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
    
        let owner = "owner".into_addr();
    
        let contract = code_id.instantiate().call(&owner).unwrap();
    
        let escrow = "escrow-1";
        let escrows = contract.get_escrow_by_operator(escrow.to_string(), None, None);
        assert!(escrows.is_ok(), "Expected Ok, but got an Err");
        assert_eq!(0, escrows.unwrap().len())
    }

    #[test]
    fn create_escrow_no_operator() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
    
        let owner = "owner".into_addr();
    
        let contract = code_id.instantiate().call(&owner).unwrap();
    
        // pub fn create_escrow(&self, ctx: ExecCtx, escrow_id: String, operator_id: String, receiver: String, expected_coins: Vec<Coin>, receiver_share: Decimal) -> Result<Response, ContractError> {

        let operator = "operator-1";
        let escrow = "escrow-1";
        let receiver = "receiver-1";
        let expected_coins = vec![Coin::new(123u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = contract.create_escrow(escrow.to_string(), operator.to_string(), receiver.to_string(), expected_coins, share).call(&owner);
        assert!(result.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Operator does not extist", result.err().unwrap().to_string());

    }

    #[test]
    fn create_and_get_escrow() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
    
        let owner = "owner".into_addr();
    
        let contract = code_id.instantiate().call(&owner).unwrap();
    
        let operator = "operator-1";
        let result = contract.create_operator(operator.to_string()).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");
        let escrow = "escrow-1";
        let receiver = "receiver-1";
        let expected_coins = vec![Coin::new(123u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = contract.create_escrow(escrow.to_string(), operator.to_string(), receiver.to_string(), expected_coins.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow_operator = contract.get_escrow(escrow.to_string());
        assert!(escrow_operator.is_ok(), "Expected Ok, but got an Err");
        let escrow_operator = escrow_operator.unwrap();
        assert_eq!(
            Escrow {
                id: escrow.to_string(),
                operator_id: operator.to_string(),
                expected_coins: expected_coins.clone(),
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver.to_string(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
            }, 
            escrow_operator.clone(),
        );

        let escrow_operators = contract.get_escrow_by_operator(operator.to_string(), None, None);
        assert!(escrow_operators.is_ok(), "Expected Ok, but got an Err");
        let escrow_operators = escrow_operators.unwrap();
        assert_eq!(1, escrow_operators.len());

        let escrow_operator: Option<&(String, Escrow)> = escrow_operators.get(0);
        assert_eq!(true, escrow_operator.is_some());
        let (id, escrow_operator)= escrow_operator.unwrap();
        assert_eq!(escrow, id);


        assert_eq!(
            Escrow {
                id: escrow.to_string(),
                operator_id: operator.to_string(),
                expected_coins: expected_coins,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver.to_string(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
            }, 
            escrow_operator.clone(),
        );
    }

    #[test]
    fn get_escrow_by_operator_index() {
        let app = App::default();
        let code_id = CodeId::store_code(&app);
    
        let owner = "owner".into_addr();
    
        let contract = code_id.instantiate().call(&owner).unwrap();
    
        let operator1 = "operator-1";
        let result = contract.create_operator(operator1.to_string()).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let operator2 = "operator-2";
        let result = contract.create_operator(operator2.to_string()).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let operator3 = "operator-3";
        let result = contract.create_operator(operator3.to_string()).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 1 escrows
        let escrow1 = "escrow-1";
        let receiver1: &str = "receiver-1";
        let expected_coins1 = vec![Coin::new(123u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = contract.create_escrow(escrow1.to_string(), operator1.to_string(), receiver1.to_string(), expected_coins1.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow2 = "escrow-2";
        let expected_coins2 = vec![Coin::new(13u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = contract.create_escrow(escrow2.to_string(), operator1.to_string(), receiver1.to_string(), expected_coins2.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 2 escrows

        let escrow3 = "escrow-3";
        let expected_coins3 = vec![Coin::new(1293u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = contract.create_escrow(escrow3.to_string(), operator2.to_string(), receiver1.to_string(), expected_coins3.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow4 = "escrow-4";
        let expected_coins4 = vec![Coin::new(77u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = contract.create_escrow(escrow4.to_string(), operator2.to_string(), receiver1.to_string(), expected_coins4.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 3 escrows

        let escrow5 = "escrow-5";
        let expected_coins5 = vec![Coin::new(1293u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = contract.create_escrow(escrow5.to_string(), operator3.to_string(), receiver1.to_string(), expected_coins5.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow6 = "escrow-6";
        let expected_coins6 = vec![Coin::new(77u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = contract.create_escrow(escrow6.to_string(), operator3.to_string(), receiver1.to_string(), expected_coins6.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 1 escrows check

        let escrow_operators = contract.get_escrow_by_operator(operator1.to_string(), None, None);
        assert!(escrow_operators.is_ok(), "Expected Ok, but got an Err");
        let escrow_operators = escrow_operators.unwrap();
        assert_eq!(2, escrow_operators.len());

        let escrow_operator: Option<&(String, Escrow)> = escrow_operators.get(0);
        assert_eq!(true, escrow_operator.is_some());
        let (id, escrow_operator)= escrow_operator.unwrap();
        assert_eq!(escrow1, id);

        assert_eq!(
            Escrow {
                id: escrow1.to_string(),
                operator_id: operator1.to_string(),
                expected_coins: expected_coins1,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
            }, 
            escrow_operator.clone(),
        );

        let escrow_operator: Option<&(String, Escrow)> = escrow_operators.get(1);
        assert_eq!(true, escrow_operator.is_some());
        let (id, escrow_operator)= escrow_operator.unwrap();
        assert_eq!(escrow2, id);

        assert_eq!(
            Escrow {
                id: escrow2.to_string(),
                operator_id: operator1.to_string(),
                expected_coins: expected_coins2,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
            }, 
            escrow_operator.clone(),
        );

        // opertor 2 escrows check

        let escrow_operators = contract.get_escrow_by_operator(operator2.to_string(), None, None);
        assert!(escrow_operators.is_ok(), "Expected Ok, but got an Err");
        let escrow_operators = escrow_operators.unwrap();
        assert_eq!(2, escrow_operators.len());

        let escrow_operator: Option<&(String, Escrow)> = escrow_operators.get(0);
        assert_eq!(true, escrow_operator.is_some());
        let (id, escrow_operator)= escrow_operator.unwrap();
        assert_eq!(escrow3, id);

        assert_eq!(
            Escrow {
                id: escrow3.to_string(),
                operator_id: operator2.to_string(),
                expected_coins: expected_coins3,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
            }, 
            escrow_operator.clone(),
        );

        let escrow_operator: Option<&(String, Escrow)> = escrow_operators.get(1);
        assert_eq!(true, escrow_operator.is_some());
        let (id, escrow_operator)= escrow_operator.unwrap();
        assert_eq!(escrow4, id);

        assert_eq!(
            Escrow {
                id: escrow4.to_string(),
                operator_id: operator2.to_string(),
                expected_coins: expected_coins4,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
            }, 
            escrow_operator.clone(),
        );

        // opertor 3 escrows check

        let escrow_operators = contract.get_escrow_by_operator(operator3.to_string(), None, None);
        assert!(escrow_operators.is_ok(), "Expected Ok, but got an Err");
        let escrow_operators = escrow_operators.unwrap();
        assert_eq!(2, escrow_operators.len());

        let escrow_operator: Option<&(String, Escrow)> = escrow_operators.get(0);
        assert_eq!(true, escrow_operator.is_some());
        let (id, escrow_operator)= escrow_operator.unwrap();
        assert_eq!(escrow5, id);

        assert_eq!(
            Escrow {
                id: escrow5.to_string(),
                operator_id: operator3.to_string(),
                expected_coins: expected_coins5,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
            }, 
            escrow_operator.clone(),
        );

        let escrow_operator: Option<&(String, Escrow)> = escrow_operators.get(1);
        assert_eq!(true, escrow_operator.is_some());
        let (id, escrow_operator)= escrow_operator.unwrap();
        assert_eq!(escrow6, id);

        assert_eq!(
            Escrow {
                id: escrow6.to_string(),
                operator_id: operator3.to_string(),
                expected_coins: expected_coins6,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
            }, 
            escrow_operator.clone(),
        );
    }

    // #[test]
    // fn replacing_document() {
    //     let app = App::default();
    //     let code_id = CodeId::store_code(&app);
    
    //     let owner = "owner".into_addr();
    
    //     let contract = code_id.instantiate().call(&owner).unwrap();
    
    //     // let did_owner = "did_owner";
    //     let did = "new_did";
    //     let mut new_did_doc = DidDocument{
    //         id: Did::new(did),
    //         controller: vec![Did::new(owner.as_str())],
    //         service: vec![Service{
    //             a_type: "".to_string(),
    //             id: Did::new("dfdsfs"),
    //             service_endpoint: "dfdsfs".to_string()
    //         }]
    //     };
    //     let mut result = contract.create_did_document(new_did_doc.clone()).call(&owner);
    //     assert!(result.is_ok(), "Expected Ok, but got an Err");

    //     new_did_doc = DidDocument{
    //         id: Did::new(did),
    //         controller: vec![Did::new(owner.as_str())],
    //         service: vec![Service{
    //             a_type: "".to_string(),
    //             id: Did::new("AAAA"),
    //             service_endpoint: "BBBBB".to_string()
    //         }]
    //     };

    //     result = contract.create_did_document(new_did_doc.clone()).call(&owner);
    //     assert!(result.is_err(), "Expected Err, but got an Ok");
    //     assert_eq!("Did document already exists", result.err().unwrap().to_string());
    // }

    // #[test]
    // fn delete_did_document_not_found() {
    //     let app = App::default();
    //     let code_id = CodeId::store_code(&app);
    
    //     let owner = "owner".into_addr();
    
    //     let contract = code_id.instantiate().call(&owner).unwrap();
    
    //     let did = "did";
    //     let no_did = contract.delete_did_document(did.to_string()).call(&owner);
    //     assert!(no_did.is_err(), "Expected Err, but got an Ok");
    //     assert_eq!("Did document not found", no_did.err().unwrap().to_string());
    // }


    // #[test]
    // fn delete_did_document() {
    //     let app = App::default();
    //     let code_id = CodeId::store_code(&app);
    
    //     // let did_owner = "did_owner";
    //     let owner_addr = "did_owner".into_addr();
    
    //     let contract = code_id.instantiate().call(&owner_addr).unwrap();
    
    //     // let did_owner = "did_owner";
    //     let did = "new_did";
    //     let new_did_doc = DidDocument{
    //         id: Did::new(did),
    //         controller: vec![Did::new_address(owner_addr.as_str())],
    //         service: vec![Service{
    //             a_type: "".to_string(),
    //             id: Did::new("dfdsfs"),
    //             service_endpoint: "dfdsfs".to_string()
    //         }]
    //     };
    //     let result = contract.create_did_document(new_did_doc.clone()).call(&owner_addr);
    //     assert!(result.is_ok(), "Expected Ok, but got an Err");

    //     let did_document = contract.get_did_document(did.to_string()).unwrap();
    //     assert_eq!(new_did_doc.clone(), did_document.clone());

    //     let result = contract.delete_did_document(did.to_string()).call(&owner_addr);
    //     assert!(result.is_ok(), "Expected Ok, but got an Err");

    //     let result = contract.get_did_document(did.to_string());
    //     assert!(result.is_err(), "Expected Err, but got an Ok");
    //     assert_eq!("Generic error: Querier contract error: Did document not found", result.err().unwrap().to_string());
    // }

    // #[test]
    // fn delete_did_document_wrong_owner() {
    //     let app = App::default();
    //     let code_id = CodeId::store_code(&app);
    
    //     // let did_owner = "did_owner";
    //     let owner_addr = "did_owner".into_addr();
    //     let wrong_owner_addr = "wrong_did_owner".into_addr();

    //     let contract = code_id.instantiate().call(&owner_addr).unwrap();
    
    //     // let did_owner = "did_owner";
    //     let did = "new_did";
    //     let new_did_doc = DidDocument{
    //         id: Did::new(did),
    //         controller: vec![Did::new_address(owner_addr.as_str())],
    //         service: vec![Service{
    //             a_type: "".to_string(),
    //             id: Did::new("dfdsfs"),
    //             service_endpoint: "dfdsfs".to_string()
    //         }]
    //     };
    //     let result = contract.create_did_document(new_did_doc.clone()).call(&owner_addr);
    //     assert!(result.is_ok(), "Expected Ok, but got an Err");

    //     let did_document = contract.get_did_document(did.to_string()).unwrap();
    //     assert_eq!(new_did_doc.clone(), did_document.clone());

    //     let result = contract.delete_did_document(did.to_string()).call(&wrong_owner_addr);
    //     assert!(result.is_err(), "Expected Err, but got an Ok");
    //     assert_eq!("Did document - wrong owner", result.err().unwrap().to_string());

    // }
}
