use std::fmt::Error;

use cosmwasm_std::{coins, from_json, to_json_binary, Addr, AllBalanceResponse, Api, Coin, Coins, Decimal, Deps, Event, Order, Reply, Response, StdError, StdResult, Storage, SubMsgResponse, SubMsgResult};
use cw_storage_plus::{Bound, Item, Map, MultiIndex};
use sylvia::{contract, entry_points};
use sylvia::types::{ExecCtx, InstantiateCtx, QueryCtx, ReplyCtx};
use crate::error::ContractError;
use crate::state::{escrows, CoinsExt, Escrow, EscrowController, EscrowOperator, EscrowState, Escrows, LoadedCoins, Share};
use did_contract::contract::DidContract;
use did_contract::state::{Controller, Did, DidDocument};
use did_contract::contract::sv::Querier;
use sylvia::types::Remote;
use cosmwasm_std::{SubMsg, BankMsg,  CosmosMsg, ReplyOn};
use cosmwasm_std::{BankQuery, QueryRequest, BalanceResponse,  Uint128};


const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
pub struct EscrowContract {
    // pub(crate) 
    pub admins: Item<Vec<Addr>>, // Think if can be did_contract controller, but what if did contract does not exist, can it be admined then? will error break contract?
    pub did_contract: Item<Addr>, 
    pub operators: Map<String, EscrowOperator>,
    // pub(crate) escrows: escrows()
}

#[entry_points]
#[contract]
#[sv::error(ContractError)]
impl EscrowContract {
    pub const fn new() -> Self {
        Self {
            admins: Item::new("admins"),
            did_contract: Item::new("did_contract"),
            operators: Map::new("operators"),
        }
    }

    #[sv::msg(instantiate)]
    pub fn instantiate(&self, ctx: InstantiateCtx, admins: Vec<Addr> , did_contract: Addr) ->  Result<Response, ContractError> {
        self.save_admins(ctx.deps.storage, &admins)?;
        self.save_did_contract_address(ctx.deps.storage, &did_contract)?;
        Ok(Response::default())
    }

    // ---- Admins ------

    #[sv::msg(exec)]
    pub fn add_admin(&self, ctx: ExecCtx, new_admin: String) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        let new_admin = self.ensure_valid_admin(ctx.deps.api, new_admin)?;
        
        let mut admins: Vec<Addr> = self.admins.load(ctx.deps.storage)?;
        self.ensure_unique_admins(&admins, &new_admin)?;

        admins.push(new_admin.clone());
        self.admins.save(ctx.deps.storage, &admins)?;

        let event = Event::new("add_admin")
            .add_attribute("executor", ctx.info.sender.to_string())
            .add_attribute("new_admin", new_admin.to_string());

        Ok(Response::new()
            .add_attribute("action", "add_admin")
            .add_attribute("new_admin", new_admin.to_string())
            .add_event(event))
    }


    #[sv::msg(exec)]
    pub fn remove_admin(&self, ctx: ExecCtx, admin_to_remove: String) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        let admin = self.ensure_valid_admin(ctx.deps.api, admin_to_remove)?;

        let mut admins = self.admins.load(ctx.deps.storage)?;

        if let Some(pos) = admins.iter().position(|x| x == &admin) {
            admins.remove(pos);
            self.admins.save(ctx.deps.storage, &admins)?;

            Ok(Response::new()
                .add_attribute("action", "remove_admin")
                .add_attribute("removed_admin", admin.to_string()))
        } else {
            Err(ContractError::AdminNotFound())
        }
    }

    // ---- Escrow Operators ------

    #[sv::msg(exec)]
    pub fn create_operator(&self, ctx: ExecCtx, operator_id: String, controllers: Vec<Controller>) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;
        for c in &controllers {
            c.ensure_valid(ctx.deps.api)?;
            // TODO ensure controller existence, add that qeury to did contract
            // TODO implemnt in did contract possibility to register did usage, to block did document removal if did is used.
        }
        self.ensure_operator_not_overwritten(ctx.deps.storage, &operator_id)?;

        let escrow: EscrowOperator = EscrowOperator {
            id: operator_id,
            controller: controllers,
            enabled: true
        };

        escrow.ensure_controller()?;
        let did_contract = self.did_contract.load(ctx.deps.storage)?;

        escrow.ensure_controller_exist(ctx.deps.as_ref(), &did_contract)?;
        match self.operators.save(ctx.deps.storage, escrow.id.clone(), &escrow) {
            Ok(_) => Ok(Response::default()),
            Err(e) => Err(ContractError::EscrowOperatorError(e))
        }
    }

    #[sv::msg(exec)]
    pub fn remove_operator(&self, ctx: ExecCtx, operator_id: String) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        self.ensure_operator_exists(ctx.deps.storage, &operator_id)?;
        // TODO ensure no escrow exists for this operator
        // TODO implemnt in did contract possibility to unregister did usage, to block did document removal if did is used.

        self.operators.remove(ctx.deps.storage, operator_id.clone());
        Ok(Response::default())
    }

    #[sv::msg(exec)]
    pub fn disable_operator(&self, ctx: ExecCtx, operator_id: String) -> Result<Response, ContractError> {
        self.enable_disable_operator(ctx, operator_id, false)
    }

    #[sv::msg(exec)]
    pub fn enable_operator(&self, ctx: ExecCtx, operator_id: String) -> Result<Response, ContractError> {
        self.enable_disable_operator(ctx, operator_id, true)
    }

    #[sv::msg(exec)]
    pub fn add_operator_controller(&self, ctx: ExecCtx, operator_id: String, controller: Controller) -> Result<Response, ContractError> {
        controller.ensure_valid(ctx.deps.api)?;
        let did_contract = self.did_contract.load(ctx.deps.storage)?;
        let mut operator = self.operators.load(ctx.deps.storage, operator_id.clone())?;
        self.authorize_admin_or_operator(ctx.deps.as_ref(), &did_contract ,&ctx.info.sender, &operator)?;

        // TODO ensure controller existence, add that qeury to did contract
        // TODO implemnt in did contract possibility to register did usage, to block did document removal if did is used.
        
        controller.ensure_exist(ctx.deps.as_ref(), &did_contract)?;

        operator.controller.push(controller);

        match self.operators.save(ctx.deps.storage, operator.id.clone(), &operator) {
            Ok(_) => Ok(Response::default()),
            Err(e) => Err(ContractError::EscrowOperatorError(e))
        }
    }

    #[sv::msg(exec)]
    pub fn delete_operator_controller(&self, ctx: ExecCtx, operator_id: String, controller: Controller) -> Result<Response, ContractError> {
        controller.ensure_valid(ctx.deps.api)?;
        let did_contract = self.did_contract.load(ctx.deps.storage)?;
        let mut operator = self.operators.load(ctx.deps.storage, operator_id.clone())?;
        self.authorize_admin_or_operator(ctx.deps.as_ref(), &did_contract ,&ctx.info.sender, &operator)?;

        // TODO implemnt in did contract possibility to unregister did usage, to block did document removal if did is used.

        if !operator.has_controller(&controller) {
            return Err(ContractError::DidDocumentControllerNotExists);
        }

        // did_doc.controller.mut_controllers().retain(|s| *s != controller);
        operator.controller.retain(|s| *s != controller);
        operator.ensure_controller()?;

        match self.operators.save(ctx.deps.storage, operator.id.clone(), &operator) {
            Ok(_) => Ok(Response::default()),
            Err(e) => Err(ContractError::EscrowOperatorError(e))
        }

    }

    // -- Escrow

    #[sv::msg(exec)]
    pub fn create_escrow(&self, ctx: ExecCtx, escrow_id: String, operator_id: String, receiver: Controller, expected_coins: Vec<Coin>, receiver_share: Decimal) -> Result<Response, ContractError> {
        // TODO is oparator enabled
        
        receiver.ensure_valid(ctx.deps.api)?;
        let did_contract = self.did_contract.load(ctx.deps.storage)?;
        let operator = self.operators.load(ctx.deps.storage, operator_id.clone())?; // TODO ensure operator exists and if not return ContractError::OperatorNotExists)
        self.authorize_admin_or_operator(ctx.deps.as_ref(), &did_contract ,&ctx.info.sender, &operator)?;
        
        let escrows = escrows();
        escrows.ensure_not_exist(ctx.deps.storage, escrow_id.as_str())?;

        receiver_share.ensure_in_range()?;
        let expected_coins = Coins::deduplicated_coins(expected_coins)?;
        // TODO some expected coins validation: > 0, at least 1 denom

        let escrow = Escrow {
            id: escrow_id,
            operator_id: operator_id,
            expected_coins: expected_coins.into_vec(),
            loaded_coins: None,
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: vec![],
            state: EscrowState::Loading,
            lock_timestamp: None

        };

       
        let r = escrows.save(ctx.deps.storage, &escrow.id.as_str(), &escrow);
        match r {
            Ok(_) => Ok(Response::default()),
            Err(e) => Err(ContractError::EscrowOperatorError(e))
        }
    }


    #[sv::msg(exec)]
    pub fn load_escrow(&self, ctx: ExecCtx, escrow_id: String) -> Result<Response, ContractError> {
        // TODO ensure valid coins
        let escrows = escrows();
        let mut escrow = escrows.load(ctx.deps.storage, &escrow_id)?;
        escrow.ensure_state(EscrowState::Loading)?;
        // TODO ensure coins equal expected coins

        // ensure coins are on user account  - TODO make method
        let balance_query = QueryRequest::Bank(BankQuery::AllBalances { 
            address: ctx.info.sender.to_string(), 
        });
        let balance: AllBalanceResponse = ctx.deps.querier.query(&balance_query)?;
        let balance = Coins::try_from(balance.amount)?;
        let loaded_coins = Coins::deduplicated_coins(ctx.info.funds.clone())?;

        for coin in &loaded_coins {
            let available_amount = balance.amount_of(&coin.denom);
            
            if available_amount < coin.amount {
                return Err(ContractError::InsufficientFunds {
                    denom: coin.denom.clone(),
                    required: coin.amount,
                    available: available_amount,
                });
            }
        }

        escrow.loaded_coins = Some(LoadedCoins{
            coins: loaded_coins.to_vec(),
            loader: ctx.info.sender.to_string()
        }); 
        escrow.lock_timestamp = Some(ctx.env.block.time);
        escrow.state = EscrowState::Locked;

        if let Err(e) = escrows.save(ctx.deps.storage, &escrow.id.as_str(), &escrow) { // TODO ?????? save on success bank send bacause from doc: 
                                                                                       // On error the submessage execution will revert any partial state changes due to this message, 
                                                                                       // but not revert any state changes in the calling contract. If this is required, 
                                                                                       // it must be done manually in the reply entry point.
            return Err(ContractError::EscrowOperatorError(e))
        }
        // match escrows.save(ctx.deps.storage, &escrow.id.as_str(), &escrow) {
        //     Ok(_) => Ok(Response::default()),
        //     Err(e) => Err(ContractError::EscrowOperatorError(e))
        // }
        
        let msg = CosmosMsg::Bank(BankMsg::Send {
            to_address: ctx.env.contract.address.to_string(),
            amount: ctx.info.funds,
        });

        
        // let sub_msg = SubMsg::reply_on_error(msg, LOAD_ESCROW_BANK_SEND).with_payload(payload);

        Ok(Response::new()
            // .add_submessage(sub_msg)
            .add_message(msg)
            .add_attribute("action", "send_coins"))
    }

    #[sv::msg(exec)]  // TODO use standard api of sending fund to contract
    pub fn release_escrow(&self, ctx: ExecCtx, escrow_id: String, used_coins: Vec<Coin>) -> Result<Response, ContractError> {
        // TODO ensure valid coins
        let escrows = escrows();
        let mut escrow = escrows.load(ctx.deps.storage, &escrow_id)?;
        escrow.ensure_state(EscrowState::Locked)?;
        // TODO check if timeout not passed

        let used_coins = Coins::deduplicated_coins(used_coins)?;

        escrow.used_coins = used_coins.to_vec(); 
        escrow.state = EscrowState::Released; 
        let expected = Coins::try_from(escrow.expected_coins.clone())?;
        if used_coins == expected {
            escrow.loader_claimed = true
        }

        if let Err(e) = escrows.save(ctx.deps.storage, &escrow.id.as_str(), &escrow) { 
            return Err(ContractError::EscrowOperatorError(e))
        }

        Ok(Response::new())
    }

    #[sv::msg(exec)]
    pub fn withdraw(&self, ctx: ExecCtx, escrow_id: String) -> Result<Response, ContractError> {
        
        let escrows = escrows();
        let mut escrow = escrows.load(ctx.deps.storage, &escrow_id)?;
        escrow.ensure_state(EscrowState::Released)?;

        let mut resp = Response::default();
        if !escrow.loader_claimed {
            println!("Withdrawing loader check");
            if let Some(l) = &escrow.loaded_coins {
                if l.loader == ctx.info.sender.to_string() { // TODO or admin
                    println!("Withdrawing - is loader");
                    let mut ec: Coins = Coins::try_from(escrow.expected_coins.clone())?;
                    for c in &escrow.used_coins {
                        ec.sub(c.clone())?;
                    }

                    let msg = CosmosMsg::Bank(BankMsg::Send {
                        to_address: l.loader.to_string(),
                        amount: ec.into_vec(),
                    });
                    resp = resp.add_message(msg);
                    escrow.loader_claimed = true;
                }
            }
        }

        if !escrow.receiver_claimed || !escrow.operator_claimed{
            println!("Withdrawing - receiver or operator");
            let did_contract = self.did_contract.load(ctx.deps.storage)?;
            let sender: Controller = ctx.info.sender.to_string().into();
           
            let receiver_share = escrow.receiver_share;
           
            let mut receiver_coins: Vec<Coin> = Vec::new();
            for c in &escrow.used_coins {
                let used =  Decimal::try_from(c.amount);
                if let Err(e) = used {
                    return Err(ContractError::SomeError); // TODO specific error
                }
                let receiver_amount = receiver_share.checked_mul(used.unwrap()); // Calculate share for each coin
                if let Err(e) = receiver_amount {
                    return Err(ContractError::SomeError); // TODO specific error
                }
                let receiver_amount = receiver_amount.unwrap();
                println!("receiver amount: {receiver_amount}");
                receiver_coins.push(Coin {
                    denom: c.denom.clone(),
                    amount: receiver_amount.to_uint_ceil(), // This will be the receiver's portion of this coin
                });
            }

            if !escrow.receiver_claimed {
                if Remote::<DidContract>::new(did_contract.clone()).querier(&ctx.deps.querier).is_controller_of(vec![escrow.receiver.clone()], sender.clone())? {
                    println!("Withdrawing - is receiver");
                    let msg = CosmosMsg::Bank(BankMsg::Send {
                        to_address: ctx.info.sender.to_string(),
                        amount: receiver_coins.clone(),
                    });
                    println!("Withdrawing - receiver {}", receiver_coins[0].amount);
                    resp = resp.add_message(msg);
                    escrow.receiver_claimed = true;
                }
            }

            if !escrow.operator_claimed {

                let operator = self.operators.load(ctx.deps.storage, escrow.operator_id.clone())?;
                let mut uc: Coins = Coins::try_from(escrow.used_coins.clone())?;
                for c in receiver_coins {
                    uc.sub(c)?;
                }

                if Remote::<DidContract>::new(did_contract.clone()).querier(&ctx.deps.querier).is_controller_of(operator.controller, sender)? {
                    println!("Withdrawing - is operator");
                    let msg = CosmosMsg::Bank(BankMsg::Send {
                        to_address: ctx.info.sender.to_string(),
                        amount: uc.to_vec(),
                    });
                    println!("Withdrawing - operator {}", uc.into_vec()[0].amount);

                    resp = resp.add_message(msg);
                    escrow.operator_claimed = true;
                }
            }
        }

        // escrow.used_coins = used_coins; 
        if escrow.receiver_claimed && escrow.loader_claimed && escrow.operator_claimed {
            escrow.state = EscrowState::Closed; 
        }
        

        if let Err(e) = escrows.save(ctx.deps.storage, &escrow.id.as_str(), &escrow) { 
            return Err(ContractError::EscrowOperatorError(e))
        }

        Ok(resp)
    }

    // #[sv::msg(reply)]
    // fn reply(&self, ctx: ReplyCtx, reply: Reply) -> Result<Response, ContractError> {
    //     match reply.id {
    //         LOAD_ESCROW_BANK_SEND => {
    //             match reply.result {
    //                 SubMsgResult::Ok(_) => Ok(Response::default()),
    //                 SubMsgResult::Err(e) => { // TODO what to do with error string??
    //                     let escrow: Escrow = from_json(reply.payload)?;
    //                     let escrows = escrows();
    //                     if let Err(e) = escrows.save(ctx.deps.storage, &escrow.id.as_str(), &escrow) {
    //                         return Err(ContractError::EscrowError(e)) // TODO check how to handle it, is send coins rolled back?
    //                     }
    //                     Ok(Response::default())
    //                 }                    
    //             }
    //         }
    //         _ => Err(ContractError::SomeError), // TODO  specify error
    //     }
    // }
    // -------


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

    fn save_admins(&self, storage: &mut dyn Storage, admins: &Vec<Addr>) ->  Result<(), ContractError> {
        let result = self.admins.save(storage, admins);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(ContractError::EscrowError(e)) //  TODO specific error
        }
    }

    fn save_did_contract_address(&self, storage: &mut dyn Storage, did_contract: &Addr) ->  Result<(), ContractError> {
        let result = self.did_contract.save(storage, did_contract);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(ContractError::EscrowError(e)) //  TODO specific error
        }
    }

    fn is_admin(&self, deps: Deps, sender: &Addr) -> Result<bool, ContractError> {
        let admins = self.admins.may_load(deps.storage); // TODO handle error
        match admins {
            Ok(admins) => {
                if let Some(admin_list) = admins {
                    // Check if the sender is one of the admins
                    Ok(admin_list.contains(sender))
                } else {
                    Ok(false)
                }
            },
            Err(e) => Err(ContractError::EscrowError(e))
        }
    }

    fn authorize_admin(&self, deps: Deps, sender: &Addr) -> Result<(), ContractError> {
        if !self.is_admin(deps, sender)? {
            return Err(ContractError::Unauthorized());
        }
        Ok(())
    }

    fn authorize_admin_or_operator(&self, deps: Deps, did_contract: &Addr, sender: &Addr, operator: &EscrowOperator) -> Result<(), ContractError> {
        if let Err(_) =  self.authorize_admin(deps, sender) {
            operator.authorize(deps, &did_contract, sender)?;
        }
        Ok(())
    }

    fn ensure_valid_admin(&self, api: &dyn Api, admin: String) -> Result<Addr, ContractError> {
        let addr = api.addr_validate(&admin)?;
        Ok(addr)
    }

    fn ensure_unique_admins(&self, admins: &Vec<Addr>, new_admin: &Addr) -> Result<(), ContractError> {
        if admins.contains(new_admin) {
            Err(ContractError::AdminAlreadyExists())
        } else {
            Ok (())
        }
    }

    fn ensure_operator_not_overwritten(&self, store: &dyn Storage, operator_id: &str) -> Result<(), ContractError> {
        if self.operators.has(store, operator_id.to_string()) {
            return Err(ContractError::OperatorAlreadyExists);
        }
        Ok(())
    }

    fn ensure_operator_exists(&self, store: &dyn Storage, operator_id: &str) -> Result<(), ContractError> {
        if !self.operators.has(store, operator_id.to_string()) {
            return Err(ContractError::OperatorDoesNotExist);
        }
        Ok(())
    }

    fn enable_disable_operator(&self, ctx: ExecCtx, operator_id: String, enabled: bool) -> Result<Response, ContractError> {
        let mut operator = self.operators.load(ctx.deps.storage, operator_id.clone())?;
        let did_contract = self.did_contract.load(ctx.deps.storage)?;

        self.authorize_admin_or_operator(ctx.deps.as_ref(), &did_contract, &ctx.info.sender, &operator)?;

        operator.enabled = enabled;

        self.operators.save(ctx.deps.storage, operator_id.clone(),  &operator)?;
        Ok(Response::default())
    }
}

// const LOAD_ESCROW_BANK_SEND: u64 = 1;

#[cfg(test)] 
mod tests {
    use std::str::FromStr;

    use cosmwasm_std::{Coin, Decimal};
    use cw_multi_test::IntoAddr;
    use sylvia::multitest::App;

    use did_contract::contract::{sv::mt::CodeId as DidContractCodeId, sv::mt::DidContractProxy, DidContract};
    use did_contract::state::{Controller, Did, DidDocument, Service};

    use crate::state::LoadedCoins;
    use crate::{contract::sv::mt::{CodeId, EscrowContractProxy}, state::{Escrow, EscrowOperator, EscrowState}};


    // -------------------- Admin tests 
    #[test]
    fn test_add_admin() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

        let admin1 = "admin1".into_addr();

        let res = escrow_contract
            .add_admin(admin1.to_string()).call(&owner).expect("error adding admin");

        assert_eq!(res.events[0].ty, "execute");
        assert_eq!(res.events[0].attributes[0].key, "_contract_address");
        assert_eq!(res.events[0].attributes[0].value, escrow_contract.contract_addr.to_string());
        
        assert_eq!(res.events[1].ty, "wasm");
        assert_eq!(res.events[1].attributes[0].key, "_contract_address");
        assert_eq!(res.events[1].attributes[0].value, escrow_contract.contract_addr.to_string());
        assert_eq!(res.events[1].attributes[1].key, "action");
        assert_eq!(res.events[1].attributes[1].value, "add_admin");
        assert_eq!(res.events[1].attributes[2].key, "new_admin");
        assert_eq!(res.events[1].attributes[2].value, admin1.to_string());

        assert_eq!(res.events[2].ty, "wasm-add_admin");
        assert_eq!(res.events[2].attributes[0].key, "_contract_address");
        assert_eq!(res.events[2].attributes[0].value, escrow_contract.contract_addr.to_string());
        assert_eq!(res.events[2].attributes[1].key, "executor");
        assert_eq!(res.events[2].attributes[1].value, owner.to_string());
        assert_eq!(res.events[2].attributes[2].key, "new_admin");
        assert_eq!(res.events[2].attributes[2].value, admin1.to_string());

        let non_admin1 = "non_admin".into_addr();
        let admin2 = "admin2".into_addr();
        let res = escrow_contract
            .add_admin(admin2.to_string()).call(&non_admin1);

        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Unauthorized", res.err().unwrap().to_string());

        let admin3 = "admin3".into_addr();

        escrow_contract
            .add_admin(admin3.to_string()).call(&admin1).expect("error adding admin3");
    }

    #[test]
    fn test_remove_admin() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);
    
        let owner = "owner".into_addr();
        
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();
    
        let admin1 = "admin1".into_addr();
    
        // First, add an admin to remove later
        escrow_contract
            .add_admin(admin1.to_string()).call(&owner).expect("error adding admin1");
    
        // Remove the admin
        let res = escrow_contract
            .remove_admin(admin1.to_string()).call(&owner).expect("error removing admin");
    
        // Validate the response attributes and events
        assert_eq!(res.events[0].ty, "execute");
        assert_eq!(res.events[0].attributes[0].key, "_contract_address");
        assert_eq!(res.events[0].attributes[0].value, escrow_contract.contract_addr.to_string());
    
        assert_eq!(res.events[1].ty, "wasm");
        assert_eq!(res.events[1].attributes[0].key, "_contract_address");
        assert_eq!(res.events[1].attributes[0].value, escrow_contract.contract_addr.to_string());
        assert_eq!(res.events[1].attributes[1].key, "action");
        assert_eq!(res.events[1].attributes[1].value, "remove_admin");
        assert_eq!(res.events[1].attributes[2].key, "removed_admin");
        assert_eq!(res.events[1].attributes[2].value, admin1.to_string());
    
        // Test removing a non-existing admin
        let non_admin = "non_admin".into_addr();
        let res = escrow_contract
            .remove_admin(non_admin.to_string()).call(&owner);
        
        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Admin not found", res.err().unwrap().to_string());
    
        // Test unauthorized removal attempt
        let unauthorized_user = "unauthorized".into_addr();
        let another_admin = "admin2".into_addr();
        
        // Add a second admin to test unauthorized removal
        escrow_contract
            .add_admin(another_admin.to_string()).call(&owner).expect("error adding admin2");
    
        let res = escrow_contract
            .remove_admin(another_admin.to_string()).call(&unauthorized_user);
    
        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Unauthorized", res.err().unwrap().to_string());
    }

    // -------------------- Operator
    #[test]
    fn test_create_operator() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

        // Test creating a valid operator
        let controller1: Controller = "controller1".into_addr().to_string().into();
        let controller2: Controller = "controller2".into_addr().to_string().into();

        let res = escrow_contract
            .create_operator("operator1".to_string(), vec![controller1.clone(), controller2.clone()])
            .call(&owner)
            .expect("error creating operator");

        // Validate the response
        assert_eq!(res.events[0].ty, "execute");
        assert_eq!(res.events[0].attributes[0].key, "_contract_address");
        assert_eq!(res.events[0].attributes[0].value, escrow_contract.contract_addr.to_string());

        // assert_eq!(res.events[1].ty, "wasm");
        // assert_eq!(res.events[1].attributes[0].key, "_contract_address");
        // assert_eq!(res.events[1].attributes[0].value, escrow_contract.contract_addr.to_string());
        // assert_eq!(res.events[1].attributes[1].key, "action");
        // assert_eq!(res.events[1].attributes[1].value, "create_operator");

        // Test trying to overwrite an existing operator
        let res = escrow_contract
            .create_operator("operator1".to_string(), vec![controller1.clone()])
            .call(&owner);

        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Operator already exists", res.err().unwrap().to_string());

        // Test invalid controller (assuming we have some validation that fails in Controller.ensure_valid)
        let invalid_controller: Controller = "invalid_controller".into();  // Assume this controller fails validation
        let res = escrow_contract
            .create_operator("operator2".to_string(), vec![invalid_controller.clone()])
            .call(&owner);

        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Controller format error", res.err().unwrap().to_string());

        // Test unauthorized creation attempt
        let unauthorized_user = "unauthorized_user".into_addr();
        let res = escrow_contract
            .create_operator("operator3".to_string(), vec![controller1.clone()])
            .call(&unauthorized_user);

        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Unauthorized", res.err().unwrap().to_string());
    }

    #[test]
    fn test_remove_operator() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

        // Add an operator to remove later
        let controller1: Controller = "controller1".into_addr().to_string().into();
        let operator_id = "operator1".to_string();

        escrow_contract
            .create_operator(operator_id.clone(), vec![controller1.clone()])
            .call(&owner)
            .expect("error creating operator");

        // Remove the operator successfully
        let res = escrow_contract
            .remove_operator(operator_id.clone())
            .call(&owner)
            .expect("error removing operator");

        // Validate the response attributes and events
        assert_eq!(res.events[0].ty, "execute");
        assert_eq!(res.events[0].attributes[0].key, "_contract_address");
        assert_eq!(res.events[0].attributes[0].value, escrow_contract.contract_addr.to_string());

        // Attempt to remove the same operator again, expecting an error
        let res = escrow_contract
            .remove_operator(operator_id.clone())
            .call(&owner);

        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Operator does not exist", res.err().unwrap().to_string());

        // Test unauthorized removal attempt
        let unauthorized_user = "unauthorized_user".into_addr();
        let operator_id2 = "operator2".to_string();

        // Add a second operator
        escrow_contract
            .create_operator(operator_id2.clone(), vec![controller1.clone()])
            .call(&owner)
            .expect("error creating operator2");

        // Unauthorized user tries to remove operator
        let res = escrow_contract
            .remove_operator(operator_id2.clone())
            .call(&unauthorized_user);

        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Unauthorized", res.err().unwrap().to_string());
    }

    #[test]
    fn test_disable_operator() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);
    
        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();
    
        // Add an operator to disable later
        let controller1: Controller = "controller1".into_addr().to_string().into();
        let operator_id = "operator1".to_string();
    
        escrow_contract
            .create_operator(operator_id.clone(), vec![controller1.clone()])
            .call(&owner)
            .expect("error creating operator");
    
        // Disable the operator
        let res = escrow_contract
            .disable_operator(operator_id.clone())
            .call(&owner)
            .expect("error disabling operator");
    
        // Validate the response attributes and events
        assert_eq!(res.events[0].ty, "execute");
        assert_eq!(res.events[0].attributes[0].key, "_contract_address");
        assert_eq!(res.events[0].attributes[0].value, escrow_contract.contract_addr.to_string());
    
        // assert_eq!(res.events[1].ty, "wasm");
        // assert_eq!(res.events[1].attributes[0].key, "_contract_address");
        // assert_eq!(res.events[1].attributes[0].value, escrow_contract.contract_addr.to_string());
        // assert_eq!(res.events[1].attributes[1].key, "action");
        // assert_eq!(res.events[1].attributes[1].value, "disable_operator");
        // assert_eq!(res.events[1].attributes[2].key, "operator_id");
        // assert_eq!(res.events[1].attributes[2].value, operator_id);
        // assert_eq!(res.events[1].attributes[3].key, "enabled");
        // assert_eq!(res.events[1].attributes[3].value, "false");
    
        // Verify the operator is actually disabled
        let operator = escrow_contract
            .get_escrow_operator(operator_id.clone())
            .expect("error querying operator");
        assert_eq!(operator.enabled, false);
    
        // Attempt to disable a non-existent operator, expecting an error
        let non_existent_operator = "non_existent_operator".to_string();
        let res = escrow_contract
            .disable_operator(non_existent_operator)
            .call(&owner);
    
        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("type: escrow_contract::state::EscrowOperator; key: [00, 09, 6F, 70, 65, 72, 61, 74, 6F, 72, 73, 6E, 6F, 6E, 5F, 65, 78, 69, 73, 74, 65, 6E, 74, 5F, 6F, 70, 65, 72, 61, 74, 6F, 72] not found", res.err().unwrap().to_string());
    
        // Test unauthorized disable attempt
        let unauthorized_user = "unauthorized_user".into_addr();
        let res = escrow_contract
            .disable_operator(operator_id.clone())
            .call(&unauthorized_user);
    
        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Unauthorized", res.err().unwrap().to_string());
    }

    #[test]
    fn test_enable_operator() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);
    
        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();
    
        // Add an operator and disable it first
        let controller1: Controller = "controller1".into_addr().to_string().into();
        let operator_id = "operator1".to_string();
    
        escrow_contract
            .create_operator(operator_id.clone(), vec![controller1.clone()])
            .call(&owner)
            .expect("error creating operator");
    
        escrow_contract
            .disable_operator(operator_id.clone())
            .call(&owner)
            .expect("error disabling operator");
    
        let operator = escrow_contract
            .get_escrow_operator(operator_id.clone())
            .expect("error querying operator");
        assert_eq!(operator.enabled, false);

        // Enable the operator
        let res = escrow_contract
            .enable_operator(operator_id.clone())
            .call(&owner)
            .expect("error enabling operator");
    
        // Validate the response attributes and events
        assert_eq!(res.events[0].ty, "execute");
        assert_eq!(res.events[0].attributes[0].key, "_contract_address");
        assert_eq!(res.events[0].attributes[0].value, escrow_contract.contract_addr.to_string());
    
        // assert_eq!(res.events[1].ty, "wasm");
        // assert_eq!(res.events[1].attributes[0].key, "_contract_address");
        // assert_eq!(res.events[1].attributes[0].value, escrow_contract.contract_addr.to_string());
        // assert_eq!(res.events[1].attributes[1].key, "action");
        // assert_eq!(res.events[1].attributes[1].value, "enable_operator");
        // assert_eq!(res.events[1].attributes[2].key, "operator_id");
        // assert_eq!(res.events[1].attributes[2].value, operator_id);
        // assert_eq!(res.events[1].attributes[3].key, "enabled");
        // assert_eq!(res.events[1].attributes[3].value, "true");
    
        // Verify the operator is actually enabled
        let operator = escrow_contract
            .get_escrow_operator(operator_id.clone())
            .expect("error querying operator");
        assert_eq!(operator.enabled, true);
    
        // Attempt to enable a non-existent operator, expecting an error
        let non_existent_operator = "non_existent_operator".to_string();
        let res = escrow_contract
            .enable_operator(non_existent_operator)
            .call(&owner);
    
        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("type: escrow_contract::state::EscrowOperator; key: [00, 09, 6F, 70, 65, 72, 61, 74, 6F, 72, 73, 6E, 6F, 6E, 5F, 65, 78, 69, 73, 74, 65, 6E, 74, 5F, 6F, 70, 65, 72, 61, 74, 6F, 72] not found", res.err().unwrap().to_string());
    
        // Test unauthorized enable attempt
        let unauthorized_user = "unauthorized_user".into_addr();
        let res = escrow_contract
            .enable_operator(operator_id.clone())
            .call(&unauthorized_user);
    
        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Unauthorized", res.err().unwrap().to_string());
    }

    #[test]
    fn test_add_operator_controller() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);
    
        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();
    
        // Add an operator
        let controller1: Controller = "controller1".into_addr().to_string().into();
        let operator_id = "operator1".to_string();
    
        escrow_contract
            .create_operator(operator_id.clone(), vec![controller1.clone()])
            .call(&owner)
            .expect("error creating operator");
    
        // Add a new controller to the operator
        let new_controller: Controller = "controller2".into_addr().to_string().into();
        
        let res = escrow_contract
            .add_operator_controller(operator_id.clone(), new_controller.clone())
            .call(&owner)
            .expect("error adding operator controller");
    
        // Validate the response attributes and events
        assert_eq!(res.events[0].ty, "execute");
        assert_eq!(res.events[0].attributes[0].key, "_contract_address");
        assert_eq!(res.events[0].attributes[0].value, escrow_contract.contract_addr.to_string());
    
        // assert_eq!(res.events[1].ty, "wasm");
        // assert_eq!(res.events[1].attributes[0].key, "_contract_address");
        // assert_eq!(res.events[1].attributes[0].value, escrow_contract.contract_addr.to_string());
        // assert_eq!(res.events[1].attributes[1].key, "action");
        // assert_eq!(res.events[1].attributes[1].value, "add_operator_controller");
        // assert_eq!(res.events[1].attributes[2].key, "operator_id");
        // assert_eq!(res.events[1].attributes[2].value, operator_id);
        // assert_eq!(res.events[1].attributes[3].key, "controller_id");
        // assert_eq!(res.events[1].attributes[3].value, new_controller.id.to_string());
    
        // Verify the operator has the new controller added
        let operator = escrow_contract
            .get_escrow_operator(operator_id.clone())
            .expect("error querying operator");
    
        assert!(operator.controller.iter().any(|c| *c == new_controller));
    
        // Attempt to add a controller to a non-existent operator
        let non_existent_operator = "non_existent_operator".to_string();
        let res = escrow_contract
            .add_operator_controller(non_existent_operator, new_controller.clone())
            .call(&owner);
    
        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("type: escrow_contract::state::EscrowOperator; key: [00, 09, 6F, 70, 65, 72, 61, 74, 6F, 72, 73, 6E, 6F, 6E, 5F, 65, 78, 69, 73, 74, 65, 6E, 74, 5F, 6F, 70, 65, 72, 61, 74, 6F, 72] not found", res.err().unwrap().to_string());
    
        // Test unauthorized addition of controller
        let unauthorized_user = "unauthorized_user".into_addr();
        let res = escrow_contract
            .add_operator_controller(operator_id.clone(), new_controller.clone())
            .call(&unauthorized_user);
    
        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Unauthorized", res.err().unwrap().to_string());
    }

    #[test]
    fn test_delete_operator_controller() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);
    
        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();
    
        // Add an operator
        let controller1: Controller = "controller1".into_addr().to_string().into();
        let controller2: Controller = "controller2".into_addr().to_string().into();
        let operator_id = "operator1".to_string();
    
        escrow_contract
            .create_operator(operator_id.clone(), vec![controller1.clone(), controller2.clone()])
            .call(&owner)
            .expect("error creating operator");
    
        // Delete an existing controller from the operator
        let res = escrow_contract
            .delete_operator_controller(operator_id.clone(), controller2.clone())
            .call(&owner)
            .expect("error deleting operator controller");
    
        // Validate the response attributes and events
        assert_eq!(res.events[0].ty, "execute");
        assert_eq!(res.events[0].attributes[0].key, "_contract_address");
        assert_eq!(res.events[0].attributes[0].value, escrow_contract.contract_addr.to_string());
    
        // assert_eq!(res.events[1].ty, "wasm");
        // assert_eq!(res.events[1].attributes[0].key, "_contract_address");
        // assert_eq!(res.events[1].attributes[0].value, escrow_contract.contract_addr.to_string());
        // assert_eq!(res.events[1].attributes[1].key, "action");
        // assert_eq!(res.events[1].attributes[1].value, "delete_operator_controller");
        // assert_eq!(res.events[1].attributes[2].key, "operator_id");
        // assert_eq!(res.events[1].attributes[2].value, operator_id);
        // assert_eq!(res.events[1].attributes[3].key, "controller_id");
        // assert_eq!(res.events[1].attributes[3].value, controller2.id.to_string());
    
        // Verify that the controller has been removed
        let operator = escrow_contract
            .get_escrow_operator(operator_id.clone())
            .expect("error querying operator");
    
        assert!(!operator.controller.iter().any(|c| *c == controller2));
    
        // Attempt to delete a non-existent controller from the operator
        let non_existent_controller: Controller = "non_existent_controller".into_addr().to_string().into();
        let res = escrow_contract
            .delete_operator_controller(operator_id.clone(), non_existent_controller)
            .call(&owner);
    
        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Did document controller not exist", res.err().unwrap().to_string());
    
        // Test unauthorized controller removal attempt
        let unauthorized_user = "unauthorized_user".into_addr();
        let res = escrow_contract
            .delete_operator_controller(operator_id.clone(), controller1.clone())
            .call(&unauthorized_user);
    
        assert!(res.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Unauthorized", res.err().unwrap().to_string());
    }

    // -------------------- Escrow

    #[test]
    fn test_create_escrow_success() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

        let op_controller_addr = "operatr_controller".into_addr();

        let op_controller: Controller = op_controller_addr.to_string().into();

        let res = escrow_contract
            .create_operator("operator1".to_string(), vec![op_controller.clone()])
            .call(&owner)
            .expect("error creating operator");

        let coin = Coin{
            denom: "uatom".to_string(),
            amount: 1000u128.into()
        };

        let receiver: Controller = "controller1".into_addr().to_string().into();
        let expected_coins = vec![coin];
        let receiver_share = Decimal::percent(50);

        let res = escrow_contract
            .create_escrow(
                "escrow1".to_string(),
                "operator1".to_string(),
                receiver.clone(),
                expected_coins.clone(),
                receiver_share,
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

        let escrow = escrow_contract.get_escrow("escrow1".to_string()).expect("getting escrow error");
        assert_eq!(Escrow {
            id: "escrow1".to_string(),
            operator_id: "operator1".to_string(),
            expected_coins: expected_coins.clone(),
            loaded_coins: None,
            operator_claimed: false,
            receiver: receiver,
            receiver_claimed: false,
            receiver_share: receiver_share,
            loader_claimed: false,
            used_coins: vec![],
            state: EscrowState::Loading,
            lock_timestamp: None

        }, escrow)
    }

    #[test]
    fn test_load_escrow() {
        let app: App<cw_multi_test::App> = App::default();

        let loader = "loader".into_addr();
        let loader_coin = Coin{
            denom: "uatom".to_string(),
            amount: 10000u128.into()
        };
        {
            let mut app_mut = app.app_mut();
            let a = app_mut.sudo(
                cw_multi_test::SudoMsg::Bank(
                    cw_multi_test::BankSudo::Mint { to_address: loader.to_string(), amount: vec![loader_coin] }
                )
            ).expect("error sudo");
        }
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

        let op_controller_addr = "operatr_controller".into_addr();

        let op_controller: Controller = op_controller_addr.to_string().into();

        let res = escrow_contract
            .create_operator("operator1".to_string(), vec![op_controller.clone()])
            .call(&owner)
            .expect("error creating operator");

        let controller: Controller = "controller1".into_addr().to_string().into();
        let coin = Coin{
            denom: "uatom".to_string(),
            amount: 1000u128.into()
        };

        let expected_coins = vec![coin.clone()];
        escrow_contract
            .create_escrow(
                "escrow1".to_string(),
                "operator1".to_string(),
                controller.clone(),
                expected_coins.clone(),
                Decimal::percent(50),
            )
            .call(&op_controller_addr)
            .expect("error creating escrow");


        
        // Attempt to load with insufficient funds
        let res = escrow_contract
            .load_escrow("escrow1".to_string())
            .with_funds(vec![coin.clone()].as_slice()) // Insufficient funds
            .call(&loader).expect("load_escrow error");

            let escrow = escrow_contract.get_escrow("escrow1".to_string()).expect("getting escrow error");
            assert_eq!(Escrow {
                id: "escrow1".to_string(),
                operator_id: "operator1".to_string(),
                expected_coins: expected_coins.clone(),
                loaded_coins: Some(LoadedCoins {
                    loader: loader.to_string(),
                    coins: expected_coins.clone()
                }),
                operator_claimed: false,
                receiver: controller.clone(),
                receiver_claimed: false,
                receiver_share: Decimal::percent(50),
                loader_claimed: false,
                used_coins: vec![],
                state: EscrowState::Locked,
                lock_timestamp: escrow.lock_timestamp
    
            }, escrow);

           let contract_coin = app.querier().query_balance(escrow_contract.contract_addr, &coin.denom).expect("error taking cntract coins");
           assert_eq!(coin, contract_coin);
    }

    #[test]
    fn test_release() {
        let app: App<cw_multi_test::App> = App::default();

        let loader = "loader".into_addr();
        let loader_coin = Coin{
            denom: "uatom".to_string(),
            amount: 10000u128.into()
        };
        {
            let mut app_mut = app.app_mut();
            let a = app_mut.sudo(
                cw_multi_test::SudoMsg::Bank(
                    cw_multi_test::BankSudo::Mint { to_address: loader.to_string(), amount: vec![loader_coin] }
                )
            ).expect("error sudo");
        }
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

        let op_controller_addr = "operatr_controller".into_addr();

        let op_controller: Controller = op_controller_addr.to_string().into();

        let res = escrow_contract
            .create_operator("operator1".to_string(), vec![op_controller.clone()])
            .call(&owner)
            .expect("error creating operator");

        let receiver: Controller = "controller1".into_addr().to_string().into();
        let coin = Coin{
            denom: "uatom".to_string(),
            amount: 1000u128.into()
        };

        let expected_coins = vec![coin.clone()];
        escrow_contract
            .create_escrow(
                "escrow1".to_string(),
                "operator1".to_string(),
                receiver.clone(),
                expected_coins.clone(),
                Decimal::percent(50),
            )
            .call(&op_controller_addr)
            .expect("error creating escrow");

        // Attempt to load 
        let res = escrow_contract
            .load_escrow("escrow1".to_string())
            .with_funds(vec![coin.clone()].as_slice())
            .call(&loader).expect("load_escrow error");

        let contract_coin = app.querier().query_balance(&escrow_contract.contract_addr, &coin.denom).expect("error taking cntract coins");
        assert_eq!(coin, contract_coin);

        // Attempt to release coins
        let rel_coin = Coin{
            denom: "uatom".to_string(),
            amount: 500u128.into()
        };

        let res = escrow_contract
            .release_escrow("escrow1".to_string(), vec![rel_coin.clone()])
            .call(&op_controller_addr).expect("load_escrow error");

        let escrow = escrow_contract.get_escrow("escrow1".to_string()).expect("getting escrow error");
            assert_eq!(Escrow {
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
                receiver_share: Decimal::percent(50),
                loader_claimed: false,
                used_coins: vec![rel_coin.clone()],
                state: EscrowState::Released,
                lock_timestamp: escrow.lock_timestamp
    
            }, escrow);

        let contract_coin = app.querier().query_balance(&escrow_contract.contract_addr, &coin.denom).expect("error taking cntract coins");
            assert_eq!(coin, contract_coin);
        let contract_coin = app.querier().query_balance(&loader, &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 9000u128.into()
            }, contract_coin);

        let contract_coin = app.querier().query_balance(receiver.to_string(), &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 0u128.into()
            }, contract_coin);

            let contract_coin = app.querier().query_balance(op_controller.to_string(), &coin.denom).expect("error taking cntract coins");
            assert_eq!(Coin{
                    denom: "uatom".to_string(),
                    amount: 0u128.into()
                }, contract_coin);
    }

    #[test]
    fn test_withdraw() {
        let app: App<cw_multi_test::App> = App::default();

        let loader = "loader".into_addr();
        let loader_coin = Coin{
            denom: "uatom".to_string(),
            amount: 10000u128.into()
        };
        {
            let mut app_mut = app.app_mut();
            let a = app_mut.sudo(
                cw_multi_test::SudoMsg::Bank(
                    cw_multi_test::BankSudo::Mint { to_address: loader.to_string(), amount: vec![loader_coin] }
                )
            ).expect("error sudo");
        }
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

        let op_controller_addr = "operatr_controller".into_addr();

        let op_controller: Controller = op_controller_addr.to_string().into();

        let res = escrow_contract
            .create_operator("operator1".to_string(), vec![op_controller.clone()])
            .call(&owner)
            .expect("error creating operator");

        let receiver_addr = "controller1".into_addr();
        let receiver: Controller = receiver_addr.to_string().into();
        let coin = Coin{
            denom: "uatom".to_string(),
            amount: 1000u128.into()
        };

        let expected_coins = vec![coin.clone()];
        escrow_contract
            .create_escrow(
                "escrow1".to_string(),
                "operator1".to_string(),
                receiver.clone(),
                expected_coins.clone(),
                Decimal::percent(50),
            )
            .call(&op_controller_addr)
            .expect("error creating escrow");

        // Attempt to load 
        let res = escrow_contract
            .load_escrow("escrow1".to_string())
            .with_funds(vec![coin.clone()].as_slice())
            .call(&loader).expect("load_escrow error");

        let contract_coin = app.querier().query_balance(&escrow_contract.contract_addr, &coin.denom).expect("error taking cntract coins");
        assert_eq!(coin, contract_coin);

        // Attempt to release coins
        let rel_coin = Coin{
            denom: "uatom".to_string(),
            amount: 500u128.into()
        };

        let res = escrow_contract
            .release_escrow("escrow1".to_string(), vec![rel_coin.clone()])
            .call(&op_controller_addr).expect("load_escrow error");

        let contract_coin = app.querier().query_balance(&escrow_contract.contract_addr, &coin.denom).expect("error taking cntract coins");
            assert_eq!(coin, contract_coin);
        let contract_coin = app.querier().query_balance(&loader, &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 9000u128.into()
            }, contract_coin);

        let contract_coin = app.querier().query_balance(receiver.to_string(), &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 0u128.into()
            }, contract_coin);

            let contract_coin = app.querier().query_balance(op_controller.to_string(), &coin.denom).expect("error taking cntract coins");
            assert_eq!(Coin{
                    denom: "uatom".to_string(),
                    amount: 0u128.into()
                }, contract_coin);

        // ---- Withdraw loader --

        let res = escrow_contract
            .withdraw("escrow1".to_string())
            .call(&loader).expect("withdraw loader error");

        let contract_coin = app.querier().query_balance(&escrow_contract.contract_addr, &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 500u128.into()
            }, contract_coin);
        let contract_coin = app.querier().query_balance(&loader, &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 9500u128.into()
            }, contract_coin);

        let contract_coin = app.querier().query_balance(receiver.to_string(), &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 0u128.into()
            }, contract_coin);

        let contract_coin = app.querier().query_balance(op_controller.to_string(), &coin.denom).expect("error taking cntract coins");
            assert_eq!(Coin{
                    denom: "uatom".to_string(),
                    amount: 0u128.into()
                }, contract_coin);


        let escrow = escrow_contract.get_escrow("escrow1".to_string()).expect("getting escrow error");
        assert_eq!(Escrow {
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
                receiver_share: Decimal::percent(50),
                loader_claimed: true,
                used_coins: vec![rel_coin.clone()],
                state: EscrowState::Released,
                lock_timestamp: escrow.lock_timestamp
    
            }, escrow);

        // ---- Withdraw oparator --

        let res = escrow_contract
            .withdraw("escrow1".to_string())
            .call(&op_controller_addr).expect("withdraw loader error");

        let contract_coin = app.querier().query_balance(&escrow_contract.contract_addr, &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 250u128.into()
            }, contract_coin);
        let contract_coin = app.querier().query_balance(&loader, &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 9500u128.into()
            }, contract_coin);

        let contract_coin = app.querier().query_balance(receiver.to_string(), &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 0u128.into()
            }, contract_coin);

        let contract_coin = app.querier().query_balance(op_controller.to_string(), &coin.denom).expect("error taking cntract coins");
            assert_eq!(Coin{
                    denom: "uatom".to_string(),
                    amount: 250u128.into()
                }, contract_coin);


        let escrow = escrow_contract.get_escrow("escrow1".to_string()).expect("getting escrow error");
        assert_eq!(Escrow {
                id: "escrow1".to_string(),
                operator_id: "operator1".to_string(),
                expected_coins: expected_coins.clone(),
                loaded_coins: Some(LoadedCoins {
                    loader: loader.to_string(),
                    coins: expected_coins.clone()
                }),
                operator_claimed: true,
                receiver: receiver.clone(),
                receiver_claimed: false,
                receiver_share: Decimal::percent(50),
                loader_claimed: true,
                used_coins: vec![rel_coin.clone()],
                state: EscrowState::Released,
                lock_timestamp: escrow.lock_timestamp
    
            }, escrow);

        // ---- Withdraw receiver --

        let res = escrow_contract
            .withdraw("escrow1".to_string())
            .call(&receiver_addr).expect("withdraw loader error");

        let contract_coin = app.querier().query_balance(&escrow_contract.contract_addr, &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 0u128.into()
            }, contract_coin);
        let contract_coin = app.querier().query_balance(&loader, &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 9500u128.into()
            }, contract_coin);

        let contract_coin = app.querier().query_balance(receiver.to_string(), &coin.denom).expect("error taking cntract coins");
        assert_eq!(Coin{
                denom: "uatom".to_string(),
                amount: 250u128.into()
            }, contract_coin);

        let contract_coin = app.querier().query_balance(op_controller.to_string(), &coin.denom).expect("error taking cntract coins");
            assert_eq!(Coin{
                    denom: "uatom".to_string(),
                    amount: 250u128.into()
                }, contract_coin);


        let escrow = escrow_contract.get_escrow("escrow1".to_string()).expect("getting escrow error");
        assert_eq!(Escrow {
                id: "escrow1".to_string(),
                operator_id: "operator1".to_string(),
                expected_coins: expected_coins.clone(),
                loaded_coins: Some(LoadedCoins {
                    loader: loader.to_string(),
                    coins: expected_coins.clone()
                }),
                operator_claimed: true,
                receiver: receiver.clone(),
                receiver_claimed: true,
                receiver_share: Decimal::percent(50),
                loader_claimed: true,
                used_coins: vec![rel_coin.clone()],
                state: EscrowState::Closed,
                lock_timestamp: escrow.lock_timestamp
    
            }, escrow);
        
    }

    #[test]
    fn get_operator_not_found() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

    
        let operator = "operator-1";
        let no_did = escrow_contract.get_escrow_operator(operator.to_string());
        assert!(no_did.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Generic error: Querier contract error: Escrow operator not found", no_did.err().unwrap().to_string());
    }

    #[test]
    fn get_escrow_not_found() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

        let escrow = "escrow-1";
        let no_did = escrow_contract.get_escrow(escrow.to_string());
        assert!(no_did.is_err(), "Expected Err, but got an Ok");
        assert_eq!("Generic error: Querier contract error: Escrow not found", no_did.err().unwrap().to_string());
    }

    #[test]
    fn get_escrow_by_operator_empty() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

        let escrow = "escrow-1";
        let escrows = escrow_contract.get_escrow_by_operator(escrow.to_string(), None, None);
        assert!(escrows.is_ok(), "Expected Ok, but got an Err");
        assert_eq!(0, escrows.unwrap().len())
    }

    #[test]
    fn create_escrow_no_operator() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();


        let operator = "operator-1";
        let escrow = "escrow-1";
        let receiver = "receiver-1".into_addr().to_string();
        let expected_coins = vec![Coin::new(123u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract.create_escrow(escrow.to_string(), operator.to_string(), receiver.into(), expected_coins, share).call(&owner);
        assert!(result.is_err(), "Expected Err, but got an Ok");
        assert_eq!("type: escrow_contract::state::EscrowOperator; key: [00, 09, 6F, 70, 65, 72, 61, 74, 6F, 72, 73, 6F, 70, 65, 72, 61, 74, 6F, 72, 2D, 31] not found", result.err().unwrap().to_string());

    }


    #[test]
    fn get_escrow_by_operator_index() {
        let app = App::default();
        let escrow_code_id = CodeId::store_code(&app);
        let did_code_id = DidContractCodeId::store_code(&app);

        let owner = "owner".into_addr();
        
        // Instantiate contracts
        let did_contract: sylvia::multitest::Proxy<'_, cw_multi_test::App, DidContract> = did_code_id.instantiate().call(&owner).unwrap();
        let escrow_contract = escrow_code_id.instantiate(vec![owner.clone()], did_contract.contract_addr).call(&owner).unwrap();

        let conrller = "cont1".into_addr().to_string();

        let operator1: &str = "operator-1";
        let result = escrow_contract.create_operator(operator1.to_string(), vec![conrller.clone().into()]).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let operator2 = "operator-2";
        let result = escrow_contract.create_operator(operator2.to_string(), vec![conrller.clone().into()]).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let operator3 = "operator-3";
        let result = escrow_contract.create_operator(operator3.to_string(), vec![conrller.clone().into()]).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 1 escrows
        let escrow1 = "escrow-1";
        let receiver1 = "receiver-1".into_addr();
        let expected_coins1 = vec![Coin::new(123u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract.create_escrow(escrow1.to_string(), operator1.to_string(), receiver1.to_string().into(), expected_coins1.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow2 = "escrow-2";
        let expected_coins2 = vec![Coin::new(13u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract.create_escrow(escrow2.to_string(), operator1.to_string(), receiver1.to_string().into(), expected_coins2.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 2 escrows

        let escrow3 = "escrow-3";
        let expected_coins3 = vec![Coin::new(1293u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract.create_escrow(escrow3.to_string(), operator2.to_string(), receiver1.to_string().into(), expected_coins3.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow4 = "escrow-4";
        let expected_coins4 = vec![Coin::new(77u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract.create_escrow(escrow4.to_string(), operator2.to_string(), receiver1.to_string().into(), expected_coins4.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 3 escrows

        let escrow5 = "escrow-5";
        let expected_coins5 = vec![Coin::new(1293u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract.create_escrow(escrow5.to_string(), operator3.to_string(), receiver1.to_string().into(), expected_coins5.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow6 = "escrow-6";
        let expected_coins6 = vec![Coin::new(77u64, "uc4e")];
        let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract.create_escrow(escrow6.to_string(), operator3.to_string(), receiver1.to_string().into(), expected_coins6.clone(), share).call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 1 escrows check

        let escrow_operators = escrow_contract.get_escrow_by_operator(operator1.to_string(), None, None);
        assert!(escrow_operators.is_ok(), "Expected Ok, but got an Err");
        let escrow_operators = escrow_operators.unwrap();
        assert_eq!(2, escrow_operators.len());

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(0);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator)= escrow.unwrap();
        assert_eq!(escrow1, id);

        assert_eq!(
            Escrow {
                id: escrow1.to_string(),
                operator_id: operator1.to_string(),
                expected_coins: expected_coins1,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string().into(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp
            }, 
            escrow_operator.clone(),
        );

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(1);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator)= escrow.unwrap();
        assert_eq!(escrow2, id);

        assert_eq!(
            Escrow {
                id: escrow2.to_string(),
                operator_id: operator1.to_string(),
                expected_coins: expected_coins2,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string().into(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp
            }, 
            escrow_operator.clone(),
        );

        // opertor 2 escrows check

        let escrow_operators = escrow_contract.get_escrow_by_operator(operator2.to_string(), None, None);
        assert!(escrow_operators.is_ok(), "Expected Ok, but got an Err");
        let escrow_operators = escrow_operators.unwrap();
        assert_eq!(2, escrow_operators.len());

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(0);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator)= escrow.unwrap();
        assert_eq!(escrow3, id);

        assert_eq!(
            Escrow {
                id: escrow3.to_string(),
                operator_id: operator2.to_string(),
                expected_coins: expected_coins3,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string().into(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp
            }, 
            escrow_operator.clone(),
        );

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(1);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator)= escrow.unwrap();
        assert_eq!(escrow4, id);

        assert_eq!(
            Escrow {
                id: escrow4.to_string(),
                operator_id: operator2.to_string(),
                expected_coins: expected_coins4,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string().into(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp
            }, 
            escrow_operator.clone(),
        );

        // opertor 3 escrows check

        let escrow_operators = escrow_contract.get_escrow_by_operator(operator3.to_string(), None, None);
        assert!(escrow_operators.is_ok(), "Expected Ok, but got an Err");
        let escrow_operators = escrow_operators.unwrap();
        assert_eq!(2, escrow_operators.len());

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(0);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator)= escrow.unwrap();
        assert_eq!(escrow5, id);

        assert_eq!(
            Escrow {
                id: escrow5.to_string(),
                operator_id: operator3.to_string(),
                expected_coins: expected_coins5,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string().into(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp
            }, 
            escrow_operator.clone(),
        );

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(1);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator)= escrow.unwrap();
        assert_eq!(escrow6, id);

        assert_eq!(
            Escrow {
                id: escrow6.to_string(),
                operator_id: operator3.to_string(),
                expected_coins: expected_coins6,
                loaded_coins: None,
                operator_claimed: false,
                receiver: receiver1.to_string().into(),
                receiver_claimed: false,
                receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp
            }, 
            escrow_operator.clone(),
        );
    }

}
