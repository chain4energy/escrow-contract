use crate::error::ContractError;
use crate::multiset::MultiSet;
use crate::state::{
    escrows, CoinsExt, Escrow, EscrowController, EscrowOperator, EscrowState, Escrows, LoadedCoins,
};
use cosmwasm_std::{
    Addr, Api, BalanceResponse, Coin, Coins, Deps, Empty, Event, Order, Response, StdError,
    Storage, Timestamp, Uint128,
};
use cosmwasm_std::{BankMsg, CosmosMsg};
use cosmwasm_std::{BankQuery, QueryRequest};
use cw_storage_plus::{Bound, Item, Map};
use did_contract::contract::sv::Querier;
use did_contract::contract::DidContract;
use did_contract::state::{Controller, ToEventData};
use std::collections::HashSet;
use std::time::Duration;
use sylvia::ctx::{ExecCtx, InstantiateCtx, QueryCtx};
use sylvia::types::Remote;
use sylvia::{contract, entry_points};

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 200;
pub struct EscrowContract {
    // pub(crate)
    pub admins: Item<Vec<Addr>>, // Think if can be did_contract controller, but what if did contract does not exist, can it be admined then? will error break contract?
    pub did_contract: Item<Addr>,
    pub operators: Map<String, EscrowOperator>,
    pub load_timeout: Item<Duration>,
    pub release_timeout: Item<Duration>,
    // pub escrows: Map<String, Escrow>,
    pub to_withdraw_by_loader: MultiSet,
    pub to_withdraw_by_receiver: MultiSet,
    pub to_withdraw_by_operator: MultiSet,
    pub loaded_by_loader: MultiSet,
    pub all_by_loader: MultiSet,
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
            load_timeout: Item::new("load_timeout"),
            release_timeout: Item::new("release_timeout"),
            to_withdraw_by_loader: MultiSet::new("to_withdraw_by_loader"),
            to_withdraw_by_receiver: MultiSet::new("to_withdraw_by_receiver"),
            to_withdraw_by_operator: MultiSet::new("to_withdraw_by_operator"),
            loaded_by_loader: MultiSet::new("loaded_by_loader"),
            all_by_loader: MultiSet::new("all_by_loader"),
            // escrows: Map::new("escrows"),
        }
    }

    #[sv::msg(instantiate)]
    pub fn instantiate(
        &self,
        ctx: InstantiateCtx,
        admins: Vec<Addr>,
        did_contract: Addr,
        load_timeout: u64,
        release_timeout: u64,
    ) -> Result<Response, ContractError> {
        self.ensure_one_admin(&admins)?;
        self.ensure_admin_not_duplicated(&admins)?;
        for admin in &admins {
            self.ensure_valid_admin(ctx.deps.api, admin.as_str())?;
        }
        self.ensure_valid_address(ctx.deps.api, &did_contract)?;
        // TODO ensure did contract exists
        self.save_admins(ctx.deps.storage, &admins)?;
        self.save_did_contract_address(ctx.deps.storage, &did_contract)?;
        self.load_timeout
            .save(ctx.deps.storage, &Duration::from_millis(load_timeout))?;
        self.release_timeout
            .save(ctx.deps.storage, &Duration::from_millis(release_timeout))?;
        Ok(Response::default())
    }

    // ---- Admins ------

    #[sv::msg(exec)]
    pub fn add_admin(&self, ctx: ExecCtx, new_admin: String) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        let new_admin = self.ensure_valid_admin(ctx.deps.api, &new_admin)?;

        let mut admins: Vec<Addr> = self.admins.load(ctx.deps.storage)?;
        self.ensure_unique_admins(&admins, &new_admin)?;

        admins.push(new_admin.clone());
        self.admins.save(ctx.deps.storage, &admins)?;

        let event = Event::new("add_admin")
            .add_attribute("executor", ctx.info.sender.to_string())
            .add_attribute("new_admin", new_admin.to_string());

        Ok(Response::new().add_event(event))
    }

    #[sv::msg(exec)]
    pub fn remove_admin(
        &self,
        ctx: ExecCtx,
        admin_to_remove: String,
    ) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        let admin = self.ensure_valid_admin(ctx.deps.api, &admin_to_remove)?;

        let mut admins = self.admins.load(ctx.deps.storage)?;

        if let Some(pos) = admins.iter().position(|x| x == &admin) {
            admins.remove(pos);
            self.ensure_one_admin(&admins)?;
            self.admins.save(ctx.deps.storage, &admins)?;

            let event = Event::new("remove_admin")
                .add_attribute("executor", ctx.info.sender.to_string())
                .add_attribute("removed_admin", admin.to_string());

            Ok(Response::new().add_event(event))
        } else {
            Err(ContractError::AdminNotFound())
        }
    }

    #[sv::msg(query)]
    pub fn get_admins(&self, ctx: QueryCtx) -> Result<Vec<Addr>, ContractError> {
        let result = self.admins.load(ctx.deps.storage)?;
        Ok(result)
    }

    #[sv::msg(query)]
    pub fn get_did_contract(&self, ctx: QueryCtx) -> Result<Addr, ContractError> {
        self.load_did_contract_address(ctx.deps.storage)
    }

    // ------ timeouts

    #[sv::msg(exec)]
    pub fn set_load_timeout(
        &self,
        ctx: ExecCtx,
        load_timeout: u64,
    ) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        self.load_timeout
            .save(ctx.deps.storage, &Duration::from_millis(load_timeout))?;
        let event =
            Event::new("set_load_timeout").add_attribute("timeout", load_timeout.to_string());

        Ok(Response::new().add_event(event))
    }

    #[sv::msg(query)]
    pub fn get_load_timeout(&self, ctx: QueryCtx) -> Result<Duration, ContractError> {
        let result = self.load_timeout.load(ctx.deps.storage)?;
        Ok(result)
    }

    #[sv::msg(exec)]
    pub fn set_release_timeout(
        &self,
        ctx: ExecCtx,
        release_timeout: u64,
    ) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        self.release_timeout
            .save(ctx.deps.storage, &Duration::from_millis(release_timeout))?;
        let event =
            Event::new("set_release_timeout").add_attribute("timeout", release_timeout.to_string());

        Ok(Response::new().add_event(event))
    }

    #[sv::msg(query)]
    pub fn get_release_timeout(&self, ctx: QueryCtx) -> Result<Duration, ContractError> {
        let result = self.release_timeout.load(ctx.deps.storage)?;
        Ok(result)
    }

    // ---- Escrow Operators ------

    #[sv::msg(exec)]
    pub fn create_operator(
        &self,
        ctx: ExecCtx,
        operator_id: String,
        controllers: Vec<Controller>,
    ) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;
        for c in &controllers {
            c.ensure_valid(ctx.deps.api)?;
            // TODO implemnt in did contract possibility to register did usage, to block did document removal if did is used.
        }
        self.ensure_operator_not_overwritten(ctx.deps.storage, &operator_id)?;

        let operator: EscrowOperator = EscrowOperator {
            id: operator_id.clone(),
            controller: controllers.clone(),
            enabled: true,
        };
        operator.ensure_controllers_not_duplicated()?;

        operator.ensure_controller()?;
        let did_contract = self.load_did_contract_address(ctx.deps.storage)?;

        operator.ensure_controller_exist(ctx.deps.as_ref(), &did_contract)?;
        self.save_operator(ctx.deps.storage, &operator)?;

        let event = Event::new("create_operator")
            .add_attribute("operator_id", operator_id.clone())
            .add_attribute("controllers", controllers.to_event_data());

        Ok(Response::new().add_event(event))
    }

    #[sv::msg(exec)]
    pub fn remove_operator(
        &self,
        ctx: ExecCtx,
        operator_id: String,
    ) -> Result<Response, ContractError> {
        self.authorize_admin(ctx.deps.as_ref(), &ctx.info.sender)?;

        self.ensure_operator_exists(ctx.deps.storage, &operator_id)?;
        // TODO implemnt in did contract possibility to unregister did usage, to block did document removal if did is used.

        self.operators.remove(ctx.deps.storage, operator_id.clone());
        let event = Event::new("remove_operator").add_attribute("operator_id", operator_id.clone());

        Ok(Response::new().add_event(event))
    }

    #[sv::msg(exec)]
    pub fn disable_operator(
        &self,
        ctx: ExecCtx,
        operator_id: String,
    ) -> Result<Response, ContractError> {
        self.enable_disable_operator(ctx, operator_id, false)
    }

    #[sv::msg(exec)]
    pub fn enable_operator(
        &self,
        ctx: ExecCtx,
        operator_id: String,
    ) -> Result<Response, ContractError> {
        self.enable_disable_operator(ctx, operator_id, true)
    }

    #[sv::msg(exec)]
    pub fn add_operator_controller(
        &self,
        ctx: ExecCtx,
        operator_id: String,
        controller: Controller,
    ) -> Result<Response, ContractError> {
        controller.ensure_valid(ctx.deps.api)?;
        let mut operator = self.ensure_load_operator(ctx.deps.storage, &operator_id)?;
        let did_contract = self.load_did_contract_address(ctx.deps.storage)?;
        self.authorize_admin_or_operator(
            ctx.deps.as_ref(),
            &did_contract,
            &ctx.info.sender,
            Some(operator.clone()),
        )?;

        // TODO implemnt in did contract possibility to register did usage, to block did document removal if did is used.

        controller.ensure_exist(ctx.deps.as_ref(), &did_contract)?;

        operator.controller.push(controller.clone());
        operator.ensure_controllers_not_duplicated()?;

        self.save_operator(ctx.deps.storage, &operator)?;

        let event = Event::new("add_operator_controller")
            .add_attribute("operator_id", operator_id.clone())
            .add_attribute("controller", controller.to_string());

        Ok(Response::new().add_event(event))
    }

    #[sv::msg(exec)]
    pub fn delete_operator_controller(
        &self,
        ctx: ExecCtx,
        operator_id: String,
        controller: Controller,
    ) -> Result<Response, ContractError> {
        controller.ensure_valid(ctx.deps.api)?;
        let did_contract = self.load_did_contract_address(ctx.deps.storage)?;
        let mut operator = self.ensure_load_operator(ctx.deps.storage, &operator_id)?;

        self.authorize_admin_or_operator(
            ctx.deps.as_ref(),
            &did_contract,
            &ctx.info.sender,
            Some(operator.clone()),
        )?;

        // TODO implemnt in did contract possibility to unregister did usage, to block did document removal if did is used.

        if !operator.has_controller(&controller) {
            return Err(ContractError::DidDocumentControllerNotExists);
        }

        // did_doc.controller.mut_controllers().retain(|s| *s != controller);
        operator.controller.retain(|s| *s != controller);
        operator.ensure_controller()?;

        self.save_operator(ctx.deps.storage, &operator)?;

        let event = Event::new("delete_operator_controller")
            .add_attribute("operator_id", operator_id.clone())
            .add_attribute("controller", controller.to_string());

        Ok(Response::new().add_event(event))
    }

    // -- Escrow

    #[sv::msg(exec)]
    pub fn create_escrow(
        &self,
        ctx: ExecCtx,
        escrow_id: String,
        operator_id: String,
        receiver: Controller,
        expected_coins: Vec<Coin>,
    ) -> Result<Response, ContractError> {
        receiver.ensure_valid(ctx.deps.api)?;
        let did_contract = self.load_did_contract_address(ctx.deps.storage)?;
        let operator = self.ensure_load_operator(ctx.deps.storage, &operator_id)?;
        operator.ensure_enabled()?;
        self.authorize_admin_or_operator(
            ctx.deps.as_ref(),
            &did_contract,
            &ctx.info.sender,
            Some(operator),
        )?;

        let escrows = escrows();
        escrows.ensure_not_exist(ctx.deps.storage, escrow_id.as_str())?;

        let expected_coins = Coins::deduplicated_coins(expected_coins)?;
        expected_coins.ensure_any_coins()?;

        let escrow = Escrow {
            id: escrow_id,
            operator_id: operator_id.clone(),
            expected_coins: expected_coins.to_vec(),
            loaded_coins: None,
            operator_claimed: false,
            receiver: receiver.clone(),
            receiver_claimed: false,
            loader_claimed: false,
            used_coins: vec![],
            operator_fee: vec![],
            state: EscrowState::Loading,
            lock_timestamp: None,
            create_timestamp: ctx.env.block.time,
        };
        self.save_escrow_in_storage(ctx.deps.storage, &escrows, &escrow)?;
        let resp = Response::new();
        let event = Event::new("escrow_create")
            .add_attribute("escrow_id", escrow.id.as_str())
            .add_attribute("operator_id", operator_id)
            .add_attribute("receiver", receiver.to_string())
            .add_attribute("expected_coins", expected_coins.to_string());
        Ok(resp.add_event(event))
    }

    #[sv::msg(exec)]
    pub fn load_escrow(&self, ctx: ExecCtx, escrow_id: String) -> Result<Response, ContractError> {
        let escrows = escrows();
        let mut escrow =
            self.ensure_load_escrow_from_storage(ctx.deps.storage, &escrows, &escrow_id)?;
        let operator = self.ensure_load_operator(ctx.deps.storage, &escrow.operator_id)?;
        operator.ensure_enabled()?;

        escrow.ensure_state(EscrowState::Loading)?;

        if self.is_loading_timeout(ctx.deps.storage, &ctx.env.block.time, &escrow)? {
            return Err(ContractError::EscrowExpired("escrow loading".to_string()));
        }
        EscrowContract::ensure_coins_as_expected(&ctx.info.funds, escrow.expected_coins.clone())?;

        let loaded_coins = Coins::deduplicated_coins(ctx.info.funds.clone())?;

        escrow.loaded_coins = Some(LoadedCoins {
            coins: loaded_coins.to_vec(),
            loader: ctx.info.sender.clone(),
        });
        escrow.lock_timestamp = Some(ctx.env.block.time);
        escrow.state = EscrowState::Locked;

        self.save_escrow_in_storage(ctx.deps.storage, &escrows, &escrow)?;
        self.save_loaded_by_loader(ctx.deps.storage, &ctx.info.sender, &escrow.id)?;
        self.save_all_by_loader(ctx.deps.storage, &ctx.info.sender, &escrow.id)?;

        let resp = Response::new();
        let event = Event::new("escrow_load")
            .add_attribute("escrow_id", escrow.id)
            .add_attribute("operator_id", escrow.operator_id)
            .add_attribute("loader", ctx.info.sender)
            .add_attribute("coins", loaded_coins.to_string());
        Ok(resp.add_event(event))
    }

    #[sv::msg(exec)]
    pub fn release_escrow(
        &self,
        ctx: ExecCtx,
        escrow_id: String,
        used_coins: Vec<Coin>,
        operator_fee: Vec<Coin>,
    ) -> Result<Response, ContractError> {
        let escrows = escrows();
        let mut escrow =
            self.ensure_load_escrow_from_storage(ctx.deps.storage, &escrows, &escrow_id)?;
        escrow.ensure_state(EscrowState::Locked)?;

        let did_contract = self.load_did_contract_address(ctx.deps.storage)?;

        let operator = self.load_operator(ctx.deps.storage, &escrow.operator_id)?;

        self.authorize_admin_or_operator(
            ctx.deps.as_ref(),
            &did_contract,
            &ctx.info.sender,
            operator,
        )?;

        if self.is_release_timeout(ctx.deps.storage, &ctx.env.block.time, &escrow)? {
            return Err(ContractError::EscrowExpired("escrow releasing".to_string()));
        }

        let used_coins = Coins::deduplicated_coins(used_coins)?;

        let operator_fee = Coins::deduplicated_coins(operator_fee)?;

        EscrowContract::ensure_correct_coins_amount_on_release(
            &used_coins,
            &operator_fee,
            escrow.expected_coins.clone(),
        )?;

        escrow.used_coins = used_coins.to_vec();
        escrow.state = EscrowState::Released;
        escrow.operator_fee = operator_fee.to_vec();
        let expected = Coins::try_from(escrow.expected_coins.clone())?;

        if used_coins == expected {
            escrow.loader_claimed = true
        }

        let mut rc_empty = true;
        let mut receiver_coins = used_coins.clone();
        for c in operator_fee.clone() {
            receiver_coins.sub(c)?;
        }

        if !receiver_coins.is_empty() {
            for c in &receiver_coins {
                if c.amount.gt(&Uint128::zero()) {
                    rc_empty = false;
                }
            }
        }
        if rc_empty {
            escrow.receiver_claimed = true;
        }

        let mut of_empty = true;
        if !operator_fee.is_empty() {
            for c in &operator_fee {
                if c.amount.gt(&Uint128::zero()) {
                    of_empty = false;
                }
            }
        }
        if of_empty {
            escrow.operator_claimed = true;
        }

        self.save_escrow_in_storage(ctx.deps.storage, &escrows, &escrow)?;

        if let Some(loaded_coins) = &escrow.loaded_coins {
            self.loaded_by_loader.remove(
                ctx.deps.storage,
                loaded_coins.loader.as_str(),
                escrow.id.as_str(),
            );
            if !escrow.loader_claimed {
                self.save_to_withdraw_by_loader(
                    ctx.deps.storage,
                    &loaded_coins.loader,
                    &escrow.id,
                )?;
            }
        }
        if !escrow.receiver_claimed {
            self.save_to_withdraw_by_receiver(ctx.deps.storage, &escrow.receiver, &escrow.id)?;
        }
        if !escrow.operator_claimed {
            self.save_to_withdraw_by_operator(ctx.deps.storage, &escrow.operator_id, &escrow.id)?;
        }

        let resp = Response::new();
        let event = Event::new("escrow_release")
            .add_attribute("escrow_id", escrow.id.as_str())
            .add_attribute("used_coins", used_coins.to_string())
            .add_attribute("operator_fee", operator_fee.to_string());
        Ok(resp.add_event(event))

        // Ok(Response::new())
    }

    fn is_loader(&self, escrow: &Escrow, sender: &Addr) -> Result<bool, ContractError> {
        if let Some(l) = &escrow.loaded_coins {
            if l.loader == sender {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_loader_or_admin(
        &self,
        deps: Deps,
        escrow: &Escrow,
        sender: &Addr,
    ) -> Result<bool, ContractError> {
        if self.is_loader(escrow, sender)? || self.is_admin(deps, sender)? {
            return Ok(true);
        }
        Ok(false)
    }

    #[sv::msg(exec)]
    pub fn withdraw(&self, ctx: ExecCtx, escrow_id: String) -> Result<Response, ContractError> {
        let escrows = escrows();
        let mut escrow =
            self.ensure_load_escrow_from_storage(ctx.deps.storage, &escrows, &escrow_id)?;
        if escrow.state == EscrowState::Closed {
            return Err(ContractError::EscowAlreadyWithdrawn);
        }

        if escrow.state == EscrowState::Locked
            && self.is_release_timeout(ctx.deps.storage, &ctx.env.block.time, &escrow)?
        {
            if let Some(l) = &escrow.loaded_coins {
                if self.is_loader_or_admin(ctx.deps.as_ref(), &escrow, &ctx.info.sender)? {
                    let msg: CosmosMsg = CosmosMsg::Bank(BankMsg::Send {
                        to_address: l.loader.to_string(),
                        amount: l.coins.clone(),
                    });
                    let mut resp: Response = Response::default();

                    let l_coins = Coins::try_from(l.coins.clone())?;

                    resp = resp.add_message(msg);
                    let event = Event::new("escrow_recover_loader")
                        .add_attribute("escrow_id", escrow.id.as_str())
                        .add_attribute("amount", l_coins.to_string());
                    resp = resp.add_event(event);

                    escrow.state = EscrowState::FailedReleaseTimeoutWithdrawned;

                    self.save_escrow_in_storage(ctx.deps.storage, &escrows, &escrow)?;
                    if let Some(loaded_coins) = &escrow.loaded_coins {
                        self.loaded_by_loader.remove(
                            ctx.deps.storage,
                            loaded_coins.loader.as_str(),
                            escrow.id.as_str(),
                        );
                    }
                    return Ok(resp);
                } else {
                    return Err(ContractError::Unauthorized());
                }
            }
            return Err(ContractError::ContractEscrowError(
                "no loaded_coins in locked state".to_string(),
            ));
        }
        escrow.ensure_state(EscrowState::Released)?;

        let mut loader_authorized = false;
        let mut receiver_authorized = false;
        let mut operator_authorized = false;

        let mut loader_claimed = false;
        let mut receiver_claimed = false;
        let mut operator_claimed = false;

        let mut resp = Response::default();
        if let Some(l) = &escrow.loaded_coins {
            if self.is_loader_or_admin(ctx.deps.as_ref(), &escrow, &ctx.info.sender)? {
                loader_authorized = true;
                if !escrow.loader_claimed {
                    let mut ec: Coins = Coins::try_from(escrow.expected_coins.clone())?;
                    for c in &escrow.used_coins {
                        ec.sub(c.clone())?;
                    }

                    let msg = CosmosMsg::Bank(BankMsg::Send {
                        to_address: l.loader.to_string(),
                        amount: ec.to_vec(),
                    });
                    resp = resp.add_message(msg);
                    let event = Event::new("escrow_withdraw_loader")
                        .add_attribute("escrow_id", escrow.id.as_str())
                        .add_attribute("amount", ec.to_string());
                    resp = resp.add_event(event);
                    escrow.loader_claimed = true;
                    loader_claimed = true;
                    if let Some(loaded_coins) = &escrow.loaded_coins {
                        self.to_withdraw_by_loader.remove(
                            ctx.deps.storage,
                            loaded_coins.loader.as_str(),
                            escrow.id.as_str(),
                        );
                    }
                }
            }
        }

        // if !escrow.receiver_claimed || !escrow.operator_claimed {
        //     println!("Withdrawing - receiver or operator");
        //     let did_contract = self.load_did_contract_address(ctx.deps.storage)?;
        //     let sender: Controller = ctx.info.sender.to_string().into();
        let did_contract = self.load_did_contract_address(ctx.deps.storage)?;
        let sender: Controller = ctx.info.sender.to_string().into();

        if Remote::<DidContract>::new(did_contract.clone())
            .querier(&ctx.deps.querier)
            .is_controller_of(vec![escrow.receiver.clone()], sender.clone())?
        {
            receiver_authorized = true;
            if !escrow.receiver_claimed {
                let mut uc: Coins = Coins::try_from(escrow.used_coins.clone())?;
                for c in escrow.operator_fee.clone() {
                    uc.sub(c)?;
                }

                let msg = CosmosMsg::Bank(BankMsg::Send {
                    to_address: ctx.info.sender.to_string(),
                    amount: uc.to_vec(),
                });
                resp = resp.add_message(msg);
                let event = Event::new("escrow_withdraw_receiver")
                    .add_attribute("escrow_id", escrow.id.as_str())
                    .add_attribute("amount", uc.to_string());
                resp = resp.add_event(event);
                escrow.receiver_claimed = true;
                receiver_claimed = true;
                self.to_withdraw_by_receiver.remove(
                    ctx.deps.storage,
                    &escrow.receiver.to_string(),
                    &escrow.id,
                );
            }
        }

        let operator = self
            .operators
            .load(ctx.deps.storage, escrow.operator_id.clone())?;

        if Remote::<DidContract>::new(did_contract.clone())
            .querier(&ctx.deps.querier)
            .is_controller_of(operator.controller, sender)?
        {
            operator_authorized = true;
            if !escrow.operator_claimed {
                let uc: Coins = Coins::try_from(escrow.operator_fee.clone())?;

                let msg = CosmosMsg::Bank(BankMsg::Send {
                    to_address: ctx.info.sender.to_string(),
                    amount: uc.to_vec(),
                });

                resp = resp.add_message(msg);
                let event = Event::new("escrow_withdraw_operator")
                    .add_attribute("escrow_id", escrow.id.as_str())
                    .add_attribute("amount", uc.to_string());
                resp = resp.add_event(event);
                escrow.operator_claimed = true;
                operator_claimed = true;
                self.to_withdraw_by_operator.remove(
                    ctx.deps.storage,
                    &escrow.operator_id,
                    &escrow.id,
                );
            }
        }
        // }

        if !loader_authorized && !receiver_authorized && !operator_authorized {
            return Err(ContractError::Unauthorized());
        }
        if !loader_claimed && !receiver_claimed && !operator_claimed {
            return Err(ContractError::EscowAlreadyWithdrawn);
        }

        // escrow.used_coins = used_coins;
        if escrow.receiver_claimed && escrow.loader_claimed && escrow.operator_claimed {
            escrow.state = EscrowState::Closed;
        }
        self.save_escrow_in_storage(ctx.deps.storage, &escrows, &escrow)?;

        Ok(resp)
    }

    #[sv::msg(query)]
    pub fn get_escrow_operator(
        &self,
        ctx: QueryCtx,
        operator_id: String,
    ) -> Result<EscrowOperator, ContractError> {
        self.ensure_load_operator(ctx.deps.storage, &operator_id)
    }

    fn is_loading_timeout(
        &self,
        store: &dyn Storage,
        now: &Timestamp,
        escrow: &Escrow,
    ) -> Result<bool, ContractError> {
        let timeout = self.ensure_load_load_timeout_from_storage(store)?;
        if timeout > Duration::from_secs(0) {
            let exp_timestamp = escrow.create_timestamp.plus_seconds(timeout.as_secs());
            if now.ge(&exp_timestamp) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_release_timeout(
        &self,
        store: &dyn Storage,
        now: &Timestamp,
        escrow: &Escrow,
    ) -> Result<bool, ContractError> {
        let timeout = self.ensure_load_release_timeout_from_storage(store)?;
        if timeout > Duration::from_secs(0) {
            if let Some(lt) = escrow.lock_timestamp {
                let exp_timestamp = lt.plus_seconds(timeout.as_secs());
                if now.ge(&exp_timestamp) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    #[sv::msg(query)]
    pub fn get_escrow(&self, ctx: QueryCtx, escrow_id: String) -> Result<Escrow, ContractError> {
        let mut escrow =
            self.ensure_load_escrow_from_storage(ctx.deps.storage, &escrows(), &escrow_id)?;
        if escrow.state == EscrowState::Loading {
            if self.is_loading_timeout(ctx.deps.storage, &ctx.env.block.time, &escrow)? {
                escrow.state = EscrowState::FailedLoadingTimeout;
            }
        } else if escrow.state == EscrowState::Locked {
            if self.is_release_timeout(ctx.deps.storage, &ctx.env.block.time, &escrow)? {
                escrow.state = EscrowState::FailedReleaseTimeout;
            }
        }
        Ok(escrow)
    }

    #[sv::msg(query)]
    pub fn get_escrows_by_operator(
        &self,
        ctx: QueryCtx,
        operator_id: String,
        limit: Option<usize>,
        start_after: Option<String>,
    ) -> Result<Vec<(String, Escrow)>, ContractError> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let start = start_after.map(Bound::exclusive);

        let res: Result<Vec<_>, _> = escrows()
            .idx
            .operator
            .prefix(operator_id)
            .range(ctx.deps.storage, start, None, Order::Ascending)
            .take(limit)
            .collect();

        let res = res.map_err(|e| match e {
            StdError::NotFound { .. } => ContractError::EscrowOperatorNotFound(e),
            _ => ContractError::EscrowError("load operator escrows".to_string(), e),
        })?;
        Ok(res)
    }

    #[sv::msg(query)]
    pub fn get_escrows_by_receiver(
        &self,
        ctx: QueryCtx,
        receiver: Controller,
        limit: Option<usize>,
        start_after: Option<String>,
    ) -> Result<Vec<(String, Escrow)>, ContractError> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let start = start_after.map(Bound::exclusive);

        let res: Result<Vec<_>, _> = escrows()
            .idx
            .receiver
            .prefix(receiver.to_string())
            .range(ctx.deps.storage, start, None, Order::Ascending)
            .take(limit)
            .collect();

        let res = res.map_err(|e| match e {
            StdError::NotFound { .. } => ContractError::EscrowOperatorNotFound(e),
            _ => ContractError::EscrowError("load receiver escrows".to_string(), e),
        })?;
        Ok(res)
    }

    #[sv::msg(query)]
    pub fn get_escrows_by_loader(
        &self,
        ctx: QueryCtx,
        loader: Addr,
        limit: Option<usize>,
        start_after: Option<String>,
    ) -> Result<Vec<(String, Escrow)>, ContractError> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let start = start_after.map(Bound::exclusive);

        let res: Result<Vec<String>, _> = self
            .all_by_loader
            .get_values(
                ctx.deps.storage,
                loader.as_str(),
                start,
                None,
                Order::Ascending,
            )
            .take(limit)
            .collect();

        let res = res.map_err(|e| match e {
            StdError::NotFound { .. } => ContractError::EscrowOperatorNotFound(e),
            _ => ContractError::EscrowError("load loader escrows".to_string(), e),
        })?;

        let mut result: Vec<(String, Escrow)> = vec![];
        for id in &res {
            let escrow = self.ensure_load_escrow_from_storage(ctx.deps.storage, &escrows(), &id)?;
            result.push((id.clone(), escrow));
        }

        Ok(result)
    }

    #[sv::msg(query)]
    pub fn get_loaded_escrows_by_loader(
        &self,
        ctx: QueryCtx,
        loader: Addr,
        limit: Option<usize>,
        start_after: Option<String>,
    ) -> Result<Vec<(String, Escrow)>, ContractError> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let start = start_after.map(Bound::exclusive);

        let res: Result<Vec<String>, _> = self
            .loaded_by_loader
            .get_values(
                ctx.deps.storage,
                loader.as_str(),
                start,
                None,
                Order::Ascending,
            )
            .take(limit)
            .collect();

        let res = res.map_err(|e| match e {
            StdError::NotFound { .. } => ContractError::EscrowOperatorNotFound(e),
            _ => ContractError::EscrowError("load loaded loader escrows".to_string(), e),
        })?;

        let mut result: Vec<(String, Escrow)> = vec![];
        for id in &res {
            let escrow = self.ensure_load_escrow_from_storage(ctx.deps.storage, &escrows(), &id)?;
            result.push((id.clone(), escrow));
        }

        Ok(result)
    }

    #[sv::msg(query)]
    pub fn get_escrows_to_withdraw_by_loader(
        &self,
        ctx: QueryCtx,
        loader: Addr,
        limit: Option<usize>,
        start_after: Option<String>,
    ) -> Result<Vec<(String, Escrow)>, ContractError> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let start = start_after.map(Bound::exclusive);

        let res: Result<Vec<String>, _> = self
            .to_withdraw_by_loader
            .get_values(
                ctx.deps.storage,
                loader.as_str(),
                start,
                None,
                Order::Ascending,
            )
            .take(limit)
            .collect();

        let res = res.map_err(|e| match e {
            StdError::NotFound { .. } => ContractError::EscrowOperatorNotFound(e),
            _ => ContractError::EscrowError("load loader to withdraw escrows".to_string(), e),
        })?;

        let mut result: Vec<(String, Escrow)> = vec![];
        for id in &res {
            let escrow = self.ensure_load_escrow_from_storage(ctx.deps.storage, &escrows(), &id)?;
            result.push((id.clone(), escrow));
        }

        Ok(result)
    }

    #[sv::msg(query)]
    pub fn get_escrows_to_withdraw_by_receiver(
        &self,
        ctx: QueryCtx,
        receiver: Controller,
        limit: Option<usize>,
        start_after: Option<String>,
    ) -> Result<Vec<(String, Escrow)>, ContractError> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let start = start_after.map(Bound::exclusive);

        let res: Result<Vec<String>, _> = self
            .to_withdraw_by_receiver
            .get_values(
                ctx.deps.storage,
                &receiver.to_string(),
                start,
                None,
                Order::Ascending,
            )
            .take(limit)
            .collect();

        let res = res.map_err(|e| match e {
            StdError::NotFound { .. } => ContractError::EscrowOperatorNotFound(e),
            _ => ContractError::EscrowError("load receiver to withdraw escrows".to_string(), e),
        })?;

        let mut result: Vec<(String, Escrow)> = vec![];
        for id in &res {
            let escrow = self.ensure_load_escrow_from_storage(ctx.deps.storage, &escrows(), &id)?;
            result.push((id.clone(), escrow));
        }

        Ok(result)
    }

    #[sv::msg(query)]
    pub fn get_escrows_to_withdraw_by_operator(
        &self,
        ctx: QueryCtx,
        operator_id: String,
        limit: Option<usize>,
        start_after: Option<String>,
    ) -> Result<Vec<(String, Escrow)>, ContractError> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let start = start_after.map(Bound::exclusive);

        let res: Result<Vec<String>, _> = self
            .to_withdraw_by_operator
            .get_values(
                ctx.deps.storage,
                &operator_id,
                start,
                None,
                Order::Ascending,
            )
            .take(limit)
            .collect();

        let res = res.map_err(|e| match e {
            StdError::NotFound { .. } => ContractError::EscrowOperatorNotFound(e),
            _ => ContractError::EscrowError("load receiver to withdraw escrows".to_string(), e),
        })?;

        let mut result: Vec<(String, Escrow)> = vec![];
        for id in &res {
            let escrow = self.ensure_load_escrow_from_storage(ctx.deps.storage, &escrows(), &id)?;
            result.push((id.clone(), escrow));
        }

        Ok(result)
    }

    fn save_admins(
        &self,
        storage: &mut dyn Storage,
        admins: &Vec<Addr>,
    ) -> Result<(), ContractError> {
        let result = self.admins.save(storage, admins);
        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(ContractError::AdminError("save admin".to_string(), e)),
        }
    }

    fn save_did_contract_address(
        &self,
        storage: &mut dyn Storage,
        did_contract: &Addr,
    ) -> Result<(), ContractError> {
        self.did_contract.save(storage, did_contract).map_err(|e| {
            ContractError::DidContractAddressError("save did contract address".to_string(), e)
        })
    }

    fn is_admin(&self, deps: Deps, sender: &Addr) -> Result<bool, ContractError> {
        let admins = self
            .admins
            .may_load(deps.storage)
            .map_err(|e| ContractError::AdminError("load admin".to_string(), e))?;
        if let Some(admin_list) = admins {
            // Check if the sender is one of the admins
            Ok(admin_list.contains(sender))
        } else {
            Ok(false)
        }
    }

    fn authorize_admin(&self, deps: Deps, sender: &Addr) -> Result<(), ContractError> {
        if !self.is_admin(deps, sender)? {
            return Err(ContractError::Unauthorized());
        }
        Ok(())
    }

    fn authorize_admin_or_operator(
        &self,
        deps: Deps,
        did_contract: &Addr,
        sender: &Addr,
        operator: Option<EscrowOperator>,
    ) -> Result<(), ContractError> {
        if let Err(_) = self.authorize_admin(deps, sender) {
            match operator {
                Some(op) => {
                    op.authorize(deps, &did_contract, sender)?;
                }
                None => {
                    return Err(ContractError::Unauthorized());
                }
            }
        }
        Ok(())
    }

    // fn ensure_valid_admin(&self, api: &dyn Api, admin: String) -> Result<Addr, ContractError> {
    //     let addr = api.addr_validate(&admin)?;
    //     Ok(addr)
    // }

    fn ensure_unique_admins(
        &self,
        admins: &Vec<Addr>,
        new_admin: &Addr,
    ) -> Result<(), ContractError> {
        if admins.contains(new_admin) {
            Err(ContractError::AdminAlreadyExists())
        } else {
            Ok(())
        }
    }

    fn ensure_operator_not_overwritten(
        &self,
        store: &dyn Storage,
        operator_id: &str,
    ) -> Result<(), ContractError> {
        if self.operators.has(store, operator_id.to_string()) {
            return Err(ContractError::OperatorAlreadyExists);
        }
        Ok(())
    }

    fn ensure_operator_exists(
        &self,
        store: &dyn Storage,
        operator_id: &str,
    ) -> Result<(), ContractError> {
        if !self.operators.has(store, operator_id.to_string()) {
            return Err(ContractError::OperatorDoesNotExist);
        }
        Ok(())
    }

    fn enable_disable_operator(
        &self,
        ctx: ExecCtx,
        operator_id: String,
        enabled: bool,
    ) -> Result<Response, ContractError> {
        let mut operator = self.ensure_load_operator(ctx.deps.storage, &operator_id)?;

        let did_contract = self.load_did_contract_address(ctx.deps.storage)?;

        self.authorize_admin_or_operator(
            ctx.deps.as_ref(),
            &did_contract,
            &ctx.info.sender,
            Some(operator.clone()),
        )?;

        if enabled {
            operator.ensure_disabled()?;
        } else {
            operator.ensure_enabled()?;
        }
        operator.enabled = enabled;

        self.operators
            .save(ctx.deps.storage, operator_id.clone(), &operator)?;
        let event_name = if enabled {
            "enable_operator"
        } else {
            "disable_operator"
        };

        let event = Event::new(event_name).add_attribute("operator_id", operator_id.clone());

        Ok(Response::new().add_event(event))
    }

    fn ensure_valid_admin(&self, api: &dyn Api, admin: &str) -> Result<Addr, ContractError> {
        api.addr_validate(admin)
            .map_err(|e| ContractError::InvalidAdminAddress(e))
    }

    fn ensure_valid_address(&self, api: &dyn Api, admin: &Addr) -> Result<Addr, ContractError> {
        api.addr_validate(admin.as_str())
            .map_err(|e| ContractError::InvalidAddress(e))
    }

    fn ensure_one_admin(&self, admins: &Vec<Addr>) -> Result<(), ContractError> {
        if admins.is_empty() {
            return Err(ContractError::NoAdmin);
        }
        Ok(())
    }

    fn ensure_admin_not_duplicated(&self, admins: &Vec<Addr>) -> Result<(), ContractError> {
        let mut seen = HashSet::new();
        for admin in admins {
            if !seen.insert(admin.to_string()) {
                return Err(ContractError::DuplicatedAdmin(admin.to_string()));
            }
        }
        Ok(())
    }

    fn load_did_contract_address(&self, storage: &dyn Storage) -> Result<Addr, ContractError> {
        self.did_contract
            .load(storage)
            .map_err(|e| ContractError::DidContractAddressError("load error".to_string(), e))
    }

    fn load_operator(
        &self,
        storage: &dyn Storage,
        operator_id: &str,
    ) -> Result<Option<EscrowOperator>, ContractError> {
        self.operators
            .may_load(storage, operator_id.to_string())
            .map_err(|e| ContractError::EscrowOperatorError("load error".to_string(), e))
    }

    fn save_operator(
        &self,
        storage: &mut dyn Storage,
        operator: &EscrowOperator,
    ) -> Result<(), ContractError> {
        self.operators
            .save(storage, operator.id.clone(), operator)
            .map_err(|e| ContractError::EscrowOperatorError("save operator".to_string(), e))
    }

    fn ensure_load_operator(
        &self,
        storage: &dyn Storage,
        operator_id: &str,
    ) -> Result<EscrowOperator, ContractError> {
        let operator = self.load_operator(storage, operator_id)?;
        match operator {
            Some(op) => Ok(op),
            None => Err(ContractError::OperatorDoesNotExist),
        }
    }

    fn load_escrow_from_storage(
        &self,
        storage: &dyn Storage,
        escrows: &cw_storage_plus::IndexedMap<&str, Escrow, crate::state::EscrowIndexes<'_>>,
        escrow_id: &str,
    ) -> Result<Option<Escrow>, ContractError> {
        escrows
            .may_load(storage, escrow_id)
            .map_err(|e| ContractError::EscrowError("load escrow".to_string(), e))
    }

    fn ensure_load_escrow_from_storage(
        &self,
        storage: &dyn Storage,
        escrows: &cw_storage_plus::IndexedMap<&str, Escrow, crate::state::EscrowIndexes<'_>>,
        escrow_id: &str,
    ) -> Result<Escrow, ContractError> {
        let escrow = self.load_escrow_from_storage(storage, escrows, escrow_id)?;
        match escrow {
            Some(esc) => Ok(esc),
            None => Err(ContractError::EscrowNotFound(escrow_id.to_string())),
        }
    }

    fn save_escrow_in_storage(
        &self,
        storage: &mut dyn Storage,
        escrows: &cw_storage_plus::IndexedMap<&str, Escrow, crate::state::EscrowIndexes<'_>>,
        escrow: &Escrow,
    ) -> Result<(), ContractError> {
        escrows
            .save(storage, &escrow.id.as_str(), &escrow)
            .map_err(|e| ContractError::EscrowError("save escrow".to_string(), e))
    }

    fn save_loaded_by_loader(
        &self,
        storage: &mut dyn Storage,
        loader: &Addr,
        escrow_id: &str,
    ) -> Result<(), ContractError> {
        self.loaded_by_loader
            .save(storage, loader.as_str(), escrow_id)
            .map_err(|e| ContractError::EscrowError("save loaded by loader".to_string(), e))
    }

    fn save_all_by_loader(
        &self,
        storage: &mut dyn Storage,
        loader: &Addr,
        escrow_id: &str,
    ) -> Result<(), ContractError> {
        self.all_by_loader
            .save(storage, loader.as_str(), escrow_id)
            .map_err(|e| ContractError::EscrowError("save all by loader".to_string(), e))
    }

    fn save_to_withdraw_by_loader(
        &self,
        storage: &mut dyn Storage,
        loader: &Addr,
        escrow_id: &str,
    ) -> Result<(), ContractError> {
        self.to_withdraw_by_loader
            .save(storage, loader.as_str(), escrow_id)
            .map_err(|e| ContractError::EscrowError("save to withdraw by loader".to_string(), e))
    }

    fn save_to_withdraw_by_operator(
        &self,
        storage: &mut dyn Storage,
        operator_id: &str,
        escrow_id: &str,
    ) -> Result<(), ContractError> {
        self.to_withdraw_by_operator
            .save(storage, operator_id, escrow_id)
            .map_err(|e| ContractError::EscrowError("save to withdraw by operator".to_string(), e))
    }

    fn save_to_withdraw_by_receiver(
        &self,
        storage: &mut dyn Storage,
        receiver: &Controller,
        escrow_id: &str,
    ) -> Result<(), ContractError> {
        self.to_withdraw_by_receiver
            .save(storage, receiver.to_string().as_str(), escrow_id)
            .map_err(|e| ContractError::EscrowError("save to withdraw by receiver".to_string(), e))
    }

    fn ensure_load_load_timeout_from_storage(
        &self,
        storage: &dyn Storage,
    ) -> Result<Duration, ContractError> {
        self.load_timeout
            .load(storage)
            .map_err(|e| ContractError::LoadTimeoutError("load load timeout".to_string(), e))
    }

    fn ensure_load_release_timeout_from_storage(
        &self,
        storage: &dyn Storage,
    ) -> Result<Duration, ContractError> {
        self.release_timeout
            .load(storage)
            .map_err(|e| ContractError::LoadTimeoutError("load release timeout".to_string(), e))
    }

    fn ensure_coins_are_on_account(
        sender: &Addr,
        querier: cosmwasm_std::QuerierWrapper<'_>,
        coins: &Vec<Coin>,
    ) -> Result<(), ContractError> {
        let loaded_coins = Coins::deduplicated_coins(coins.clone())?;

        for coin in &loaded_coins {
            let balance_query: QueryRequest<Empty> = QueryRequest::Bank(BankQuery::Balance {
                address: sender.to_string(),
                denom: coin.denom.clone(),
            });
            let balance: BalanceResponse = querier.query(&balance_query)?;

            let available_amount = balance.amount.amount;

            if available_amount < coin.amount {
                return Err(ContractError::InsufficientFunds {
                    denom: coin.denom.clone(),
                    required: coin.amount,
                    available: available_amount,
                });
            }
        }
        Ok(())
    }

    fn ensure_coins_as_expected(
        receiving_coins: &Vec<Coin>,
        expected_coins: Vec<Coin>,
    ) -> Result<(), ContractError> {
        let receiving_coins = Coins::deduplicated_coins(receiving_coins.clone())?;

        if receiving_coins.len() != expected_coins.len() {
            return Err(ContractError::CoinsMismatch {
                info: "receiving coins are more than expected".to_string(),
                expected: Coins::deduplicated_coins(expected_coins)?.to_string(),
                got: receiving_coins.to_string(),
            });
        }

        if let Some(_) = expected_coins
            .iter()
            .find(|coin| receiving_coins.amount_of(&coin.denom) != coin.amount)
        {
            return Err(ContractError::CoinsMismatch {
                info: "receiving coins are more than expected".to_string(),
                expected: Coins::deduplicated_coins(expected_coins)?.to_string(),
                got: receiving_coins.to_string(),
            });
        }
        Ok(())
    }

    fn ensure_correct_coins_amount_on_release(
        used: &Coins,
        operator_fee: &Coins,
        expected_coins: Vec<Coin>,
    ) -> Result<(), ContractError> {
        if operator_fee.len() > used.len() {
            return Err(ContractError::CoinsMismatch {
                info: "operator fee coins are more than used".to_string(),
                expected: used.to_string(),
                got: operator_fee.to_string(),
            });
        }

        if let Some(_) = operator_fee
            .iter()
            .find(|coin| used.amount_of(&coin.denom) < coin.amount)
        {
            return Err(ContractError::CoinsMismatch {
                info: "operator fee coins are more than used".to_string(),
                expected: used.to_string(),
                got: operator_fee.to_string(),
            });
        }

        let expected_coins = Coins::deduplicated_coins(expected_coins)?;
        if used.len() > expected_coins.len() {
            return Err(ContractError::CoinsMismatch {
                info: "used coins are more than expected".to_string(),
                expected: expected_coins.to_string(),
                got: used.to_string(),
            });
        }

        if let Some(_) = used
            .iter()
            .find(|coin| expected_coins.amount_of(&coin.denom) < coin.amount)
        {
            return Err(ContractError::CoinsMismatch {
                info: "used coins are more than expected".to_string(),
                expected: expected_coins.to_string(),
                got: used.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use cosmwasm_std::Coin;
    use cw_multi_test::IntoAddr;
    use sylvia::multitest::App;

    use crate::{
        contract::sv::mt::{CodeId, EscrowContractProxy},
        state::{Escrow, EscrowState},
    };
    use did_contract::contract::{sv::mt::CodeId as DidContractCodeId, DidContract};

    // -------------------- Admin tests

    // -------------------- Operator

    // -------------------- Escrow

    #[test]
    fn get_operator_not_found() {
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
                did_contract.contract_addr,
                60000,
                5 * 24 * 3600 * 1000,
            )
            .call(&owner)
            .unwrap();

        let operator = "operator-1";
        let no_did = escrow_contract.get_escrow_operator(operator.to_string());
        assert!(no_did.is_err(), "Expected Err, but got an Ok");
        assert_eq!(
            "Generic error: Querier contract error: Operator does not exist",
            no_did.err().unwrap().to_string()
        );
    }

    #[test]
    fn get_escrow_not_found() {
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
                did_contract.contract_addr,
                60000,
                5 * 24 * 3600 * 1000,
            )
            .call(&owner)
            .unwrap();

        let escrow = "escrow-1";
        let no_did = escrow_contract.get_escrow(escrow.to_string());
        assert!(no_did.is_err(), "Expected Err, but got an Ok");
        assert_eq!(
            "Generic error: Querier contract error: Escrow not found: escrow-1",
            no_did.err().unwrap().to_string()
        );
    }

    #[test]
    fn get_escrow_by_operator_empty() {
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
                did_contract.contract_addr,
                60000,
                5 * 24 * 3600 * 1000,
            )
            .call(&owner)
            .unwrap();

        let escrow = "escrow-1";
        let escrows = escrow_contract.get_escrows_by_operator(escrow.to_string(), None, None);
        assert!(escrows.is_ok(), "Expected Ok, but got an Err");
        assert_eq!(0, escrows.unwrap().len())
    }

    #[test]
    fn get_escrow_by_operator_index() {
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
                did_contract.contract_addr,
                60000,
                5 * 24 * 3600 * 1000,
            )
            .call(&owner)
            .unwrap();

        let conrller = "cont1".into_addr().to_string();

        let operator1: &str = "operator-1";
        let result = escrow_contract
            .create_operator(operator1.to_string(), vec![conrller.clone().into()])
            .call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let operator2 = "operator-2";
        let result = escrow_contract
            .create_operator(operator2.to_string(), vec![conrller.clone().into()])
            .call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let operator3 = "operator-3";
        let result = escrow_contract
            .create_operator(operator3.to_string(), vec![conrller.clone().into()])
            .call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 1 escrows
        let escrow1 = "escrow-1";
        let receiver1 = "receiver-1".into_addr();
        let expected_coins1 = vec![Coin::new(123u64, "uc4e")];
        // let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract
            .create_escrow(
                escrow1.to_string(),
                operator1.to_string(),
                receiver1.to_string().into(),
                expected_coins1.clone(),
            )
            .call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow2 = "escrow-2";
        let expected_coins2 = vec![Coin::new(13u64, "uc4e")];
        // let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract
            .create_escrow(
                escrow2.to_string(),
                operator1.to_string(),
                receiver1.to_string().into(),
                expected_coins2.clone(),
            )
            .call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 2 escrows

        let escrow3 = "escrow-3";
        let expected_coins3 = vec![Coin::new(1293u64, "uc4e")];
        // let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract
            .create_escrow(
                escrow3.to_string(),
                operator2.to_string(),
                receiver1.to_string().into(),
                expected_coins3.clone(),
            )
            .call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow4 = "escrow-4";
        let expected_coins4 = vec![Coin::new(77u64, "uc4e")];
        // let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract
            .create_escrow(
                escrow4.to_string(),
                operator2.to_string(),
                receiver1.to_string().into(),
                expected_coins4.clone(),
            )
            .call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 3 escrows

        let escrow5 = "escrow-5";
        let expected_coins5 = vec![Coin::new(1293u64, "uc4e")];
        // let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract
            .create_escrow(
                escrow5.to_string(),
                operator3.to_string(),
                receiver1.to_string().into(),
                expected_coins5.clone(),
            )
            .call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        let escrow6 = "escrow-6";
        let expected_coins6 = vec![Coin::new(77u64, "uc4e")];
        // let share = Decimal::from_str("0.34").expect("error parsing decimale");
        let result = escrow_contract
            .create_escrow(
                escrow6.to_string(),
                operator3.to_string(),
                receiver1.to_string().into(),
                expected_coins6.clone(),
            )
            .call(&owner);
        assert!(result.is_ok(), "Expected Ok, but got an Err");

        // opertor 1 escrows check

        let escrow_operators =
            escrow_contract.get_escrows_by_operator(operator1.to_string(), None, None);
        assert!(escrow_operators.is_ok(), "Expected Ok, but got an Err");
        let escrow_operators = escrow_operators.unwrap();
        assert_eq!(2, escrow_operators.len());

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(0);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator) = escrow.unwrap();
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
                operator_fee: vec![],
                // receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp,
                create_timestamp: escrow.unwrap().1.create_timestamp,
            },
            escrow_operator.clone(),
        );

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(1);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator) = escrow.unwrap();
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
                operator_fee: vec![],
                // receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp,
                create_timestamp: escrow.unwrap().1.create_timestamp,
            },
            escrow_operator.clone(),
        );

        // opertor 2 escrows check

        let escrow_operators =
            escrow_contract.get_escrows_by_operator(operator2.to_string(), None, None);
        assert!(escrow_operators.is_ok(), "Expected Ok, but got an Err");
        let escrow_operators = escrow_operators.unwrap();
        assert_eq!(2, escrow_operators.len());

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(0);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator) = escrow.unwrap();
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
                operator_fee: vec![],
                // receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp,
                create_timestamp: escrow.unwrap().1.create_timestamp,
            },
            escrow_operator.clone(),
        );

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(1);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator) = escrow.unwrap();
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
                operator_fee: vec![],
                // receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp,
                create_timestamp: escrow.unwrap().1.create_timestamp,
            },
            escrow_operator.clone(),
        );

        // opertor 3 escrows check

        let escrow_operators =
            escrow_contract.get_escrows_by_operator(operator3.to_string(), None, None);
        assert!(escrow_operators.is_ok(), "Expected Ok, but got an Err");
        let escrow_operators = escrow_operators.unwrap();
        assert_eq!(2, escrow_operators.len());

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(0);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator) = escrow.unwrap();
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
                operator_fee: vec![],
                // receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp,
                create_timestamp: escrow.unwrap().1.create_timestamp,
            },
            escrow_operator.clone(),
        );

        let escrow: Option<&(String, Escrow)> = escrow_operators.get(1);
        assert_eq!(true, escrow.is_some());
        let (id, escrow_operator) = escrow.unwrap();
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
                operator_fee: vec![],
                // receiver_share: share,
                used_coins: vec![],
                state: EscrowState::Loading,
                loader_claimed: false,
                lock_timestamp: escrow.unwrap().1.lock_timestamp,
                create_timestamp: escrow.unwrap().1.create_timestamp,
            },
            escrow_operator.clone(),
        );
    }
}
