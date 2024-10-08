use constcat::concat as constcat;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Coin, Coins, Decimal, Deps, StdError, Storage, Timestamp};
use cw_storage_plus::{Index, IndexList, IndexedMap, Item, MultiIndex};
use did_contract::{contract::DidContract, state::Controller};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sylvia::{types::Remote};
use did_contract::contract::sv::Querier;
use crate::error::ContractError;

#[cw_serde]
pub struct EscrowOperator {
    pub id: String,
    pub controller: Vec<Controller>,
    pub enabled: bool
}

impl EscrowOperator {

    pub fn ensure_controller(&self) -> Result<(), ContractError> {
        if self.controller.is_empty() {
            return Err(ContractError::ControllerRequired());
        }
        Ok(())
    }

    pub fn has_controller(&self, controller: &Controller) -> bool {
        self.controller.contains(controller)
    }

    pub fn authorize(&self, deps: Deps, did_contract: &Addr, sender: &Addr) -> Result<(), ContractError> {
        // let did_contract = did_contract.load(deps.storage)?;
        let sender: Controller = sender.to_string().into();
        if !Remote::<DidContract>::new(did_contract.clone()).querier(&deps.querier).is_controller_of(self.controller.clone(), sender)? {
            return Err(ContractError::Unauthorized())
        }
        Ok(())
    }

    pub fn ensure_controller_exist(&self, deps: Deps, did_contract: &Addr) -> Result<(), ContractError> {
        // let did_contract = did_contract.load(deps.storage)?;
        if !Remote::<DidContract>::new(did_contract.clone()).querier(&deps.querier).do_controllers_exist(self.controller.clone())? {
            return Err(ContractError::ControllerDoesNotExist())
        }
        Ok(())
    }
}

pub(crate) trait EscrowController {
    fn ensure_exist(&self, deps: Deps, did_contract: &Addr) -> Result<(), ContractError>;
}

impl EscrowController for Controller {
    fn ensure_exist(&self, deps: Deps, did_contract: &Addr) -> Result<(), ContractError> {
        if !Remote::<DidContract>::new(did_contract.clone()).querier(&deps.querier).does_controller_exist(self.clone())? {
            return Err(ContractError::ControllerDoesNotExist())
        }
        Ok(())
    }   

}

// pub fn ensure_controller_exist(deps: Deps, did_contract: &Item<Addr>, controller: &Controller) -> Result<(), ContractError> {
//     let did_contract = did_contract.load(deps.storage)?;
//     if !Remote::<DidContract>::new(did_contract).querier(&deps.querier).does_controller_exist(controller.clone())? {
//         return Err(ContractError::ControllerDoesNotExist())
//     }
//     Ok(())
// }

#[cw_serde]
pub struct Escrow {
    pub id: String,
    pub operator_id: String,
    pub expected_coins: Vec<Coin>,
    pub loaded_coins: Option<LoadedCoins>,
    pub used_coins: Vec<Coin>,
    pub state: EscrowState,
    pub receiver: Controller,
    pub receiver_share: Decimal,
    pub receiver_claimed: bool,
    pub operator_claimed: bool,
    pub loader_claimed: bool,
    pub lock_timestamp: Option<Timestamp>,
}

impl Escrow {
    pub fn ensure_state(&self, expected_state: EscrowState) -> Result<(), ContractError>{
        match (&self.state, expected_state) {
            // Match simple enum variants
            (EscrowState::Loading, EscrowState::Loading) => Ok(()),
            (EscrowState::Locked, EscrowState::Locked) => Ok(()),
            (EscrowState::Closed, EscrowState::Closed) => Ok(()),
            (EscrowState::Released, EscrowState::Released) => Ok(()),
            _ => Err(ContractError::EscrowWrongSate()), // Default case, states don't match
        }
    }
}

#[cw_serde]
pub struct LoadedCoins {
    pub loader: String,
    pub coins: Vec<Coin>,
}

#[cw_serde]
pub enum EscrowState {
    Loading,
    Locked,
    Released,
    Closed,
}

impl EscrowState {
    fn state_name(&self) -> String {
        let g = self;
        match g {
            EscrowState::Loading => "loading".to_string(),
            EscrowState::Locked => "locked".to_string(),
            EscrowState::Released => "released".to_string(),
            EscrowState::Closed => "closed".to_string(),
        }
    }
}

impl Escrow {
    fn receiver_state_index(&self) -> String {
        let mut r = self.receiver.to_string();
        r.push_str(self.state.state_name().as_str());
        r
    }

    fn operator_state_index(&self) -> String {
        let mut r = self.operator_id.clone();
        r.push_str(self.state.state_name().as_str());
        r
    }
}

pub struct EscrowIndexes<'a> {
    pub operator: MultiIndex<'a, String, Escrow, String>,
    pub receiver: MultiIndex<'a, String, Escrow, String>,
    pub operator_state: MultiIndex<'a, String, Escrow, String>,
    pub receiver_state: MultiIndex<'a, String, Escrow, String>,
}

impl<'a> IndexList<Escrow> for EscrowIndexes<'a> {
    fn get_indexes(&'_ self) -> Box<dyn Iterator<Item = &'_ dyn Index<Escrow>> + '_> {
        let v: Vec<&dyn Index<Escrow>> = vec![&self.operator];
        Box::new(v.into_iter())
    }
}

pub fn escrows<'a>() -> IndexedMap<&'a str, Escrow, EscrowIndexes<'a>> {
    let indexes = EscrowIndexes {
        operator: MultiIndex::new(
            |_pk, d: &Escrow| d.operator_id.clone(),
            "escrows",
            "escrow_operator",
        ),
        receiver: MultiIndex::new(
            |_pk, d: &Escrow| d.receiver.to_string(),
            "escrows",
            "escrow_receiver",
        ),

        operator_state: MultiIndex::new(
            |_pk, d: &Escrow| d.operator_state_index(),
            "escrows",
            "escrow_operator_state",
        ),
        receiver_state: MultiIndex::new(
            |_pk, d: &Escrow| d.receiver_state_index(),
            "escrows",
            "escrow_receiver_state",
        ),
    };
    IndexedMap::new("escrows", indexes)
}

pub trait Escrows {
    fn ensure_not_exist(&self, store: &dyn Storage, key: &str) -> Result<(), ContractError>;
}

impl<'a> Escrows for IndexedMap<&'a str, Escrow, EscrowIndexes<'a>> {
    fn ensure_not_exist(&self, store: &dyn Storage, key: &str) -> Result<(), ContractError> {
        if self.has(store, key) {
            return Err(ContractError::EscrowAlreadyExists);
        }
        Ok(())
    }
}

pub trait Share {
    fn ensure_in_range(&self) -> Result<(), ContractError>;

}

impl Share for Decimal {
    fn ensure_in_range(&self) -> Result<(), ContractError> {
        if *self >= Decimal::zero() && *self <= Decimal::one() {
            Ok(())
        } else {
            Err(ContractError::ShareValue)
        }
    }
}

pub trait CoinsExt {
    fn deduplicated_coins(coins: Vec<Coin>) -> Result<Coins, StdError>;
} 

impl CoinsExt for Coins { 
    fn deduplicated_coins(coins: Vec<Coin>) -> Result<Coins, StdError> {
        let mut consolidated = Coins::default(); // Start with an empty Coins collection
        for coin in coins {
            consolidated.add(coin)?; // Use the .add() method to consolidate coins
        }
        Ok(consolidated)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use serde_json::{from_str, json, to_string};

    #[test]
    fn test_escrow_state_serialization() {
        let state: EscrowState = EscrowState::Loading;
        let serialized = to_string(&state).unwrap();
        let expected_json = json!("loading");
        let serialized_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serialized_value, expected_json);
        let deserialized: EscrowState = from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);

        let state: EscrowState = EscrowState::Locked;
        let serialized = to_string(&state).unwrap();
        let expected_json = json!("locked");
        let serialized_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serialized_value, expected_json);
        let deserialized: EscrowState = from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);

        let state: EscrowState = EscrowState::Released;
        let serialized = to_string(&state).unwrap();
        let expected_json = json!("released");
        let serialized_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serialized_value, expected_json);
        let deserialized: EscrowState = from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);

        let state: EscrowState = EscrowState::Closed;
        let serialized = to_string(&state).unwrap();
        let expected_json = json!("closed");
        let serialized_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serialized_value, expected_json);
        let deserialized: EscrowState = from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn test_loaded_coins_serialization() {
        let obj = LoadedCoins {
            loader: "loader".to_string(),
            coins: vec![Coin::new(123u64, "uc4e")],
        };
        let serialized = serde_json::to_string(&obj).unwrap();
        let expected_json = json!({
            "loader": "loader",
            "coins": [{"denom":"uc4e","amount":"123"}]
        });
        let serialized_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serialized_value, expected_json);
        let deserialized: LoadedCoins = serde_json::from_str(&serialized).unwrap();
        assert_eq!(obj, deserialized);
    }

    #[test]
    fn test_escrow_operator_serialization() {
        let obj: EscrowOperator = EscrowOperator {
            id: "op_id".to_string(),
            controller: vec!["con1".to_string().into(), "con2".to_string().into()],
            enabled: true,
        };
        let serialized = serde_json::to_string(&obj).unwrap();
        let expected_json = json!({
            "id": "op_id",
            "controller": ["con1","con2"],
            "enabled": true
        });
        let serialized_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serialized_value, expected_json);
        let deserialized: EscrowOperator = serde_json::from_str(&serialized).unwrap();
        assert_eq!(obj, deserialized);
    }

    #[test]
    fn test_escrow_serialization() {
        let obj: Escrow = Escrow {
            id: "id".to_string(),
            operator_id: "op_id".to_string(),
            expected_coins: vec![Coin::new(123u64, "uc4e")],
            loaded_coins: Some(LoadedCoins {
                loader: "loader".to_string(),
                coins: vec![Coin::new(120u64, "uc4e")],
            }),
            operator_claimed: true,
            receiver: "recevier".to_string().into(),
            receiver_claimed: true,
            receiver_share: Decimal::from_str("334.05").expect("decimal error"),
            used_coins: vec![Coin::new(103u64, "utom")],
            state: EscrowState::Loading,
            loader_claimed: true,
            lock_timestamp: Some(Timestamp::from_nanos(1232141423))
        };
        let serialized = serde_json::to_string(&obj).unwrap();
        let expected_json = json!({
            "id": "id",
            "operator_id": "op_id",
            "expected_coins": [{"denom":"uc4e","amount":"123"}],
            "loaded_coins": {
                "loader": "loader",
                "coins": [{"denom":"uc4e","amount":"120"}]
            },
            "operator_claimed": true,
            "receiver": "recevier",
            "receiver_claimed": true,
            "receiver_share": "334.05",
            "used_coins": [{"denom":"utom","amount":"103"}],
            "state": "loading",
            "loader_claimed": true,
            "lock_timestamp": "1232141423"
        });
        let serialized_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serialized_value, expected_json);
        let deserialized: Escrow = serde_json::from_str(&serialized).unwrap();
        assert_eq!(obj, deserialized);
    }
}
