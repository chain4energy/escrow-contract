use cosmwasm_schema::cw_serde;
use schemars::JsonSchema;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use constcat::concat as constcat;
use cosmwasm_std::{Coin, Decimal, Addr};
use cw_storage_plus::{Index, IndexList, IndexedMap, MultiIndex};

#[cw_serde]
pub struct EscrowOperator {
    pub id: String,
    pub controller: Vec<String>,
}

impl EscrowOperator {
    pub fn has_controller(&self, did: &str) -> bool {
        self.controller.contains(&did.to_string())
    }
}

#[cw_serde]
pub struct Escrow {
    pub id: String,
    pub operator_id: String,
    pub expected_coins: Vec<Coin>,
    pub loaded_coins: Option<LoadedCoins>,
    pub used_coins: Vec<Coin>,
    pub state: EscrowState,
    pub receiver: String,
    pub receiver_share: Decimal,
    pub receiver_claimed: bool,
    pub operator_claimed: bool,
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
    Released{used_coins: Vec<Coin>},
    Closed
}

impl EscrowState {
    fn state_name(&self) -> String{
        let g = self;
        match g {
            EscrowState::Loading => "loading".to_string(),
            EscrowState::Locked => "locked".to_string(),
            EscrowState::Released { used_coins: _ } => "released".to_string(),
            EscrowState::Closed => "closed".to_string(),
        }
    }
}

impl Escrow {
    fn receiver_state_index(&self) -> String{
        let mut r = self.receiver.clone();
        r.push_str(self.state.state_name().as_str());
        r
    }

    fn operator_state_index(&self) -> String{
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
        |_pk, d: &Escrow| d.receiver.clone(),
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
        assert_eq!(serialized_value , expected_json);
        let deserialized: EscrowState = from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);

        let state: EscrowState = EscrowState::Locked;
        let serialized = to_string(&state).unwrap();
        let expected_json = json!("locked");
        let serialized_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serialized_value , expected_json);
        let deserialized: EscrowState = from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);

        let state: EscrowState = EscrowState::Released { used_coins: vec![Coin::new(123u64, "uc4e")] };
        let serialized = to_string(&state).unwrap();
        println!("dfsdfdsfds {}", serialized);
        assert_eq!("{\"released\":{\"used_coins\":[{\"denom\":\"uc4e\",\"amount\":\"123\"}]}}" , serialized);
        let deserialized: EscrowState = from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);

        let state: EscrowState = EscrowState::Closed;
        let serialized = to_string(&state).unwrap();
        let expected_json = json!("closed");
        let serialized_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serialized_value , expected_json);
        let deserialized: EscrowState = from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn test_loaded_coins_serialization() {
        let obj = LoadedCoins {
            loader: "loader".to_string(),
            coins:  vec![Coin::new(123u64, "uc4e")],
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
            controller:  vec!["con1".to_string(), "con2".to_string()],
        };
        let serialized = serde_json::to_string(&obj).unwrap();
        let expected_json = json!({
            "id": "op_id",
            "controller": ["con1","con2"]
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
            loaded_coins:  Some(LoadedCoins {
                loader: "loader".to_string(),
                coins:  vec![Coin::new(120u64, "uc4e")],
            }),
            operator_claimed: true,
            receiver: "recevier".to_string(),
            receiver_claimed: true,
            receiver_share: Decimal::from_str("334.05").expect("decimal error"),
            used_coins: vec![Coin::new(103u64, "utom")],
            state: EscrowState::Loading,
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
            "state": "loading"
        });
        let serialized_value: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(serialized_value, expected_json);
        let deserialized: Escrow = serde_json::from_str(&serialized).unwrap();
        assert_eq!(obj, deserialized);
    }

}
