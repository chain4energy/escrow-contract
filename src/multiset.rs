use cw_storage_plus::{Bound, Map};
use cosmwasm_std::{Empty, Storage};

pub struct MultiSet {
    // Name for the map, used as a base for constructing key paths
    namespace: &'static str,
    primary_keys: Map<String, Empty>
}

impl MultiSet {
    // Create a new MultiMap with the given name
    pub const fn new(namespace: &'static str) -> Self {
        MultiSet { 
            namespace: namespace,
            primary_keys: Map::new(namespace)
         }
    }

    // Create a Path using the base name, primary key, and secondary key
    fn create_submap_key(&self, primary_key: &str) -> String {
        let mut r = self.namespace.to_string();
        r.push_str(primary_key);
        r
    }

    // fn create_prefix(&self, primary_key: &str) -> Path<bool> {
    //     Path::new(self.namespace.as_bytes(), &[primary_key.as_bytes()])
    // }

    // Add a value to the multi-map under the composite key (primary_key, secondary_key)
    pub fn save(
        &self,
        storage: &mut dyn Storage,
        primary_key: &str,
        value: &str
    ) -> Result<(), cosmwasm_std::StdError>  {
        let k = self.create_submap_key(primary_key);
        let map = get_map(&k);
        let empty = map.is_empty(storage);
        // let prefix = self.create_prefix(primary_key); 
        // let map: Map<String, bool> = Map::new_dyn(prefix.);
        map.save(storage, value.to_string(), &())?;
        if empty {
            self.primary_keys.save(storage, primary_key.to_string(), &Empty {})?;
        }
        Ok(())
    }

    // Remove a value from the multi-map under the composite key (primary_key, secondary_key)
    pub fn remove(
        &self,
        storage: &mut dyn Storage,
        primary_key: &str,
        secondary_key: &str,
    ) {
        let k = self.create_submap_key(primary_key);
        let map = get_map(&k);
        map.remove(storage, secondary_key.to_string());
        if map.is_empty(storage) {
            self.primary_keys.remove(storage, primary_key.to_string());
        }
    }

    // Get all values associated with a primary key by scanning the prefix
    pub fn is_empty(&self, storage: &dyn Storage, primary_key: &str) -> bool {
        let k = self.create_submap_key(primary_key);
        let map = get_map(&k);
        map.is_empty(storage)
    }



}

impl<'a> MultiSet {
    // Function to get all keys associated with a primary key
    pub fn get_values<'c>(
        &'a self,
        storage: &'c dyn Storage,
        primary_key: &str,
        min: Option<Bound<'a, String>>,
        max: Option<Bound<'a, String>>,
        order: cosmwasm_std::Order,
    ) -> Box<dyn Iterator<Item = Result<String, cosmwasm_std::StdError>> + 'c> {
        let k = self.create_submap_key(primary_key);
        let map: Map<String, bool> = Map::new_dyn(k);
        map.keys(storage, min, max, order)
    }

    pub fn get_primary_keys<'c>(
        &'a self,
        storage: &'c dyn Storage,
        min: Option<Bound<'a, String>>,
        max: Option<Bound<'a, String>>,
        order: cosmwasm_std::Order,
    ) -> Box<dyn Iterator<Item = Result<String, cosmwasm_std::StdError>> + 'c> {
        // let primary_keys_map: Map<String, bool> = Map::new_dyn(self.namespace);
        self.primary_keys.keys(storage, min, max, order)
    }
}

fn get_map(key: &str) -> Map<String, ()> {
    Map::new_dyn(key.to_string())
}