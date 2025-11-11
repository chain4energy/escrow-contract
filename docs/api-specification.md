# Escrow Contract - API Specification

## Overview

This document provides the complete API specification for the Escrow Contract, including all instantiate, execute, and query messages with their parameters, return types, and usage examples.

## Contract Information

- **Contract Name**: `escrow-contract`
- **Version**: `0.1.0`
- **Framework**: Sylvia (CosmWASM)
- **Language**: Rust

## Message Types

### Instantiate Message

Initialize the contract with a list of administrators.

**Message Structure**:
```rust
pub struct InstantiateMsg {
    pub admins: Vec<Addr>,
}
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `admins` | `Vec<Addr>` | Yes | List of initial administrator addresses |

**Example**:
```bash
c4ed tx wasm instantiate $CODE_ID '{
  "admins": ["c4e1admin1...", "c4e1admin2..."]
}' \
  --from admin \
  --label "escrow-v1" \
  --gas auto \
  --gas-adjustment 1.3
```

**Response**:
- Standard instantiation response with contract address

**Errors**:
- `ContractError::EscrowError`: Storage error during initialization

---

## Execute Messages

### 1. Add Admin

Add a new administrator to the contract.

**Authorization**: Requires caller to be an existing admin.

**Message Structure**:
```rust
pub fn add_admin(new_admin: String) -> Result<Response, ContractError>
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `new_admin` | `String` | Yes | Address of the new admin to add |

**Example**:
```bash
c4ed tx wasm execute $CONTRACT_ADDRESS '{
  "add_admin": {
    "new_admin": "c4e1newadmin..."
  }
}' --from admin --gas auto
```

**Response**:
```json
{
  "attributes": [
    {"key": "action", "value": "add_admin"},
    {"key": "new_admin", "value": "c4e1newadmin..."}
  ],
  "events": [
    {
      "type": "wasm-add_admin",
      "attributes": [
        {"key": "executor", "value": "c4e1admin..."},
        {"key": "new_admin", "value": "c4e1newadmin..."}
      ]
    }
  ]
}
```

**Errors**:
- `ContractError::Unauthorized`: Caller is not an admin
- `StdError::GenericErr`: Address validation failed

---

### 2. Remove Admin

Remove an existing administrator from the contract.

**Authorization**: Requires caller to be an existing admin.

**Message Structure**:
```rust
pub fn remove_admin(admin_to_remove: String) -> Result<Response, ContractError>
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `admin_to_remove` | `String` | Yes | Address of the admin to remove |

**Example**:
```bash
c4ed tx wasm execute $CONTRACT_ADDRESS '{
  "remove_admin": {
    "admin_to_remove": "c4e1oldadmin..."
  }
}' --from admin --gas auto
```

**Response**:
```json
{
  "attributes": [
    {"key": "action", "value": "remove_admin"},
    {"key": "removed_admin", "value": "c4e1oldadmin..."}
  ]
}
```

**Errors**:
- `ContractError::Unauthorized`: Caller is not an admin
- `ContractError::AdminNotFound`: Admin to remove does not exist
- `StdError::GenericErr`: Address validation failed

---

### 3. Create Operator

Create a new escrow operator.

**Authorization**: Requires caller to be an admin.

**Message Structure**:
```rust
pub fn create_operator(operator_id: String) -> Result<Response, ContractError>
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `operator_id` | `String` | Yes | Unique identifier for the operator |

**Example**:
```bash
c4ed tx wasm execute $CONTRACT_ADDRESS '{
  "create_operator": {
    "operator_id": "operator-energy-provider-001"
  }
}' --from admin --gas auto
```

**Response**:
- Standard response (no specific attributes currently)

**Errors**:
- `ContractError::Unauthorized`: Caller is not an admin
- `ContractError::OperatorAlreadyExists`: Operator ID already in use
- `ContractError::EscrowOperatorError`: Storage error

---

### 4. Create Escrow

Create a new escrow with specified parameters.

**Authorization**: Currently unrestricted (TODO: implement operator controller verification).

**Message Structure**:
```rust
pub fn create_escrow(
    escrow_id: String,
    operator_id: String,
    receiver: String,
    expected_coins: Vec<Coin>,
    receiver_share: Decimal
) -> Result<Response, ContractError>
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `escrow_id` | `String` | Yes | Unique identifier for the escrow |
| `operator_id` | `String` | Yes | ID of the operator creating this escrow |
| `receiver` | `String` | Yes | Address that will receive their share |
| `expected_coins` | `Vec<Coin>` | Yes | Expected amount and denomination of funds |
| `receiver_share` | `Decimal` | Yes | Decimal percentage (0.0-1.0) for receiver |

**Example**:
```bash
c4ed tx wasm execute $CONTRACT_ADDRESS '{
  "create_escrow": {
    "escrow_id": "escrow-payment-001",
    "operator_id": "operator-energy-provider-001",
    "receiver": "c4e1receiver...",
    "expected_coins": [
      {
        "denom": "uc4e",
        "amount": "1000000"
      }
    ],
    "receiver_share": "0.7"
  }
}' --from operator --gas auto
```

**Response**:
- Standard response (no specific attributes currently)

**Errors**:
- `ContractError::OperatorNotExists`: Specified operator does not exist
- `ContractError::EscrowAlreadyExists`: Escrow ID already in use
- `ContractError::EscrowOperatorError`: Storage error

**Notes**:
- `receiver_share` should be between 0.0 and 1.0 (validation TODO)
- Initial state will be `Loading`

---

## Query Messages

### 1. Get DID (Temporary Example)

Query DID document from the DID contract (example integration).

**Message Structure**:
```rust
pub fn get_did(addr: Addr, did: String) -> Result<DidDocument, ContractError>
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `addr` | `Addr` | Yes | Address of the DID contract |
| `did` | `String` | Yes | DID identifier to query |

**Example**:
```bash
c4ed query wasm contract-state smart $CONTRACT_ADDRESS '{
  "get_did": {
    "addr": "c4e1didcontract...",
    "did": "did:c4e:owner:alice"
  }
}'
```

**Response**:
```json
{
  "id": "did:c4e:owner:alice",
  "controller": ["c4e1controller..."],
  "service": [
    {
      "id": "did:c4e:owner:alice#service1",
      "a_type": "ServiceType",
      "service_endpoint": "https://example.com"
    }
  ]
}
```

**Errors**:
- `ContractError::EscrowError`: DID contract query failed

---

### 2. Get Escrow Operator

Retrieve operator information by ID.

**Message Structure**:
```rust
pub fn get_escrow_operator(operator_id: String) -> Result<EscrowOperator, ContractError>
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `operator_id` | `String` | Yes | Unique identifier of the operator |

**Example**:
```bash
c4ed query wasm contract-state smart $CONTRACT_ADDRESS '{
  "get_escrow_operator": {
    "operator_id": "operator-energy-provider-001"
  }
}'
```

**Response**:
```json
{
  "id": "operator-energy-provider-001",
  "controller": []
}
```

**Errors**:
- `ContractError::EscrowOperatorNotFound`: Operator does not exist
- `ContractError::EscrowOperatorError`: Storage error

---

### 3. Get Escrow

Retrieve escrow information by ID.

**Message Structure**:
```rust
pub fn get_escrow(escrow_id: String) -> Result<Escrow, ContractError>
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `escrow_id` | `String` | Yes | Unique identifier of the escrow |

**Example**:
```bash
c4ed query wasm contract-state smart $CONTRACT_ADDRESS '{
  "get_escrow": {
    "escrow_id": "escrow-payment-001"
  }
}'
```

**Response**:
```json
{
  "id": "escrow-payment-001",
  "operator_id": "operator-energy-provider-001",
  "expected_coins": [
    {
      "denom": "uc4e",
      "amount": "1000000"
    }
  ],
  "loaded_coins": null,
  "used_coins": [],
  "state": "loading",
  "receiver": "c4e1receiver...",
  "receiver_share": "0.7",
  "receiver_claimed": false,
  "operator_claimed": false
}
```

**State Values**:
- `"loading"`: Waiting for funds
- `"locked"`: Funds loaded, awaiting release
- `{"released": {"used_coins": [...]}}`: Funds available for claiming
- `"closed"`: Escrow completed

**Errors**:
- `ContractError::EscrowNotFound`: Escrow does not exist
- `ContractError::EscrowError`: Storage error

---

### 4. Get Escrows by Operator

Retrieve all escrows for a specific operator with pagination.

**Message Structure**:
```rust
pub fn get_escrow_by_operator(
    operator_id: String,
    limit: Option<usize>,
    start_after: Option<String>
) -> Result<Vec<(String, Escrow)>, ContractError>
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `operator_id` | `String` | Yes | Operator ID to query escrows for |
| `limit` | `Option<usize>` | No | Maximum number of results (default: 50, max: 200) |
| `start_after` | `Option<String>` | No | Escrow ID to start pagination after |

**Example**:
```bash
# Get first page (up to 50 escrows)
c4ed query wasm contract-state smart $CONTRACT_ADDRESS '{
  "get_escrow_by_operator": {
    "operator_id": "operator-energy-provider-001"
  }
}'

# Get next page with custom limit
c4ed query wasm contract-state smart $CONTRACT_ADDRESS '{
  "get_escrow_by_operator": {
    "operator_id": "operator-energy-provider-001",
    "limit": 100,
    "start_after": "escrow-payment-050"
  }
}'
```

**Response**:
```json
[
  [
    "escrow-payment-001",
    {
      "id": "escrow-payment-001",
      "operator_id": "operator-energy-provider-001",
      "expected_coins": [{"denom": "uc4e", "amount": "1000000"}],
      "loaded_coins": null,
      "used_coins": [],
      "state": "loading",
      "receiver": "c4e1receiver...",
      "receiver_share": "0.7",
      "receiver_claimed": false,
      "operator_claimed": false
    }
  ],
  [
    "escrow-payment-002",
    {
      "id": "escrow-payment-002",
      "operator_id": "operator-energy-provider-001",
      ...
    }
  ]
]
```

**Errors**:
- `ContractError::EscrowOperatorNotFound`: No escrows found for operator
- `ContractError::EscrowOperatorError`: Storage error

**Pagination Notes**:
- Results ordered by escrow ID (ascending)
- Use last escrow ID from previous response as `start_after` for next page
- Empty array returned when no more results

---

## Data Structures

### EscrowOperator

```rust
pub struct EscrowOperator {
    pub id: String,
    pub controller: Vec<String>,
}
```

**Fields**:
- `id`: Unique operator identifier
- `controller`: List of DIDs that control this operator

### Escrow

```rust
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
```

**Fields**:
- `id`: Unique escrow identifier
- `operator_id`: ID of the operator managing this escrow
- `expected_coins`: Amount and denomination expected
- `loaded_coins`: Actual loaded funds with loader info (optional)
- `used_coins`: Funds utilized (tracking purposes)
- `state`: Current escrow state
- `receiver`: Address receiving their share
- `receiver_share`: Decimal (0.0-1.0) representing receiver's percentage
- `receiver_claimed`: Whether receiver has claimed
- `operator_claimed`: Whether operator has claimed

### LoadedCoins

```rust
pub struct LoadedCoins {
    pub loader: String,
    pub coins: Vec<Coin>,
}
```

**Fields**:
- `loader`: Address that loaded the funds
- `coins`: Actual coins loaded

### EscrowState

```rust
pub enum EscrowState {
    Loading,
    Locked,
    Released { used_coins: Vec<Coin> },
    Closed,
}
```

**Variants**:
- `Loading`: Initial state, awaiting fund deposit
- `Locked`: Funds loaded, awaiting release
- `Released`: Funds unlocked with used_coins tracking
- `Closed`: Final state, all funds distributed

---

## Error Types

### ContractError

```rust
pub enum ContractError {
    Std(StdError),
    Unauthorized(),
    AdminNotFound(),
    EscrowOperatorNotFound(StdError),
    EscrowNotFound(StdError),
    EscrowError(StdError),
    EscrowOperatorError(StdError),
    OperatorNotExists,
    DidDocumentWrongOwner,
    OperatorAlreadyExists,
    EscrowAlreadyExists,
    DidDocumentControllerNotExists,
    DidDocumentServiceAlreadyExists,
    DidDocumentServiceNotExists,
}
```

**Error Descriptions**:
- `Unauthorized`: Caller lacks required permissions
- `AdminNotFound`: Admin to remove does not exist
- `EscrowOperatorNotFound`: Operator not found in storage
- `EscrowNotFound`: Escrow not found in storage
- `EscrowError`: General escrow operation error
- `EscrowOperatorError`: General operator operation error
- `OperatorNotExists`: Referenced operator does not exist
- `OperatorAlreadyExists`: Operator ID already used
- `EscrowAlreadyExists`: Escrow ID already used

---

## Usage Examples

### Complete Escrow Workflow

```bash
# 1. Instantiate contract
CODE_ID=123
c4ed tx wasm instantiate $CODE_ID '{
  "admins": ["c4e1admin..."]
}' --from admin --label "escrow-v1" --gas auto

CONTRACT_ADDRESS="c4e1contract..."

# 2. Create operator
c4ed tx wasm execute $CONTRACT_ADDRESS '{
  "create_operator": {
    "operator_id": "energy-provider-001"
  }
}' --from admin --gas auto

# 3. Create escrow
c4ed tx wasm execute $CONTRACT_ADDRESS '{
  "create_escrow": {
    "escrow_id": "payment-001",
    "operator_id": "energy-provider-001",
    "receiver": "c4e1receiver...",
    "expected_coins": [{"denom": "uc4e", "amount": "1000000"}],
    "receiver_share": "0.7"
  }
}' --from operator --gas auto

# 4. Query escrow status
c4ed query wasm contract-state smart $CONTRACT_ADDRESS '{
  "get_escrow": {
    "escrow_id": "payment-001"
  }
}'

# 5. Query all operator escrows
c4ed query wasm contract-state smart $CONTRACT_ADDRESS '{
  "get_escrow_by_operator": {
    "operator_id": "energy-provider-001"
  }
}'
```

### Admin Management

```bash
# Add new admin
c4ed tx wasm execute $CONTRACT_ADDRESS '{
  "add_admin": {
    "new_admin": "c4e1newadmin..."
  }
}' --from admin --gas auto

# Remove admin
c4ed tx wasm execute $CONTRACT_ADDRESS '{
  "remove_admin": {
    "admin_to_remove": "c4e1oldadmin..."
  }
}' --from admin --gas auto
```

---

## Future API Extensions

### Planned Execute Messages
1. `load_funds()`: Deposit funds into escrow (move to Locked state)
2. `release_funds()`: Release locked funds (move to Released state)
3. `claim_receiver_share()`: Receiver claims their funds
4. `claim_operator_share()`: Operator claims their funds
5. `refund_escrow()`: Refund funds if conditions not met
6. `cancel_escrow()`: Cancel escrow in Loading state

### Planned Query Messages
1. `get_escrows_by_receiver()`: Find all escrows for a receiver
2. `get_escrows_by_state()`: Find all escrows in a specific state
3. `get_escrow_statistics()`: Get aggregate statistics
4. `is_admin()`: Check if address is admin
5. `list_admins()`: Get all admin addresses

---

## Notes

- All addresses are validated using `deps.api.addr_validate()`
- Pagination uses `DEFAULT_LIMIT = 50` and `MAX_LIMIT = 200`
- State transitions are validated (cannot skip states)
- Claims are idempotent (claiming twice has no effect)
- The contract uses Sylvia framework for cleaner code generation

## Version History

- **v0.1.0**: Initial implementation
  - Basic admin management
  - Operator and escrow creation
  - Query functionality
  - Multi-index support
  - DID contract integration example
