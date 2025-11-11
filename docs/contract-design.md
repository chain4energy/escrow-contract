# Escrow Contract - Design Document

## Overview

The Escrow Contract is a CosmWASM smart contract that implements a trustless escrow system for managing secure fund transfers between parties. It enables operators to create escrows that hold funds until specific conditions are met, with automated distribution between receivers and operators based on predefined shares.

## Purpose

The escrow contract serves as a **trustless intermediary** for financial transactions, particularly useful in scenarios where:
- Payments need to be held until service delivery is confirmed
- Revenue sharing between multiple parties needs to be automated
- Conditional releases of funds based on external verification are required
- Transparent and auditable fund management is essential

## Key Concepts

### Escrow Operator
An **Escrow Operator** is an entity authorized to create and manage escrows. Operators are identified by unique IDs and have associated controllers (DIDs or addresses) that can manage their escrows.

**Properties**:
- `id`: Unique identifier for the operator
- `controller`: List of DIDs that control the operator

**Use Cases**:
- Service providers managing multiple escrows
- Organizations handling payments for delivered services
- Automated systems that create escrows based on business logic

### Escrow
An **Escrow** represents a locked fund container with specific rules for distribution.

**Properties**:
- `id`: Unique identifier for the escrow
- `operator_id`: The operator who created this escrow
- `expected_coins`: The amount and denomination of funds expected to be loaded
- `loaded_coins`: Actual funds loaded into the escrow (with loader information)
- `used_coins`: Funds that have been utilized (for tracking purposes)
- `receiver`: Address that will receive their share of funds
- `receiver_share`: Decimal percentage (0.0 to 1.0) of funds allocated to receiver
- `receiver_claimed`: Flag indicating if receiver has claimed their funds
- `operator_claimed`: Flag indicating if operator has claimed their funds
- `state`: Current state of the escrow (Loading, Locked, Released, Closed)

### Escrow States

The escrow lifecycle follows a state machine pattern:

```
┌─────────┐
│ Loading │  ← Initial state: Waiting for funds to be deposited
└────┬────┘
     │ load_funds()
     ▼
┌─────────┐
│ Locked  │  ← Funds received: Awaiting release conditions
└────┬────┘
     │ release_funds()
     ▼
┌─────────┐
│Released │  ← Funds available for claiming by receiver & operator
└────┬────┘
     │ both parties claim
     ▼
┌─────────┐
│ Closed  │  ← Final state: All funds distributed
└─────────┘
```

**State Descriptions**:

1. **Loading**: 
   - Initial state after escrow creation
   - Waiting for funds to be deposited
   - Expected coins amount is defined

2. **Locked**: 
   - Funds have been loaded into the escrow
   - Awaiting external trigger to release
   - No claims can be made in this state

3. **Released**: 
   - Release conditions met, funds unlocked
   - Contains `used_coins` tracking for transparency
   - Receiver and operator can claim their respective shares
   - Distribution calculated based on `receiver_share` percentage

4. **Closed**: 
   - Both parties have claimed their funds
   - Escrow lifecycle complete
   - No further actions possible

## Architecture

### Contract Structure

```
EscrowContract
├── admins: Item<Vec<Addr>>           # List of contract administrators
├── did_contract: Item<Addr>          # Reference to DID contract (future use)
├── operators: Map<String, EscrowOperator>  # Operator registry
└── escrows: IndexedMap<Escrow>       # Escrow storage with indexes
```

### Storage Design

The contract uses efficient storage structures:

- **Item**: For singleton values (admin list, DID contract reference)
- **Map**: For simple key-value lookups (operators by ID)
- **IndexedMap**: For escrows with multiple query patterns

**Escrow Indexes**:
- `operator`: Find all escrows by operator ID
- `receiver`: Find all escrows by receiver address
- `operator_state`: Find escrows by operator and state combination
- `receiver_state`: Find escrows by receiver and state combination

This indexing strategy enables efficient queries like:
- "Show me all escrows for operator X"
- "Show me all locked escrows for receiver Y"
- "List all released escrows for operator Z"

### Access Control

The contract implements role-based access control:

1. **Admins**: 
   - Can add/remove other admins
   - Can create operators
   - Set during instantiation

2. **Operators**: 
   - Can create escrows
   - Can claim their share from released escrows
   - Identified by operator_id with optional controller DIDs

3. **Receivers**: 
   - Can claim their share from released escrows
   - Specified per escrow

4. **Loaders**: 
   - Can deposit funds into loading escrows
   - Tracked in LoadedCoins structure

## Fund Distribution Logic

When an escrow is released, funds are distributed according to the `receiver_share`:

```
Total Funds = loaded_coins.amount

Receiver Share = Total Funds × receiver_share
Operator Share = Total Funds × (1 - receiver_share)
```

**Example**:
- Total funds: 1000 uc4e
- Receiver share: 0.3 (30%)
- Receiver gets: 300 uc4e
- Operator gets: 700 uc4e

## Security Considerations

### Access Control
- All admin functions require caller to be in admin list
- Escrow creation requires caller to be authorized (TODO: implement controller verification)
- Claims can only be made by designated receiver or operator

### Fund Safety
- Funds are locked in contract until proper release conditions
- Double-claiming prevented by `receiver_claimed` and `operator_claimed` flags
- State machine prevents unauthorized state transitions

### Validation
- Addresses validated using `deps.api.addr_validate()`
- Duplicate operator/escrow IDs prevented
- Receiver share should be validated to be between 0.0 and 1.0 (TODO: implement)

## Integration Points

### DID Contract Integration
The escrow contract can integrate with the DID contract for:
- Verifying operator controllers via DIDs
- Linking escrows to decentralized identities
- Enhanced authorization based on DID documents

**Current Status**: Basic query integration implemented as example; full integration pending.

### Multi-Index Query Patterns
Efficient querying through indexes:
```rust
// Query by operator
get_escrow_by_operator(operator_id, limit, start_after)

// Future: Query by receiver
get_escrow_by_receiver(receiver_address, limit, start_after)

// Future: Query by state
get_escrows_by_state(state, limit, start_after)
```

## Use Case Examples

### 1. Service Payment Escrow
**Scenario**: Customer pays for a service; funds released upon completion.

```
1. Operator creates escrow (expected: 1000 uc4e, receiver_share: 0.8)
2. Customer loads funds into escrow → State: Locked
3. Service completed, operator releases funds → State: Released
4. Service provider (receiver) claims 800 uc4e
5. Operator claims 200 uc4e commission
6. Escrow closed
```

### 2. Revenue Sharing
**Scenario**: Platform shares revenue with content creator.

```
1. Platform (operator) creates escrow for creator (receiver_share: 0.7)
2. Revenue accumulated and loaded → State: Locked
3. Period ends, platform releases funds → State: Released
4. Creator claims 70% share
5. Platform claims 30% commission
6. Escrow closed
```

### 3. Conditional Payment
**Scenario**: Payment held until external verification.

```
1. Operator creates escrow with verification requirements
2. Payer loads funds → State: Locked
3. External oracle verifies conditions met
4. Operator releases funds → State: Released
5. Both parties claim respective shares
6. Escrow closed
```

## Future Enhancements

### Planned Features
1. **Time-based Releases**: Automatic release after specified block height/timestamp
2. **Multi-party Escrows**: Support for more than two parties with custom share distributions
3. **Refund Mechanism**: Allow refunds if conditions not met within timeframe
4. **Partial Releases**: Support for incremental fund releases
5. **Controller Verification**: Implement DID-based controller authorization
6. **State Queries**: Add queries to list escrows by state
7. **Dispute Resolution**: Mechanism for handling disputes with arbitration
8. **Event Emissions**: Comprehensive event logging for all state changes

### Technical Improvements
1. **Migration Support**: Add migrate entry point for contract upgrades
2. **Receiver Share Validation**: Enforce 0.0 ≤ receiver_share ≤ 1.0
3. **Gas Optimization**: Optimize storage patterns for large-scale usage
4. **Batch Operations**: Support batch escrow creation and claims
5. **Admin Governance**: Multi-sig admin control for critical operations

## Performance Considerations

### Storage Efficiency
- IndexedMap enables O(1) lookups with multiple query patterns
- Pagination support (DEFAULT_LIMIT: 50, MAX_LIMIT: 200) for large result sets
- Efficient state transitions without full escrow reloading

### Gas Optimization
- Minimal storage writes during state transitions
- Indexed queries reduce iteration overhead
- Bounded pagination prevents excessive gas consumption

### Scalability
- Design supports thousands of concurrent escrows
- Multi-index structure scales with escrow count
- Efficient cleanup of closed escrows (future enhancement)

## Testing Strategy

The contract includes comprehensive tests covering:
- Admin management (add/remove)
- Operator creation and retrieval
- Escrow lifecycle (create, load, release, claim, close)
- Multi-index queries and pagination
- Error conditions and unauthorized access
- Integration with DID contract

## Conclusion

The Escrow Contract provides a robust, secure, and flexible foundation for managing trustless fund transfers on the Chain4Energy blockchain. Its state machine design, multi-index storage, and role-based access control make it suitable for a wide range of escrow use cases while maintaining security and efficiency.
