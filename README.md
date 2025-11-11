# Escrow Contract

A CosmWASM smart contract implementing a trustless escrow system for secure fund transfers between parties on the Chain4Energy blockchain.

## Overview

The Escrow Contract enables operators to create escrows that hold funds until specific conditions are met, with automated distribution between receivers and operators based on predefined shares. It provides a secure, transparent, and auditable way to manage conditional payments and revenue sharing.

## Key Features

- ✅ **Multi-party Escrows**: Support for operator and receiver with configurable share distribution
- ✅ **State Machine**: Clear escrow lifecycle (Loading → Locked → Released → Closed)
- ✅ **Admin Management**: Flexible admin system with add/remove capabilities
- ✅ **Operator System**: Create and manage multiple escrow operators
- ✅ **Multi-Index Queries**: Efficient queries by operator, receiver, and state
- ✅ **Pagination Support**: Handle large result sets efficiently
- ✅ **DID Integration**: Ready for integration with DID contract for enhanced authorization
- ✅ **Comprehensive Testing**: Unit tests with cw-multi-test framework

## Use Cases

### 1. Service Payment Escrow
Hold customer payments until service delivery is confirmed, then automatically distribute funds between service provider and platform.

### 2. Revenue Sharing
Automate revenue distribution between content creators and platforms based on configurable percentages.

### 3. Conditional Payments
Lock funds until external verification confirms conditions are met, then release to appropriate parties.

## Quick Start

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown

# Install CosmWASM tools
cargo install cosmwasm-check
```

### Build

```bash
# Clone repository
git clone https://github.com/chain4energy/escrow-contract.git
cd escrow-contract

# Build contract
cargo build

# Run tests
cargo test

# Build optimized WASM
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer:0.14.0
```

### Deploy

```bash
# Store contract
c4ed tx wasm store artifacts/escrow_contract.wasm --from admin --gas auto

# Instantiate
c4ed tx wasm instantiate $CODE_ID \
  '{"admins": ["c4e1admin..."]}' \
  --from admin --label "escrow-v1" --gas auto

# Create operator
c4ed tx wasm execute $CONTRACT_ADDRESS \
  '{"create_operator": {"operator_id": "operator-001"}}' \
  --from admin --gas auto

# Create escrow
c4ed tx wasm execute $CONTRACT_ADDRESS \
  '{
    "create_escrow": {
      "escrow_id": "escrow-001",
      "operator_id": "operator-001",
      "receiver": "c4e1receiver...",
      "expected_coins": [{"denom": "uc4e", "amount": "1000000"}],
      "receiver_share": "0.7"
    }
  }' \
  --from operator --gas auto
```

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[Contract Design](docs/contract-design.md)**: Architecture, concepts, and design decisions
- **[API Specification](docs/api-specification.md)**: Complete API reference with examples
- **[Deployment Guide](docs/deployment-guide.md)**: Step-by-step deployment instructions

## Project Structure

```
escrow-contract/
├── src/
│   ├── contract.rs      # Main contract logic and entry points
│   ├── state.rs         # State structures and storage definitions
│   ├── error.rs         # Custom error types
│   ├── lib.rs           # Library entry point
│   └── e2e_test/        # End-to-end tests
├── docs/
│   ├── contract-design.md       # Design documentation
│   ├── api-specification.md     # API reference
│   └── deployment-guide.md      # Deployment guide
├── artifacts/           # Compiled WASM binaries (generated)
├── schema/             # JSON schemas (generated)
├── Cargo.toml          # Rust dependencies
└── README.md           # This file
```

## API Overview

### Execute Messages

| Message | Description | Authorization |
|---------|-------------|---------------|
| `add_admin` | Add new administrator | Admin only |
| `remove_admin` | Remove administrator | Admin only |
| `create_operator` | Create escrow operator | Admin only |
| `create_escrow` | Create new escrow | Unrestricted (TODO: operator auth) |

### Query Messages

| Query | Description | Returns |
|-------|-------------|---------|
| `get_escrow_operator` | Get operator details | `EscrowOperator` |
| `get_escrow` | Get escrow details | `Escrow` |
| `get_escrow_by_operator` | List operator's escrows | `Vec<(String, Escrow)>` |
| `get_did` | Query DID from DID contract | `DidDocument` (example) |

## Escrow Lifecycle

```
┌─────────┐  load_funds()    ┌────────┐  release_funds()   ┌──────────┐
│ Loading │ ───────────────► │ Locked │ ─────────────────► │ Released │
└─────────┘                  └────────┘                    └────┬─────┘
                                                                │
                                                                │ claim()
                                                                ▼
                                                           ┌────────┐
                                                           │ Closed │
                                                           └────────┘
```

**States**:
- **Loading**: Awaiting fund deposit
- **Locked**: Funds loaded, awaiting release
- **Released**: Funds available for claiming
- **Closed**: All funds distributed

## Example Usage

### Create and Query Escrow

```bash
# Create operator
c4ed tx wasm execute $CONTRACT '{
  "create_operator": {"operator_id": "energy-provider"}
}' --from admin --gas auto

# Create escrow with 70% receiver share
c4ed tx wasm execute $CONTRACT '{
  "create_escrow": {
    "escrow_id": "payment-001",
    "operator_id": "energy-provider",
    "receiver": "c4e1customer...",
    "expected_coins": [{"denom": "uc4e", "amount": "1000000"}],
    "receiver_share": "0.7"
  }
}' --from operator --gas auto

# Query escrow
c4ed query wasm contract-state smart $CONTRACT '{
  "get_escrow": {"escrow_id": "payment-001"}
}'

# List all operator escrows
c4ed query wasm contract-state smart $CONTRACT '{
  "get_escrow_by_operator": {"operator_id": "energy-provider"}
}'
```

## Development

### Run Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_create_escrow

# Run with output
cargo test -- --nocapture
```

### Generate Schema

```bash
cargo run --bin schema
ls schema/
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint
cargo clippy -- -D warnings

# Check WASM
cosmwasm-check artifacts/escrow_contract.wasm
```

## Security Considerations

### Current Implementation
- ✅ Admin-only operator creation
- ✅ Address validation for all addresses
- ✅ State machine prevents invalid transitions
- ✅ Multi-index storage for efficient queries

### Planned Enhancements
- 🔄 DID-based operator controller verification
- 🔄 Receiver share validation (0.0-1.0 range)
- 🔄 Time-lock mechanisms
- 🔄 Refund functionality
- 🔄 Multi-sig admin operations

## Dependencies

- **cosmwasm-std**: ^2.1.3 - CosmWASM standard library
- **cw-storage-plus**: ^2.0.0 - Enhanced storage utilities
- **sylvia**: ^1.2.1 - CosmWASM framework for cleaner code
- **did-contract**: Local path - DID contract integration
- **serde**: ^1.0.210 - Serialization framework
- **thiserror**: ^1.0.64 - Error handling

## Testing

The contract includes comprehensive tests:
- ✅ Admin management tests
- ✅ Operator creation and retrieval
- ✅ Escrow creation and queries
- ✅ Multi-index query tests
- ✅ Error condition handling
- ✅ DID contract integration tests

Test coverage focuses on:
- Functionality correctness
- Access control enforcement
- Error handling
- State management
- Query efficiency

## Roadmap

### v0.1.0 (Current)
- [x] Basic contract structure
- [x] Admin management
- [x] Operator system
- [x] Escrow creation
- [x] Multi-index queries

### v0.2.0 (Planned)
- [ ] State transition functions (load, release, claim)
- [ ] Fund distribution logic
- [ ] DID-based authorization
- [ ] Enhanced error handling
- [ ] Comprehensive events

### v0.3.0 (Future)
- [ ] Time-lock mechanisms
- [ ] Refund functionality
- [ ] Batch operations
- [ ] Contract migration support
- [ ] Advanced queries (by state, receiver)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

### Code Standards

- Follow Rust best practices
- Use `cargo fmt` for formatting
- Pass `cargo clippy` without warnings
- Add documentation for public APIs
- Include unit tests for new features
- Update CHANGELOG.md

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/chain4energy/escrow-contract/issues)
- **Discord**: [Chain4Energy Discord](https://discord.gg/c4e)
- **Documentation**: [docs/](docs/)
- **Website**: [https://c4e.io](https://c4e.io)

## Acknowledgments

Built with:
- [CosmWASM](https://cosmwasm.com/) - Smart contract platform
- [Sylvia](https://github.com/CosmWasm/sylvia) - CosmWASM framework
- [Chain4Energy](https://c4e.io/) - Blockchain infrastructure

## Version

Current version: **0.1.0**

For detailed changes, see [CHANGELOG.md](CHANGELOG.md) (if available).