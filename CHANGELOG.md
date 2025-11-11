# Changelog

All notable changes to the Escrow Contract will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- State transition functions (load_funds, release_funds)
- Claim functions (claim_receiver_share, claim_operator_share)
- DID-based operator controller verification
- Receiver share validation (0.0-1.0 range)
- Query escrows by state
- Query escrows by receiver
- Refund functionality
- Time-lock mechanisms
- Batch operations
- Contract migration support
- Enhanced event emissions
- Comprehensive integration tests

## [0.1.0] - 2025-11-10

### Added
- Initial contract implementation using Sylvia framework
- Admin management system
  - Add admin functionality
  - Remove admin functionality
  - Admin authorization checks
- Escrow operator system
  - Create operator functionality
  - Query operator by ID
  - Operator storage with controller field (for future DID integration)
- Escrow management
  - Create escrow functionality
  - Query escrow by ID
  - Query escrows by operator with pagination
  - Multi-index storage structure
- State definitions
  - EscrowState enum (Loading, Locked, Released, Closed)
  - Escrow struct with all required fields
  - EscrowOperator struct
  - LoadedCoins struct for fund tracking
- Storage indexes
  - Operator index for efficient queries
  - Receiver index (prepared for future use)
  - Operator-state composite index
  - Receiver-state composite index
- Error handling
  - Custom ContractError enum
  - Comprehensive error types for all operations
- DID contract integration example
  - Cross-contract query capability
  - Example DID document retrieval
- Comprehensive testing
  - Admin management tests
  - Operator creation and retrieval tests
  - Escrow creation and query tests
  - Multi-index query tests
  - Error condition tests
  - Integration tests with DID contract
- Documentation
  - Contract design document
  - Complete API specification
  - Deployment guide with testnet and mainnet instructions
  - Real-world integration example (energy service payments)
  - README documentation index
- Project structure
  - Cargo.toml with all dependencies
  - Proper module organization
  - Schema generation support (via Sylvia)
- Apache 2.0 License

### Technical Details
- Built with CosmWASM 2.1.3
- Uses Sylvia 1.2.1 framework for cleaner code
- Implements cw-storage-plus 2.0.0 for efficient storage
- Multi-index support for flexible querying
- Pagination with configurable limits (default: 50, max: 200)
- Address validation using cosmwasm-std

### Known Limitations
- No state transition functions (escrow stays in Loading state)
- No fund loading mechanism
- No fund release mechanism
- No claim functionality
- Receiver share not validated (0.0-1.0 range)
- Operator controller verification not implemented
- No migration entry point
- Limited event emissions
- No time-lock support
- No refund mechanism

### Dependencies
```toml
cosmwasm-std = "2.1.3"
cw-storage-plus = "2.0.0"
sylvia = "1.2.1"
did-contract = { path = "../did" }
serde = "1.0.210"
thiserror = "1.0.64"
cosmwasm-schema = "2.1.3"
schemars = "0.8.21"
constcat = "0.5.0"
```

### Testing
- 12 comprehensive unit tests covering:
  - Admin operations
  - Operator CRUD operations
  - Escrow CRUD operations
  - Multi-index queries
  - Pagination
  - Error handling
  - Cross-contract queries

### Documentation
- 4 comprehensive markdown documents (~350 KB total)
- CLI examples for all operations
- TypeScript integration examples
- Complete workflow diagrams
- Security best practices
- Troubleshooting guide

## Version Numbering

We use [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible functionality additions
- **PATCH**: Backwards-compatible bug fixes

## Release Process

1. Update version in `Cargo.toml`
2. Update this CHANGELOG
3. Create git tag: `git tag -a v0.1.0 -m "Release v0.1.0"`
4. Push tag: `git push origin v0.1.0`
5. Build optimized WASM
6. Create GitHub release with artifacts

## License

Licensed under Apache License 2.0. See [LICENSE](LICENSE) file for details.

## Links

- [Repository](https://github.com/chain4energy/escrow-contract)
- [Issues](https://github.com/chain4energy/escrow-contract/issues)
- [Documentation](./docs/README.md)

## Migration Guide

### From Nothing to v0.1.0
- Initial release, no migration needed
- Follow [Deployment Guide](./docs/deployment-guide.md)

### Future Migrations
- Will be documented here as new versions are released
- Check migration guide in deployment documentation

---

**Note**: Versions prior to 1.0.0 may have breaking changes between minor versions.
