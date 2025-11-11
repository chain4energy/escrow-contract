# Escrow Contract - Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the Escrow Contract to Chain4Energy blockchain, including local testing, testnet deployment, and mainnet deployment procedures.

## Prerequisites

### Required Tools

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
rustup target add wasm32-unknown-unknown

# CosmWasm tools
cargo install cosmwasm-check

# Chain4Energy CLI
# Download from: https://github.com/chain4energy/c4e-chain/releases
c4ed version

# Docker (for optimization)
docker --version
```

### Development Dependencies

```bash
# Install required Rust tools
cargo install cargo-generate cargo-run-script

# Verify installations
cargo --version
rustc --version
wasm32-unknown-unknown --version
```

## Project Setup

### Clone and Build

```bash
# Clone repository
git clone https://github.com/chain4energy/escrow-contract.git
cd escrow-contract

# Build contract
cargo build

# Run tests
cargo test

# Build WASM
cargo build --release --target wasm32-unknown-unknown
```

### Verify Build

```bash
# Check WASM binary
ls -lh target/wasm32-unknown-unknown/release/escrow_contract.wasm

# Verify with cosmwasm-check
cosmwasm-check target/wasm32-unknown-unknown/release/escrow_contract.wasm
```

Expected output:
```
Available capabilities: {"iterator", "staking", "stargate", "cosmwasm_1_1", "cosmwasm_1_2"}

target/wasm32-unknown-unknown/release/escrow_contract.wasm: pass

All contracts passed checks!
```

## Contract Optimization

### Using rust-optimizer

For production deployments, optimize the WASM binary to reduce size and gas costs.

```bash
# Using Docker
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer:0.14.0

# Output will be in artifacts/
ls -lh artifacts/
```

Expected artifacts:
```
artifacts/
├── checksums.txt
└── escrow_contract.wasm
```

### Verify Optimized Binary

```bash
# Check size (should be < 500KB)
ls -lh artifacts/escrow_contract.wasm

# Verify with cosmwasm-check
cosmwasm-check artifacts/escrow_contract.wasm
```

## Local Testing with cw-multi-test

### Run Unit Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_add_admin

# Run with output
cargo test -- --nocapture

# Run integration tests
cargo test --test '*'
```

### Generate Schema

```bash
# Generate JSON schemas
cargo run --bin schema

# Verify schemas generated
ls -lh schema/
```

Expected schema files:
```
schema/
├── instantiate_msg.json
├── execute_msg.json
├── query_msg.json
└── ...
```

## Testnet Deployment

### Network Configuration

```bash
# Set environment variables
export CHAIN_ID="c4e-testnet-1"
export NODE="https://rpc-testnet.c4e.io:443"
export ADMIN_WALLET="admin"
```

### Upload Contract

```bash
# Store code on-chain
c4ed tx wasm store artifacts/escrow_contract.wasm \
  --from $ADMIN_WALLET \
  --chain-id $CHAIN_ID \
  --node $NODE \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  -y

# Get transaction hash from output
TX_HASH="ABC123..."

# Query code ID
c4ed query tx $TX_HASH --node $NODE --output json | jq -r '.logs[0].events[] | select(.type == "store_code") | .attributes[] | select(.key == "code_id") | .value'

# Store code ID
CODE_ID=123
```

### Instantiate Contract

```bash
# Get admin address
ADMIN_ADDRESS=$(c4ed keys show $ADMIN_WALLET --address)

# Instantiate contract
c4ed tx wasm instantiate $CODE_ID \
  '{
    "admins": ["'$ADMIN_ADDRESS'"]
  }' \
  --from $ADMIN_WALLET \
  --label "escrow-contract-v1" \
  --admin $ADMIN_ADDRESS \
  --chain-id $CHAIN_ID \
  --node $NODE \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  -y

# Get contract address from transaction
TX_HASH="DEF456..."
c4ed query tx $TX_HASH --node $NODE --output json | jq -r '.logs[0].events[] | select(.type == "instantiate") | .attributes[] | select(.key == "_contract_address") | .value'

# Store contract address
CONTRACT_ADDRESS="c4e1contract..."
```

### Verify Deployment

```bash
# Query contract info
c4ed query wasm contract $CONTRACT_ADDRESS --node $NODE

# Query contract state (get admin via internal query)
c4ed query wasm contract-state smart $CONTRACT_ADDRESS \
  '{"get_escrow_operator": {"operator_id": "test"}}' \
  --node $NODE
```

## Mainnet Deployment

### Pre-deployment Checklist

- [ ] All tests passing (`cargo test`)
- [ ] Contract optimized (using rust-optimizer)
- [ ] WASM size < 500KB
- [ ] Security audit completed
- [ ] Admin keys secured (hardware wallet recommended)
- [ ] Migration plan documented
- [ ] Monitoring setup ready
- [ ] Backup admin addresses prepared

### Network Configuration

```bash
# Mainnet configuration
export CHAIN_ID="c4e-chain-1"
export NODE="https://rpc.c4e.io:443"
export ADMIN_WALLET="mainnet-admin"

# Verify connection
c4ed status --node $NODE
```

### Upload to Mainnet

```bash
# Store optimized WASM
c4ed tx wasm store artifacts/escrow_contract.wasm \
  --from $ADMIN_WALLET \
  --chain-id $CHAIN_ID \
  --node $NODE \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  -y

# Get code ID
CODE_ID=456
```

### Instantiate on Mainnet

```bash
# Prepare admin addresses
ADMIN_1=$(c4ed keys show admin1 --address)
ADMIN_2=$(c4ed keys show admin2 --address)
ADMIN_3=$(c4ed keys show admin3 --address)

# Instantiate with multiple admins
c4ed tx wasm instantiate $CODE_ID \
  '{
    "admins": ["'$ADMIN_1'", "'$ADMIN_2'", "'$ADMIN_3'"]
  }' \
  --from $ADMIN_WALLET \
  --label "escrow-contract-mainnet-v1" \
  --admin $ADMIN_1 \
  --chain-id $CHAIN_ID \
  --node $NODE \
  --gas auto \
  --gas-adjustment 1.3 \
  --gas-prices 0.025uc4e \
  -y

# Save contract address
CONTRACT_ADDRESS="c4e1mainnet..."
```

## Post-Deployment Setup

### Initial Configuration

```bash
# 1. Create operators
c4ed tx wasm execute $CONTRACT_ADDRESS \
  '{
    "create_operator": {
      "operator_id": "operator-001"
    }
  }' \
  --from $ADMIN_WALLET \
  --chain-id $CHAIN_ID \
  --node $NODE \
  --gas auto \
  -y

# 2. Verify operator creation
c4ed query wasm contract-state smart $CONTRACT_ADDRESS \
  '{
    "get_escrow_operator": {
      "operator_id": "operator-001"
    }
  }' \
  --node $NODE

# 3. Add additional admins if needed
c4ed tx wasm execute $CONTRACT_ADDRESS \
  '{
    "add_admin": {
      "new_admin": "c4e1newadmin..."
    }
  }' \
  --from $ADMIN_WALLET \
  --chain-id $CHAIN_ID \
  --node $NODE \
  --gas auto \
  -y
```

### Create Test Escrow

```bash
# Create test escrow to verify functionality
c4ed tx wasm execute $CONTRACT_ADDRESS \
  '{
    "create_escrow": {
      "escrow_id": "test-escrow-001",
      "operator_id": "operator-001",
      "receiver": "c4e1receiver...",
      "expected_coins": [
        {
          "denom": "uc4e",
          "amount": "1000000"
        }
      ],
      "receiver_share": "0.7"
    }
  }' \
  --from operator \
  --chain-id $CHAIN_ID \
  --node $NODE \
  --gas auto \
  -y

# Verify escrow creation
c4ed query wasm contract-state smart $CONTRACT_ADDRESS \
  '{
    "get_escrow": {
      "escrow_id": "test-escrow-001"
    }
  }' \
  --node $NODE
```

## Contract Migration

### When to Migrate

- Bug fixes in contract logic
- New features added
- Security vulnerabilities discovered
- Performance improvements

### Migration Process

```bash
# 1. Build and optimize new version
cargo build --release --target wasm32-unknown-unknown
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer:0.14.0

# 2. Upload new version
c4ed tx wasm store artifacts/escrow_contract.wasm \
  --from $ADMIN_WALLET \
  --chain-id $CHAIN_ID \
  --node $NODE \
  --gas auto \
  -y

NEW_CODE_ID=789

# 3. Migrate contract (if migrate entry point implemented)
c4ed tx wasm migrate $CONTRACT_ADDRESS $NEW_CODE_ID \
  '{}' \
  --from $ADMIN_WALLET \
  --chain-id $CHAIN_ID \
  --node $NODE \
  --gas auto \
  -y

# 4. Verify migration
c4ed query wasm contract $CONTRACT_ADDRESS --node $NODE
```

**Note**: Current contract does not implement migrate entry point. This is a planned feature.

## Monitoring and Maintenance

### Query Contract State

```bash
# Get specific escrow
c4ed query wasm contract-state smart $CONTRACT_ADDRESS \
  '{"get_escrow": {"escrow_id": "escrow-001"}}' \
  --node $NODE

# Get operator escrows
c4ed query wasm contract-state smart $CONTRACT_ADDRESS \
  '{"get_escrow_by_operator": {"operator_id": "operator-001"}}' \
  --node $NODE

# Get contract info
c4ed query wasm contract $CONTRACT_ADDRESS --node $NODE
```

### Event Monitoring

```bash
# Subscribe to contract events
c4ed query tx-search \
  "wasm._contract_address='$CONTRACT_ADDRESS'" \
  --node $NODE \
  --limit 10

# Monitor specific event types
c4ed query tx-search \
  "wasm._contract_address='$CONTRACT_ADDRESS' AND wasm.action='create_escrow'" \
  --node $NODE
```

### Logging and Alerts

Set up monitoring for:
- Contract execution failures
- Unauthorized access attempts
- State changes (escrow creation, releases, claims)
- Admin modifications
- Unusual gas consumption patterns

## Troubleshooting

### Common Issues

#### 1. Contract Upload Fails

```bash
# Issue: Out of gas
# Solution: Increase gas limit
--gas 3000000

# Issue: Insufficient funds
# Solution: Ensure wallet has enough balance
c4ed query bank balances $ADMIN_ADDRESS --node $NODE
```

#### 2. Instantiation Fails

```bash
# Issue: Invalid admin address
# Solution: Verify address format
c4ed keys show $ADMIN_WALLET --address

# Issue: Code ID not found
# Solution: Verify code ID exists
c4ed query wasm code $CODE_ID --node $NODE
```

#### 3. Execution Fails

```bash
# Issue: Unauthorized
# Solution: Check if sender is admin
c4ed query wasm contract-state smart $CONTRACT_ADDRESS \
  '{"is_admin": {"address": "'$SENDER_ADDRESS'"}}' \
  --node $NODE

# Issue: Invalid JSON
# Solution: Validate JSON syntax
echo '{"create_operator": {"operator_id": "test"}}' | jq .
```

#### 4. Query Returns Error

```bash
# Issue: Contract not found
# Solution: Verify contract address
c4ed query wasm contract $CONTRACT_ADDRESS --node $NODE

# Issue: Escrow not found
# Solution: Check escrow ID spelling
c4ed query wasm contract-state smart $CONTRACT_ADDRESS \
  '{"get_escrow_by_operator": {"operator_id": "operator-001"}}' \
  --node $NODE
```

## Gas Estimation

### Typical Gas Costs

| Operation | Estimated Gas | Cost (0.025 uc4e/gas) |
|-----------|---------------|------------------------|
| Store Code | ~2,000,000 | ~50,000 uc4e |
| Instantiate | ~200,000 | ~5,000 uc4e |
| Create Operator | ~100,000 | ~2,500 uc4e |
| Create Escrow | ~150,000 | ~3,750 uc4e |
| Query | Free | 0 uc4e |

**Note**: Actual costs may vary based on network conditions and message complexity.

## Security Best Practices

### Key Management

1. **Hardware Wallets**: Use for mainnet admin keys
2. **Multi-sig**: Implement multiple admins for critical operations
3. **Key Rotation**: Regularly rotate admin keys
4. **Backup**: Securely store mnemonic phrases offline

### Access Control

1. **Principle of Least Privilege**: Grant minimum necessary permissions
2. **Regular Audits**: Review admin list periodically
3. **Operator Verification**: Implement DID-based controller checks
4. **Rate Limiting**: Consider implementing rate limits for escrow creation

### Operational Security

1. **Testnet First**: Always test on testnet before mainnet
2. **Gradual Rollout**: Start with small limits and scale up
3. **Monitoring**: Set up alerts for suspicious activity
4. **Incident Response**: Have a plan for security incidents
5. **Regular Updates**: Keep contract updated with security patches

## Environment Variables Template

Create a `.env` file (never commit to git):

```bash
# Network Configuration
CHAIN_ID="c4e-testnet-1"
NODE="https://rpc-testnet.c4e.io:443"

# Contract Details
CODE_ID="123"
CONTRACT_ADDRESS="c4e1contract..."

# Admin Configuration
ADMIN_WALLET="admin"
ADMIN_ADDRESS="c4e1admin..."

# Gas Configuration
GAS_PRICES="0.025uc4e"
GAS_ADJUSTMENT="1.3"

# Operator Configuration
OPERATOR_ID="operator-001"
```

## Resources

### Documentation
- [CosmWASM Documentation](https://docs.cosmwasm.com/)
- [Chain4Energy Documentation](https://docs.c4e.io/)
- [Sylvia Framework](https://github.com/CosmWasm/sylvia)

### Tools
- [CosmWASM IDE](https://ide.cosmwasm.com/)
- [Contract Explorer](https://explorer.c4e.io/)
- [Gas Estimator](https://gas.cosmwasm.com/)

### Support
- GitHub Issues: https://github.com/chain4energy/escrow-contract/issues
- Discord: https://discord.gg/c4e
- Telegram: https://t.me/chain4energy

## Changelog

### v0.1.0 (Current)
- Initial release
- Admin management
- Operator creation
- Escrow creation
- Multi-index queries
- DID contract integration example

### Planned Features
- State transition functions (load, release, claim)
- Migration support
- Enhanced DID integration
- Batch operations
- Event emissions
- Advanced queries
