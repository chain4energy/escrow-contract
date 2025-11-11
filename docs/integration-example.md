# Escrow Contract Integration Example: Energy Service Payments

## Overview

This document demonstrates how to integrate the Escrow Contract with the DID Contract to build a secure payment system for energy services on Chain4Energy. This example shows a real-world scenario where energy providers deliver services and receive automated payments through escrow.

***NOTE**: This is a demonstration example for illustrative purposes. Adapt as needed for production use.*

## Scenario: Green Energy Service Provider

### Business Context

**GreenPower Inc.** is an energy service provider that installs and maintains solar panels for customers. They use the escrow system to:
- Hold customer payments until installation is completed
- Automatically split revenue with their installation partners
- Provide transparent payment tracking
- Enable decentralized verification through DIDs

## System Architecture

### Component Roles

```
┌─────────────────────┐
│   Customer          │
│   (has DID)         │
└──────────┬──────────┘
           │ pays
           ▼
┌─────────────────────┐       manages        ┌─────────────────────┐
│   Escrow            │◄─────────────────────│  GreenPower Operator│
│   (holds funds)     │                      │  (has DID)          │
└──────────┬──────────┘                      └─────────────────────┘
           │ distributes
           ▼
┌─────────────────────┐
│  Installation Team  │
│  (receiver, has DID)│
└─────────────────────┘
```

### Data Flow

```
1. Customer orders solar panel installation
2. GreenPower creates escrow (70% to installer, 30% commission)
3. Customer loads payment into escrow → Locked
4. Installation team completes work
5. GreenPower verifies and releases funds → Released
6. Installation team claims 70%
7. GreenPower claims 30% commission
8. Escrow closed ✓
```

## Prerequisites

### Deployed Contracts

```bash
# Contract addresses
DID_CONTRACT="c4e1did..."
ESCROW_CONTRACT="c4e1escrow..."
```

### Participant Accounts

```bash
# System admin
ADMIN_ADDRESS="c4e1admin..."

# GreenPower operator
OPERATOR_ADDRESS="c4e1operator..."

# Installation team
INSTALLER_ADDRESS="c4e1installer..."

# Customer
CUSTOMER_ADDRESS="c4e1customer..."
```

## Step-by-Step Integration

### Phase 1: Setup Identities (DID Contract)

#### Step 1.1: Create Organization DID

GreenPower creates its organizational identity.

```bash
# Create GreenPower organization DID
c4ed tx wasm execute $DID_CONTRACT '{
  "create_did_document": {
    "did_doc": {
      "id": "did:c4e:greenpower-org",
      "controller": ["'$ADMIN_ADDRESS'"],
      "service": [
        {
          "id": "did:c4e:greenpower-org#website",
          "a_type": "Website",
          "service_endpoint": "https://greenpower.example.com"
        },
        {
          "id": "did:c4e:greenpower-org#api",
          "a_type": "ApiService",
          "service_endpoint": "https://api.greenpower.example.com"
        }
      ]
    }
  }
}' --from admin --gas auto
```

#### Step 1.2: Create Operator DID

The GreenPower operator identity with dual control.

```bash
# Create operator DID
c4ed tx wasm execute $DID_CONTRACT '{
  "create_did_document": {
    "did_doc": {
      "id": "did:c4e:greenpower-operator",
      "controller": [
        "'$OPERATOR_ADDRESS'",
        "did:c4e:greenpower-org"
      ],
      "service": [
        {
          "id": "did:c4e:greenpower-operator#profile",
          "a_type": "OperatorProfile",
          "service_endpoint": "https://greenpower.example.com/operator"
        }
      ]
    }
  }
}' --from admin --gas auto
```

#### Step 1.3: Create Installation Team DID

```bash
# Create installer DID
c4ed tx wasm execute $DID_CONTRACT '{
  "create_did_document": {
    "did_doc": {
      "id": "did:c4e:installer:solar-team-01",
      "controller": ["'$INSTALLER_ADDRESS'"],
      "service": [
        {
          "id": "did:c4e:installer:solar-team-01#contact",
          "a_type": "ContactService",
          "service_endpoint": "mailto:team01@solarinstall.example.com"
        },
        {
          "id": "did:c4e:installer:solar-team-01#certifications",
          "a_type": "CertificationService",
          "service_endpoint": "https://certs.solarinstall.example.com/team01"
        }
      ]
    }
  }
}' --from installer --gas auto
```

#### Step 1.4: Create Customer DID

```bash
# Customer creates their DID
c4ed tx wasm execute $DID_CONTRACT '{
  "create_did_document": {
    "did_doc": {
      "id": "did:c4e:customer:alice-homeowner",
      "controller": ["'$CUSTOMER_ADDRESS'"],
      "service": [
        {
          "id": "did:c4e:customer:alice-homeowner#profile",
          "a_type": "CustomerProfile",
          "service_endpoint": "https://greenpower.example.com/customers/alice"
        }
      ]
    }
  }
}' --from customer --gas auto
```

#### Step 1.5: Verify Identity Setup

```bash
# Verify all DIDs created
c4ed query wasm contract-state smart $DID_CONTRACT '{
  "get_did_document": {
    "did": "did:c4e:greenpower-org"
  }
}'

c4ed query wasm contract-state smart $DID_CONTRACT '{
  "get_did_document": {
    "did": "did:c4e:greenpower-operator"
  }
}'

c4ed query wasm contract-state smart $DID_CONTRACT '{
  "get_did_document": {
    "did": "did:c4e:installer:solar-team-01"
  }
}'

c4ed query wasm contract-state smart $DID_CONTRACT '{
  "get_did_document": {
    "did": "did:c4e:customer:alice-homeowner"
  }
}'

# Verify organization controls operator
c4ed query wasm contract-state smart $DID_CONTRACT '{
  "is_did_controller": {
    "did": "did:c4e:greenpower-operator",
    "controller": "did:c4e:greenpower-org"
  }
}'
```

### Phase 2: Setup Escrow System

#### Step 2.1: Create Escrow Operator

```bash
# Admin creates GreenPower operator in escrow contract
c4ed tx wasm execute $ESCROW_CONTRACT '{
  "create_operator": {
    "operator_id": "greenpower-operator-001"
  }
}' --from admin --gas auto

# Verify operator creation
c4ed query wasm contract-state smart $ESCROW_CONTRACT '{
  "get_escrow_operator": {
    "operator_id": "greenpower-operator-001"
  }
}'
```

**Response**:
```json
{
  "id": "greenpower-operator-001",
  "controller": []
}
```

**Note**: Future enhancement will link this operator to the DID `did:c4e:greenpower-operator`.

#### Step 2.2: Create Service Escrow

Customer orders solar panel installation worth 10,000 uc4e.

```bash
# GreenPower creates escrow for the installation project
# 70% goes to installation team, 30% is commission
c4ed tx wasm execute $ESCROW_CONTRACT '{
  "create_escrow": {
    "escrow_id": "escrow-solar-install-alice-001",
    "operator_id": "greenpower-operator-001",
    "receiver": "'$INSTALLER_ADDRESS'",
    "expected_coins": [
      {
        "denom": "uc4e",
        "amount": "10000000"
      }
    ],
    "receiver_share": "0.7"
  }
}' --from operator --gas auto
```

**What happens**:
- Escrow created in `Loading` state
- Receiver (installer) will get 70% = 7,000,000 uc4e
- Operator (GreenPower) will get 30% = 3,000,000 uc4e
- Awaiting customer payment

#### Step 2.3: Verify Escrow Creation

```bash
# Query escrow details
c4ed query wasm contract-state smart $ESCROW_CONTRACT '{
  "get_escrow": {
    "escrow_id": "escrow-solar-install-alice-001"
  }
}'
```

**Response**:
```json
{
  "id": "escrow-solar-install-alice-001",
  "operator_id": "greenpower-operator-001",
  "expected_coins": [
    {
      "denom": "uc4e",
      "amount": "10000000"
    }
  ],
  "loaded_coins": null,
  "used_coins": [],
  "state": "loading",
  "receiver": "c4e1installer...",
  "receiver_share": "0.7",
  "receiver_claimed": false,
  "operator_claimed": false
}
```

### Phase 3: Payment and Service Delivery

#### Step 3.1: Customer Loads Payment (Future Implementation)

**Note**: This function is not yet implemented. Here's how it would work:

```bash
# Customer sends payment to escrow
c4ed tx wasm execute $ESCROW_CONTRACT '{
  "load_funds": {
    "escrow_id": "escrow-solar-install-alice-001"
  }
}' \
  --from customer \
  --amount 10000000uc4e \
  --gas auto
```

**What would happen**:
1. Contract receives 10,000,000 uc4e from customer
2. Escrow state transitions: `Loading` → `Locked`
3. `loaded_coins` field populated with loader info
4. Funds held securely until release conditions met

#### Step 3.2: Installation Team Completes Work

**Off-chain process**:
1. Installation team installs solar panels
2. Customer verifies installation quality
3. GreenPower quality control checks
4. Digital signatures collected (optional)

#### Step 3.3: Release Funds (Future Implementation)

```bash
# GreenPower operator releases funds after verification
c4ed tx wasm execute $ESCROW_CONTRACT '{
  "release_funds": {
    "escrow_id": "escrow-solar-install-alice-001",
    "verification_proof": "ipfs://QmXxx..."
  }
}' --from operator --gas auto
```

**What would happen**:
1. Contract verifies caller is authorized operator
2. Escrow state transitions: `Locked` → `Released`
3. Funds now available for claiming
4. Event emitted for transparency

### Phase 4: Fund Distribution (Future Implementation)

#### Step 4.1: Installation Team Claims Their Share

```bash
# Installer claims 70% share
c4ed tx wasm execute $ESCROW_CONTRACT '{
  "claim_receiver_share": {
    "escrow_id": "escrow-solar-install-alice-001"
  }
}' --from installer --gas auto
```

**What would happen**:
1. Contract verifies caller is designated receiver
2. Calculates share: 10,000,000 × 0.7 = 7,000,000 uc4e
3. Transfers 7,000,000 uc4e to installer address
4. Sets `receiver_claimed = true`
5. Emits claim event

#### Step 4.2: GreenPower Claims Commission

```bash
# Operator claims 30% commission
c4ed tx wasm execute $ESCROW_CONTRACT '{
  "claim_operator_share": {
    "escrow_id": "escrow-solar-install-alice-001"
  }
}' --from operator --gas auto
```

**What would happen**:
1. Contract verifies caller is operator
2. Calculates share: 10,000,000 × 0.3 = 3,000,000 uc4e
3. Transfers 3,000,000 uc4e to operator address
4. Sets `operator_claimed = true`
5. Escrow state transitions: `Released` → `Closed`
6. Emits completion event

### Phase 5: Query and Audit

#### Step 5.1: View All Operator Escrows

```bash
# List all GreenPower escrows
c4ed query wasm contract-state smart $ESCROW_CONTRACT '{
  "get_escrow_by_operator": {
    "operator_id": "greenpower-operator-001",
    "limit": 50
  }
}'
```

**Response**:
```json
[
  [
    "escrow-solar-install-alice-001",
    {
      "id": "escrow-solar-install-alice-001",
      "operator_id": "greenpower-operator-001",
      "state": "closed",
      "receiver_claimed": true,
      "operator_claimed": true,
      ...
    }
  ],
  [
    "escrow-solar-install-bob-002",
    {
      "id": "escrow-solar-install-bob-002",
      "state": "locked",
      ...
    }
  ]
]
```

#### Step 5.2: Audit Trail

```bash
# Get transaction history for transparency
c4ed query tx-search \
  "wasm._contract_address='$ESCROW_CONTRACT' AND wasm.escrow_id='escrow-solar-install-alice-001'" \
  --limit 50

# Get all events for this escrow
c4ed query tx-search \
  "wasm.action='create_escrow' OR wasm.action='load_funds' OR wasm.action='release_funds'" \
  --limit 100
```

## Complete Workflow Visualization

```
┌─────────────────────────────────────────────────────────────────┐
│           Energy Service Payment Workflow                       │
└─────────────────────────────────────────────────────────────────┘

1. IDENTITY SETUP (DID Contract)
   ┌──────────────────────────────┐
   │  • GreenPower Organization   │
   │  • Operator Identity         │
   │  • Installation Team         │
   │  • Customer                  │
   └──────────────────────────────┘

2. ESCROW SETUP (Escrow Contract)
   ┌──────────────────────────────┐
   │  • Create Operator           │
   │  • Create Escrow             │
   │    - 70% to installer        │
   │    - 30% commission          │
   └──────────────────────────────┘

3. SERVICE ORDER
   Customer ──► Order Solar Panel Installation
                Expected Cost: 10,000,000 uc4e

4. PAYMENT LOADING
   Customer ──► Send 10,000,000 uc4e ──► Escrow (Locked)

5. SERVICE DELIVERY
   Installation Team ──► Install Solar Panels
   Quality Check ──► Verification ──► Approval

6. FUND RELEASE
   Operator ──► Release Funds ──► Escrow (Released)

7. CLAIMING
   ├─► Installer Claims 70% = 7,000,000 uc4e
   └─► Operator Claims 30% = 3,000,000 uc4e

8. COMPLETION
   Escrow ──► Closed ✓
   All parties satisfied
   Transparent audit trail maintained
```

## Integration with DID Contract

### Current Implementation

The escrow contract has basic DID contract query capability:

```typescript
// Example: Query DID from escrow contract
async function verifyParticipantDID(
  escrowContract: string,
  didContract: string,
  did: string
): Promise<DidDocument> {
  return await client.queryContractSmart(escrowContract, {
    get_did: {
      addr: didContract,
      did: did
    }
  });
}

// Verify operator DID exists
const operatorDid = await verifyParticipantDID(
  ESCROW_CONTRACT,
  DID_CONTRACT,
  "did:c4e:greenpower-operator"
);
```

### Future Enhancements

1. **Controller Verification**: Link escrow operators to DID controllers
2. **Automatic DID Checks**: Verify all participants have valid DIDs
3. **Service Attestations**: Link escrow to service DIDs for proof of delivery
4. **Multi-sig Releases**: Require multiple DID-controlled signatures

## Advanced Use Cases

### 1. Recurring Service Payments

For monthly maintenance contracts:

```bash
# Create monthly escrow series
for month in {1..12}; do
  c4ed tx wasm execute $ESCROW_CONTRACT '{
    "create_escrow": {
      "escrow_id": "maintenance-2024-month-'$month'",
      "operator_id": "greenpower-operator-001",
      "receiver": "'$INSTALLER_ADDRESS'",
      "expected_coins": [{"denom": "uc4e", "amount": "500000"}],
      "receiver_share": "0.8"
    }
  }' --from operator --gas auto
done
```

### 2. Multi-Project Portfolio

Query all active escrows:

```bash
# Get all operator escrows with pagination
c4ed query wasm contract-state smart $ESCROW_CONTRACT '{
  "get_escrow_by_operator": {
    "operator_id": "greenpower-operator-001",
    "limit": 100
  }
}' | jq '.[] | select(.[1].state != "closed")'
```

### 3. Performance Dashboard

```typescript
interface EscrowMetrics {
  totalEscrows: number;
  activeEscrows: number;
  completedEscrows: number;
  totalVolume: string;
  averageShare: string;
}

async function getOperatorMetrics(
  operatorId: string
): Promise<EscrowMetrics> {
  const escrows = await client.queryContractSmart(ESCROW_CONTRACT, {
    get_escrow_by_operator: {
      operator_id: operatorId
    }
  });

  const metrics: EscrowMetrics = {
    totalEscrows: escrows.length,
    activeEscrows: escrows.filter(([_, e]) => 
      e.state !== "closed"
    ).length,
    completedEscrows: escrows.filter(([_, e]) => 
      e.state === "closed"
    ).length,
    totalVolume: escrows.reduce((sum, [_, e]) => 
      sum + parseInt(e.expected_coins[0].amount), 0
    ).toString(),
    averageShare: (
      escrows.reduce((sum, [_, e]) => 
        sum + parseFloat(e.receiver_share), 0
      ) / escrows.length
    ).toFixed(2)
  };

  return metrics;
}
```

## Security Best Practices

### 1. Identity Verification
- Always verify DIDs exist before creating escrows
- Check DID controller relationships
- Maintain audit trail of all identity changes

### 2. Fund Safety
- Never bypass state machine transitions
- Verify all addresses before fund transfers
- Implement timeouts for dispute resolution
- Use multi-sig for high-value escrows

### 3. Operational Security
- Regular security audits
- Monitor for unusual escrow patterns
- Implement rate limiting for escrow creation
- Backup all escrow state regularly

## Future Development

### Planned Features

1. **State Transition Functions**
   - `load_funds()`: Accept customer payments
   - `release_funds()`: Authorize fund distribution
   - `claim_receiver_share()`: Receiver claims funds
   - `claim_operator_share()`: Operator claims commission

2. **Enhanced DID Integration**
   - Link operators to DID controllers
   - Verify installer certifications via DIDs
   - Customer identity verification
   - Service attestations

3. **Dispute Resolution**
   - Arbitration mechanism
   - Refund functionality
   - Partial releases
   - Multi-party agreements

4. **Automation**
   - Time-locked releases
   - Conditional releases based on oracles
   - Scheduled payments
   - Recurring escrows

5. **Analytics**
   - Query escrows by state
   - Query escrows by receiver
   - Performance metrics
   - Revenue statistics

## Troubleshooting

### Common Issues

**Issue**: Cannot create operator
```bash
# Solution: Ensure caller is admin
# Check admin status first
```

**Issue**: Escrow creation fails
```bash
# Solution: Verify operator exists
c4ed query wasm contract-state smart $ESCROW_CONTRACT '{
  "get_escrow_operator": {"operator_id": "your-operator-id"}
}'
```

**Issue**: Cannot query escrow
```bash
# Solution: Check escrow ID spelling
c4ed query wasm contract-state smart $ESCROW_CONTRACT '{
  "get_escrow_by_operator": {"operator_id": "greenpower-operator-001"}
}'
```

## Conclusion

This integration example demonstrates how the Escrow Contract and DID Contract work together to create a comprehensive, trustless payment system for service delivery. The combination enables:

- ✅ Decentralized identity for all participants
- ✅ Secure fund holding until service completion
- ✅ Automated revenue sharing based on predefined rules
- ✅ Complete transparency and auditability
- ✅ Trustless operations without central authority

The escrow system provides a solid foundation for building complex payment workflows in the energy sector and beyond, with clear upgrade paths for enhanced functionality.
