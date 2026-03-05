# DCTIN - Decentralized Cyber Threat Intelligence Network

A secure, gas-optimized Solidity smart contract for storing cyber threat intelligence on the blockchain.

## Overview

DCTIN provides an immutable, tamper-proof registry for cyber threat data including malware hashes, malicious IPs, phishing URLs, and attack signatures. The system uses role-based access control to ensure only authorized security researchers can submit threat reports.

## Features

- **Immutable Storage**: Threat reports cannot be deleted or modified once submitted
- **Role-Based Access Control**: Separate Admin and Reporter roles
- **Duplicate Prevention**: Automatic detection of existing threat hashes
- **Gas Optimized**: Efficient storage layout and O(1) lookups
- **Event Transparency**: Full audit trail via indexed events
- **Pagination Support**: Efficient data retrieval for large datasets

## Smart Contract Architecture

### Core Components

```
DCTIN.sol
├── AccessControl (OpenZeppelin)
├── ReentrancyGuard (OpenZeppelin)
├── ThreatReport Struct
├── ThreatType Enum
└── Mappings & Arrays for Storage
```

### Threat Types

| ID | Type | Description |
|----|------|-------------|
| 0 | MALWARE | Malware file hashes (MD5, SHA256) |
| 1 | PHISHING_URL | Phishing website URLs |
| 2 | MALICIOUS_IP | Malicious IP addresses |
| 3 | C2_SERVER | Command & Control servers |
| 4 | BOTNET_NODE | Botnet participant nodes |
| 5 | RANSOMWARE | Ransomware signatures |
| 6 | EXPLOIT_PAYLOAD | Exploit code/payloads |
| 7 | SUSPICIOUS_DOMAIN | Suspicious domains |

## Security Features

### 1. Access Control
- Uses OpenZeppelin's `AccessControl` for fine-grained permissions
- `DEFAULT_ADMIN_ROLE`: Can add/remove reporters, upgrade contract
- `REPORTER_ROLE`: Can submit new threat reports
- Deployer automatically receives both roles

### 2. Input Validation
- Empty threat hash rejection
- Invalid threat type detection
- Duplicate hash prevention via mapping lookup

### 3. Reentrancy Protection
- `nonReentrant` modifier on external state-changing functions
- Prevents reentrancy attacks on report submission

### 4. Gas Optimizations
- **1-based indexing**: Mapping uses index+1 to distinguish between "not found" (0) and index 0
- **Struct packing**: `address` (20) + `uint64` (8) + `enum` (1) = 29 bytes → fits in one slot
- **Indexed events**: Efficient off-chain filtering by hash, type, and reporter
- **Pagination**: Batch retrieval prevents gas limit issues with large datasets

### 5. Error Handling
- Custom errors instead of strings (gas efficient in Solidity 0.8.4+)
- Descriptive error names for debugging

## Key Functions

### Write Functions

```solidity
// Submit a new threat (reporter only)
function reportThreat(string calldata _threatHash, ThreatType _threatType) external;

// Add a new reporter (admin only)
function addReporter(address _reporter) external;

// Remove a reporter (admin only)
function removeReporter(address _reporter) external;
```

### Read Functions

```solidity
// Get threat by hash
function getThreatByHash(string calldata _threatHash) external view returns (ThreatReport memory);

// Check if threat exists
function threatExists(string calldata _threatHash) external view returns (bool);

// Get paginated threats
function getThreatsPaginated(uint256 _startIndex, uint256 _count) external view returns (ThreatReport[] memory);

// Get threats by reporter address
function getThreatsByReporter(address _reporter) external view returns (string[] memory);

// Get total threat count
function getTotalThreats() external view returns (uint256);
```

## Deployment

### Prerequisites
```bash
# Install dependencies
npm install

# Start local Hardhat network
npx hardhat node
```

### Deploy to Local Network
```bash
npx hardhat run scripts/deploy.js --network localhost
```

### Deploy to Testnet
Configure `hardhat.config.js` with your network settings, then:
```bash
npx hardhat run scripts/deploy.js --network <network-name>
```

## Testing

Run the comprehensive test suite:
```bash
npx hardhat test
```

Tests cover:
- Deployment and role assignment
- Threat reporting (success and failure cases)
- Access control (adding/removing reporters)
- Duplicate prevention
- Query functions and pagination
- Input validation

## Gas Costs

| Operation | Estimated Gas |
|-----------|--------------|
| Deploy | ~2,500,000 |
| Report Threat | ~65,000 |
| Add Reporter | ~45,000 |
| Get Threat (view) | ~2,500 |
| Check Existence | ~2,200 |

## Suggested Security Improvements

### Phase 2 Enhancements

1. **Multi-Signature Admin Control**
   - Replace single admin with Gnosis Safe or multi-sig
   - Requires M-of-N signatures for critical operations
   - Prevents single point of failure

2. **Timelock for Admin Actions**
   - 24-48 hour delay on admin operations
   - Allows community to review and react to changes
   - Prevents instant malicious admin actions

3. **Threat Verification Oracle**
   - Integrate with third-party verification services
   - Staking mechanism for reporters (stake to report)
   - Slashing for false positives

4. **Reputation System**
   - Track reporter accuracy over time
   - Weight reports by reporter reputation
   - Incentivize high-quality submissions

5. **IPFS Integration**
   - Store detailed metadata off-chain on IPFS
   - Store only CID on-chain for reference
   - Reduces on-chain storage costs significantly

6. **Threat Severity Levels**
   - Add severity field (LOW, MEDIUM, HIGH, CRITICAL)
   - Different reporting requirements per severity
   - Escalation procedures for critical threats

7. **Batch Reporting**
   - Submit multiple threats in single transaction
   - Further gas savings for bulk operations
   - Merkle tree verification for large batches

8. **Upgradeability**
   - Implement proxy pattern (UUPS or Transparent)
   - Allows security patches without losing data
   - Requires careful access control on upgrades

### Audit Recommendations

Before mainnet deployment:
1. **Formal Audit**: Engage reputable firm (Trail of Bits, OpenZeppelin, Certik)
2. **Bug Bounty**: Launch bounty program on Immunefi or HackerOne
3. **Testnet Deployment**: Run on public testnet for 2-4 weeks
4. **Stress Testing**: Simulate high volume of reports
5. **Access Control Review**: Verify all role assignments

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    DCTIN Smart Contract                      │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │   Access     │  │  Threat      │  │  Events &    │        │
│  │   Control    │  │  Storage     │  │  Queries     │        │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤        │
│  │ • Admin Role │  │ • Mapping    │  │ • ThreatReported     │
│  │ • Reporter   │  │   hash→index │  │ • ReporterAdded      │
│  │   Role       │  │ • Array of   │  │ • ReporterRemoved    │
│  │ • addReporter│  │   reports    │  │ • getThreatByHash    │
│  │ • remove     │  │ • Duplicate  │  │ • getThreatsPaged    │
│  │   Reporter   │  │   prevention │  │ • threatExists       │
│  └──────────────┘  └──────────────┘  └──────────────┘        │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  Admins  │   │ Reporters│   │  Public  │
        │          │   │          │   │          │
        │• Add     │   │• Submit  │   │• Query   │
        │  reporters    │  threats │   │  threats │
        │• Remove  │   │          │   │• Verify  │
        │  reporters    │          │   │  existence
        └──────────┘   └──────────┘   └──────────┘
```

## License

MIT License - See SPDX identifiers in source files

## Contact

For security issues, please follow responsible disclosure practices.

---

**Built with**: Solidity 0.8.28, OpenZeppelin Contracts, Hardhat 3.x
