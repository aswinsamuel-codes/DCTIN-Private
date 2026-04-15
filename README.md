# DCTIN - Decentralized Cyber Threat Intelligence Network

A secure, gas-optimized Solidity smart contract with AI-powered threat detection for storing cyber threat intelligence on the blockchain.

## Overview

DCTIN provides an immutable, tamper-proof registry for cyber threat data including malware hashes, malicious IPs, phishing URLs, and attack signatures. The system combines:

- **AI Threat Detection Engine** - Automatically analyzes URLs and classifies threats with confidence scoring
- **Blockchain Integration** - Immutable storage on Ethereum-compatible chains
- **RESTful API** - Easy integration with security tools and SOC workflows
- **Dashboard UI** - Real-time threat monitoring with analytics

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT / FRONTEND                         │
│  Dashboard | URL Analyzer | Threat Explorer | Hash Search        │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   AI THREAT DETECTION ENGINE                     │
│  • 24+ URL features analyzed                                     │
│  • Rule-based classifier (ML-ready)                              │
│  • Confidence threshold: 0.8 → auto-derived severity            │
└─────────────────────────┬───────────────────────────────────────┘
                          │ Threat Confirmed (>0.8 confidence)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                      BACKEND API (Node.js)                       │
│  /analyze-url  /report-threat  /report-threat-batch             │
│  /threats  /reporter/:addr/stats  /threat/:hash/status  /stats  │
└─────────────────────────┬───────────────────────────────────────┘
                          │ Signed Transaction
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DCTIN SMART CONTRACT (Solidity 0.8.28)        │
│  • ThreatReport: hash | reporter | timestamp | type | severity | status │
│  • ReporterStats: totalReports | criticalReports | highReports   │
│  • reportThreat() | reportThreatBatch() | updateThreatStatus()   │
│  Security: AccessControl, Rate Limiting (10/block), ReentrancyGuard │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Core Capabilities
- **AI-Powered Detection**: Automatic URL analysis with 24+ threat indicators; confidence → severity mapping
- **Immutable Storage**: Threat reports cannot be deleted or modified once submitted
- **Role-Based Access Control**: Separate Admin and Reporter roles (OpenZeppelin `AccessControl`)
- **Duplicate Prevention**: O(1) mapping-based detection of existing threat hashes
- **Rate Limiting**: Protection against spam (10 reports per block per reporter)
- **Gas Optimized**: 2-slot struct packing, O(1) lookups, paginated queries
- **Event Transparency**: Full audit trail via indexed events
- **RESTful API**: Complete API for integration with security tools

### Threat Severity Levels
| Level | ID | Confidence Threshold |
|-------|----|---------------------|
| LOW | 0 | < 60 % |
| MEDIUM | 1 | 60 – 74 % |
| HIGH | 2 | 75 – 89 % |
| CRITICAL | 3 | ≥ 90 % |

### Threat Status / Resolution
Threats have a lifecycle: **ACTIVE → RESOLVED / DISPUTED**
- Original reporter **or** admin can update the status
- Fully auditable via the `ThreatStatusUpdated` event

### Batch Reporting
Submit up to **50 threats** in a single transaction via `reportThreatBatch()` — ideal for SIEM integrations.

### Reporter Reputation System
Each reporter's on-chain stats are tracked automatically:
- `totalReports` — lifetime submission count
- `criticalReports` — CRITICAL severity submissions
- `highReports` — HIGH severity submissions
- `firstReportAt` / `lastReportAt` — activity timestamps

### Frontend Dashboard
- **Dashboard** — live stats, latest threats with severity/status badges, Reporter Leaderboard, AI engine status
- **URL Analyzer** — paste any URL for real-time AI analysis + one-click blockchain submission
- **Threat Explorer** — paginated table with Type / Severity / Status filters and CSV export
- **Hash Search** — look up any threat by bytes32 hash, view full details, update status inline

## Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn
- Git

### Step 1: Start Local Blockchain

```bash
npx hardhat node
```

### Step 2: Deploy Smart Contract

```bash
npx hardhat run scripts/deploy.js --network localhost
```

### Step 3: Configure Backend

```bash
cd backend && npm install
```

Create `.env`:

```env
RPC_URL=http://127.0.0.1:8545
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
CONTRACT_ADDRESS=0xYourDeployedContractAddressHere
PORT=3000
```

### Step 4: Start Backend

```bash
npm start
```

### Step 5: Open Frontend

Open `frontend/index.html` in your browser (or serve with `python3 -m http.server`).

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/report-threat` | Report a single threat `{ hash, type, severity? }` |
| POST | `/report-threat-batch` | Batch report up to 50 threats |
| GET | `/threats?page=1&limit=10` | Paginated threat list |
| GET | `/threat/:hash` | Get threat by bytes32 hash |
| PUT | `/threat/:hash/status` | Update threat status `{ status: 0/1/2 }` |
| GET | `/threat/:hash/confirmations` | Get confirmation count for a threat |
| POST | `/confirm-threat` | Confirm an existing threat `{ hash }` |
| GET | `/reporter/:address` | All threats by reporter |
| GET | `/reporter/:address/stats` | Reporter reputation stats |
| GET | `/threat-exists/:hash` | Check if hash is registered |
| GET | `/analytics` | Aggregated analytics (by type, severity, status, 7-day trend) |
| POST | `/analyze-url` | AI analysis only (no blockchain write) |
| POST | `/report-threat-ai` | AI analysis + auto blockchain submission |
| GET | `/stats` | Total threat count |
| GET | `/health` | Service health check |

## Smart Contract Functions

### Write Functions

```solidity
// Single threat (reporter only)
function reportThreat(bytes32 hash, uint256 type, uint256 severity) external;

// Batch (reporter only, max 50)
function reportThreatBatch(ThreatInput[] calldata threats) external;

// Update status: 0=ACTIVE, 1=RESOLVED, 2=DISPUTED (reporter of that threat OR admin)
function updateThreatStatus(bytes32 hash, uint256 status) external;

// Confirm an existing threat (reporter only; cannot confirm own submission; once per reporter)
function confirmThreat(bytes32 hash) external;

// Role management (admin only)
function addReporter(address reporter) external;
function removeReporter(address reporter) external;
```

### Read Functions

```solidity
function getThreatByHash(bytes32 hash) external view returns (ThreatReport memory);
function getThreatStatus(bytes32 hash) external view returns (ThreatStatus);
function getReporterStats(address reporter) external view returns (ReporterStats memory);
function getConfirmationCount(bytes32 hash) external view returns (uint256);
function hasConfirmedThreat(bytes32 hash, address confirmer) external view returns (bool);
function getThreatsPaginated(uint256 start, uint256 count) external view returns (ThreatReport[] memory);
function getThreatsByReporter(address reporter) external view returns (bytes32[] memory);
function threatExists(bytes32 hash) external view returns (bool);
function getTotalThreats() external view returns (uint256);
```

## Threat Types

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

## Testing

```bash
npx hardhat test
```

Tests cover: deployment, threat reporting (single + batch), severity validation, batch errors, access control, rate limiting, pagination, reporter reputation stats, threat status lifecycle, and threat confirmation.

## Gas Costs

| Operation | Estimated Gas |
|-----------|--------------|
| Deploy | ~2,700,000 |
| Report Threat (single) | ~70,000 |
| Report Threat Batch (10) | ~450,000 |
| Update Threat Status | ~35,000 |
| Confirm Threat | ~55,000 |
| Add Reporter | ~45,000 |
| Get Threat (view) | ~2,500 |

## Security Features

1. **Access Control** — `DEFAULT_ADMIN_ROLE` + `REPORTER_ROLE` via OpenZeppelin `AccessControl`
2. **Rate Limiting** — 10 reports per block per reporter; batch counts against quota atomically
3. **Input Validation** — zero hash rejected; enum ranges validated before casting; batch size capped at 50
4. **Reentrancy Protection** — state written before events (checks-effects-interactions pattern)
5. **Custom Errors** — gas-efficient `DCTIN__*` custom error types
6. **Duplicate Prevention** — O(1) mapping lookup; same hash can never be reported twice
7. **Status Authorization** — only original reporter or admin can change threat status
8. **Confirmation Integrity** — reporters cannot confirm their own threats; one confirmation per reporter per threat

## Roadmap

### Phase 3 (Complete)
- ✅ **Threat Confirmation** — `confirmThreat()` + `getConfirmationCount()` + `hasConfirmedThreat()`
- ✅ **Analytics API** — `GET /analytics`: per-type, per-severity, per-status counts + 7-day trend
- ✅ **Analytics Tab** — Chart.js donut + bar + line charts in the frontend dashboard

### Phase 4 (Planned)
- **Multi-Sig Admin Control** — Gnosis Safe / M-of-N governance
- **Timelock** — 24 h delay on admin actions via OpenZeppelin `TimelockController`
- **IPFS Metadata** — store full threat metadata off-chain, CID on-chain
- **Threat Verification Oracle** — integrate with third-party threat feeds
- **Staking & Slashing** — incentivise accurate reporting

## License

MIT License — See SPDX identifiers in source files

---

**Built with**: Solidity 0.8.28, OpenZeppelin Contracts, Hardhat 3.x, Node.js / Express, ethers.js v6

