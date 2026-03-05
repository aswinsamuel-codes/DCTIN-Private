# DCTIN Backend API

Node.js backend service for interacting with the DCTIN (Decentralized Cyber Threat Intelligence Network) smart contract.

## Features

- RESTful API for blockchain interaction
- Report threats to the blockchain
- Query threats by hash, pagination, or reporter
- Automatic error handling for contract reverts
- Console logging for all blockchain transactions
- CORS enabled for frontend integration

## Tech Stack

- Node.js 18+
- Express.js
- ethers.js v6
- dotenv
- cors

## Quick Start

### Step 1: Start Hardhat Node

From the project root directory:

```bash
npx hardhat node
```

This starts a local blockchain at `http://127.0.0.1:8545`.

### Step 2: Deploy the Contract

In a new terminal, from the project root:

```bash
npx hardhat run scripts/deploy.js --network localhost
```

Copy the deployed contract address.

### Step 3: Configure Backend

Navigate to the backend folder:

```bash
cd backend
```

Install dependencies:

```bash
npm install
```

Create `.env` file from the example:

```bash
cp .env.example .env
```

Edit `.env` and set the `CONTRACT_ADDRESS`:

```env
CONTRACT_ADDRESS=0xYourDeployedContractAddress
```

### Step 4: Start Backend Server

```bash
npm start
```

For development with auto-restart:

```bash
npm run dev
```

The server will start at `http://localhost:3000`.

## API Endpoints

### Health Check
```bash
GET /health
```

### Report a Threat
```bash
POST /report-threat
Content-Type: application/json

{
  "hash": "0x1234567890abcdef...",
  "type": 0
}
```

**Threat Types:**
- `0` - MALWARE
- `1` - PHISHING_URL
- `2` - C2_SERVER
- `3` - DATA_EXFILTRATION
- `4` - RANSOMWARE
- `5` - BOTNET_NODE
- `6` - ANOMALOUS_BEHAVIOR
- `7` - SUSPICIOUS_DOMAIN

### Get Threat by Hash
```bash
GET /threat/:hash
```

### Get Threats (Paginated)
```bash
GET /threats?page=1&limit=10
```

### Get Threats by Reporter
```bash
GET /reporter/:address
```

### Check if Threat Exists
```bash
GET /threat-exists/:hash
```

### Get Statistics
```bash
GET /stats
```

## Testing with curl

### Report a threat:
```bash
curl -X POST http://localhost:3000/report-threat \
  -H "Content-Type: application/json" \
  -d '{
    "hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "type": 0
  }'
```

### Get a threat:
```bash
curl http://localhost:3000/threat/0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
```

### Get paginated threats:
```bash
curl "http://localhost:3000/threats?page=1&limit=5"
```

### Get reporter threats:
```bash
curl http://localhost:3000/reporter/0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

### Check stats:
```bash
curl http://localhost:3000/stats
```

## Error Handling

The API returns appropriate HTTP status codes:

- `200` - Success
- `201` - Created (threat reported)
- `400` - Bad Request (invalid input)
- `403` - Forbidden (unauthorized reporter)
- `404` - Not Found (threat doesn't exist)
- `409` - Conflict (duplicate threat)
- `429` - Too Many Requests (rate limit exceeded)
- `500` - Internal Server Error

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RPC_URL` | Hardhat blockchain URL | `http://127.0.0.1:8545` |
| `PRIVATE_KEY` | Wallet private key for signing | Hardhat test account #0 |
| `CONTRACT_ADDRESS` | Deployed DCTIN contract address | Required |
| `PORT` | Backend server port | `3000` |
| `CORS_ORIGIN` | CORS allowed origin | `*` |

## Project Structure

```
backend/
├── server.js              # Entry point
├── package.json           # Dependencies
├── .env.example           # Environment template
├── config/
│   └── blockchain.js      # Contract connection
├── services/
│   └── blockchainService.js  # Contract interactions
├── controllers/
│   └── threatController.js   # API logic
├── routes/
│   └── threatRoutes.js    # Route definitions
└── utils/
    └── hashUtils.js       # Hash utilities
```

## Contract Functions

The backend interacts with these DCTIN contract functions:

- `reportThreat(bytes32 _threatHash, uint256 _threatTypeRaw)` - Report new threat
- `getThreatByHash(bytes32 _threatHash)` - Get threat details
- `getThreatsPaginated(uint256 _startIndex, uint256 _count)` - Paginated query
- `getThreatsByReporter(address _reporter)` - Get reporter's threats
- `threatExists(bytes32 _threatHash)` - Check existence
- `getTotalThreats()` - Get total count

## Security Notes

⚠️ **WARNING**: The default `.env` uses Hardhat's test private key. **Never use this in production.**

For production:
1. Use a secure private key with proper permissions
2. Enable HTTPS
3. Implement authentication/authorization
4. Add rate limiting on API endpoints
5. Use a proper secret management service

## Troubleshooting

### Contract ABI not found
Run `npx hardhat compile` from the project root to generate the ABI.

### Contract not initialized
Set `CONTRACT_ADDRESS` in `.env` after deploying the contract.

### Connection refused
Make sure Hardhat node is running at `http://127.0.0.1:8545`.

### Rate limit errors
The contract limits 10 reports per block per reporter. Wait for the next block or use a different reporter account.

## License

MIT
