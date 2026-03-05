import { ethers } from 'ethers';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '../.env') });

// Load contract ABI
const contractPath = join(__dirname, '../../artifacts/contracts/DCTIN.sol/DCTIN.json');
let contractABI;
try {
  const contractJSON = JSON.parse(fs.readFileSync(contractPath, 'utf8'));
  contractABI = contractJSON.abi;
} catch (error) {
  console.error('Failed to load contract ABI. Make sure the contract is compiled.');
  console.error('Run: npx hardhat compile');
  process.exit(1);
}

// Validate environment variables
const requiredEnvVars = ['RPC_URL', 'PRIVATE_KEY'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Missing required environment variable: ${envVar}`);
    console.error('Please check your .env file');
    process.exit(1);
  }
}

// Create provider
const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);

// Create wallet
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);

// Contract instance (will be initialized with address after deployment)
let contract = null;

export function initializeContract(contractAddress) {
  if (!contractAddress) {
    throw new Error('Contract address is required');
  }
  contract = new ethers.Contract(contractAddress, contractABI, wallet);
  return contract;
}

export function getContract() {
  if (!contract) {
    if (!process.env.CONTRACT_ADDRESS) {
      throw new Error('Contract not initialized. Please set CONTRACT_ADDRESS in .env or call initializeContract()');
    }
    contract = new ethers.Contract(process.env.CONTRACT_ADDRESS, contractABI, wallet);
  }
  return contract;
}

export function getProvider() {
  return provider;
}

export function getWallet() {
  return wallet;
}

export { contractABI };

// Auto-initialize if CONTRACT_ADDRESS is set
if (process.env.CONTRACT_ADDRESS) {
  try {
    initializeContract(process.env.CONTRACT_ADDRESS);
    console.log(`✓ Contract initialized at ${process.env.CONTRACT_ADDRESS}`);
  } catch (error) {
    console.error('Failed to initialize contract:', error.message);
  }
}
