import { getContract, getWallet } from '../config/blockchain.js';
import { ethers } from 'ethers';

/**
 * Report a new threat to the blockchain
 * @param {string} hash - bytes32 threat hash (0x... format)
 * @param {number} type - Threat type enum value (0-7)
 * @returns {Promise<Object>} Transaction receipt and threat details
 */
export async function reportThreat(hash, type) {
  try {
    const contract = getContract();
    const wallet = getWallet();
    
    // Validate hash format
    if (!hash || !ethers.isHexString(hash) || hash.length !== 66) {
      throw new Error('Invalid hash format. Expected 32-byte hex string (0x... + 64 chars)');
    }
    
    // Validate type range
    if (typeof type !== 'number' || type < 0 || type > 7) {
      throw new Error('Invalid threat type. Expected integer 0-7');
    }
    
    // Convert to bytes32 if needed
    const bytes32Hash = hash.startsWith('0x') ? hash : `0x${hash}`;
    
    console.log(`📤 Reporting threat - Hash: ${bytes32Hash}, Type: ${type}`);
    console.log(`👤 Reporter: ${wallet.address}`);
    
    // Send transaction
    const tx = await contract.reportThreat(bytes32Hash, type);
    
    console.log(`⏳ Transaction sent: ${tx.hash}`);
    console.log(`⛽ Gas limit: ${tx.gasLimit.toString()}`);
    
    // Wait for confirmation
    const receipt = await tx.wait();
    
    console.log(`✅ Transaction confirmed in block ${receipt.blockNumber}`);
    console.log(`🔢 Gas used: ${receipt.gasUsed.toString()}`);
    console.log(`💰 Effective gas price: ${receipt.gasPrice?.toString() || 'N/A'}`);
    
    // Get the threat index from the event
    const threatReportedEvent = receipt.logs.find(
      log => {
        try {
          const parsed = contract.interface.parseLog(log);
          return parsed?.name === 'ThreatReported';
        } catch {
          return false;
        }
      }
    );
    
    let threatIndex = null;
    if (threatReportedEvent) {
      const parsedEvent = contract.interface.parseLog(threatReportedEvent);
      threatIndex = parsedEvent.args[4].toString(); // threatIndex is the 5th argument
      console.log(`📝 Threat index: ${threatIndex}`);
    }
    
    return {
      success: true,
      transactionHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      gasUsed: receipt.gasUsed.toString(),
      threatHash: bytes32Hash,
      threatType: type,
      threatIndex: threatIndex,
      reporter: wallet.address
    };
    
  } catch (error) {
    // Handle specific contract errors
    if (error.code === 'CALL_EXCEPTION' || error.code === 'ACTION_REJECTED') {
      // Try to extract custom error
      const errorMessage = error.reason || error.shortMessage || error.message;
      
      if (errorMessage?.includes('DCTIN__ThreatAlreadyExists')) {
        throw new Error('DUPLICATE_THREAT: This threat hash has already been reported');
      }
      if (errorMessage?.includes('DCTIN__InvalidThreatType')) {
        throw new Error('INVALID_TYPE: Threat type must be between 0 and 7');
      }
      if (errorMessage?.includes('DCTIN__InvalidThreatHash')) {
        throw new Error('INVALID_HASH: Threat hash cannot be zero');
      }
      if (errorMessage?.includes('DCTIN__RateLimitExceeded')) {
        throw new Error('RATE_LIMIT_EXCEEDED: Maximum reports per block reached (10)');
      }
      if (errorMessage?.includes('DCTIN__UnauthorizedReporter')) {
        throw new Error('UNAUTHORIZED: Address does not have reporter role');
      }
      
      throw new Error(`CONTRACT_ERROR: ${errorMessage}`);
    }
    
    console.error('❌ Error reporting threat:', error);
    throw error;
  }
}

/**
 * Get threat details by hash
 * @param {string} hash - bytes32 threat hash
 * @returns {Promise<Object>} Threat details
 */
export async function getThreatByHash(hash) {
  try {
    const contract = getContract();
    
    // Validate hash format
    if (!hash || !ethers.isHexString(hash) || hash.length !== 66) {
      throw new Error('Invalid hash format. Expected 32-byte hex string (0x... + 64 chars)');
    }
    
    const bytes32Hash = hash.startsWith('0x') ? hash : `0x${hash}`;
    
    console.log(`🔍 Fetching threat by hash: ${bytes32Hash}`);
    
    const threat = await contract.getThreatByHash(bytes32Hash);
    
    return {
      success: true,
      threatHash: threat.threatHash,
      reporter: threat.reporter,
      timestamp: new Date(Number(threat.timestamp) * 1000).toISOString(),
      threatType: Number(threat.threatType),
      threatTypeName: getThreatTypeName(Number(threat.threatType))
    };
    
  } catch (error) {
    if (error.message?.includes('DCTIN__ThreatNotFound')) {
      throw new Error('NOT_FOUND: Threat not found');
    }
    console.error('❌ Error fetching threat:', error);
    throw error;
  }
}

/**
 * Get threats with pagination
 * @param {number} start - Starting index
 * @param {number} count - Number of threats to fetch
 * @returns {Promise<Object>} Paginated threats
 */
export async function getThreatsPaginated(start, count) {
  try {
    const contract = getContract();
    
    // Validate parameters
    if (typeof start !== 'number' || start < 0) {
      throw new Error('Invalid start index. Expected non-negative integer');
    }
    if (typeof count !== 'number' || count <= 0 || count > 1000) {
      throw new Error('Invalid count. Expected integer between 1 and 1000');
    }
    
    console.log(`📄 Fetching threats - Start: ${start}, Count: ${count}`);
    
    const threats = await contract.getThreatsPaginated(start, count);
    
    // Format threats
    const formattedThreats = threats.map(threat => ({
      threatHash: threat.threatHash,
      reporter: threat.reporter,
      timestamp: new Date(Number(threat.timestamp) * 1000).toISOString(),
      threatType: Number(threat.threatType),
      threatTypeName: getThreatTypeName(Number(threat.threatType))
    }));
    
    return {
      success: true,
      threats: formattedThreats,
      count: formattedThreats.length,
      startIndex: start
    };
    
  } catch (error) {
    if (error.message?.includes('DCTIN__InvalidPaginationRange')) {
      throw new Error('INVALID_RANGE: Count exceeds maximum allowed (1000)');
    }
    console.error('❌ Error fetching paginated threats:', error);
    throw error;
  }
}

/**
 * Get threats by reporter address
 * @param {string} address - Reporter Ethereum address
 * @returns {Promise<Object>} Threats reported by the address
 */
export async function getThreatsByReporter(address) {
  try {
    const contract = getContract();
    
    // Validate address
    if (!ethers.isAddress(address)) {
      throw new Error('Invalid Ethereum address format');
    }
    
    console.log(`👤 Fetching threats by reporter: ${address}`);
    
    const threatHashes = await contract.getThreatsByReporter(address);
    
    // Fetch full details for each threat
    const threats = [];
    for (const hash of threatHashes) {
      try {
        const threat = await contract.getThreatByHash(hash);
        threats.push({
          threatHash: threat.threatHash,
          reporter: threat.reporter,
          timestamp: new Date(Number(threat.timestamp) * 1000).toISOString(),
          threatType: Number(threat.threatType),
          threatTypeName: getThreatTypeName(Number(threat.threatType))
        });
      } catch (e) {
        console.warn(`Failed to fetch threat details for ${hash}:`, e.message);
      }
    }
    
    return {
      success: true,
      reporter: address,
      threats: threats,
      count: threats.length
    };
    
  } catch (error) {
    console.error('❌ Error fetching threats by reporter:', error);
    throw error;
  }
}

/**
 * Check if a threat exists
 * @param {string} hash - bytes32 threat hash
 * @returns {Promise<Object>} Existence status
 */
export async function threatExists(hash) {
  try {
    const contract = getContract();
    
    if (!hash || !ethers.isHexString(hash) || hash.length !== 66) {
      throw new Error('Invalid hash format');
    }
    
    const bytes32Hash = hash.startsWith('0x') ? hash : `0x${hash}`;
    const exists = await contract.threatExists(bytes32Hash);
    
    return {
      success: true,
      threatHash: bytes32Hash,
      exists: exists
    };
    
  } catch (error) {
    console.error('❌ Error checking threat existence:', error);
    throw error;
  }
}

/**
 * Get total number of threats
 * @returns {Promise<Object>} Total threats count
 */
export async function getTotalThreats() {
  try {
    const contract = getContract();
    const total = await contract.getTotalThreats();
    
    return {
      success: true,
      totalThreats: Number(total)
    };
    
  } catch (error) {
    console.error('❌ Error fetching total threats:', error);
    throw error;
  }
}

/**
 * Get threat type name from enum value
 * @param {number} type - Threat type enum value
 * @returns {string} Human-readable threat type name
 */
function getThreatTypeName(type) {
  const types = {
    0: 'MALWARE',
    1: 'PHISHING_URL',
    2: 'MALICIOUS_IP',
    3: 'C2_SERVER',
    4: 'BOTNET_NODE',
    5: 'RANSOMWARE',
    6: 'EXPLOIT_PAYLOAD',
    7: 'SUSPICIOUS_DOMAIN'
  };
  return types[type] || 'UNKNOWN';
}
