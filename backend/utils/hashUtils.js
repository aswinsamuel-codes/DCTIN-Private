import { ethers } from 'ethers';

/**
 * Utility functions for hash operations
 */

/**
 * Generate a bytes32 hash from a string input
 * @param {string} input - String to hash
 * @returns {string} bytes32 hash (0x... + 64 hex chars)
 */
export function generateBytes32Hash(input) {
  if (!input || typeof input !== 'string') {
    throw new Error('Input must be a non-empty string');
  }
  
  // Use ethers.id() which computes keccak256 hash
  return ethers.id(input);
}

/**
 * Validate a bytes32 hash format
 * @param {string} hash - Hash to validate
 * @returns {boolean} True if valid bytes32 hash
 */
export function isValidBytes32Hash(hash) {
  if (!hash || typeof hash !== 'string') {
    return false;
  }
  
  // Check if it's a valid hex string of correct length
  // bytes32 = 32 bytes = 64 hex chars + 0x prefix = 66 chars total
  return ethers.isHexString(hash) && hash.length === 66;
}

/**
 * Normalize a hash to bytes32 format
 * @param {string} hash - Hash to normalize
 * @returns {string} Normalized bytes32 hash
 */
export function normalizeHash(hash) {
  if (!hash) {
    throw new Error('Hash is required');
  }
  
  // Remove 0x prefix if present, then add it back
  const cleanHash = hash.startsWith('0x') ? hash.slice(2) : hash;
  
  // Pad to 64 characters if needed
  const paddedHash = cleanHash.padStart(64, '0');
  
  // Check length
  if (paddedHash.length !== 64) {
    throw new Error('Invalid hash length. Expected 32 bytes');
  }
  
  return `0x${paddedHash}`;
}

/**
 * Convert a string to a threat hash with metadata
 * @param {string} threatData - Threat data string (e.g., IP, domain, file hash)
 * @param {string} threatType - Type of threat for metadata
 * @returns {Object} Hash object with metadata
 */
export function createThreatHash(threatData, threatType = 'GENERIC') {
  const hash = generateBytes32Hash(threatData);
  const timestamp = new Date().toISOString();
  
  return {
    hash,
    rawData: threatData,
    type: threatType,
    createdAt: timestamp,
    length: threatData.length
  };
}

/**
 * Threat type enum mapping
 */
export const ThreatType = {
  MALWARE: 0,
  PHISHING_URL: 1,
  MALICIOUS_IP: 2,
  C2_SERVER: 3,
  BOTNET_NODE: 4,
  RANSOMWARE: 5,
  EXPLOIT_PAYLOAD: 6,
  SUSPICIOUS_DOMAIN: 7
};

/**
 * Get threat type name from enum value
 * @param {number} type - Threat type enum value
 * @returns {string} Human-readable threat type name
 */
export function getThreatTypeName(type) {
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

/**
 * Validate threat type
 * @param {number} type - Threat type to validate
 * @returns {boolean} True if valid
 */
export function isValidThreatType(type) {
  const numType = parseInt(type, 10);
  return !isNaN(numType) && numType >= 0 && numType <= 7;
}
