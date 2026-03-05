/**
 * @file detector.js
 * @description Main AI Threat Detection Engine
 * Entry point for threat analysis and classification
 */

import { classifyURL, getModelInfo, classifyBatch } from './model.js';
import { ethers } from 'ethers';

// Configuration
const CONFIDENCE_THRESHOLD = 0.8;

/**
 * Analyze a URL for phishing threats
 * @param {string} url - URL to analyze
 * @returns {Object} Analysis result with threat assessment
 */
export function analyzeURL(url) {
  console.log('\n[AI ENGINE]');
  console.log(`Analyzing URL: ${url}`);
  
  const startTime = Date.now();
  
  // Perform classification
  const result = classifyURL(url);
  
  const duration = Date.now() - startTime;
  
  // Log results
  console.log(`Classification: ${result.type}`);
  console.log(`Confidence: ${result.confidence}`);
  if (result.reasons && result.reasons.length > 0) {
    console.log('Reasons:');
    result.reasons.forEach(reason => console.log(`  - ${reason}`));
  }
  console.log(`Analysis time: ${duration}ms`);
  console.log('');
  
  return {
    ...result,
    analysisTimeMs: duration,
    shouldReport: result.threat && result.confidence >= CONFIDENCE_THRESHOLD
  };
}

/**
 * Analyze multiple URLs in batch
 * @param {string[]} urls - Array of URLs to analyze
 * @returns {Object[]} Array of analysis results
 */
export function analyzeBatch(urls) {
  console.log(`\n[AI ENGINE] Batch Analysis`);
  console.log(`Analyzing ${urls.length} URLs...\n`);
  
  const startTime = Date.now();
  const results = classifyBatch(urls);
  const duration = Date.now() - startTime;
  
  // Summary statistics
  const threats = results.filter(r => r.threat);
  const highConfidence = results.filter(r => r.confidence >= CONFIDENCE_THRESHOLD);
  
  console.log('\n[AI ENGINE] Batch Summary');
  console.log(`Total analyzed: ${results.length}`);
  console.log(`Threats detected: ${threats.length}`);
  console.log(`High confidence (>0.8): ${highConfidence.length}`);
  console.log(`Total time: ${duration}ms`);
  console.log('');
  
  return results.map(r => ({
    ...r,
    shouldReport: r.threat && r.confidence >= CONFIDENCE_THRESHOLD
  }));
}

/**
 * Generate a threat hash from URL analysis result
 * @param {string} url - Original URL
 * @param {Object} analysis - Analysis result
 * @returns {Object} Threat data ready for blockchain
 */
export function generateThreatData(url, analysis) {
  // Generate bytes32 hash from URL
  const threatHash = ethers.id(url);
  
  // Map classification to threat type enum
  const threatType = getThreatTypeEnum(analysis.type);
  
  return {
    hash: threatHash,
    type: threatType,
    originalUrl: url,
    confidence: analysis.confidence,
    reasons: analysis.reasons,
    timestamp: new Date().toISOString()
  };
}

/**
 * Validate if a URL should be reported to blockchain
 * @param {string} url - URL to validate
 * @returns {Object} Validation result with report decision
 */
export function validateForReporting(url) {
  const analysis = analyzeURL(url);
  
  if (!analysis.threat) {
    return {
      valid: false,
      reason: 'URL classified as SAFE',
      analysis: analysis
    };
  }
  
  if (analysis.confidence < CONFIDENCE_THRESHOLD) {
    return {
      valid: false,
      reason: `Confidence too low (${analysis.confidence} < ${CONFIDENCE_THRESHOLD})`,
      analysis: analysis
    };
  }
  
  const threatData = generateThreatData(url, analysis);
  
  return {
    valid: true,
    threatData: threatData,
    analysis: analysis
  };
}

/**
 * Get AI engine status and information
 * @returns {Object} Engine status
 */
export function getEngineStatus() {
  return {
    status: 'OPERATIONAL',
    version: '1.0.0',
    confidenceThreshold: CONFIDENCE_THRESHOLD,
    model: getModelInfo(),
    capabilities: [
      'Phishing URL Detection',
      'Feature Extraction',
      'Confidence Scoring'
    ],
    supportedThreatTypes: [
      'PHISHING_URL',
      'MALWARE',
      'SUSPICIOUS_DOMAIN'
    ]
  };
}

/**
 * Update confidence threshold
 * @param {number} newThreshold - New threshold value (0-1)
 */
export function setConfidenceThreshold(newThreshold) {
  if (newThreshold >= 0 && newThreshold <= 1) {
    CONFIDENCE_THRESHOLD = newThreshold;
    console.log(`[AI ENGINE] Confidence threshold updated to ${newThreshold}`);
    return true;
  }
  return false;
}

/**
 * Map classification type to contract threat type enum
 * @param {string} classification - Classification label
 * @returns {number} Threat type enum value
 */
function getThreatTypeEnum(classification) {
  const typeMap = {
    'PHISHING': 1,        // PHISHING_URL
    'SUSPICIOUS': 7,      // SUSPICIOUS_DOMAIN
    'SAFE': 0,            // Would not be reported
    'ERROR': 0
  };
  
  return typeMap[classification] ?? 7; // Default to SUSPICIOUS_DOMAIN
}

/**
 * Get threat type name from enum
 * @param {number} enumValue - Threat type enum value
 * @returns {string} Human-readable threat type name
 */
export function getThreatTypeName(enumValue) {
  const names = {
    0: 'MALWARE',
    1: 'PHISHING_URL',
    2: 'C2_SERVER',
    3: 'DATA_EXFILTRATION',
    4: 'RANSOMWARE',
    5: 'BOTNET_NODE',
    6: 'ANOMALOUS_BEHAVIOR',
    7: 'SUSPICIOUS_DOMAIN'
  };
  return names[enumValue] || 'UNKNOWN';
}

// Export default for easier imports
export default {
  analyzeURL,
  analyzeBatch,
  validateForReporting,
  generateThreatData,
  getEngineStatus,
  setConfidenceThreshold,
  getThreatTypeName
};
