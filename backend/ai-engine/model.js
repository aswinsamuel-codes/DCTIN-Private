/**
 * @file model.js
 * @description Threat classification model for phishing URL detection
 * Implements a rule-based classifier with weighted scoring
 * Can be extended to use ML models (TensorFlow.js, etc.)
 */

import { extractFeatures, featuresToVector, getFeatureExplanations } from './featureExtractor.js';

/**
 * Feature weights for phishing detection
 * Higher weight = more significant indicator of phishing
 */
const FEATURE_WEIGHTS = {
  hasIPAddress: 0.85,           // IP addresses in URLs are highly suspicious
  hasSuspiciousTLD: 0.70,       // Suspicious TLDs common in phishing
  hasBrandImpersonation: 0.90,   // Brand impersonation is strong phishing indicator
  suspiciousKeywordCount: 0.15,  // Per keyword (max ~1.5 total)
  isShortenedURL: 0.60,         // URL shorteners mask malicious destinations
  hasMultipleSubdomains: 0.50,   // Multiple subdomains can indicate subdomain takeover
  hasUserInfo: 0.75,            // User info in URL is credential phishing technique
  isHTTPS: -0.30,               // HTTPS is a positive signal (negative weight)
  hasExecutableExtension: 0.80,   // Executable downloads are highly dangerous
  atSymbolCount: 0.65,          // @ symbol used in credential phishing
  hasEncoding: 0.40,            // URL encoding can hide malicious content
  specialCharCount: 0.01,       // Per special char (normalized)
  dashCount: 0.05,              // Per dash (normalized) - often used in typosquatting
  domainLength: 0.002,          // Per char - very long domains can be suspicious
  urlLength: 0.001,             // Per char
  hasPort: 0.30,                // Non-standard ports can be suspicious
  hasMultiplePaths: 0.25,       // Deep paths can be suspicious
  queryParamCount: 0.10,        // Many query params can hide tracking
  subdomainDepth: 0.15,         // Per subdomain level
};

/**
 * Classification thresholds for 4-level system
 */
const THRESHOLDS = {
  PHISHING: 0.85,   // High confidence phishing
  HIGH_RISK: 0.65,  // Elevated risk - likely malicious
  SUSPICIOUS: 0.40, // Some suspicious indicators
  SAFE: 0.0         // Below this: safe
};

/**
 * Known safe domains whitelist
 */
const SAFE_DOMAINS = [
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
  'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
  'stackoverflow.com', 'wikipedia.org', 'reddit.com',
  'youtube.com', 'netflix.com', 'spotify.com'
];

/**
 * Known malicious patterns blacklist
 */
const MALICIOUS_PATTERNS = [
  /free.*money/i,
  /win.*prize/i,
  /click.*here.*now/i,
  /verify.*account.*now/i,
  /urgent.*action.*required/i,
  /limited.*time.*offer/i,
  /you.*have.*won/i,
  /confirm.*your.*identity/i,
  /update.*payment.*info/i,
  /suspended.*account/i
];

/**
 * Classify URL as phishing or safe
 * @param {string} url - URL to classify
 * @returns {Object} Classification result with confidence and explanations
 */
export function classifyURL(url) {
  try {
    // Extract features
    const features = extractFeatures(url);
    
    // Check whitelist first
    if (isWhitelisted(url)) {
      return createResult(false, 0.05, 'SAFE', features, ['Domain is in whitelist']);
    }
    
    // Check blacklist patterns
    const blacklistedReason = checkBlacklist(url);
    if (blacklistedReason) {
      return createResult(true, 0.95, 'PHISHING', features, [blacklistedReason]);
    }
    
    // Calculate weighted score
    const score = calculatePhishingScore(features);
    
    // Get explanations for suspicious features
    const explanations = getFeatureExplanations(features);
    
    // Determine classification using 4-level system
    let classification = 'SAFE';
    let isThreat = false;
    
    if (score >= 0.85) {
      isThreat = true;
      classification = 'PHISHING';
    } else if (score >= 0.65) {
      isThreat = true;
      classification = 'HIGH_RISK';
    } else if (score >= 0.40) {
      isThreat = true;
      classification = 'SUSPICIOUS';
    } else {
      isThreat = false;
      classification = 'SAFE';
    }
    
    console.log('Score:', score);
    console.log('Classification:', classification);
    
    return createResult(isThreat, score, classification, features, explanations);
    
  } catch (error) {
    console.error('❌ Classification error:', error);
    return createResult(false, 0, 'ERROR', null, ['Classification failed']);
  }
}

/**
 * Calculate phishing probability score
 * @param {Object} features - Extracted features
 * @returns {number} Score between 0 (safe) and 1 (phishing)
 */
function calculatePhishingScore(features) {
  let totalWeight = 0;
  let weightedScore = 0;
  
  for (const [feature, weight] of Object.entries(FEATURE_WEIGHTS)) {
    let value = features[feature];
    
    // Handle boolean features
    if (typeof value === 'boolean') {
      value = value ? 1 : 0;
    }
    
    // Normalize numeric features that need it
    if (feature === 'suspiciousKeywordCount') {
      value = Math.min(value / 10, 1); // Cap at 10 keywords = 1.0
    }
    
    weightedScore += value * weight;
    totalWeight += Math.abs(weight);
  }
  
  // Normalize to 0-1 range
  let normalizedScore = weightedScore / (totalWeight * 0.5);
  
  // Apply sigmoid-like transformation for better distribution
  normalizedScore = Math.min(Math.max(normalizedScore, 0), 1);
  
  return normalizedScore;
}

/**
 * Check if URL is in whitelist
 * @param {string} url - URL to check
 * @returns {boolean} True if whitelisted
 */
function isWhitelisted(url) {
  try {
    if (!url.startsWith('http')) {
      url = 'http://' + url;
    }
    const hostname = new URL(url).hostname.toLowerCase();
    
    return SAFE_DOMAINS.some(safe => hostname === safe || hostname.endsWith('.' + safe));
  } catch {
    return false;
  }
}

/**
 * Check URL against blacklist patterns
 * @param {string} url - URL to check
 * @returns {string|null} Blacklist reason or null
 */
function checkBlacklist(url) {
  const lowerUrl = url.toLowerCase();
  
  for (const pattern of MALICIOUS_PATTERNS) {
    if (pattern.test(lowerUrl)) {
      return `Matches malicious pattern: ${pattern.source}`;
    }
  }
  
  return null;
}

/**
 * Create classification result object
 * @param {boolean} isThreat - Whether URL is a threat
 * @param {number} confidence - Confidence score 0-1
 * @param {string} classification - Classification label
 * @param {Object} features - Extracted features
 * @param {string[]} reasons - Reasons for classification
 * @returns {Object} Result object
 */
function createResult(isThreat, confidence, classification, features, reasons) {
  // Map classification to threat type for blockchain
  const threatTypeMap = {
    'PHISHING': 'PHISHING_URL',
    'HIGH_RISK': 'SUSPICIOUS_DOMAIN',
    'SUSPICIOUS': 'SUSPICIOUS_DOMAIN',
    'SAFE': null
  };
  
  return {
    threat: isThreat,
    confidence: Math.round(confidence * 100) / 100,
    classification: classification,
    type: classification,
    threatType: threatTypeMap[classification],
    features: features ? {
      domainLength: features.domainLength,
      hasIPAddress: features.hasIPAddress,
      isHTTPS: features.isHTTPS,
      suspiciousKeywords: features.suspiciousKeywordCount,
      hasBrandImpersonation: features.hasBrandImpersonation
    } : null,
    reasons: reasons,
    timestamp: new Date().toISOString()
  };
}

/**
 * Batch classify multiple URLs
 * @param {string[]} urls - Array of URLs to classify
 * @returns {Object[]} Array of classification results
 */
export function classifyBatch(urls) {
  return urls.map(url => ({
    url: url,
    ...classifyURL(url)
  }));
}

/**
 * Get model statistics and configuration
 * @returns {Object} Model information
 */
export function getModelInfo() {
  return {
    version: '1.0.0',
    type: 'Rule-based Classifier',
    thresholds: THRESHOLDS,
    featureCount: Object.keys(FEATURE_WEIGHTS).length,
    whitelistSize: SAFE_DOMAINS.length,
    blacklistPatterns: MALICIOUS_PATTERNS.length,
    description: 'Weighted feature-based phishing URL classifier'
  };
}

/**
 * Update classification threshold
 * @param {string} level - Threshold level ('SAFE', 'SUSPICIOUS', 'PHISHING')
 * @param {number} value - New threshold value 0-1
 */
export function updateThreshold(level, value) {
  if (THRESHOLDS[level] !== undefined && value >= 0 && value <= 1) {
    THRESHOLDS[level] = value;
    return true;
  }
  return false;
}

/**
 * Add domain to whitelist
 * @param {string} domain - Domain to add
 */
export function addToWhitelist(domain) {
  if (!SAFE_DOMAINS.includes(domain.toLowerCase())) {
    SAFE_DOMAINS.push(domain.toLowerCase());
  }
}

/**
 * Add pattern to blacklist
 * @param {RegExp} pattern - Regex pattern to add
 */
export function addToBlacklist(pattern) {
  MALICIOUS_PATTERNS.push(pattern);
}
