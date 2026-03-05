/**
 * @file featureExtractor.js
 * @description Feature extraction module for URL threat analysis
 * Extracts features from URLs to determine threat likelihood
 */

import { URL } from 'url';

/**
 * Suspicious keywords commonly found in phishing URLs
 */
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'account', 'secure', 'update',
  'confirm', 'validate', 'authenticate', 'password', 'credential',
  'banking', 'payment', 'paypal', 'apple', 'microsoft', 'google',
  'facebook', 'amazon', 'netflix', 'urgent', 'alert', 'suspend',
  'limited', 'access', 'security', 'unlock', 'restore'
];

/**
 * Shortened URL services often used to mask malicious URLs
 */
const SHORTENED_URL_SERVICES = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
  'buff.ly', 'is.gd', 'short.link', 'rebrand.ly', 'cutt.ly'
];

/**
 * Brand domains commonly impersonated in phishing
 */
const IMPERSONATED_BRANDS = [
  'paypal', 'apple', 'microsoft', 'google', 'amazon',
  'facebook', 'instagram', 'twitter', 'linkedin', 'netflix',
  'bank', 'chase', 'wellsfargo', 'citi', 'amex'
];

/**
 * Extract all features from a URL for threat analysis
 * @param {string} urlString - The URL to analyze
 * @returns {Object} Feature vector with extracted features
 */
export function extractFeatures(urlString) {
  try {
    // Normalize URL
    if (!urlString.startsWith('http')) {
      urlString = 'http://' + urlString;
    }

    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();
    const searchParams = url.search.toLowerCase();
    
    const features = {
      // Domain features
      domainLength: hostname.length,
      hasIPAddress: checkIPAddress(hostname),
      hasSuspiciousTLD: checkSuspiciousTLD(hostname),
      subdomainDepth: countSubdomains(hostname),
      
      // URL structure features
      urlLength: urlString.length,
      pathLength: pathname.length,
      hasQueryParams: url.search.length > 0,
      queryParamCount: url.searchParams.size,
      
      // Security features
      isHTTPS: url.protocol === 'https:',
      hasPort: url.port !== '',
      hasUserInfo: url.username !== '' || url.password !== '',
      hasFragment: url.hash !== '',
      
      // Content features
      suspiciousKeywordCount: countSuspiciousKeywords(hostname + pathname + searchParams),
      hasBrandImpersonation: checkBrandImpersonation(hostname),
      hasEncoding: urlString.includes('%') || urlString.includes('&#'),
      hasMultipleSubdomains: countSubdomains(hostname) > 2,
      
      // Path features
      hasExecutableExtension: checkExecutableExtension(pathname),
      hasMultiplePaths: (pathname.match(/\//g) || []).length > 3,
      
      // Shortened URL check
      isShortenedURL: checkShortenedURL(hostname),
      
      // Special character features
      specialCharCount: countSpecialCharacters(urlString),
      digitCount: (urlString.match(/\d/g) || []).length,
      dashCount: (hostname.match(/-/g) || []).length,
      dotCount: (hostname.match(/\./g) || []).length,
      atSymbolCount: (urlString.match(/@/g) || []).length,
    };

    return features;
  } catch (error) {
    console.error('❌ Feature extraction failed:', error.message);
    return createDefaultFeatures();
  }
}

/**
 * Check if hostname contains an IP address
 * @param {string} hostname - URL hostname
 * @returns {boolean} True if contains IP address
 */
function checkIPAddress(hostname) {
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  return ipPattern.test(hostname);
}

/**
 * Check for suspicious top-level domains
 * @param {string} hostname - URL hostname
 * @returns {boolean} True if TLD is suspicious
 */
function checkSuspiciousTLD(hostname) {
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.work'];
  return suspiciousTLDs.some(tld => hostname.endsWith(tld));
}

/**
 * Count subdomains in hostname
 * @param {string} hostname - URL hostname
 * @returns {number} Number of subdomains
 */
function countSubdomains(hostname) {
  const parts = hostname.split('.');
  // Remove TLD and domain name, count remaining as subdomains
  return Math.max(0, parts.length - 2);
}

/**
 * Count suspicious keywords in URL
 * @param {string} text - URL text to analyze
 * @returns {number} Count of suspicious keywords
 */
function countSuspiciousKeywords(text) {
  let count = 0;
  for (const keyword of SUSPICIOUS_KEYWORDS) {
    if (text.includes(keyword)) {
      count++;
    }
  }
  return count;
}

/**
 * Check if URL impersonates a well-known brand
 * @param {string} hostname - URL hostname
 * @returns {boolean} True if impersonating a brand
 */
function checkBrandImpersonation(hostname) {
  const domainParts = hostname.split('.');
  
  for (const brand of IMPERSONATED_BRANDS) {
    // Check if brand name appears but is not the primary domain
    const hasBrand = hostname.includes(brand);
    const isPrimaryDomain = domainParts.length >= 2 && 
                           (domainParts[domainParts.length - 2] === brand ||
                            domainParts[0] === brand);
    
    // If brand appears but not as primary domain, likely impersonation
    if (hasBrand && !isPrimaryDomain) {
      return true;
    }
  }
  return false;
}

/**
 * Check if URL path has executable extensions
 * @param {string} pathname - URL pathname
 * @returns {boolean} True if has executable extension
 */
function checkExecutableExtension(pathname) {
  const execExtensions = ['.exe', '.dll', '.bat', '.sh', '.js', '.vbs', '.ps1', '.msi', '.zip'];
  return execExtensions.some(ext => pathname.endsWith(ext));
}

/**
 * Check if URL uses a shortened URL service
 * @param {string} hostname - URL hostname
 * @returns {boolean} True if shortened URL
 */
function checkShortenedURL(hostname) {
  return SHORTENED_URL_SERVICES.some(service => hostname.includes(service));
}

/**
 * Count special characters in URL
 * @param {string} url - URL string
 * @returns {number} Count of special characters
 */
function countSpecialCharacters(url) {
  const specialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?]/g;
  const matches = url.match(specialChars);
  return matches ? matches.length : 0;
}

/**
 * Create default features for failed extraction
 * @returns {Object} Default feature vector
 */
function createDefaultFeatures() {
  return {
    domainLength: 0,
    hasIPAddress: false,
    hasSuspiciousTLD: false,
    subdomainDepth: 0,
    urlLength: 0,
    pathLength: 0,
    hasQueryParams: false,
    queryParamCount: 0,
    isHTTPS: false,
    hasPort: false,
    hasUserInfo: false,
    hasFragment: false,
    suspiciousKeywordCount: 0,
    hasBrandImpersonation: false,
    hasEncoding: false,
    hasMultipleSubdomains: false,
    hasExecutableExtension: false,
    hasMultiplePaths: false,
    isShortenedURL: false,
    specialCharCount: 0,
    digitCount: 0,
    dashCount: 0,
    dotCount: 0,
    atSymbolCount: 0
  };
}

/**
 * Convert features to normalized array for model input
 * @param {Object} features - Feature object
 * @returns {number[]} Normalized feature array
 */
export function featuresToVector(features) {
  return [
    normalize(features.domainLength, 0, 100),
    features.hasIPAddress ? 1 : 0,
    features.hasSuspiciousTLD ? 1 : 0,
    normalize(features.subdomainDepth, 0, 5),
    normalize(features.urlLength, 0, 500),
    normalize(features.pathLength, 0, 200),
    features.hasQueryParams ? 1 : 0,
    normalize(features.queryParamCount, 0, 10),
    features.isHTTPS ? 1 : 0,
    features.hasPort ? 1 : 0,
    features.hasUserInfo ? 1 : 0,
    features.hasFragment ? 1 : 0,
    normalize(features.suspiciousKeywordCount, 0, 10),
    features.hasBrandImpersonation ? 1 : 0,
    features.hasEncoding ? 1 : 0,
    features.hasMultipleSubdomains ? 1 : 0,
    features.hasExecutableExtension ? 1 : 0,
    features.hasMultiplePaths ? 1 : 0,
    features.isShortenedURL ? 1 : 0,
    normalize(features.specialCharCount, 0, 50),
    normalize(features.digitCount, 0, 50),
    normalize(features.dashCount, 0, 10),
    normalize(features.dotCount, 0, 10),
    normalize(features.atSymbolCount, 0, 5)
  ];
}

/**
 * Normalize value to 0-1 range
 * @param {number} value - Value to normalize
 * @param {number} min - Minimum value
 * @param {number} max - Maximum value
 * @returns {number} Normalized value between 0 and 1
 */
function normalize(value, min, max) {
  if (value <= min) return 0;
  if (value >= max) return 1;
  return (value - min) / (max - min);
}

/**
 * Get feature importance explanations
 * @param {Object} features - Feature object
 * @returns {string[]} Array of explanations for suspicious features
 */
export function getFeatureExplanations(features) {
  const explanations = [];
  
  if (features.hasIPAddress) explanations.push('Uses IP address instead of domain name');
  if (features.hasSuspiciousTLD) explanations.push('Uses suspicious top-level domain');
  if (features.hasBrandImpersonation) explanations.push('Possible brand impersonation detected');
  if (features.suspiciousKeywordCount > 0) explanations.push(`Contains ${features.suspiciousKeywordCount} suspicious keywords`);
  if (features.isShortenedURL) explanations.push('Uses URL shortening service');
  if (features.hasMultipleSubdomains) explanations.push('Has multiple subdomains (possible subdomain takeover)');
  if (features.hasUserInfo) explanations.push('Contains user credentials in URL');
  if (!features.isHTTPS) explanations.push('Not using HTTPS encryption');
  if (features.hasExecutableExtension) explanations.push('Links to executable file');
  if (features.atSymbolCount > 0) explanations.push('Contains @ symbol (credential phishing technique)');
  if (features.specialCharCount > 20) explanations.push('High number of special characters');
  
  return explanations;
}
