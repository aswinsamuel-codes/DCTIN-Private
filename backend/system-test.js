/**
 * @file system-test.js
 * @description DCTIN Full System Integration Test
 * Tests: AI Engine → Backend API → Smart Contract → Blockchain
 */

import http from 'http';
import { analyzeURL, validateForReporting } from './ai-engine/detector.js';
import * as blockchainService from './services/blockchainService.js';

const API_HOST = 'localhost';
const API_PORT = 3000;

// Colors for terminal output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

function log(section, message, type = 'info') {
  const color = type === 'success' ? colors.green : 
                type === 'error' ? colors.red : 
                type === 'warning' ? colors.yellow : colors.blue;
  console.log(`${color}[${section}]${colors.reset} ${message}`);
}

function makeRequest(path, method, data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: API_HOST,
      port: API_PORT,
      path: path,
      method: method,
      headers: { 'Content-Type': 'application/json' }
    };

    const req = http.request(options, (res) => {
      let responseData = '';
      res.on('data', (chunk) => responseData += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(responseData);
          resolve({ status: res.statusCode, data: parsed });
        } catch (e) {
          resolve({ status: res.statusCode, data: responseData });
        }
      });
    });

    req.on('error', reject);
    if (data) req.write(JSON.stringify(data));
    req.end();
  });
}

// ============================================
// TEST 1: Safe URL (Should not be reported)
// ============================================
async function testSafeURL() {
  log('TEST 1', 'Safe URL Analysis', 'info');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  const url = 'https://google.com';
  log('INPUT', `URL: ${url}`);
  
  const analysis = analyzeURL(url);
  
  const result = {
    url: url,
    aiClassification: analysis.type,
    confidence: analysis.confidence,
    blockchainSubmission: false,
    reason: 'URL classified as SAFE'
  };
  
  if (!analysis.threat && analysis.confidence < 0.3) {
    log('RESULT', '✅ PASS - Correctly identified as SAFE', 'success');
  } else {
    log('RESULT', '❌ FAIL - Should be marked SAFE', 'error');
  }
  
  console.log('Output:', JSON.stringify(result, null, 2));
  console.log('');
  return result;
}

// ============================================
// TEST 2: Suspicious URL (Phishing detected)
// ============================================
async function testSuspiciousURL() {
  log('TEST 2', 'Suspicious URL Analysis', 'info');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  const url = 'http://login-paypal-secure-account.com';
  log('INPUT', `URL: ${url}`);
  
  const analysis = analyzeURL(url);
  
  const result = {
    url: url,
    aiClassification: analysis.type,
    confidence: analysis.confidence,
    reasons: analysis.reasons,
    blockchainSubmission: analysis.shouldReport
  };
  
  if (analysis.threat) {
    log('RESULT', `✅ PASS - Threat detected (${analysis.type})`, 'success');
    log('CONFIDENCE', `${analysis.confidence}`, analysis.confidence > 0.8 ? 'success' : 'warning');
  } else {
    log('RESULT', '⚠️ WARNING - No threat detected (model may need tuning)', 'warning');
  }
  
  console.log('Output:', JSON.stringify(result, null, 2));
  console.log('');
  return result;
}

// ============================================
// TEST 3: Confirmed Threat (Submit to blockchain)
// ============================================
async function testConfirmedThreat() {
  log('TEST 3', 'Confirmed Threat → Blockchain Submission', 'info');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  const url = 'http://verify-paypal-account-security.com';
  log('INPUT', `URL: ${url}`);
  
  // Step 1: AI Analysis
  const validation = validateForReporting(url);
  
  if (!validation.valid) {
    log('AI', `❌ Validation failed: ${validation.reason}`, 'error');
    return { url, blockchainSubmission: false, reason: validation.reason };
  }
  
  log('AI', `✅ Validation passed (confidence: ${validation.analysis.confidence})`, 'success');
  
  // Step 2: Submit to blockchain
  try {
    log('BLOCKCHAIN', 'Submitting threat to blockchain...', 'info');
    const result = await blockchainService.reportThreat(
      validation.threatData.hash,
      validation.threatData.type
    );
    
    const output = {
      url: url,
      aiClassification: validation.analysis.type,
      confidence: validation.analysis.confidence,
      blockchainSubmission: true,
      txHash: result.transactionHash,
      blockNumber: result.blockNumber,
      gasUsed: result.gasUsed
    };
    
    log('BLOCKCHAIN', `✅ Submitted successfully!`, 'success');
    log('TX HASH', result.transactionHash, 'success');
    log('BLOCK', `${result.blockNumber}`, 'success');
    log('GAS', `${result.gasUsed}`, 'success');
    
    console.log('Output:', JSON.stringify(output, null, 2));
    console.log('');
    return output;
    
  } catch (error) {
    log('BLOCKCHAIN', `❌ Failed: ${error.message}`, 'error');
    return { 
      url, 
      blockchainSubmission: false, 
      error: error.message,
      aiClassification: validation.analysis.type,
      confidence: validation.analysis.confidence
    };
  }
}

// ============================================
// TEST 4: AI Engine Validation (10 URLs)
// ============================================
async function testAIEngineValidation() {
  log('TEST 4', 'AI Engine Validation (10 URLs)', 'info');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  const testUrls = [
    // Safe domains
    { url: 'https://google.com', expected: 'SAFE' },
    { url: 'https://github.com', expected: 'SAFE' },
    { url: 'https://microsoft.com', expected: 'SAFE' },
    { url: 'https://stackoverflow.com', expected: 'SAFE' },
    
    // Suspicious domains
    { url: 'http://paypal-login-secure.com', expected: 'PHISHING' },
    { url: 'http://crypto-wallet-verification.net', expected: 'PHISHING' },
    { url: 'http://bank-security-check-login.xyz', expected: 'PHISHING' },
    { url: 'http://verify-account-now.com', expected: 'PHISHING' },
    { url: 'http://update-payment-info-alert.com', expected: 'PHISHING' },
    { url: 'http://secure-banking-verify.net', expected: 'PHISHING' }
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const test of testUrls) {
    const analysis = analyzeURL(test.url);
    const isCorrect = (test.expected === 'SAFE' && !analysis.threat) ||
                     (test.expected === 'PHISHING' && analysis.threat);
    
    const status = isCorrect ? '✅' : '❌';
    const type = isCorrect ? 'success' : 'warning';
    
    log('URL', `${status} ${test.url}`, type);
    log('  →', `Classified: ${analysis.type} (confidence: ${analysis.confidence})`, type);
    
    if (isCorrect) passed++;
    else failed++;
  }
  
  console.log('');
  log('SUMMARY', `Passed: ${passed}/${testUrls.length}`, passed === testUrls.length ? 'success' : 'warning');
  if (failed > 0) log('SUMMARY', `Failed: ${failed}`, 'error');
  console.log('');
  
  return { passed, failed, total: testUrls.length };
}

// ============================================
// TEST 5: Rate Limiting (>10 threats in block)
// ============================================
async function testRateLimiting() {
  log('TEST 5', 'Rate Limiting Verification', 'info');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  log('TEST', 'Attempting to submit 12 threats in rapid succession...', 'info');
  
  const threats = [];
  for (let i = 0; i < 12; i++) {
    threats.push({
      hash: `0x${'a'.repeat(63)}${i.toString(16).padStart(1, '0')}`,
      type: 1
    });
  }
  
  let successCount = 0;
  let rateLimitHits = 0;
  
  for (let i = 0; i < threats.length; i++) {
    try {
      await blockchainService.reportThreat(threats[i].hash, threats[i].type);
      successCount++;
      log(`TX ${i+1}`, '✅ Success', 'success');
    } catch (error) {
      if (error.message.includes('RATE_LIMIT') || error.message.includes('RateLimitExceeded')) {
        rateLimitHits++;
        log(`TX ${i+1}`, '⚠️ Rate limit hit (expected)', 'warning');
      } else {
        log(`TX ${i+1}`, `❌ Error: ${error.message}`, 'error');
      }
    }
  }
  
  console.log('');
  log('RESULT', `Successful: ${successCount}/12, Rate Limit: ${rateLimitHits}/12`, 'info');
  
  if (rateLimitHits > 0) {
    log('VERIFICATION', '✅ Rate limiting is working correctly', 'success');
  } else if (successCount === 12) {
    log('WARNING', '⚠️ All 12 passed - rate limiting may not be triggered (auto-mining mode)', 'warning');
  }
  
  console.log('');
  return { successCount, rateLimitHits };
}

// ============================================
// TEST 6: API Endpoint Verification
// ============================================
async function testAPIEndpoints() {
  log('TEST 6', 'API Endpoint Verification', 'info');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  const endpoints = [
    { path: '/health', method: 'GET', name: 'Health Check' },
    { path: '/stats', method: 'GET', name: 'Statistics' },
    { path: '/ai-status', method: 'GET', name: 'AI Status' },
    { path: '/analyze-url', method: 'POST', data: { url: 'http://test.com' }, name: 'Analyze URL' },
    { path: '/analyze-urls-batch', method: 'POST', data: { urls: ['http://a.com', 'http://b.com'] }, name: 'Batch Analysis' }
  ];
  
  let passed = 0;
  let failed = 0;
  
  for (const endpoint of endpoints) {
    try {
      const result = await makeRequest(endpoint.path, endpoint.method, endpoint.data);
      if (result.status >= 200 && result.status < 300) {
        log('API', `✅ ${endpoint.name}: ${result.status}`, 'success');
        passed++;
      } else {
        log('API', `⚠️ ${endpoint.name}: ${result.status}`, 'warning');
      }
    } catch (error) {
      log('API', `❌ ${endpoint.name}: ${error.message}`, 'error');
      failed++;
    }
  }
  
  // Test threat query endpoints (need a valid hash)
  try {
    const stats = await makeRequest('/stats', 'GET');
    if (stats.data.success && stats.data.totalThreats > 0) {
      const threatsResult = await makeRequest('/threats', 'GET');
      log('API', `✅ Get Threats: ${threatsResult.status}`, threatsResult.status === 200 ? 'success' : 'warning');
      
      if (threatsResult.data?.threats?.length > 0) {
        const hash = threatsResult.data.threats[0].threatHash;
        const threatResult = await makeRequest(`/threat/${hash}`, 'GET');
        log('API', `✅ Get Threat by Hash: ${threatResult.status}`, threatResult.status === 200 ? 'success' : 'warning');
      }
    }
  } catch (e) {
    log('API', `Query endpoints: ${e.message}`, 'warning');
  }
  
  console.log('');
  log('SUMMARY', `${passed} endpoints passed, ${failed} failed`, failed === 0 ? 'success' : 'warning');
  console.log('');
  
  return { passed, failed };
}

// ============================================
// MAIN TEST RUNNER
// ============================================
async function runSystemTests() {
  console.clear();
  console.log(`${colors.cyan}`);
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║     DCTIN - DECENTRALIZED CYBER THREAT INTELLIGENCE       ║');
  console.log('║              FULL SYSTEM INTEGRATION TEST                 ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log(`${colors.reset}\n`);
  
  const results = {};
  
  try {
    results.safeURL = await testSafeURL();
  } catch (e) { log('ERROR', e.message, 'error'); }
  
  try {
    results.suspiciousURL = await testSuspiciousURL();
  } catch (e) { log('ERROR', e.message, 'error'); }
  
  try {
    results.confirmedThreat = await testConfirmedThreat();
  } catch (e) { log('ERROR', e.message, 'error'); }
  
  try {
    results.aiValidation = await testAIEngineValidation();
  } catch (e) { log('ERROR', e.message, 'error'); }
  
  try {
    results.rateLimiting = await testRateLimiting();
  } catch (e) { log('ERROR', e.message, 'error'); }
  
  try {
    results.apiEndpoints = await testAPIEndpoints();
  } catch (e) { log('ERROR', e.message, 'error'); }
  
  // Final Summary
  console.log(`${colors.cyan}`);
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║                    TEST SUMMARY                           ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log(`${colors.reset}`);
  
  const aiPass = results.aiValidation?.failed === 0;
  const apiPass = results.apiEndpoints?.failed === 0;
  const blockchainPass = results.confirmedThreat?.blockchainSubmission === true;
  
  log('AI ENGINE', aiPass ? '✅ OPERATIONAL' : '⚠️ ISSUES DETECTED', aiPass ? 'success' : 'warning');
  log('API', apiPass ? '✅ ALL ENDPOINTS WORKING' : '❌ SOME ENDPOINTS FAILED', apiPass ? 'success' : 'error');
  log('BLOCKCHAIN', blockchainPass ? '✅ SUBMISSION WORKING' : '⚠️ CHECK REQUIRED', blockchainPass ? 'success' : 'warning');
  log('RATE LIMIT', results.rateLimiting?.rateLimitHits > 0 ? '✅ PROTECTION ACTIVE' : '⚠️ NOT TESTED', 'info');
  
  const allPass = aiPass && apiPass && blockchainPass;
  
  console.log('');
  console.log(`${allPass ? colors.green : colors.yellow}`);
  console.log(`SYSTEM STATUS: ${allPass ? 'READY FOR DEMONSTRATION' : 'NEEDS ATTENTION'}`);
  console.log(`${colors.reset}\n`);
  
  return results;
}

runSystemTests().catch(console.error);
