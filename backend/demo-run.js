/**
 * @file demo-run.js
 * @description DCTIN One-Command Demonstration Script
 * Shows: AI Analysis → Blockchain Submission → Threat Intelligence Feed
 */

import http from 'http';

const API_HOST = 'localhost';
const API_PORT = 3000;

// Demo banner
console.log('\n');
console.log('╔══════════════════════════════════════════════════════════════════╗');
console.log('║     🛡️  DCTIN - DECENTRALIZED CYBER THREAT INTELLIGENCE       ║');
console.log('║                    LIVE DEMONSTRATION                          ║');
console.log('╚══════════════════════════════════════════════════════════════════╝');
console.log('\n');

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

function printSection(title) {
  console.log('\n┌────────────────────────────────────────────────────────────────┐');
  console.log(`│ ${title.padEnd(62)} │`);
  console.log('└────────────────────────────────────────────────────────────────┘');
}

function printAIResult(result) {
  console.log('\n[DCTIN AI ENGINE]');
  console.log(`  URL analyzed: ${result.url}`);
  console.log(`  Classification: ${result.analysis?.type || 'UNKNOWN'}`);
  console.log(`  Confidence: ${result.analysis?.confidence || 0}`);
  if (result.analysis?.reasons?.length > 0) {
    console.log('  Detection reasons:');
    result.analysis.reasons.forEach(r => console.log(`    • ${r}`));
  }
}

function printBlockchainResult(result) {
  if (result.blockchain) {
    console.log('\n[DCTIN BLOCKCHAIN]');
    console.log(`  ✅ Threat recorded successfully`);
    console.log(`  Transaction Hash: ${result.blockchain.transactionHash}`);
    console.log(`  Block Number: ${result.blockchain.blockNumber}`);
    console.log(`  Gas Used: ${result.blockchain.gasUsed}`);
    console.log(`  Threat Index: ${result.blockchain.threatIndex}`);
  } else if (result.aiValidation?.passed === false) {
    console.log('\n[DCTIN BLOCKCHAIN]');
    console.log(`  ⚠️  Not submitted - ${result.message || 'AI validation failed'}`);
  }
}

// ============================================
// DEMO STEP 1: Analyze URLs
// ============================================
async function step1_analyzeURLs() {
  printSection('STEP 1: AI Threat Analysis - 3 URLs');
  
  const urls = [
    { url: 'https://google.com', description: 'Safe - Trusted Domain' },
    { url: 'http://paypal-login-secure.com', description: 'Suspicious - Brand Impersonation' },
    { url: 'http://verify-bank-account-security.com', description: 'Threat - High Confidence Phishing' }
  ];
  
  for (const item of urls) {
    console.log(`\n🔍 Analyzing: ${item.description}`);
    console.log(`   URL: ${item.url}`);
    
    const result = await makeRequest('/analyze-url', 'POST', { url: item.url });
    printAIResult(result.data);
  }
}

// ============================================
// DEMO STEP 2: Submit Confirmed Threat
// ============================================
async function step2_submitThreat() {
  printSection('STEP 2: Submit Confirmed Threat to Blockchain');
  
  const threatUrl = 'http://verify-account-secure-paypal.com/login';
  console.log(`\n🚀 Submitting: ${threatUrl}`);
  
  const result = await makeRequest('/report-threat-ai', 'POST', { url: threatUrl });
  
  if (result.data.success) {
    printBlockchainResult(result.data);
    return result.data.blockchain?.transactionHash;
  } else {
    console.log('\n❌ Submission failed:');
    console.log(`   ${result.data.message || result.data.error}`);
    return null;
  }
}

// ============================================
// DEMO STEP 3: Query Blockchain
// ============================================
async function step3_queryBlockchain(txHash) {
  printSection('STEP 3: Query Blockchain Threat Registry');
  
  // Get stats
  const stats = await makeRequest('/stats', 'GET');
  if (stats.data.success) {
    console.log('\n📊 Network Statistics:');
    console.log(`  Total Threats Recorded: ${stats.data.totalThreats}`);
    console.log(`  Contract Address: ${stats.data.contractAddress}`);
    console.log(`  Reporter Address: ${stats.data.reporter || 'Not available'}`);
  }
  
  // Get recent threats
  const threats = await makeRequest('/threats?page=1&limit=5', 'GET');
  if (threats.data.success && threats.data.threats?.length > 0) {
    console.log('\n📋 Recent Threat Intelligence Feed:');
    console.log('  ┌─────────┬────────────────────────┬────────────────────────────┐');
    console.log('  │ Index   │ Type                   │ Hash (truncated)           │');
    console.log('  ├─────────┼────────────────────────┼────────────────────────────┤');
    
    threats.data.threats.slice(0, 5).forEach((threat, i) => {
      const hash = threat.threatHash?.substring(0, 26) + '...' || 'N/A';
      const type = threat.threatType?.padEnd(22) || 'UNKNOWN';
      console.log(`  │ #${(threat.index || i).toString().padStart(3)}   │ ${type} │ ${hash.padEnd(26)} │`);
    });
    
    console.log('  └─────────┴────────────────────────┴────────────────────────────┘');
  }
  
  // Query specific threat by hash if available
  if (txHash) {
    console.log('\n🔎 Looking up threat by transaction hash...');
    // Note: In a real scenario, we'd get the threat hash from the submission
    // For demo, we'll show the last threat
    if (threats.data.threats?.length > 0) {
      const lastThreat = threats.data.threats[threats.data.threats.length - 1];
      const threatDetail = await makeRequest(`/threat/${lastThreat.threatHash}`, 'GET');
      if (threatDetail.data.success) {
        console.log('  ✅ Threat verified on blockchain!');
        console.log(`     Reporter: ${threatDetail.data.threat?.reporter}`);
        console.log(`     Timestamp: ${new Date(threatDetail.data.threat?.timestamp * 1000).toISOString()}`);
      }
    }
  }
}

// ============================================
// DEMO STEP 4: AI Engine Status
// ============================================
async function step4_engineStatus() {
  printSection('STEP 4: AI Engine Status & Capabilities');
  
  const status = await makeRequest('/ai-status', 'GET');
  if (status.data.success) {
    console.log('\n🤖 AI Engine Status:');
    console.log(`  Status: ${status.data.status}`);
    console.log(`  Version: ${status.data.version}`);
    console.log(`  Confidence Threshold: ${status.data.confidenceThreshold}`);
    console.log(`  Model Type: ${status.data.model?.type}`);
    console.log(`  Features: ${status.data.model?.featureCount}`);
    
    console.log('\n  Capabilities:');
    status.data.capabilities.forEach(cap => console.log(`    ✓ ${cap}`));
    
    console.log('\n  Supported Threat Types:');
    status.data.supportedThreatTypes.forEach(type => console.log(`    • ${type}`));
  }
}

// ============================================
// MAIN DEMO RUNNER
// ============================================
async function runDemo() {
  const startTime = Date.now();
  
  try {
    // Check if backend is running
    const health = await makeRequest('/health', 'GET');
    if (health.status !== 200) {
      console.log('\n❌ Backend server not responding. Please start it with:');
      console.log('   cd backend && npm start');
      process.exit(1);
    }
    
    console.log('✅ Backend connected');
    console.log(`   Contract: ${health.data.contract?.address || 'Not available'}`);
    
    // Run demo steps
    await step1_analyzeURLs();
    const txHash = await step2_submitThreat();
    await step3_queryBlockchain(txHash);
    await step4_engineStatus();
    
    const duration = Date.now() - startTime;
    
    console.log('\n╔══════════════════════════════════════════════════════════════════╗');
    console.log('║                   🎉 DEMO COMPLETE! 🎉                           ║');
    console.log(`║              Total time: ${duration}ms`.padEnd(65) + '║');
    console.log('╚══════════════════════════════════════════════════════════════════╝');
    console.log('\nNext steps:');
    console.log('  • Run system tests: node system-test.js');
    console.log('  • View API docs: http://localhost:3000/');
    console.log('  • Check contract: npx hardhat console --network localhost');
    console.log('\n');
    
  } catch (error) {
    console.log('\n❌ Demo failed:', error.message);
    console.log('\nTroubleshooting:');
    console.log('  1. Ensure Hardhat node is running: npx hardhat node');
    console.log('  2. Ensure backend is running: cd backend && npm start');
    console.log('  3. Check .env configuration');
    console.log('\n');
    process.exit(1);
  }
}

runDemo();
