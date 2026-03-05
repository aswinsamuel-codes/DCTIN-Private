import http from 'http';

// Test configuration
const PORT = 3000;
const HOST = 'localhost';

// Helper function to make HTTP requests
function makeRequest(path, method, data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: HOST,
      port: PORT,
      path: path,
      method: method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    if (data) {
      const jsonData = JSON.stringify(data);
      options.headers['Content-Length'] = Buffer.byteLength(jsonData);
    }

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

    if (data) {
      req.write(JSON.stringify(data));
    }
    req.end();
  });
}

// Test cases
async function runTests() {
  console.log('═══════════════════════════════════════════');
  console.log('   DCTIN AI ENGINE - INTEGRATION TESTS');
  console.log('═══════════════════════════════════════════\n');

  // Test 1: AI Status
  console.log('Test 1: AI Engine Status');
  console.log('─────────────────────────');
  try {
    const result = await makeRequest('/ai-status', 'GET');
    console.log('Status:', result.status === 200 ? '✅ PASS' : '❌ FAIL');
    console.log('Response:', JSON.stringify(result.data, null, 2));
  } catch (err) {
    console.log('❌ ERROR:', err.message);
  }
  console.log();

  // Test 2: Analyze phishing URL
  console.log('Test 2: Analyze Phishing URL');
  console.log('─────────────────────────────');
  try {
    const result = await makeRequest('/analyze-url', 'POST', {
      url: 'http://suspicious-login-paypal.com'
    });
    console.log('Status:', result.status === 200 ? '✅ PASS' : '❌ FAIL');
    console.log('Threat Detected:', result.data.analysis?.threat ? '✅ YES' : '❌ NO');
    console.log('Confidence:', result.data.analysis?.confidence);
    console.log('Type:', result.data.analysis?.type);
    console.log('Should Report:', result.data.shouldReport ? '✅ YES' : '❌ NO');
    console.log('Reasons:', result.data.analysis?.reasons?.join(', ') || 'N/A');
  } catch (err) {
    console.log('❌ ERROR:', err.message);
  }
  console.log();

  // Test 3: Analyze safe URL
  console.log('Test 3: Analyze Safe URL');
  console.log('──────────────────────────');
  try {
    const result = await makeRequest('/analyze-url', 'POST', {
      url: 'https://google.com'
    });
    console.log('Status:', result.status === 200 ? '✅ PASS' : '❌ FAIL');
    console.log('Threat Detected:', result.data.analysis?.threat ? '❌ YES (unexpected)' : '✅ NO (correct)');
    console.log('Confidence:', result.data.analysis?.confidence);
    console.log('Type:', result.data.analysis?.type);
    console.log('Should Report:', result.data.shouldReport ? '❌ YES (unexpected)' : '✅ NO (correct)');
  } catch (err) {
    console.log('❌ ERROR:', err.message);
  }
  console.log();

  // Test 4: Batch Analysis
  console.log('Test 4: Batch URL Analysis');
  console.log('────────────────────────────');
  try {
    const result = await makeRequest('/analyze-urls-batch', 'POST', {
      urls: [
        'http://verify-account-now.com',
        'https://github.com',
        'http://bit.ly/suspicious'
      ]
    });
    console.log('Status:', result.status === 200 ? '✅ PASS' : '❌ FAIL');
    console.log('Total Analyzed:', result.data.totalAnalyzed);
    console.log('Threats Detected:', result.data.threatsDetected);
    console.log('High Confidence:', result.data.highConfidenceThreats);
    
    if (result.data.results) {
      console.log('\nIndividual Results:');
      result.data.results.forEach((r, i) => {
        console.log(`  ${i+1}. ${r.url}`);
        console.log(`     → ${r.threat ? '🔴 THREAT' : '🟢 SAFE'} (${r.type}, confidence: ${r.confidence})`);
      });
    }
  } catch (err) {
    console.log('❌ ERROR:', err.message);
  }
  console.log();

  // Test 5: Report with AI Validation
  console.log('Test 5: Report Threat with AI Validation');
  console.log('─────────────────────────────────────────');
  try {
    const result = await makeRequest('/report-threat-ai', 'POST', {
      url: 'http://verify-account-secure-bank-login.com'
    });
    
    if (result.status === 201) {
      console.log('Status: ✅ PASS (Reported to blockchain)');
      console.log('AI Validation:', result.data.aiValidation?.passed ? '✅ PASSED' : '❌ FAILED');
      console.log('Confidence:', result.data.aiValidation?.confidence);
      console.log('Transaction Hash:', result.data.blockchain?.transactionHash);
      console.log('Block Number:', result.data.blockchain?.blockNumber);
      console.log('Gas Used:', result.data.blockchain?.gasUsed);
    } else if (result.status === 400) {
      console.log('Status: ⚠️ REJECTED (AI validation failed)');
      console.log('Reason:', result.data.message);
    } else {
      console.log('Status: ❌ FAIL');
      console.log('Response:', result.data);
    }
  } catch (err) {
    console.log('❌ ERROR:', err.message);
  }
  console.log();

  console.log('═══════════════════════════════════════════');
  console.log('         TESTING COMPLETE');
  console.log('═══════════════════════════════════════════');
}

runTests().catch(console.error);
