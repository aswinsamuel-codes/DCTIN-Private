import http from 'http';

function makeRequest(path, method, data = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: path,
      method: method,
      headers: { 'Content-Type': 'application/json', 'X-API-Key': process.env.ADMIN_API_KEY || '' }
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

async function testThresholdUpdate() {
  console.log('Testing AI Threshold Update...\n');
  
  // Get current status
  console.log('1. Getting current AI status...');
  const status1 = await makeRequest('/ai-status', 'GET');
  console.log('   Current threshold:', status1.data.confidenceThreshold);
  
  // Update threshold
  console.log('\n2. Updating threshold to 0.6...');
  const update = await makeRequest('/ai-threshold', 'PUT', { threshold: 0.6 });
  console.log('   Response:', JSON.stringify(update.data, null, 2));
  
  // Verify update
  console.log('\n3. Verifying new threshold...');
  const status2 = await makeRequest('/ai-status', 'GET');
  console.log('   New threshold:', status2.data.confidenceThreshold);
  
  // Test result
  if (status2.data.confidenceThreshold === 0.6) {
    console.log('\n✅ SUCCESS: Threshold updated correctly!');
  } else {
    console.log('\n❌ FAILED: Threshold not updated');
  }
}

testThresholdUpdate().catch(console.error);
