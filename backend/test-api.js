import http from 'http';

const testData = JSON.stringify({
  hash: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
  type: 0
});

const options = {
  hostname: 'localhost',
  port: 3000,
  path: '/report-threat',
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': process.env.ADMIN_API_KEY || '',
    'Content-Length': Buffer.byteLength(testData)
  }
};

console.log('Testing POST /report-threat...');
console.log('Request body:', testData);
console.log('');

const req = http.request(options, (res) => {
  let data = '';
  
  res.on('data', (chunk) => {
    data += chunk;
  });
  
  res.on('end', () => {
    console.log(`Status Code: ${res.statusCode}`);
    console.log('Response:');
    try {
      const parsed = JSON.parse(data);
      console.log(JSON.stringify(parsed, null, 2));
    } catch (e) {
      console.log(data);
    }
    
    if (res.statusCode === 201) {
      console.log('\n✅ SUCCESS: Threat reported to blockchain!');
    } else {
      console.log('\n❌ Failed to report threat');
    }
  });
});

req.on('error', (error) => {
  console.error('Request failed:', error.message);
});

req.write(testData);
req.end();
