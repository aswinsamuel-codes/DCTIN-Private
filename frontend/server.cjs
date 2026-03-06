/**
 * Simple HTTP server for DCTIN Frontend Dashboard
 * Serves static files on port 4000
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 4000;
const PUBLIC_DIR = __dirname;

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const server = http.createServer((req, res) => {
  // Add CORS headers to allow requests to backend
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // Default to index.html
  let filePath = req.url === '/' ? '/index.html' : req.url;
  filePath = path.join(PUBLIC_DIR, filePath);

  const extname = String(path.extname(filePath)).toLowerCase();
  const contentType = MIME_TYPES[extname] || 'application/octet-stream';

  fs.readFile(filePath, (error, content) => {
    if (error) {
      if (error.code === 'ENOENT') {
        // File not found
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('<h1>404 Not Found</h1>', 'utf-8');
      } else {
        // Server error
        res.writeHead(500);
        res.end(`Server Error: ${error.code}`, 'utf-8');
      }
    } else {
      // Success
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

server.listen(PORT, () => {
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║        DCTIN Frontend Dashboard Server                 ║');
  console.log('╚════════════════════════════════════════════════════════╝');
  console.log(`\n🌐 Dashboard running at: http://localhost:${PORT}`);
  console.log(`🔗 API Backend: http://localhost:3000`);
  console.log(`\n📁 Serving files from: ${PUBLIC_DIR}`);
  console.log('\nFeatures:');
  console.log('  • Dashboard Overview - View threat statistics');
  console.log('  • URL Analyzer - AI-powered threat detection');
  console.log('  • Threat Explorer - Browse blockchain records');
  console.log('\nPress Ctrl+C to stop the server\n');
});
