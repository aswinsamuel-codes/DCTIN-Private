import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import threatRoutes from './routes/threatRoutes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
dotenv.config({ path: join(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  next();
});

// Routes
app.use('/', threatRoutes);

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'DCTIN Backend API',
    version: '1.0.0',
    endpoints: {
      health: 'GET /health',
      reportThreat: 'POST /report-threat',
      getThreat: 'GET /threat/:hash',
      getThreats: 'GET /threats?page=1&limit=10',
      getReporterThreats: 'GET /reporter/:address',
      checkThreatExists: 'GET /threat-exists/:hash',
      getStats: 'GET /stats'
    },
    documentation: 'See README.md for full documentation'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not Found',
    message: `Endpoint ${req.method} ${req.path} not found`
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  res.status(err.status || 500).json({
    success: false,
    error: err.name || 'Internal Server Error',
    message: err.message || 'An unexpected error occurred'
  });
});

// Start server
app.listen(PORT, () => {
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║        DCTIN Backend Server Started                   ║');
  console.log('╚════════════════════════════════════════════════════════╝');
  console.log(`📡 Server running on http://localhost:${PORT}`);
  console.log(`🔗 Blockchain RPC: ${process.env.RPC_URL || 'Not configured'}`);
  console.log(`📋 Contract Address: ${process.env.CONTRACT_ADDRESS || 'Not configured'}`);
  console.log('');
  console.log('Available endpoints:');
  console.log('  GET  /health           - Health check');
  console.log('  POST /report-threat    - Report new threat');
  console.log('  GET  /threat/:hash     - Get threat by hash');
  console.log('  GET  /threats          - Get paginated threats');
  console.log('  GET  /reporter/:addr   - Get threats by reporter');
  console.log('  GET  /threat-exists    - Check threat existence');
  console.log('  GET  /stats            - Get statistics');
  console.log('');
  
  if (!process.env.CONTRACT_ADDRESS) {
    console.log('⚠️  WARNING: CONTRACT_ADDRESS not set in .env');
    console.log('   Please deploy the contract and update .env file');
    console.log('');
  }
});

export default app;
