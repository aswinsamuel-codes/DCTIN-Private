import express from 'express';
import {
  reportThreat,
  reportThreatBatch,
  getThreatByHash,
  getThreatsPaginated,
  getThreatsByReporter,
  threatExists,
  getStats
} from '../controllers/threatController.js';

const router = express.Router();

/**
 * @route   POST /report-threat
 * @desc    Report a new threat to the blockchain
 * @body    { hash: string, type: number, severity?: number }
 */
router.post('/report-threat', reportThreat);

/**
 * @route   POST /report-threat-batch
 * @desc    Report multiple threats in a single blockchain transaction
 * @body    { threats: Array<{ hash: string, type: number, severity?: number }> }
 */
router.post('/report-threat-batch', reportThreatBatch);

/**
 * @route   GET /threat/:hash
 * @desc    Get threat details by hash
 * @param   hash - bytes32 threat hash
 */
router.get('/threat/:hash', getThreatByHash);

/**
 * @route   GET /threats
 * @desc    Get threats with pagination
 * @query   page - Page number (default: 1)
 * @query   limit - Items per page (default: 10, max: 1000)
 */
router.get('/threats', getThreatsPaginated);

/**
 * @route   GET /reporter/:address
 * @desc    Get all threats reported by a specific address
 * @param   address - Ethereum address of the reporter
 */
router.get('/reporter/:address', getThreatsByReporter);

/**
 * @route   GET /threat-exists/:hash
 * @desc    Check if a threat hash exists
 * @param   hash - bytes32 threat hash
 */
router.get('/threat-exists/:hash', threatExists);

/**
 * @route   GET /stats
 * @desc    Get blockchain statistics
 */
router.get('/stats', getStats);

/**
 * @route   GET /health
 * @desc    Health check endpoint
 */
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    service: 'DCTIN Backend API'
  });
});

export default router;
