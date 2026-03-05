import express from 'express';
import {
  analyzeUrl,
  analyzeUrlsBatch,
  reportThreatWithAI,
  getAIStatus,
  updateThreshold
} from '../controllers/aiController.js';

const router = express.Router();

/**
 * @route   POST /analyze-url
 * @desc    Analyze a URL for phishing threats using AI engine
 * @body    { url: string }
 * @access  Public
 */
router.post('/analyze-url', analyzeUrl);

/**
 * @route   POST /analyze-urls-batch
 * @desc    Analyze multiple URLs in batch
 * @body    { urls: string[] }
 * @access  Public
 */
router.post('/analyze-urls-batch', analyzeUrlsBatch);

/**
 * @route   POST /report-threat-ai
 * @desc    Report threat with AI validation (analyzes then submits to blockchain)
 * @body    { url: string, skipValidation?: boolean }
 * @access  Public
 */
router.post('/report-threat-ai', reportThreatWithAI);

/**
 * @route   GET /ai-status
 * @desc    Get AI engine status and configuration
 * @access  Public
 */
router.get('/ai-status', getAIStatus);

/**
 * @route   PUT /ai-threshold
 * @desc    Update AI confidence threshold
 * @body    { threshold: number (0-1) }
 * @access  Admin only (in production)
 */
router.put('/ai-threshold', updateThreshold);

export default router;
