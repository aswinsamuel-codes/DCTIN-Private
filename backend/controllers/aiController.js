import { analyzeURL, analyzeBatch, validateForReporting, getEngineStatus } from '../ai-engine/detector.js';
import * as blockchainService from '../services/blockchainService.js';

/**
 * Analyze URL for threats (non-blocking, test endpoint)
 * POST /analyze-url
 */
export async function analyzeUrl(req, res) {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({
        success: false,
        error: 'Missing required field: url'
      });
    }
    
    console.log(`\n[API] Analyze URL request: ${url}`);
    
    // Perform AI analysis
    const analysis = analyzeURL(url);
    
    return res.status(200).json({
      success: true,
      url: url,
      analysis: {
        threat: analysis.threat,
        confidence: analysis.confidence,
        type: analysis.type,
        threatType: analysis.threatType,
        reasons: analysis.reasons,
        analysisTimeMs: analysis.analysisTimeMs
      },
      shouldReport: analysis.shouldReport,
      message: analysis.shouldReport 
        ? 'Threat detected with high confidence - ready for blockchain submission'
        : 'No high-confidence threat detected'
    });
    
  } catch (error) {
    console.error('Controller error - analyzeUrl:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: error.message
    });
  }
}

/**
 * Analyze batch of URLs
 * POST /analyze-urls-batch
 */
export async function analyzeUrlsBatch(req, res) {
  try {
    const { urls } = req.body;
    
    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Missing or invalid field: urls (array required)'
      });
    }
    
    if (urls.length > 100) {
      return res.status(400).json({
        success: false,
        error: 'Batch size too large. Maximum 100 URLs allowed'
      });
    }
    
    console.log(`\n[API] Batch analysis request: ${urls.length} URLs`);
    
    const results = analyzeBatch(urls);
    const threats = results.filter(r => r.shouldReport);
    
    return res.status(200).json({
      success: true,
      totalAnalyzed: results.length,
      threatsDetected: results.filter(r => r.threat).length,
      highConfidenceThreats: threats.length,
      results: results,
      readyForSubmission: threats.map(t => ({
        url: t.url,
        confidence: t.confidence,
        type: t.threatType
      }))
    });
    
  } catch (error) {
    console.error('Controller error - analyzeUrlsBatch:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: error.message
    });
  }
}

/**
 * Report threat with AI validation
 * POST /report-threat-ai
 * This endpoint analyzes URL first, then submits to blockchain if threat confirmed
 */
export async function reportThreatWithAI(req, res) {
  try {
    const { url, skipValidation } = req.body;
    
    if (!url) {
      return res.status(400).json({
        success: false,
        error: 'Missing required field: url'
      });
    }
    
    console.log(`\n[API] AI-validated threat report request: ${url}`);
    
    // Step 1: AI Analysis
    const validation = validateForReporting(url);
    
    // Log AI decision
    console.log(`[AI VALIDATION] Result: ${validation.valid ? 'APPROVED' : 'REJECTED'}`);
    console.log(`[AI VALIDATION] Reason: ${validation.reason || 'Threat confirmed'}`);
    console.log(`[AI VALIDATION] Confidence: ${validation.analysis?.confidence}`);
    
    // Step 2: Check if validation passed
    if (!validation.valid && !skipValidation) {
      return res.status(400).json({
        success: false,
        error: 'AI Validation Failed',
        message: validation.reason,
        analysis: validation.analysis,
        suggestion: 'Use skipValidation: true to bypass (admin only)'
      });
    }
    
    // Step 3: Submit to blockchain
    console.log('[BLOCKCHAIN] Submitting validated threat to blockchain...');
    
    const threatData = validation.valid ? validation.threatData : {
      hash: require('ethers').id(url),
      type: 7, // SUSPICIOUS_DOMAIN
      originalUrl: url
    };
    
    const result = await blockchainService.reportThreat(
      threatData.hash,
      threatData.type
    );
    
    return res.status(201).json({
      success: true,
      message: 'Threat analyzed and reported to blockchain',
      aiValidation: {
        passed: validation.valid,
        confidence: validation.analysis?.confidence,
        reasons: validation.analysis?.reasons
      },
      blockchain: result
    });
    
  } catch (error) {
    console.error('Controller error - reportThreatWithAI:', error);
    
    if (error.message?.includes('DUPLICATE_THREAT')) {
      return res.status(409).json({
        success: false,
        error: 'Conflict',
        message: error.message
      });
    }
    
    if (error.message?.includes('RATE_LIMIT_EXCEEDED')) {
      return res.status(429).json({
        success: false,
        error: 'Too Many Requests',
        message: error.message
      });
    }
    
    return res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: error.message
    });
  }
}

/**
 * Get AI engine status
 * GET /ai-status
 */
export async function getAIStatus(req, res) {
  try {
    const status = getEngineStatus();
    
    return res.status(200).json({
      success: true,
      ...status
    });
    
  } catch (error) {
    console.error('Controller error - getAIStatus:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: error.message
    });
  }
}

/**
 * Update AI confidence threshold
 * PUT /ai-threshold
 */
export async function updateThreshold(req, res) {
  try {
    const { threshold } = req.body;
    
    if (threshold === undefined || threshold === null) {
      return res.status(400).json({
        success: false,
        error: 'Missing required field: threshold'
      });
    }
    
    const numThreshold = parseFloat(threshold);
    
    if (isNaN(numThreshold) || numThreshold < 0 || numThreshold > 1) {
      return res.status(400).json({
        success: false,
        error: 'Invalid threshold. Must be a number between 0 and 1'
      });
    }
    
    const { setConfidenceThreshold } = await import('../ai-engine/detector.js');
    const updated = setConfidenceThreshold(numThreshold);
    
    if (updated) {
      return res.status(200).json({
        success: true,
        message: `Confidence threshold updated to ${numThreshold}`,
        threshold: numThreshold
      });
    } else {
      return res.status(500).json({
        success: false,
        error: 'Failed to update threshold'
      });
    }
    
  } catch (error) {
    console.error('Controller error - updateThreshold:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: error.message
    });
  }
}
