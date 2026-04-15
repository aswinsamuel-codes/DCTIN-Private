import * as blockchainService from '../services/blockchainService.js';

/**
 * Report a new threat
 * POST /report-threat
 */
export async function reportThreat(req, res) {
  try {
    const { hash, type, severity } = req.body;
    
    // Validate request body
    if (!hash) {
      return res.status(400).json({
        success: false,
        error: 'Missing required field: hash'
      });
    }
    
    if (type === undefined || type === null) {
      return res.status(400).json({
        success: false,
        error: 'Missing required field: type'
      });
    }
    
    // Convert type to number if it's a string
    const typeNum = parseInt(type, 10);
    if (isNaN(typeNum)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid type: must be an integer between 0 and 7'
      });
    }

    // Severity defaults to LOW (0) if not provided
    const severityNum = severity !== undefined ? parseInt(severity, 10) : 0;
    if (isNaN(severityNum) || severityNum < 0 || severityNum > 3) {
      return res.status(400).json({
        success: false,
        error: 'Invalid severity: must be an integer between 0 and 3 (0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL)'
      });
    }
    
    const result = await blockchainService.reportThreat(hash, typeNum, severityNum);
    
    return res.status(201).json(result);
    
  } catch (error) {
    console.error('Controller error - reportThreat:', error);
    
    // Handle specific error types
    if (error.message?.includes('DUPLICATE_THREAT')) {
      return res.status(409).json({
        success: false,
        error: 'Conflict',
        message: error.message
      });
    }
    
    if (error.message?.includes('INVALID_TYPE')) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
        message: error.message
      });
    }
    
    if (error.message?.includes('INVALID_HASH')) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
        message: error.message
      });
    }

    if (error.message?.includes('INVALID_SEVERITY')) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
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
    
    if (error.message?.includes('UNAUTHORIZED')) {
      return res.status(403).json({
        success: false,
        error: 'Forbidden',
        message: error.message
      });
    }
    
    if (error.message?.includes('Contract not initialized')) {
      return res.status(500).json({
        success: false,
        error: 'Server Error',
        message: 'Contract not initialized. Please deploy the contract and set CONTRACT_ADDRESS in .env'
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
 * Batch report multiple threats in a single transaction
 * POST /report-threat-batch
 */
export async function reportThreatBatch(req, res) {
  try {
    const { threats } = req.body;

    if (!Array.isArray(threats) || threats.length === 0) {
      return res.status(400).json({
        success: false,
        error: 'Missing or invalid field: threats (non-empty array required)'
      });
    }

    if (threats.length > 50) {
      return res.status(400).json({
        success: false,
        error: 'Batch too large. Maximum 50 threats per batch'
      });
    }

    // Validate each threat entry
    for (let i = 0; i < threats.length; i++) {
      const t = threats[i];
      if (!t.hash) {
        return res.status(400).json({ success: false, error: `Missing hash at index ${i}` });
      }
      const typeNum = parseInt(t.type, 10);
      if (isNaN(typeNum) || typeNum < 0 || typeNum > 7) {
        return res.status(400).json({ success: false, error: `Invalid type at index ${i}: must be 0-7` });
      }
      const sevNum = t.severity !== undefined ? parseInt(t.severity, 10) : 0;
      if (isNaN(sevNum) || sevNum < 0 || sevNum > 3) {
        return res.status(400).json({ success: false, error: `Invalid severity at index ${i}: must be 0-3` });
      }
      // Normalise back to numbers for the service layer
      threats[i] = { hash: t.hash, type: typeNum, severity: sevNum };
    }

    const result = await blockchainService.reportThreatBatch(threats);
    return res.status(201).json(result);

  } catch (error) {
    console.error('Controller error - reportThreatBatch:', error);

    if (error.message?.includes('DUPLICATE_THREAT')) {
      return res.status(409).json({ success: false, error: 'Conflict', message: error.message });
    }
    if (error.message?.includes('BATCH_TOO_LARGE')) {
      return res.status(400).json({ success: false, error: 'Bad Request', message: error.message });
    }
    if (error.message?.includes('RATE_LIMIT_EXCEEDED')) {
      return res.status(429).json({ success: false, error: 'Too Many Requests', message: error.message });
    }

    return res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: error.message
    });
  }
}

/**
 * Get threat by hash
 * GET /threat/:hash
 */
export async function getThreatByHash(req, res) {
  try {
    const { hash } = req.params;
    
    if (!hash) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameter: hash'
      });
    }
    
    const result = await blockchainService.getThreatByHash(hash);
    return res.status(200).json(result);
    
  } catch (error) {
    console.error('Controller error - getThreatByHash:', error);
    
    if (error.message?.includes('NOT_FOUND')) {
      return res.status(404).json({
        success: false,
        error: 'Not Found',
        message: 'Threat not found'
      });
    }
    
    if (error.message?.includes('Invalid hash format')) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
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
 * Get threats with pagination
 * GET /threats?page=1&limit=10
 */
export async function getThreatsPaginated(req, res) {
  try {
    // Get pagination parameters from query
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    
    // Validate parameters
    if (page < 1) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
        message: 'Page must be >= 1'
      });
    }
    
    if (limit < 1 || limit > 1000) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
        message: 'Limit must be between 1 and 1000'
      });
    }
    
    // Convert page/limit to start/count for contract
    const start = (page - 1) * limit;
    const count = limit;
    
    const result = await blockchainService.getThreatsPaginated(start, count);
    
    // Add pagination metadata
    const response = {
      ...result,
      pagination: {
        page: page,
        limit: limit,
        startIndex: start
      }
    };
    
    return res.status(200).json(response);
    
  } catch (error) {
    console.error('Controller error - getThreatsPaginated:', error);
    
    if (error.message?.includes('INVALID_RANGE')) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
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
 * Get threats by reporter
 * GET /reporter/:address
 */
export async function getThreatsByReporter(req, res) {
  try {
    const { address } = req.params;
    
    if (!address) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameter: address'
      });
    }
    
    const result = await blockchainService.getThreatsByReporter(address);
    return res.status(200).json(result);
    
  } catch (error) {
    console.error('Controller error - getThreatsByReporter:', error);
    
    if (error.message?.includes('Invalid Ethereum address')) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request',
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
 * Check if threat exists
 * GET /threat-exists/:hash
 */
export async function threatExists(req, res) {
  try {
    const { hash } = req.params;
    
    if (!hash) {
      return res.status(400).json({
        success: false,
        error: 'Missing required parameter: hash'
      });
    }
    
    const result = await blockchainService.threatExists(hash);
    return res.status(200).json(result);
    
  } catch (error) {
    console.error('Controller error - threatExists:', error);
    
    return res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: error.message
    });
  }
}

/**
 * Get total threats count
 * GET /stats
 */
export async function getStats(req, res) {
  try {
    const result = await blockchainService.getTotalThreats();
    return res.status(200).json(result);
    
  } catch (error) {
    console.error('Controller error - getStats:', error);
    
    return res.status(500).json({
      success: false,
      error: 'Internal Server Error',
      message: error.message
    });
  }
}

/**
 * Get reporter reputation stats
 * GET /reporter/:address/stats
 */
export async function getReporterStats(req, res) {
  try {
    const { address } = req.params;

    if (!address) {
      return res.status(400).json({ success: false, error: 'Missing required parameter: address' });
    }

    const result = await blockchainService.getReporterStats(address);
    return res.status(200).json(result);

  } catch (error) {
    console.error('Controller error - getReporterStats:', error);

    if (error.message?.includes('Invalid Ethereum address')) {
      return res.status(400).json({ success: false, error: 'Bad Request', message: error.message });
    }

    return res.status(500).json({ success: false, error: 'Internal Server Error', message: error.message });
  }
}

/**
 * Update threat status (ACTIVE / RESOLVED / DISPUTED)
 * PUT /threat/:hash/status
 */
export async function updateThreatStatus(req, res) {
  try {
    const { hash } = req.params;
    const { status } = req.body;

    if (!hash) {
      return res.status(400).json({ success: false, error: 'Missing required parameter: hash' });
    }
    if (status === undefined || status === null) {
      return res.status(400).json({ success: false, error: 'Missing required field: status (0=ACTIVE, 1=RESOLVED, 2=DISPUTED)' });
    }

    const statusNum = parseInt(status, 10);
    if (isNaN(statusNum) || statusNum < 0 || statusNum > 2) {
      return res.status(400).json({ success: false, error: 'Invalid status: must be 0 (ACTIVE), 1 (RESOLVED), or 2 (DISPUTED)' });
    }

    const result = await blockchainService.updateThreatStatus(hash, statusNum);
    return res.status(200).json(result);

  } catch (error) {
    console.error('Controller error - updateThreatStatus:', error);

    if (error.message?.includes('UNAUTHORIZED_STATUS_UPDATE')) {
      return res.status(403).json({ success: false, error: 'Forbidden', message: error.message });
    }
    if (error.message?.includes('NOT_FOUND')) {
      return res.status(404).json({ success: false, error: 'Not Found', message: 'Threat not found' });
    }
    if (error.message?.includes('INVALID_STATUS')) {
      return res.status(400).json({ success: false, error: 'Bad Request', message: error.message });
    }

    return res.status(500).json({ success: false, error: 'Internal Server Error', message: error.message });
  }
}
