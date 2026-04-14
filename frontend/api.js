/**
 * API Client for DCTIN Dashboard
 * Connects to backend at http://localhost:3000
 */

const API_BASE_URL = 'http://localhost:3000';

/**
 * Make API request
 */
async function apiRequest(endpoint, method = 'GET', body = null) {
  const options = {
    method,
    headers: {
      'Content-Type': 'application/json'
    }
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
    const data = await response.json();
    return { success: response.ok, status: response.status, data };
  } catch (error) {
    console.error(`API Error [${endpoint}]:`, error);
    return { success: false, error: error.message };
  }
}

/**
 * Health check
 */
async function checkHealth() {
  return apiRequest('/health');
}

/**
 * Get statistics
 */
async function getStats() {
  return apiRequest('/stats');
}

/**
 * Get threats with pagination
 */
async function getThreats(page = 1, limit = 10) {
  return apiRequest(`/threats?page=${page}&limit=${limit}`);
}

/**
 * Get threat by hash
 */
async function getThreatByHash(hash) {
  return apiRequest(`/threat/${hash}`);
}

/**
 * Analyze URL for threats
 */
async function analyzeUrl(url) {
  return apiRequest('/analyze-url', 'POST', { url });
}

/**
 * Report threat with AI validation
 */
async function reportThreatAI(url) {
  return apiRequest('/report-threat-ai', 'POST', { url });
}

/**
 * Get AI engine status
 */
async function getAIStatus() {
  return apiRequest('/ai-status');
}

/**
 * Check if threat exists
 */
async function checkThreatExists(hash) {
  return apiRequest(`/threat-exists/${hash}`);
}

/**
 * Report multiple threats in a single blockchain transaction
 * @param {Array<{hash: string, type: number, severity?: number}>} threats
 */
async function reportThreatBatch(threats) {
  return apiRequest('/report-threat-batch', 'POST', { threats });
}

// Export API functions
window.DCTIN_API = {
  checkHealth,
  getStats,
  getThreats,
  getThreatByHash,
  analyzeUrl,
  reportThreatAI,
  getAIStatus,
  checkThreatExists,
  reportThreatBatch
};
