/**
 * DCTIN Dashboard Application Logic
 */

// State management
const state = {
  currentView: 'dashboard',
  currentPage: 1,
  threatsPerPage: 10,
  totalThreats: 0,
  threats: [],
  lastAnalysis: null
};

// Threat type mapping
const THREAT_TYPES = {
  0: 'Malware',
  1: 'Phishing URL',
  2: 'Malicious IP',
  3: 'C2 Server',
  4: 'Botnet Node',
  5: 'Ransomware',
  6: 'Exploit Payload',
  7: 'Suspicious Domain'
};

// Severity mapping
const SEVERITY_NAMES = {
  0: 'Low',
  1: 'Medium',
  2: 'High',
  3: 'Critical'
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initAnalyzer();
  initExplorer();
  initSearch();
  loadDashboardData();
  checkConnection();
});

// Navigation
function initNavigation() {
  const navButtons = document.querySelectorAll('.nav-btn');
  const views = document.querySelectorAll('.view');

  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const viewName = btn.dataset.view;
      
      // Update active button
      navButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      // Show corresponding view
      views.forEach(view => view.classList.remove('active'));
      document.getElementById(`${viewName}-view`).classList.add('active');
      
      state.currentView = viewName;
      
      // Refresh data when switching views
      if (viewName === 'dashboard') loadDashboardData();
      if (viewName === 'explorer') loadThreats();
    });
  });
}

// Check backend connection
async function checkConnection() {
  const statusBadge = document.getElementById('connection-status');
  const result = await DCTIN_API.checkHealth();
  
  if (result.success) {
    statusBadge.textContent = 'Connected';
    statusBadge.classList.remove('offline');
    statusBadge.classList.add('online');
    
    if (result.data.contract?.address) {
      document.getElementById('contract-addr').textContent = 
        result.data.contract.address.substring(0, 10) + '...';
    }
  } else {
    statusBadge.textContent = 'Disconnected';
    statusBadge.classList.remove('online');
    statusBadge.classList.add('offline');
  }
}

// Load dashboard data
async function loadDashboardData() {
  await Promise.all([
    loadStats(),
    loadLatestThreats(),
    loadAIStatus()
  ]);
}

// Load statistics
async function loadStats() {
  const result = await DCTIN_API.getStats();
  
  if (result.success) {
    const stats = result.data;
    state.totalThreats = stats.totalThreats || 0;
    
    document.getElementById('total-threats').textContent = stats.totalThreats || 0;
    document.getElementById('reporter-count').textContent = 
      stats.reporters ? stats.reporters.length : 1;
    
    // Count by type
    const counts = {};
    if (stats.threatsByType) {
      stats.threatsByType.forEach(t => {
        counts[t.type] = t.count;
      });
    }
    
    document.getElementById('phishing-count').textContent = counts['1'] || 0;
    document.getElementById('malware-count').textContent = counts['0'] || 0;
  }
}

// Load latest threats
async function loadLatestThreats() {
  const container = document.getElementById('latest-threats');
  const result = await DCTIN_API.getThreats(1, 5);
  
  if (result.success && result.data.threats?.length > 0) {
    container.innerHTML = result.data.threats.map(threat => `
      <div class="threat-item ${getThreatClass(threat.threatType)}">
        <div class="threat-info">
          <span class="threat-type">${THREAT_TYPES[threat.threatType] || 'Unknown'}</span>
          <span class="threat-hash">${truncateHash(threat.threatHash)}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="severity-badge sev-${threat.severity ?? 0}">${SEVERITY_NAMES[threat.severity ?? 0] || 'Low'}</span>
          <span class="threat-time">${formatTimestamp(threat.timestamp)}</span>
        </div>
      </div>
    `).join('');
  } else {
    container.innerHTML = '<p class="empty">No threats recorded yet</p>';
  }
}

// Load AI status
async function loadAIStatus() {
  const container = document.getElementById('ai-status');
  const result = await DCTIN_API.getAIStatus();
  
  if (result.success) {
    const status = result.data;
    container.innerHTML = `
      <div class="status-item">
        <span class="label">Status:</span>
        <span class="value status-badge ${status.status === 'OPERATIONAL' ? 'operational' : ''}">${status.status}</span>
      </div>
      <div class="status-item">
        <span class="label">Version:</span>
        <span class="value">${status.version}</span>
      </div>
      <div class="status-item">
        <span class="label">Confidence Threshold:</span>
        <span class="value">${status.confidenceThreshold}</span>
      </div>
      <div class="status-item">
        <span class="label">Model:</span>
        <span class="value">${status.model?.type || 'Rule-based Classifier'}</span>
      </div>
      <div class="status-item">
        <span class="label">Features:</span>
        <span class="value">${status.model?.featureCount || 24} indicators</span>
      </div>
    `;
  } else {
    container.innerHTML = '<p class="error">Unable to load AI status</p>';
  }
}

// Initialize URL Analyzer
function initAnalyzer() {
  const analyzeBtn = document.getElementById('analyze-btn');
  const urlInput = document.getElementById('url-input');
  
  analyzeBtn.addEventListener('click', () => analyzeURL(urlInput.value));
  urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') analyzeURL(urlInput.value);
  });
}

// Analyze URL
async function analyzeURL(url) {
  if (!url) {
    alert('Please enter a URL');
    return;
  }
  
  const resultContainer = document.getElementById('analysis-result');
  const blockchainContainer = document.getElementById('blockchain-result');
  const analyzeBtn = document.getElementById('analyze-btn');
  
  analyzeBtn.disabled = true;
  analyzeBtn.textContent = 'Analyzing...';
  
  resultContainer.classList.remove('hidden');
  resultContainer.innerHTML = '<p class="loading">Analyzing URL with AI engine...</p>';
  blockchainContainer.classList.add('hidden');
  
  const result = await DCTIN_API.analyzeUrl(url);
  state.lastAnalysis = result;
  
  analyzeBtn.disabled = false;
  analyzeBtn.textContent = 'Analyze URL';
  
  if (result.success) {
    const analysis = result.data.analysis;
    const isThreat = analysis.threat;
    const confidence = analysis.confidence;
    const severityName = analysis.severityName || 'LOW';
    const severityNum = analysis.severity ?? 0;
    
    resultContainer.innerHTML = `
      <div class="analysis-result ${isThreat ? 'threat' : 'safe'}">
        <div class="result-header">
          <span class="classification ${isThreat ? 'phishing' : 'safe'}">
            ${analysis.type}
          </span>
          <span class="confidence ${confidence > 0.8 ? 'high' : confidence > 0.5 ? 'medium' : 'low'}">
            Confidence: ${(confidence * 100).toFixed(1)}%
          </span>
          ${isThreat ? `<span class="severity-badge sev-${severityNum}">Severity: ${severityName}</span>` : ''}
        </div>
        
        <div class="result-details">
          <p><strong>URL:</strong> ${url}</p>
          <p><strong>Threat Type:</strong> ${analysis.threatType || 'N/A'}</p>
          
          ${analysis.reasons?.length > 0 ? `
            <div class="reasons">
              <strong>Detection Reasons:</strong>
              <ul>
                ${analysis.reasons.map(r => `<li>${r}</li>`).join('')}
              </ul>
            </div>
          ` : ''}
          
          <p><strong>Analysis Time:</strong> ${result.data.analysis?.analysisTimeMs || '-'}ms</p>
        </div>
        
        ${isThreat && confidence >= 0.8 ? `
          <button id="report-btn" class="btn primary report-btn">
            📤 Report to Blockchain
          </button>
        ` : isThreat ? `
          <div class="warning-box">
            ⚠️ Threat detected but confidence (${(confidence * 100).toFixed(1)}%) is below threshold (80%).
            Not submitted to blockchain.
          </div>
        ` : `
          <div class="success-box">
            ✅ URL appears safe. No threat detected.
          </div>
        `}
      </div>
    `;
    
    // Add report button listener
    const reportBtn = document.getElementById('report-btn');
    if (reportBtn) {
      reportBtn.addEventListener('click', () => reportToBlockchain(url));
    }
  } else {
    resultContainer.innerHTML = `
      <div class="error-box">
        ❌ Analysis failed: ${result.data.error || 'Unknown error'}
      </div>
    `;
  }
}

// Report to blockchain
async function reportToBlockchain(url) {
  const blockchainContainer = document.getElementById('blockchain-result');
  const reportBtn = document.getElementById('report-btn');
  
  reportBtn.disabled = true;
  reportBtn.textContent = 'Submitting...';
  blockchainContainer.classList.remove('hidden');
  blockchainContainer.innerHTML = '<p class="loading">Submitting threat to blockchain...</p>';
  
  const result = await DCTIN_API.reportThreatAI(url);
  
  if (result.success) {
    const bc = result.data.blockchain;
    const ai = result.data.aiValidation;
    blockchainContainer.innerHTML = `
      <div class="blockchain-success">
        <h3>✅ Threat Recorded on Blockchain</h3>
        <div class="tx-details">
          <div class="tx-row">
            <span class="tx-label">Transaction Hash:</span>
            <span class="tx-value mono">${bc.transactionHash}</span>
          </div>
          <div class="tx-row">
            <span class="tx-label">Block Number:</span>
            <span class="tx-value">${bc.blockNumber}</span>
          </div>
          <div class="tx-row">
            <span class="tx-label">Gas Used:</span>
            <span class="tx-value">${bc.gasUsed}</span>
          </div>
          <div class="tx-row">
            <span class="tx-label">Threat Hash:</span>
            <span class="tx-value mono">${bc.threatHash}</span>
          </div>
          ${ai?.severityName ? `
          <div class="tx-row">
            <span class="tx-label">Severity:</span>
            <span class="tx-value"><span class="severity-badge sev-${ai.severity ?? 0}">${ai.severityName}</span></span>
          </div>` : ''}
        </div>
      </div>
    `;
    
    // Refresh dashboard data
    loadDashboardData();
  } else {
    blockchainContainer.innerHTML = `
      <div class="error-box">
        ❌ Blockchain submission failed: ${result.data.message || result.data.error}
      </div>
    `;
    reportBtn.disabled = false;
    reportBtn.textContent = '📤 Retry Report to Blockchain';
  }
}

// Initialize Threat Explorer
function initExplorer() {
  document.getElementById('refresh-btn').addEventListener('click', loadThreats);
  document.getElementById('export-csv-btn').addEventListener('click', exportThreatsCSV);
  document.getElementById('prev-page').addEventListener('click', () => changePage(-1));
  document.getElementById('next-page').addEventListener('click', () => changePage(1));
  document.getElementById('type-filter').addEventListener('change', () => {
    state.currentPage = 1;
    loadThreats();
  });
  document.getElementById('severity-filter').addEventListener('change', () => {
    state.currentPage = 1;
    loadThreats();
  });
}

// Load threats
async function loadThreats() {
  const tbody = document.getElementById('threats-tbody');
  const typeFilter = document.getElementById('type-filter').value;
  const severityFilter = document.getElementById('severity-filter').value;
  
  tbody.innerHTML = '<tr><td colspan="5" class="loading">Loading threats...</td></tr>';
  
  const result = await DCTIN_API.getThreats(state.currentPage, state.threatsPerPage);
  
  if (result.success) {
    let threats = result.data.threats || [];
    
    // Apply type filter if selected
    if (typeFilter) {
      threats = threats.filter(t => t.threatType.toString() === typeFilter);
    }

    // Apply severity filter if selected
    if (severityFilter) {
      threats = threats.filter(t => (t.severity ?? 0).toString() === severityFilter);
    }
    
    state.threats = threats;
    
    if (threats.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty">No threats found</td></tr>';
    } else {
      tbody.innerHTML = threats.map(threat => `
        <tr class="${getThreatClass(threat.threatType)}">
          <td class="mono" title="${threat.threatHash}">${truncateHash(threat.threatHash, 16)}</td>
          <td><span class="type-badge type-${threat.threatType}">${THREAT_TYPES[threat.threatType] || 'Unknown'}</span></td>
          <td><span class="severity-badge sev-${threat.severity ?? 0}">${SEVERITY_NAMES[threat.severity ?? 0] || 'Low'}</span></td>
          <td class="mono">${truncateHash(threat.reporter, 10)}</td>
          <td>${formatTimestamp(threat.timestamp)}</td>
        </tr>
      `).join('');
    }
    
    // Update pagination - use total from API response (fixed)
    const total = result.data.total || 0;
    const totalPages = Math.ceil(total / state.threatsPerPage) || 1;
    document.getElementById('page-info').textContent = `Page ${state.currentPage} of ${totalPages}`;
    document.getElementById('prev-page').disabled = state.currentPage <= 1;
    document.getElementById('next-page').disabled = state.currentPage >= totalPages;
  } else {
    tbody.innerHTML = `<tr><td colspan="5" class="error">Error loading threats: ${result.error}</td></tr>`;
  }
}

// Export threats table as CSV
async function exportThreatsCSV() {
  const exportBtn = document.getElementById('export-csv-btn');
  exportBtn.disabled = true;
  exportBtn.textContent = 'Exporting...';

  try {
    // Fetch all threats (up to 1000 for export)
    const result = await DCTIN_API.getThreats(1, 1000);
    if (!result.success || !result.data.threats?.length) {
      alert('No threats to export.');
      return;
    }

    const threats = result.data.threats;
    const headers = ['Hash', 'Type', 'Type Name', 'Severity', 'Severity Name', 'Reporter', 'Timestamp'];
    const rows = threats.map(t => [
      t.threatHash,
      t.threatType,
      THREAT_TYPES[t.threatType] || 'Unknown',
      t.severity ?? 0,
      SEVERITY_NAMES[t.severity ?? 0] || 'Low',
      t.reporter,
      t.timestamp ? new Date(t.timestamp).toLocaleString() : 'N/A'
    ]);

    const csvContent = [headers, ...rows]
      .map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
      .join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `dctin-threats-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  } finally {
    exportBtn.disabled = false;
    exportBtn.textContent = 'Export CSV';
  }
}

// Initialize Hash Search
function initSearch() {
  const searchBtn = document.getElementById('search-btn');
  const hashInput = document.getElementById('hash-input');

  searchBtn.addEventListener('click', () => searchByHash(hashInput.value.trim()));
  hashInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') searchByHash(hashInput.value.trim());
  });
}

// Search threat by hash
async function searchByHash(hash) {
  if (!hash) {
    alert('Please enter a hash to search');
    return;
  }

  const resultContainer = document.getElementById('search-result');
  const searchBtn = document.getElementById('search-btn');

  searchBtn.disabled = true;
  searchBtn.textContent = 'Searching...';
  resultContainer.classList.remove('hidden');
  resultContainer.innerHTML = '<p class="loading">Searching blockchain...</p>';

  const result = await DCTIN_API.getThreatByHash(hash);

  searchBtn.disabled = false;
  searchBtn.textContent = 'Search';

  if (result.success) {
    const t = result.data;
    resultContainer.innerHTML = `
      <div class="analysis-result threat">
        <div class="result-header">
          <span class="classification phishing">${THREAT_TYPES[t.threatType] || 'Unknown'}</span>
          <span class="severity-badge sev-${t.severity ?? 0}">${SEVERITY_NAMES[t.severity ?? 0] || 'Low'}</span>
        </div>
        <div class="result-details">
          <p><strong>Hash:</strong> <span class="mono">${t.threatHash}</span></p>
          <p><strong>Type:</strong> ${t.threatTypeName || THREAT_TYPES[t.threatType] || 'Unknown'}</p>
          <p><strong>Severity:</strong> ${t.severityName || SEVERITY_NAMES[t.severity ?? 0] || 'Low'}</p>
          <p><strong>Reporter:</strong> <span class="mono">${t.reporter}</span></p>
          <p><strong>Reported At:</strong> ${new Date(t.timestamp).toLocaleString()}</p>
        </div>
      </div>
    `;
  } else if (result.status === 404) {
    resultContainer.innerHTML = `
      <div class="success-box">
        ✅ No threat found for this hash — it is not in the registry.
      </div>
    `;
  } else {
    resultContainer.innerHTML = `
      <div class="error-box">
        ❌ Search failed: ${result.data?.message || result.data?.error || 'Unknown error'}
      </div>
    `;
  }
}

// Change page
function changePage(direction) {
  state.currentPage += direction;
  if (state.currentPage < 1) state.currentPage = 1;
  loadThreats();
}

// Utility functions
function truncateHash(hash, length = 8) {
  if (!hash) return 'N/A';
  if (hash.length <= length * 2 + 2) return hash;
  return hash.substring(0, length) + '...' + hash.substring(hash.length - length);
}

function formatTimestamp(timestamp) {
  if (!timestamp) return 'N/A';
  // ISO string from backend
  if (typeof timestamp === 'string') return new Date(timestamp).toLocaleString();
  // Unix timestamp in seconds
  const date = new Date(timestamp * 1000);
  return date.toLocaleString();
}

function getThreatClass(type) {
  const classes = {
    0: 'malware',
    1: 'phishing',
    2: 'malicious-ip',
    3: 'c2-server',
    4: 'botnet',
    5: 'ransomware',
    6: 'exploit',
    7: 'suspicious'
  };
  return classes[type] || '';
}

// Auto-refresh every 30 seconds when dashboard is active
setInterval(() => {
  if (state.currentView === 'dashboard') {
    loadDashboardData();
  }
}, 30000);
