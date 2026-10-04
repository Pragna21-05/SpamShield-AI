/**
 * SpamShield AI - Frontend Application Controller
 * Handles tabs, real-time scanning, explainability rendering,
 * history management, analytics chart rendering, safety hub quiz, and settings.
 */

// Application Global State
const state = {
  currentTab: 'scan',
  activeSource: 'Email',
  currentUser: {
    username: 'Security Analyst',
    email: 'analyst@spamshield.ai',
    avatar: 'SA',
    role: 'Cybersecurity Lead'
  },
  lastScanResult: null,
  history: [],
  historyFilters: {
    search: '',
    status: 'ALL',
    risk: 'ALL',
    source: 'ALL'
  },
  analytics: null,
  settings: {
    threshold_high: 75,
    threshold_med: 40,
    active_model: 'ensemble',
    custom_blacklist: [],
    custom_whitelist: []
  },
  simulator: {
    currentIndex: 0,
    score: 0,
    answered: false,
    questions: [
      {
        id: 1,
        sender: 'security@amzn-order-verify.xyz',
        subject: 'URGENT: Order #492-9182 Locked Due to Fraud',
        source: 'Email',
        body: 'Dear Amazon Customer: Your order #492-9182 for Apple iPhone 15 Pro ($1,199.00) has been placed. If you did not make this purchase, click here within 2 hours to cancel: http://bit.ly/amzn-cancel-order',
        isSpam: true,
        reason: 'Spoofed sender domain (.xyz), artificial urgency (within 2 hours), and masked shortened URL (bit.ly).'
      },
      {
        id: 2,
        sender: 'GOOGLE-AUTH (22000)',
        subject: 'Google Verification Code',
        source: 'SMS',
        body: 'G-749102 is your Google verification code. Do not share this code with anyone. Google employees will never call to request this code.',
        isSpam: false,
        reason: 'Legitimate authentic 2FA message explicitly warning user never to disclose the code.'
      },
      {
        id: 3,
        sender: '+44 7921 849201',
        subject: 'WhatsApp Direct Message',
        source: 'WhatsApp',
        body: 'Congratulations! Your phone number won $850,000 in the UK Mobile Anniversary Draw. To claim your prize, send your full name, bank account number, and national ID photo immediately to claims@uk-lottery.buzz',
        isSpam: true,
        reason: 'Classic advanced fee / lottery fraud with unsolicited cash prize and suspicious .buzz domain.'
      }
    ]
  }
};

// DOM Ready Initialization
document.addEventListener('DOMContentLoaded', () => {
  initUserSession();
  initNavigation();
  initScannerInputs();
  initPresetButtons();
  initHistoryControls();
  initSettingsControls();
  initSimulator();
  loadInitialData();
});

// -------------------------------------------------------------
// Authentication & User Session
// -------------------------------------------------------------
function initUserSession() {
  const savedUser = localStorage.getItem('SpamShield_User');
  if (savedUser) {
    try {
      state.currentUser = JSON.parse(savedUser);
    } catch (e) {
      console.error(e);
    }
  }
  updateUserDisplay();
}

function updateUserDisplay() {
  const avatarEl = document.getElementById('userAvatarDisplay');
  const nameEl = document.getElementById('userNameDisplay');
  if (avatarEl) avatarEl.textContent = state.currentUser.avatar || 'SA';
  if (nameEl) nameEl.textContent = state.currentUser.username || 'Security Analyst';
}

function openAuthModal() {
  const modal = document.getElementById('authModal');
  if (modal) modal.classList.add('active');
}

function closeAuthModal() {
  const modal = document.getElementById('authModal');
  if (modal) modal.classList.remove('active');
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('loginUsername').value.trim() || 'analyst';
  const res = await apiFetch('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password: 'password123' })
  });
  if (res && res.user) {
    state.currentUser = res.user;
    localStorage.setItem('SpamShield_User', JSON.stringify(res.user));
    updateUserDisplay();
    closeAuthModal();
    showToast(`Welcome back, ${res.user.username}!`, 'success');
  }
}

// -------------------------------------------------------------
// Navigation & Tab Switching
// -------------------------------------------------------------
function initNavigation() {
  const tabButtons = document.querySelectorAll('.nav-tab-btn');
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });
}

function switchTab(tabName) {
  state.currentTab = tabName;

  // Update nav buttons
  document.querySelectorAll('.nav-tab-btn').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-tab') === tabName);
  });

  // Update tab sections
  document.querySelectorAll('.tab-section').forEach(sec => {
    sec.classList.toggle('active', sec.id === `tab-${tabName}`);
  });

  // Trigger section-specific data refreshes
  if (tabName === 'history') {
    fetchHistory();
  } else if (tabName === 'analytics') {
    fetchAnalytics();
  } else if (tabName === 'settings') {
    fetchSettings();
  }
}

// -------------------------------------------------------------
// Message Scanner Module
// -------------------------------------------------------------
function initScannerInputs() {
  // Source selector buttons
  const sourceChips = document.querySelectorAll('.source-chip');
  sourceChips.forEach(chip => {
    chip.addEventListener('click', () => {
      sourceChips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      state.activeSource = chip.getAttribute('data-source');
      
      // Update form context
      const subjectGroup = document.getElementById('subjectGroup');
      if (subjectGroup) {
        subjectGroup.style.display = state.activeSource === 'Email' ? 'block' : 'none';
      }
      const senderInput = document.getElementById('scanSender');
      if (senderInput) {
        senderInput.placeholder = state.activeSource === 'Email' 
          ? 'e.g. security-alert@chase.com' 
          : state.activeSource === 'SMS' 
            ? 'e.g. +1 (800) 555-0199' 
            : 'e.g. +44 7911 123456';
      }
    });
  });

  // Textarea character counter
  const textarea = document.getElementById('scanMessageText');
  const counter = document.getElementById('charCount');
  if (textarea && counter) {
    textarea.addEventListener('input', () => {
      counter.textContent = `${textarea.value.length} chars`;
    });
  }

  // Scanner Form Submit
  const form = document.getElementById('scannerForm');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      executeScan();
    });
  }

  // Clear form button
  const clearBtn = document.getElementById('btnResetScanner');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      resetScanForm();
    });
  }
}

function initPresetButtons() {
  const presetChips = document.querySelectorAll('.preset-chip');
  presetChips.forEach(chip => {
    chip.addEventListener('click', async () => {
      const presetId = chip.getAttribute('data-preset');
      loadPreset(presetId);
    });
  });
}

async function loadPreset(presetId) {
  try {
    const samples = await apiFetch('/api/samples');
    if (!samples) return;
    const sample = samples.find(s => s.id === presetId);
    if (!sample) return;

    // Set source
    const chip = document.querySelector(`.source-chip[data-source="${sample.source}"]`);
    if (chip) chip.click();

    // Populate inputs
    document.getElementById('scanSender').value = sample.sender || '';
    if (document.getElementById('scanSubject')) {
      document.getElementById('scanSubject').value = sample.subject || '';
    }
    document.getElementById('scanUrl').value = sample.link_url || '';
    const textarea = document.getElementById('scanMessageText');
    textarea.value = sample.text || '';
    textarea.dispatchEvent(new Event('input'));

    showToast(`Loaded preset: "${sample.title}"`, 'info');
  } catch (err) {
    console.error(err);
  }
}

function resetScanForm() {
  document.getElementById('scanSender').value = '';
  if (document.getElementById('scanSubject')) {
    document.getElementById('scanSubject').value = '';
  }
  document.getElementById('scanUrl').value = '';
  const textarea = document.getElementById('scanMessageText');
  textarea.value = '';
  textarea.dispatchEvent(new Event('input'));

  // Reset results view
  document.getElementById('resultsEmptyState').style.display = 'flex';
  document.getElementById('resultsContent').style.display = 'none';
  state.lastScanResult = null;
}

async function executeScan() {
  const text = document.getElementById('scanMessageText').value.trim();
  if (!text) {
    showToast('Please enter message text to analyze.', 'error');
    return;
  }

  const sender = document.getElementById('scanSender').value.trim();
  const subject = document.getElementById('scanSubject') ? document.getElementById('scanSubject').value.trim() : '';
  const link_url = document.getElementById('scanUrl').value.trim();
  const source = state.activeSource;

  // UI Scanning State
  const scanBtn = document.getElementById('btnSubmitScan');
  const scanIndicator = document.getElementById('scanningIndicatorBox');
  scanBtn.disabled = true;
  scanBtn.classList.add('scanning');
  scanIndicator.classList.add('active');

  try {
    const payload = {
      message_text: text,
      sender,
      subject,
      link_url,
      source,
      save_to_history: true
    };

    const result = await apiFetch('/api/scan', {
      method: 'POST',
      body: JSON.stringify(payload)
    });

    if (result) {
      state.lastScanResult = result;
      renderScanResults(result, text);
      showToast(`Scan complete: Classified as ${result.verdict}`, result.is_spam ? 'error' : 'success');
      fetchAnalytics(); // Update floating capsule stats in real-time
    }
  } catch (error) {
    showToast('Scan processing failed. Check backend connection.', 'error');
    console.error(error);
  } finally {
    scanBtn.disabled = false;
    scanBtn.classList.remove('scanning');
    scanIndicator.classList.remove('active');
  }
}

// -------------------------------------------------------------
// Render Scan Results & Explainability
// -------------------------------------------------------------
function renderScanResults(data, originalText) {
  document.getElementById('resultsEmptyState').style.display = 'none';
  const content = document.getElementById('resultsContent');
  content.style.display = 'block';

  // 1. Verdict Banner
  const banner = document.getElementById('verdictBanner');
  banner.className = `verdict-hero-banner ${data.is_spam ? 'spam' : 'ham'}`;
  
  const headline = document.getElementById('verdictHeadline');
  headline.textContent = data.verdict;

  const substatus = document.getElementById('verdictSubstatus');
  substatus.textContent = data.risk_label;

  const shieldIcon = document.getElementById('verdictShieldIcon');
  shieldIcon.innerHTML = data.is_spam 
    ? `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`
    : `<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg>`;

  // 2. Circular Gauge Meter
  const gaugeValText = document.getElementById('gaugeRiskScoreText');
  gaugeValText.textContent = `${data.risk_score}%`;
  
  const circle = document.getElementById('gaugeCircleVal');
  const circumference = 2 * Math.PI * 28; // r=28
  const offset = circumference - (data.risk_score / 100) * circumference;
  circle.style.strokeDasharray = `${circumference}`;
  circle.style.strokeDashoffset = `${offset}`;
  circle.style.stroke = data.risk_color;

  // 3. Highlighted Text Viewer
  renderHighlightedText(originalText, data.heuristics.highlight_spans || []);

  // 4. Feature Metrics Pills
  document.getElementById('pillUrgencyCount').textContent = data.heuristics.urgency_count;
  document.getElementById('pillCredCount').textContent = data.heuristics.credential_count;
  document.getElementById('pillFinancialCount').textContent = data.heuristics.financial_count;
  document.getElementById('pillConfidence').textContent = `${data.confidence_pct}%`;

  // 5. Why Was It Detected? (Detection Reasons)
  const reasonsList = document.getElementById('detectionReasonsList');
  reasonsList.innerHTML = '';
  const reasons = data.explainability.detection_reasons || [];
  reasons.forEach(r => {
    const li = document.createElement('li');
    li.className = 'reason-item';
    li.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
      <span>${escapeHtml(r)}</span>
    `;
    reasonsList.appendChild(li);
  });

  // 6. Actionable Safety Recommendations
  const recList = document.getElementById('safetyRecommendationsList');
  recList.innerHTML = '';
  const recs = data.explainability.recommendations || [];
  recs.forEach(rec => {
    const div = document.createElement('div');
    div.className = 'rec-item';
    div.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
      <span>${escapeHtml(rec)}</span>
    `;
    recList.appendChild(div);
  });

  // 7. Preprocessing Pipeline Steps
  renderPipelineSteps(data.preprocessing_pipeline.steps || []);
}

function renderHighlightedText(text, spans) {
  const container = document.getElementById('highlightedTextViewer');
  if (!container) return;

  if (!spans || spans.length === 0) {
    container.textContent = text;
    return;
  }

  // Sort spans ascending by start
  const sortedSpans = [...spans].sort((a, b) => a.start - b.start);
  let html = '';
  let lastIdx = 0;

  for (const span of sortedSpans) {
    if (span.start < lastIdx) continue; // skip overlapping
    html += escapeHtml(text.slice(lastIdx, span.start));
    
    let badgeClass = 'mark-urgency';
    if (span.category === 'credential') badgeClass = 'mark-credential';
    else if (span.category === 'financial') badgeClass = 'mark-financial';
    else if (span.category === 'custom_blacklist') badgeClass = 'mark-blacklist';

    html += `<span class="${badgeClass}" title="${span.category.toUpperCase()} TRIGGER">${escapeHtml(span.match)}</span>`;
    lastIdx = span.end;
  }
  html += escapeHtml(text.slice(lastIdx));
  container.innerHTML = html;
}

function renderPipelineSteps(steps) {
  const container = document.getElementById('pipelineStepsContainer');
  if (!container) return;
  container.innerHTML = '';

  steps.forEach(st => {
    const div = document.createElement('div');
    div.className = 'step-flow-item';
    div.innerHTML = `
      <div class="step-left-info">
        <div class="step-num-badge">${st.step_id}</div>
        <div>
          <div class="step-name">${st.name}</div>
          <div class="step-desc">${st.desc}</div>
        </div>
      </div>
      <div class="step-stat-badge">${st.stats}</div>
    `;
    container.appendChild(div);
  });
}

// -------------------------------------------------------------
// Action Engine Operations
// -------------------------------------------------------------
function copyScanSummary() {
  if (!state.lastScanResult) return;
  const res = state.lastScanResult;
  const summary = `[SpamShield AI Incident Report]
Verdict: ${res.verdict}
Risk Score: ${res.risk_score}% (${res.risk_level})
Model Confidence: ${res.confidence_pct}%
Reasons:
- ${res.explainability.detection_reasons.join('\n- ')}
Recommendations:
- ${res.explainability.recommendations.join('\n- ')}`;

  navigator.clipboard.writeText(summary).then(() => {
    showToast('Incident analysis copied to clipboard.', 'success');
  }).catch(() => {
    showToast('Failed to copy to clipboard.', 'error');
  });
}

async function reportCurrentScan(reportType) {
  if (!state.lastScanResult || !state.lastScanResult.saved_scan_id) {
    showToast('No active scan record to report.', 'error');
    return;
  }
  const scanId = state.lastScanResult.saved_scan_id;
  const res = await apiFetch(`/api/scans/${scanId}/report`, {
    method: 'POST',
    body: JSON.stringify({ report_type: reportType })
  });
  if (res && res.success) {
    showToast(`Report submitted: ${reportType.replace('_', ' ')}`, 'info');
  }
}

// -------------------------------------------------------------
// Scan History Section
// -------------------------------------------------------------
function initHistoryControls() {
  const searchInput = document.getElementById('historySearch');
  if (searchInput) {
    searchInput.addEventListener('input', debounce(() => {
      state.historyFilters.search = searchInput.value;
      fetchHistory();
    }, 300));
  }

  const statusFilter = document.getElementById('historyStatusFilter');
  if (statusFilter) {
    statusFilter.addEventListener('change', () => {
      state.historyFilters.status = statusFilter.value;
      fetchHistory();
    });
  }

  const riskFilter = document.getElementById('historyRiskFilter');
  if (riskFilter) {
    riskFilter.addEventListener('change', () => {
      state.historyFilters.risk = riskFilter.value;
      fetchHistory();
    });
  }

  const sourceFilter = document.getElementById('historySourceFilter');
  if (sourceFilter) {
    sourceFilter.addEventListener('change', () => {
      state.historyFilters.source = sourceFilter.value;
      fetchHistory();
    });
  }

  const btnExportCsv = document.getElementById('btnExportCsv');
  if (btnExportCsv) {
    btnExportCsv.addEventListener('click', exportHistoryCsv);
  }

  const btnExportJson = document.getElementById('btnExportJson');
  if (btnExportJson) {
    btnExportJson.addEventListener('click', exportHistoryJson);
  }
}

async function fetchHistory() {
  const { search, status, risk, source } = state.historyFilters;
  const url = `/api/scans?search=${encodeURIComponent(search)}&status=${status}&risk=${risk}&source=${source}&limit=50`;
  const data = await apiFetch(url);
  if (data && data.scans) {
    state.history = data.scans;
    renderHistoryTable(data.scans);
  }
}

function renderHistoryTable(scans) {
  const tbody = document.getElementById('historyTableBody');
  const countEl = document.getElementById('historyRecordCount');
  if (!tbody) return;

  if (countEl) countEl.textContent = `${scans.length} records`;

  if (scans.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 2.5rem; color: var(--text-dim);">
          No matching scan logs found in history.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = '';
  scans.forEach(s => {
    const tr = document.createElement('tr');
    const isSpam = s.result === 'SPAM';
    const riskBadgeClass = s.risk_level === 'High' ? 'badge-risk-high' : s.risk_level === 'Medium' ? 'badge-risk-med' : 'badge-risk-low';

    tr.innerHTML = `
      <td style="font-family: var(--font-mono); font-size: 0.775rem; color: var(--text-dim); white-space: nowrap;">
        ${s.timestamp}
      </td>
      <td>
        <span class="source-icon-badge">
          ${getSourceIcon(s.source)} ${escapeHtml(s.source)}
        </span>
      </td>
      <td>
        <div style="font-weight: 600; color: #FFFFFF; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${escapeHtml(s.subject || s.sender || 'No Subject')}
        </div>
        <div style="font-size: 0.75rem; color: var(--text-dim); max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          ${escapeHtml(s.snippet)}
        </div>
      </td>
      <td>
        <span class="badge-pill ${isSpam ? 'badge-spam' : 'badge-ham'}">
          ${s.result}
        </span>
      </td>
      <td>
        <span class="badge-pill ${riskBadgeClass}">
          ${s.risk_score}% ${s.risk_level}
        </span>
      </td>
      <td style="font-family: var(--font-mono); font-size: 0.775rem;">
        ${s.confidence_pct}%
      </td>
      <td>
        <div class="table-actions-cell">
          <button class="btn-icon-table" title="Deep Inspect" onclick="inspectScan(${s.id})">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
          </button>
          <button class="btn-icon-table" title="Re-scan" onclick="rescanHistoryItem(${s.id})">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
          </button>
          <button class="btn-icon-table delete" title="Delete Log" onclick="deleteHistoryItem(${s.id})">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function getSourceIcon(source) {
  if (source === 'Email') {
    return `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>`;
  } else if (source === 'SMS') {
    return `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>`;
  }
  return `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"></path></svg>`;
}

async function inspectScan(scanId) {
  const scan = await apiFetch(`/api/scans/${scanId}`);
  if (!scan) return;

  const modal = document.getElementById('inspectModal');
  const detailsBox = document.getElementById('inspectModalContent');

  detailsBox.innerHTML = `
    <div style="margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between;">
      <span class="badge-pill ${scan.result === 'SPAM' ? 'badge-spam' : 'badge-ham'}" style="font-size: 0.9rem;">
        ${scan.result}
      </span>
      <span style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-dim);">${scan.timestamp}</span>
    </div>

    <div style="background: var(--bg-input); padding: 0.85rem; border-radius: var(--radius-md); margin-bottom: 1rem; font-size: 0.85rem;">
      <div><strong>Sender:</strong> ${escapeHtml(scan.sender || 'Unknown')}</div>
      ${scan.subject ? `<div><strong>Subject:</strong> ${escapeHtml(scan.subject)}</div>` : ''}
      <div><strong>Channel:</strong> ${escapeHtml(scan.source)}</div>
      ${scan.link_url ? `<div><strong>URL:</strong> <a href="#" style="color: var(--neon-purple);">${escapeHtml(scan.link_url)}</a></div>` : ''}
    </div>

    <div style="margin-bottom: 1rem;">
      <label style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Message Content</label>
      <div style="background: var(--bg-secondary); padding: 0.85rem; border-radius: var(--radius-md); font-size: 0.85rem; line-height: 1.5; color: #E2E8F0; margin-top: 0.35rem; max-height: 140px; overflow-y: auto;">
        ${escapeHtml(scan.message_text)}
      </div>
    </div>

    <div style="margin-bottom: 1rem;">
      <label style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Detection Reasons</label>
      <ul style="margin-top: 0.35rem; padding-left: 1.25rem; font-size: 0.825rem; color: #CBD5E1;">
        ${scan.detection_reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
      </ul>
    </div>

    <div>
      <label style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Safety Recommendations</label>
      <ul style="margin-top: 0.35rem; padding-left: 1.25rem; font-size: 0.825rem; color: #6EE7B7;">
        ${scan.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
      </ul>
    </div>
  `;

  modal.classList.add('active');
}

function closeInspectModal() {
  const modal = document.getElementById('inspectModal');
  if (modal) modal.classList.remove('active');
}

async function rescanHistoryItem(scanId) {
  const scan = await apiFetch(`/api/scans/${scanId}`);
  if (!scan) return;
  
  // Switch to Scan Message tab
  switchTab('scan');

  // Populate inputs
  document.getElementById('scanSender').value = scan.sender || '';
  if (document.getElementById('scanSubject')) {
    document.getElementById('scanSubject').value = scan.subject || '';
  }
  document.getElementById('scanUrl').value = scan.link_url || '';
  const textarea = document.getElementById('scanMessageText');
  textarea.value = scan.message_text || '';
  textarea.dispatchEvent(new Event('input'));

  // Set active source
  const chip = document.querySelector(`.source-chip[data-source="${scan.source}"]`);
  if (chip) chip.click();

  // Execute scan immediately
  executeScan();
}

async function deleteHistoryItem(scanId) {
  if (!confirm('Are you sure you want to delete this scan record?')) return;
  const res = await apiFetch(`/api/scans/${scanId}`, { method: 'DELETE' });
  if (res && res.success) {
    showToast('Record deleted.', 'info');
    fetchHistory();
  }
}

function exportHistoryCsv() {
  if (!state.history.length) {
    showToast('No history records to export.', 'error');
    return;
  }
  const headers = ['ID', 'Timestamp', 'Source', 'Sender', 'Subject', 'Verdict', 'RiskScore', 'ConfidencePct', 'MessageSnippet'];
  const rows = state.history.map(s => [
    s.id,
    `"${s.timestamp}"`,
    `"${s.source}"`,
    `"${(s.sender || '').replace(/"/g, '""')}"`,
    `"${(s.subject || '').replace(/"/g, '""')}"`,
    s.result,
    s.risk_score,
    s.confidence_pct,
    `"${(s.snippet || '').replace(/"/g, '""')}"`
  ]);

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  downloadBlob(csvContent, 'spamshield_scan_history.csv', 'text/csv');
  showToast('Exported history as CSV.', 'success');
}

function exportHistoryJson() {
  if (!state.history.length) {
    showToast('No history records to export.', 'error');
    return;
  }
  const jsonContent = JSON.stringify(state.history, null, 2);
  downloadBlob(jsonContent, 'spamshield_scan_history.json', 'application/json');
  showToast('Exported history as JSON.', 'success');
}

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// -------------------------------------------------------------
// Security Analytics Dashboard & Canvas Charts
// -------------------------------------------------------------
async function fetchAnalytics() {
  const data = await apiFetch('/api/analytics');
  if (data) {
    state.analytics = data;
    renderAnalyticsKPIs(data);
    renderCharts(data);
  }
}

function renderAnalyticsKPIs(data) {
  // Update floating capsule stats container (Bottom visual container)
  const capTotal = document.getElementById('capsuleTotalScans');
  const capSpam = document.getElementById('capsuleSpamPct');
  const capHam = document.getElementById('capsuleHamPct');
  const capRisk = document.getElementById('capsuleHighRisk');
  const capConf = document.getElementById('capsuleConfidence');

  if (capTotal) capTotal.textContent = data.total_scans;
  if (capSpam) capSpam.textContent = `${data.spam_percentage}%`;
  if (capHam) capHam.textContent = `${data.ham_percentage}%`;
  if (capRisk) capRisk.textContent = data.high_risk_count;
  if (capConf) capConf.textContent = `${data.avg_confidence}%`;

  // Top KPI metrics in Analytics tab if present
  const kpiTotal = document.getElementById('kpiTotalScans');
  const kpiSpam = document.getElementById('kpiSpamPct');
  const kpiHam = document.getElementById('kpiHamPct');
  const kpiRisk = document.getElementById('kpiHighRisk');
  const kpiConf = document.getElementById('kpiAvgConf');

  if (kpiTotal) kpiTotal.textContent = data.total_scans;
  if (kpiSpam) kpiSpam.textContent = `${data.spam_percentage}%`;
  if (kpiHam) kpiHam.textContent = `${data.ham_percentage}%`;
  if (kpiRisk) kpiRisk.textContent = data.high_risk_count;
  if (kpiConf) kpiConf.textContent = `${data.avg_confidence}%`;
}

function renderCharts(data) {
  renderTimelineChart(data.timeline_trends || []);
  renderRiskDonutChart(data.high_risk_count, data.medium_risk_count, data.low_risk_count);
  renderThreatCategoriesBar(data.threat_categories || {});
  renderSourceChannelsChart(data.source_breakdown || {});
  renderTopKeywordsList(data.top_keywords || []);
}

function renderTimelineChart(trends) {
  const canvas = document.getElementById('timelineChartCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.parentElement.clientWidth || 550;
  const h = canvas.height = 240;

  ctx.clearRect(0, 0, w, h);
  if (!trends.length) return;

  const padding = { top: 30, right: 30, bottom: 40, left: 45 };
  const chartW = w - padding.left - padding.right;
  const chartH = h - padding.top - padding.bottom;

  // Find max value
  const maxVal = Math.max(...trends.map(t => Math.max(t.spam, t.ham, t.total)), 5);

  // Draw grid lines
  ctx.strokeStyle = 'rgba(70, 95, 133, 0.25)';
  ctx.lineWidth = 1;
  const gridLines = 4;
  for (let i = 0; i <= gridLines; i++) {
    const y = padding.top + (chartH / gridLines) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(w - padding.right, y);
    ctx.stroke();

    const val = Math.round(maxVal - (maxVal / gridLines) * i);
    ctx.fillStyle = '#94A3B8';
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(val, padding.left - 8, y + 3);
  }

  // Draw X axis labels
  const step = chartW / (trends.length - 1 || 1);
  trends.forEach((t, i) => {
    const x = padding.left + i * step;
    ctx.fillStyle = '#94A3B8';
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'center';
    const label = t.date ? t.date.slice(5) : `D${i+1}`;
    ctx.fillText(label, x, h - 12);
  });

  // Helper to draw a line series
  function drawSeries(key, strokeColor, fillColor) {
    ctx.beginPath();
    trends.forEach((t, i) => {
      const x = padding.left + i * step;
      const y = padding.top + chartH - (t[key] / maxVal) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });

    if (fillColor) {
      ctx.lineTo(padding.left + (trends.length - 1) * step, padding.top + chartH);
      ctx.lineTo(padding.left, padding.top + chartH);
      ctx.closePath();
      ctx.fillStyle = fillColor;
      ctx.fill();
    }

    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Draw dots
    trends.forEach((t, i) => {
      const x = padding.left + i * step;
      const y = padding.top + chartH - (t[key] / maxVal) * chartH;
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = strokeColor;
      ctx.fill();
      ctx.strokeStyle = '#0D1B2A';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });
  }

  // Draw Spam Line (Red) and Ham Line (Neon Lime Green)
  drawSeries('spam', '#EF4444', 'rgba(239, 68, 68, 0.15)');
  drawSeries('ham', '#22C55E', 'rgba(34, 197, 94, 0.15)');
}

function renderRiskDonutChart(high, med, low) {
  const canvas = document.getElementById('riskDonutCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.parentElement.clientWidth || 320;
  const h = canvas.height = 240;

  ctx.clearRect(0, 0, w, h);

  const total = high + med + low;
  if (total === 0) return;

  const cx = w / 2;
  const cy = h / 2 - 10;
  const radius = 68;
  const innerRadius = 45;

  const data = [
    { label: 'High', value: high, color: '#EF4444' },
    { label: 'Medium', value: med, color: '#F59E0B' },
    { label: 'Low', value: low, color: '#22C55E' }
  ];

  let startAngle = -Math.PI / 2;
  data.forEach(item => {
    const sliceAngle = (item.value / total) * 2 * Math.PI;
    const endAngle = startAngle + sliceAngle;

    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, endAngle);
    ctx.arc(cx, cy, innerRadius, endAngle, startAngle, true);
    ctx.closePath();
    ctx.fillStyle = item.color;
    ctx.fill();

    startAngle = endAngle;
  });

  // Center text
  ctx.fillStyle = '#FFFFFF';
  ctx.font = '700 16px JetBrains Mono, monospace';
  ctx.textAlign = 'center';
  ctx.fillText(total, cx, cy + 2);
  ctx.fillStyle = '#94A3B8';
  ctx.font = '10px Inter, sans-serif';
  ctx.fillText('SCANS', cx, cy + 18);
}

function renderThreatCategoriesBar(categories) {
  const container = document.getElementById('threatCategoriesBarContainer');
  if (!container) return;
  container.innerHTML = '';

  const entries = Object.entries(categories);
  const max = Math.max(...entries.map(e => e[1]), 1);

  entries.forEach(([name, count]) => {
    const pct = Math.round((count / max) * 100);
    const row = document.createElement('div');
    row.style.marginBottom = '0.75rem';
    row.innerHTML = `
      <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 0.25rem;">
        <span style="color: #E2E8F0;">${escapeHtml(name)}</span>
        <span style="font-family: var(--font-mono); color: var(--neon-lime-bright);">${count} hits</span>
      </div>
      <div style="background: rgba(255, 255, 255, 0.06); height: 8px; border-radius: 4px; overflow: hidden;">
        <div style="width: ${pct}%; height: 100%; background: linear-gradient(90deg, var(--sky-blue), var(--neon-lime)); border-radius: 4px; box-shadow: 0 0 10px rgba(34, 197, 94, 0.35);"></div>
      </div>
    `;
    container.appendChild(row);
  });
}

function renderSourceChannelsChart(sources) {
  const container = document.getElementById('sourceChannelsContainer');
  if (!container) return;
  container.innerHTML = '';

  const total = Object.values(sources).reduce((a, b) => a + b, 0) || 1;
  const icons = {
    'Email': '✉️',
    'SMS': '💬',
    'WhatsApp': '📱'
  };

  Object.entries(sources).forEach(([src, count]) => {
    const pct = Math.round((count / total) * 100);
    const item = document.createElement('div');
    item.className = 'feature-pill-card';
    item.innerHTML = `
      <div style="font-size: 1.25rem; margin-bottom: 0.25rem;">${icons[src] || '📨'}</div>
      <div class="feature-pill-val">${pct}%</div>
      <div class="feature-pill-lbl">${escapeHtml(src)} (${count})</div>
    `;
    container.appendChild(item);
  });
}

function renderTopKeywordsList(keywords) {
  const container = document.getElementById('topKeywordsContainer');
  if (!container) return;
  container.innerHTML = '';

  if (!keywords.length) {
    container.innerHTML = `<div style="color: var(--text-dim); font-size: 0.85rem;">No spam keywords recorded yet.</div>`;
    return;
  }

  keywords.forEach(kw => {
    const badge = document.createElement('span');
    badge.className = 'tag-chip blacklist';
    badge.innerHTML = `<span>${escapeHtml(kw.keyword)}</span><strong style="color: #FFFFFF; margin-left: 0.25rem;">×${kw.count}</strong>`;
    container.appendChild(badge);
  });
}

// -------------------------------------------------------------
// Safety Hub & Threat Simulator Quiz
// -------------------------------------------------------------
function initSimulator() {
  loadSimulatorQuestion();
}

function loadSimulatorQuestion() {
  const q = state.simulator.questions[state.simulator.currentIndex];
  state.simulator.answered = false;

  const countBadge = document.getElementById('simCounterBadge');
  if (countBadge) {
    countBadge.textContent = `Scenario ${state.simulator.currentIndex + 1} of ${state.simulator.questions.length}`;
  }

  document.getElementById('simSender').textContent = q.sender;
  document.getElementById('simSubject').textContent = q.subject;
  document.getElementById('simSource').textContent = q.source;
  document.getElementById('simBody').textContent = q.body;

  const feedback = document.getElementById('simFeedback');
  feedback.className = 'sim-feedback-box';
  feedback.style.display = 'none';

  // Re-enable choice buttons
  document.querySelectorAll('.btn-sim-choice').forEach(b => b.disabled = false);
}

function answerSimulator(userGuessSpam) {
  if (state.simulator.answered) return;
  state.simulator.answered = true;

  const q = state.simulator.questions[state.simulator.currentIndex];
  const isCorrect = userGuessSpam === q.isSpam;

  if (isCorrect) state.simulator.score++;

  const feedback = document.getElementById('simFeedback');
  feedback.style.display = 'block';

  if (isCorrect) {
    feedback.style.background = 'rgba(16, 185, 129, 0.15)';
    feedback.style.border = '1px solid var(--safe-green)';
    feedback.style.color = '#6EE7B7';
    feedback.innerHTML = `<strong>Correct Analysis!</strong> ${escapeHtml(q.reason)}`;
  } else {
    feedback.style.background = 'rgba(239, 68, 68, 0.15)';
    feedback.style.border = '1px solid var(--alert-red)';
    feedback.style.color = '#FCA5A5';
    feedback.innerHTML = `<strong>Incorrect.</strong> ${escapeHtml(q.reason)}`;
  }

  document.querySelectorAll('.btn-sim-choice').forEach(b => b.disabled = true);

  // Next question button
  const nextBtn = document.getElementById('btnNextSim');
  if (nextBtn) {
    nextBtn.style.display = 'inline-flex';
    nextBtn.onclick = () => {
      state.simulator.currentIndex = (state.simulator.currentIndex + 1) % state.simulator.questions.length;
      nextBtn.style.display = 'none';
      loadSimulatorQuestion();
    };
  }
}

// -------------------------------------------------------------
// Settings Management
// -------------------------------------------------------------
function initSettingsControls() {
  const highSlider = document.getElementById('sliderThresholdHigh');
  const highVal = document.getElementById('valThresholdHigh');
  if (highSlider && highVal) {
    highSlider.addEventListener('input', () => {
      highVal.textContent = `${highSlider.value}%`;
    });
  }

  const medSlider = document.getElementById('sliderThresholdMed');
  const medVal = document.getElementById('valThresholdMed');
  if (medSlider && medVal) {
    medSlider.addEventListener('input', () => {
      medVal.textContent = `${medSlider.value}%`;
    });
  }

  const btnSaveSettings = document.getElementById('btnSaveSettings');
  if (btnSaveSettings) {
    btnSaveSettings.addEventListener('click', saveCurrentSettings);
  }

  const btnResetDb = document.getElementById('btnResetDatabase');
  if (btnResetDb) {
    btnResetDb.addEventListener('click', resetDatabase);
  }
}

async function fetchSettings() {
  const data = await apiFetch('/api/settings');
  if (data) {
    state.settings = data;
    document.getElementById('sliderThresholdHigh').value = data.threshold_high;
    document.getElementById('valThresholdHigh').textContent = `${data.threshold_high}%`;
    document.getElementById('sliderThresholdMed').value = data.threshold_med;
    document.getElementById('valThresholdMed').textContent = `${data.threshold_med}%`;
    document.getElementById('settingActiveModel').value = data.active_model;

    renderKeywordTags('blacklistTagsBox', data.custom_blacklist, 'blacklist');
    renderKeywordTags('whitelistTagsBox', data.custom_whitelist, 'whitelist');
  }
}

function renderKeywordTags(containerId, list, type) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';

  list.forEach((word, idx) => {
    const chip = document.createElement('span');
    chip.className = `tag-chip ${type}`;
    chip.innerHTML = `
      <span>${escapeHtml(word)}</span>
      <span class="tag-chip-remove" onclick="removeKeywordTag('${type}', ${idx})">×</span>
    `;
    container.appendChild(chip);
  });
}

function addKeywordTag(type) {
  const inputId = type === 'blacklist' ? 'inputAddBlacklist' : 'inputAddWhitelist';
  const input = document.getElementById(inputId);
  if (!input) return;
  const word = input.value.trim().toLowerCase();
  if (!word) return;

  const list = type === 'blacklist' ? state.settings.custom_blacklist : state.settings.custom_whitelist;
  if (!list.includes(word)) {
    list.push(word);
    renderKeywordTags(type === 'blacklist' ? 'blacklistTagsBox' : 'whitelistTagsBox', list, type);
    input.value = '';
  }
}

function removeKeywordTag(type, idx) {
  const list = type === 'blacklist' ? state.settings.custom_blacklist : state.settings.custom_whitelist;
  list.splice(idx, 1);
  renderKeywordTags(type === 'blacklist' ? 'blacklistTagsBox' : 'whitelistTagsBox', list, type);
}

async function saveCurrentSettings() {
  const threshold_high = parseInt(document.getElementById('sliderThresholdHigh').value);
  const threshold_med = parseInt(document.getElementById('sliderThresholdMed').value);
  const active_model = document.getElementById('settingActiveModel').value;

  const payload = {
    threshold_high,
    threshold_med,
    active_model,
    custom_blacklist: state.settings.custom_blacklist,
    custom_whitelist: state.settings.custom_whitelist
  };

  const res = await apiFetch('/api/settings', {
    method: 'PUT',
    body: JSON.stringify(payload)
  });

  if (res && res.success) {
    showToast('Security thresholds and keyword policies updated.', 'success');
  }
}

async function resetDatabase() {
  if (!confirm('This will purge current scan logs and restore realistic historical baseline data. Proceed?')) return;
  const res = await apiFetch('/api/settings/reset', { method: 'POST' });
  if (res && res.success) {
    showToast('Database reset and seeded with initial baseline logs.', 'info');
    fetchHistory();
    fetchAnalytics();
  }
}

// -------------------------------------------------------------
// Utilities & Toast Notifications
// -------------------------------------------------------------
async function apiFetch(endpoint, options = {}) {
  try {
    const defaultHeaders = { 'Content-Type': 'application/json' };
    const res = await fetch(endpoint, {
      ...options,
      headers: { ...defaultHeaders, ...(options.headers || {}) }
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'API Error' }));
      throw new Error(err.detail || 'Server responded with an error');
    }
    return await res.json();
  } catch (err) {
    console.error('API Fetch error:', err);
    throw err;
  }
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  let icon = `ℹ️`;
  if (type === 'success') icon = `✅`;
  if (type === 'error') icon = `⚠️`;

  toast.innerHTML = `<span>${icon}</span><span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(20px)';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function debounce(func, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => func(...args), delay);
  };
}

async function loadInitialData() {
  try {
    await fetchHistory();
    await fetchSettings();
    await fetchAnalytics(); // Load capsule stats immediately
  } catch (e) {
    console.error('Failed to load initial data:', e);
  }
}
