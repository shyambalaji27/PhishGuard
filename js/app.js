/**
 * PhishGuard - Main Application Controller
 * 
 * Coordinates navigation, user input, scanning workflow, history filtering,
 * modal dialogs, and dynamic page state updates.
 */

document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  // Core state
  let currentScanResult = null;
  let activePage = 'overview';
  let historySearchTerm = '';
  let historyVerdictFilter = 'all';
  let historySortBy = 'date-desc';

  // Initialize data persistence
  StorageManager.init();

  // Initialize theme from storage
  const savedTheme = StorageManager.getTheme();
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeToggleButtons(savedTheme);

  // Initialize UI & Icons
  initLucideIcons();
  setupNavigation();
  setupThemeToggle();
  setupScannerEvents();
  setupHistoryEvents();
  setupSettingsEvents();
  setupModalEvents();

  // Initial dashboard render
  updateDashboardOverview();
  renderHistoryTable();

  // ----------------------------------------------------
  // Navigation & Page Switching
  // ----------------------------------------------------
  function setupNavigation() {
    const navLinks = document.querySelectorAll('[data-page-target]');
    navLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const target = link.getAttribute('data-page-target');
        navigateTo(target);

        // Close mobile sidebar if open
        const sidebar = document.getElementById('sidebar');
        if (sidebar && sidebar.classList.contains('mobile-open')) {
          sidebar.classList.remove('mobile-open');
        }
      });
    });

    // Mobile hamburger menu toggle
    const mobileMenuBtn = document.getElementById('mobileMenuToggle');
    const sidebar = document.getElementById('sidebar');
    if (mobileMenuBtn && sidebar) {
      mobileMenuBtn.addEventListener('click', () => {
        sidebar.classList.toggle('mobile-open');
      });
    }

    // Quick action buttons (e.g., from overview hero banner)
    const quickScanBtns = document.querySelectorAll('.action-quick-scan');
    quickScanBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        navigateTo('scanner');
        const input = document.getElementById('urlInput');
        if (input) input.focus();
      });
    });

    // Hash change routing support
    window.addEventListener('hashchange', () => {
      const hash = window.location.hash.replace('#', '');
      if (hash && document.getElementById(`page-${hash}`)) {
        navigateTo(hash, false);
      }
    });

    // Initial hash routing check
    const initialHash = window.location.hash.replace('#', '');
    if (initialHash && document.getElementById(`page-${initialHash}`)) {
      navigateTo(initialHash, false);
    }
  }

  function navigateTo(pageId, updateHash = true) {
    activePage = pageId;
    if (updateHash && window.location.hash.replace('#', '') !== pageId) {
      window.location.hash = pageId;
    }

    // Update active nav links
    document.querySelectorAll('[data-page-target]').forEach(link => {
      if (link.getAttribute('data-page-target') === pageId) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Update active page view
    document.querySelectorAll('.page-view').forEach(view => {
      if (view.id === `page-${pageId}`) {
        view.classList.add('active');
      } else {
        view.classList.remove('active');
      }
    });

    // Page-specific refreshes
    if (pageId === 'overview') {
      updateDashboardOverview();
    } else if (pageId === 'history') {
      renderHistoryTable();
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
    initLucideIcons();
  }

  // ----------------------------------------------------
  // Theme Switching
  // ----------------------------------------------------
  function setupThemeToggle() {
    const toggleBtns = document.querySelectorAll('.theme-toggle-btn');
    toggleBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme') || 'dark';
        const nextTheme = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', nextTheme);
        StorageManager.setTheme(nextTheme);
        updateThemeToggleButtons(nextTheme);

        // Refresh charts for theme contrast
        const stats = StorageManager.getStatistics();
        const history = StorageManager.getHistory();
        ChartManager.refreshTheme(stats, history);
        initLucideIcons();
      });
    });
  }

  function updateThemeToggleButtons(theme) {
    const isLight = theme === 'light';
    const icons = document.querySelectorAll('.theme-toggle-icon');
    icons.forEach(icon => {
      icon.setAttribute('data-lucide', isLight ? 'moon' : 'sun');
    });
    initLucideIcons();
  }

  // ----------------------------------------------------
  // Dashboard Overview Metrics & Charts
  // ----------------------------------------------------
  function updateDashboardOverview() {
    const stats = StorageManager.getStatistics();
    const history = StorageManager.getHistory();

    // Summary Metric Cards
    setElementText('statTotalScans', stats.total);
    setElementText('statSafeScans', stats.safe);
    setElementText('statSuspiciousScans', stats.suspicious);
    setElementText('statPhishingScans', stats.phishing);

    // Percentage pills
    setElementText('statSafePct', `${stats.safePercent}%`);
    setElementText('statSuspiciousPct', `${stats.suspiciousPercent}%`);
    setElementText('statPhishingPct', `${stats.phishingPercent}%`);

    // Render Charts
    ChartManager.renderDistributionChart('distributionChart', stats);
    ChartManager.renderActivityChart('activityChart', history);

    // Recent Scans Table in Dashboard
    renderRecentDashboardTable(history.slice(0, 5));
  }

  function renderRecentDashboardTable(recentScans) {
    const container = document.getElementById('recentScansTableBody');
    if (!container) return;

    if (!recentScans || recentScans.length === 0) {
      container.innerHTML = `
        <tr>
          <td colspan="5" class="empty-state-cell">
            <div class="empty-state">
              <i data-lucide="shield-alert"></i>
              <p>No recent scans available. Submit your first URL to begin.</p>
            </div>
          </td>
        </tr>
      `;
      initLucideIcons();
      return;
    }

    container.innerHTML = recentScans.map(scan => {
      const badgeClass = getVerdictBadgeClass(scan.verdict);
      const timeStr = formatRelativeTime(scan.timestamp);
      const cleanUrl = UIManager.escapeHTML(scan.url);
      const isDemoBadge = scan.isDemo ? '<span class="badge-tag-demo" title="Sample evaluation record">Sample</span>' : '';

      return `
        <tr>
          <td>
            <div class="url-cell" title="${cleanUrl}">
              <i data-lucide="${scan.url.startsWith('https') ? 'lock' : 'unlock'}" class="url-protocol-icon"></i>
              <span class="url-text">${cleanUrl}</span>
              ${isDemoBadge}
            </div>
          </td>
          <td>
            <span class="verdict-badge ${badgeClass}">${scan.verdict}</span>
          </td>
          <td>
            <div class="score-progress-wrap">
              <div class="score-progress-bar">
                <div class="score-progress-fill ${badgeClass}" style="width: ${scan.score}%"></div>
              </div>
              <span class="score-value">${scan.score}</span>
            </div>
          </td>
          <td class="timestamp-cell">${timeStr}</td>
          <td class="action-cell">
            <button class="btn-table-action btn-inspect-scan" data-scan-id="${scan.id}" title="Inspect full diagnostic">
              <i data-lucide="external-link"></i>
            </button>
          </td>
        </tr>
      `;
    }).join('');

    // Bind inspect buttons
    container.querySelectorAll('.btn-inspect-scan').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-scan-id');
        openScanDetailModal(id);
      });
    });

    initLucideIcons();
  }

  // ----------------------------------------------------
  // Scanner Engine & User Interactions
  // ----------------------------------------------------
  function setupScannerEvents() {
    const scanBtn = document.getElementById('scanBtn');
    const urlInput = document.getElementById('urlInput');
    const pasteBtn = document.getElementById('pasteUrlBtn');
    const clearBtn = document.getElementById('clearUrlBtn');
    const examplePills = document.querySelectorAll('.example-url-pill');

    // Trigger scan on button click
    if (scanBtn) {
      scanBtn.addEventListener('click', handleScanExecution);
    }

    // Trigger scan on Enter key
    if (urlInput) {
      urlInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          handleScanExecution();
        }
      });
    }

    // Paste button
    if (pasteBtn && urlInput) {
      pasteBtn.addEventListener('click', async () => {
        try {
          if (navigator.clipboard && navigator.clipboard.readText) {
            const text = await navigator.clipboard.readText();
            urlInput.value = text.trim();
            UIManager.showToast('URL pasted from clipboard', 'info');
          } else {
            UIManager.showToast('Clipboard access not permitted by browser.', 'warning');
          }
        } catch (err) {
          UIManager.showToast('Please paste manually using Ctrl+V.', 'info');
        }
      });
    }

    // Clear input button
    if (clearBtn && urlInput) {
      clearBtn.addEventListener('click', () => {
        urlInput.value = '';
        urlInput.focus();
        document.getElementById('scanResultPanel').classList.add('hidden');
      });
    }

    // Quick example URL pills
    examplePills.forEach(pill => {
      pill.addEventListener('click', () => {
        const exampleUrl = pill.getAttribute('data-example-url');
        if (urlInput && exampleUrl) {
          urlInput.value = exampleUrl;
          handleScanExecution();
        }
      });
    });

    // Copy report button
    const copyReportBtn = document.getElementById('copyReportBtn');
    if (copyReportBtn) {
      copyReportBtn.addEventListener('click', () => {
        if (!currentScanResult) return;
        const reportText = generateReportMarkdown(currentScanResult);
        UIManager.copyToClipboard(reportText, 'Security report copied to clipboard!');
      });
    }

    // Scan another URL button
    const scanAnotherBtn = document.getElementById('scanAnotherBtn');
    if (scanAnotherBtn && urlInput) {
      scanAnotherBtn.addEventListener('click', () => {
        document.getElementById('scanResultPanel').classList.add('hidden');
        urlInput.value = '';
        urlInput.focus();
        window.scrollTo({ top: 120, behavior: 'smooth' });
      });
    }

    // Export single scan JSON
    const exportJsonBtn = document.getElementById('exportJsonBtn');
    if (exportJsonBtn) {
      exportJsonBtn.addEventListener('click', () => {
        if (!currentScanResult) return;
        const jsonStr = JSON.stringify(currentScanResult, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `phishguard_scan_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
      });
    }
  }

  /**
   * Main scan execution workflow with animated progress simulation
   */
  async function handleScanExecution() {
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const loadingState = document.getElementById('scannerLoadingState');
    const resultPanel = document.getElementById('scanResultPanel');
    const scanStepText = document.getElementById('scanProgressStepText');

    if (!urlInput) return;
    const rawUrl = urlInput.value.trim();

    if (!rawUrl) {
      UIManager.showToast('Please enter or paste a URL to analyze.', 'warning');
      urlInput.focus();
      return;
    }

    // Hide result while scanning
    resultPanel.classList.add('hidden');
    scanBtn.disabled = true;
    loadingState.classList.remove('hidden');

    const steps = [
      'Normalizing syntax & protocol verification...',
      'Inspecting hostname, subdomains & DGA entropy...',
      'Checking typosquatting & brand impersonation heuristics...',
      'Evaluating URL shorteners, encodings & open redirects...',
      'Computing transparent risk coefficients...'
    ];

    try {
      // Micro-step animation for realistic cyber diagnostic feel (~750ms total)
      for (let i = 0; i < steps.length; i++) {
        if (scanStepText) scanStepText.textContent = steps[i];
        await delay(150);
      }

      // Execute Heuristic Analysis
      const analysis = URLAnalyzer.analyze(rawUrl);
      currentScanResult = analysis;

      // Save into persistence safely
      try {
        StorageManager.addScan(analysis);
      } catch (storageErr) {
        console.warn('Storage persistence deferred:', storageErr);
      }

      // Render Results
      renderScanResults(analysis);

      // Refresh overview metrics safely without blocking result display
      try {
        updateDashboardOverview();
      } catch (overviewErr) {
        console.warn('Overview refresh deferred:', overviewErr);
      }

      // Smooth scroll to result
      resultPanel.classList.remove('hidden');
      resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      UIManager.showToast(`Analysis complete: ${analysis.verdict} (${analysis.score}/100)`, getToastTypeForVerdict(analysis.verdict));

    } catch (err) {
      console.error('Scan execution error:', err);
      const isSyntaxErr = err.message && (
        err.message.includes('URL') || 
        err.message.includes('hostname') || 
        err.message.includes('scheme') ||
        err.message.includes('Incomplete') ||
        err.message.includes('Malformed')
      );
      UIManager.showToast(err.message || 'An error occurred during analysis.', 'error', isSyntaxErr ? 'Invalid URL' : 'Scan Notice');
    } finally {
      scanBtn.disabled = false;
      loadingState.classList.add('hidden');
      initLucideIcons();
    }
  }

  /**
   * Populate Result Panel with Diagnostic Details
   */
  function renderScanResults(data) {
    const cleanUrl = UIManager.escapeHTML(data.url);
    const cleanSummary = UIManager.escapeHTML(data.summary);
    const cleanRec = UIManager.escapeHTML(data.recommendation);

    setElementText('resultDisplayUrl', cleanUrl);
    setElementText('resultRiskLevelText', data.riskLevel);
    setElementText('resultSummaryText', cleanSummary);
    setElementText('resultRecommendationText', cleanRec);
    setElementText('resultTimestamp', new Date(data.timestamp).toLocaleString());

    // Update circular SVG gauge
    UIManager.updateRiskGauge(data.score, data.verdict);

    // Suspicious pattern chips
    const patternContainer = document.getElementById('resultPatternChips');
    if (patternContainer) {
      if (data.suspiciousPatterns && data.suspiciousPatterns.length > 0) {
        patternContainer.innerHTML = data.suspiciousPatterns.map(p => {
          return `<span class="pattern-chip"><i data-lucide="alert-circle"></i> ${UIManager.escapeHTML(p)}</span>`;
        }).join('');
      } else {
        patternContainer.innerHTML = `<span class="pattern-chip pattern-chip-clean"><i data-lucide="check-check"></i> No suspicious structural anomalies detected</span>`;
      }
    }

    // Checks Breakdown List
    const checksList = document.getElementById('resultChecksList');
    if (checksList) {
      checksList.innerHTML = data.checks.map(c => {
        let icon = 'check-circle';
        let badgeClass = 'check-pass';
        let badgeLabel = 'PASSED';

        if (c.status === 'fail') {
          icon = 'x-circle';
          badgeClass = 'check-fail';
          badgeLabel = `FAILED (+${c.points} pts)`;
        } else if (c.status === 'warn') {
          icon = 'alert-triangle';
          badgeClass = 'check-warn';
          badgeLabel = `WARNING (+${c.points} pts)`;
        }

        return `
          <div class="check-item ${badgeClass}">
            <div class="check-header">
              <div class="check-title-group">
                <i data-lucide="${icon}" class="check-icon"></i>
                <span class="check-name">${UIManager.escapeHTML(c.name)}</span>
                <span class="check-category">${UIManager.escapeHTML(c.category)}</span>
              </div>
              <span class="check-badge ${badgeClass}">${badgeLabel}</span>
            </div>
            <p class="check-desc">${UIManager.escapeHTML(c.explanation)}</p>
            <div class="check-meta">${UIManager.escapeHTML(c.details)}</div>
          </div>
        `;
      }).join('');
    }

    // Optional Threat Intelligence Backend Proxy Check
    checkThreatIntelBackend(data.url);

    initLucideIcons();
  }

  /**
   * Optional check against local threat intelligence proxy (Section 9)
   */
  async function checkThreatIntelBackend(targetUrl) {
    const block = document.getElementById('resultThreatIntelBlock');
    const body = document.getElementById('resultThreatIntelBody');
    if (!block || !body) return;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 600);

      const statusRes = await fetch('http://127.0.0.1:8765/api/status', {
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!statusRes.ok) {
        block.classList.add('hidden');
        return;
      }

      const statusData = await statusRes.json();
      const checkRes = await fetch('http://127.0.0.1:8765/api/check-threat-intel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      });

      if (checkRes.ok) {
        const intel = await checkRes.json();
        const gsb = intel.reputation_services?.google_safe_browsing;
        const vt = intel.reputation_services?.virustotal;

        let html = '';
        if (gsb && gsb.checked) {
          const color = gsb.status === 'MALICIOUS' ? 'var(--color-danger)' : 'var(--color-safe)';
          html += `<div><strong>Google Safe Browsing:</strong> <span style="color:${color}; font-weight:700;">${UIManager.escapeHTML(gsb.status)}</span> — ${UIManager.escapeHTML(gsb.details)}</div>`;
        }
        if (vt && vt.checked) {
          html += `<div style="margin-top: 0.35rem;"><strong>VirusTotal Community:</strong> ${UIManager.escapeHTML(vt.details || vt.status)}</div>`;
        }
        if (!html) {
          html = `<div>Proxy connected in <em>${UIManager.escapeHTML(statusData.mode)}</em> mode. (Heuristic analysis active; configure API keys in <code>proxy_server.py</code> for live cloud feeds).</div>`;
        }

        body.innerHTML = html;
        block.classList.remove('hidden');
        initLucideIcons();
      }
    } catch (e) {
      block.classList.add('hidden');
    }
  }

  // ----------------------------------------------------
  // Scan History Management, Filtering, Sorting & CSV
  // ----------------------------------------------------
  function setupHistoryEvents() {
    const searchInput = document.getElementById('historySearchInput');
    const filterSelect = document.getElementById('historyVerdictFilter');
    const sortSelect = document.getElementById('historySortSelect');
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    const clearHistoryBtn = document.getElementById('clearHistoryBtn');

    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        historySearchTerm = e.target.value.toLowerCase().trim();
        renderHistoryTable();
      });
    }

    if (filterSelect) {
      filterSelect.addEventListener('change', (e) => {
        historyVerdictFilter = e.target.value;
        renderHistoryTable();
      });
    }

    if (sortSelect) {
      sortSelect.addEventListener('change', (e) => {
        historySortBy = e.target.value;
        renderHistoryTable();
      });
    }

    if (exportCsvBtn) {
      exportCsvBtn.addEventListener('click', () => {
        try {
          StorageManager.exportToCsv();
          UIManager.showToast('CSV export downloaded successfully', 'success');
        } catch (err) {
          UIManager.showToast(err.message, 'warning');
        }
      });
    }

    if (clearHistoryBtn) {
      clearHistoryBtn.addEventListener('click', () => {
        UIManager.showModal('modalConfirmClear');
      });
    }
  }

  function renderHistoryTable() {
    const container = document.getElementById('historyTableBody');
    const counterBadge = document.getElementById('historyTotalCount');
    if (!container) return;

    let items = StorageManager.getHistory();

    if (counterBadge) {
      counterBadge.textContent = `${items.length} records`;
    }

    // Apply Search Filter
    if (historySearchTerm) {
      items = items.filter(item => {
        return (item.url && item.url.toLowerCase().includes(historySearchTerm)) ||
               (item.summary && item.summary.toLowerCase().includes(historySearchTerm));
      });
    }

    // Apply Verdict Filter
    if (historyVerdictFilter !== 'all') {
      items = items.filter(item => item.verdict.toLowerCase() === historyVerdictFilter.toLowerCase());
    }

    // Apply Sorting
    items.sort((a, b) => {
      const dateA = new Date(a.timestamp).getTime();
      const dateB = new Date(b.timestamp).getTime();
      const scoreA = a.score || 0;
      const scoreB = b.score || 0;

      if (historySortBy === 'date-desc') return dateB - dateA;
      if (historySortBy === 'date-asc') return dateA - dateB;
      if (historySortBy === 'score-desc') return scoreB - scoreA;
      if (historySortBy === 'score-asc') return scoreA - scoreB;
      return 0;
    });

    if (items.length === 0) {
      container.innerHTML = `
        <tr>
          <td colspan="6" class="empty-state-cell">
            <div class="empty-state">
              <i data-lucide="search-x"></i>
              <p>No scan records match your filter criteria.</p>
            </div>
          </td>
        </tr>
      `;
      initLucideIcons();
      return;
    }

    container.innerHTML = items.map(scan => {
      const badgeClass = getVerdictBadgeClass(scan.verdict);
      const cleanUrl = UIManager.escapeHTML(scan.url);
      const isDemoBadge = scan.isDemo ? '<span class="badge-tag-demo">Sample</span>' : '';

      return `
        <tr>
          <td>
            <div class="url-cell" title="${cleanUrl}">
              <i data-lucide="${scan.url.startsWith('https') ? 'lock' : 'unlock'}" class="url-protocol-icon"></i>
              <span class="url-text">${cleanUrl}</span>
              ${isDemoBadge}
            </div>
          </td>
          <td>
            <span class="verdict-badge ${badgeClass}">${scan.verdict}</span>
          </td>
          <td>
            <div class="score-progress-wrap">
              <div class="score-progress-bar">
                <div class="score-progress-fill ${badgeClass}" style="width: ${scan.score}%"></div>
              </div>
              <span class="score-value">${scan.score}</span>
            </div>
          </td>
          <td class="timestamp-cell">${new Date(scan.timestamp).toLocaleString()}</td>
          <td class="action-cell">
            <div class="table-actions-group">
              <button class="btn-table-action btn-inspect-scan" data-scan-id="${scan.id}" title="View details">
                <i data-lucide="eye"></i>
              </button>
              <button class="btn-table-action btn-delete-scan" data-scan-id="${scan.id}" title="Delete record">
                <i data-lucide="trash-2"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Bind item action listeners
    container.querySelectorAll('.btn-inspect-scan').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-scan-id');
        openScanDetailModal(id);
      });
    });

    container.querySelectorAll('.btn-delete-scan').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-scan-id');
        StorageManager.deleteScan(id);
        renderHistoryTable();
        updateDashboardOverview();
        UIManager.showToast('Scan record deleted', 'info');
      });
    });

    initLucideIcons();
  }

  // ----------------------------------------------------
  // Modals & Details Inspector
  // ----------------------------------------------------
  function setupModalEvents() {
    // Generic modal close buttons
    document.querySelectorAll('.modal-close, [data-modal-dismiss]').forEach(btn => {
      btn.addEventListener('click', () => {
        const modal = btn.closest('.modal-backdrop');
        if (modal) {
          modal.classList.remove('active');
          document.body.style.overflow = '';
        }
      });
    });

    // Close on backdrop click
    document.querySelectorAll('.modal-backdrop').forEach(modal => {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.classList.remove('active');
          document.body.style.overflow = '';
        }
      });
    });

    // Confirm Clear All History modal action
    const confirmClearBtn = document.getElementById('btnConfirmClearAll');
    if (confirmClearBtn) {
      confirmClearBtn.addEventListener('click', () => {
        StorageManager.clearAllHistory();
        UIManager.hideModal('modalConfirmClear');
        renderHistoryTable();
        updateDashboardOverview();
        UIManager.showToast('All scan records have been cleared.', 'info');
      });
    }
  }

  function openScanDetailModal(scanId) {
    const history = StorageManager.getHistory();
    const item = history.find(s => s.id === scanId);
    if (!item) return;

    const modal = document.getElementById('modalScanDetail');
    if (!modal) return;

    setElementText('modalDetailUrl', item.url);
    setElementText('modalDetailVerdict', item.verdict);
    setElementText('modalDetailScore', `${item.score}/100 (${item.riskLevel})`);
    setElementText('modalDetailTimestamp', new Date(item.timestamp).toUTCString());
    setElementText('modalDetailSummary', item.summary);
    setElementText('modalDetailRecommendation', item.recommendation);

    const badge = document.getElementById('modalDetailVerdictBadge');
    if (badge) {
      badge.className = `verdict-badge ${getVerdictBadgeClass(item.verdict)}`;
      badge.textContent = item.verdict;
    }

    const patternsContainer = document.getElementById('modalDetailPatterns');
    if (patternsContainer) {
      if (item.suspiciousPatterns && item.suspiciousPatterns.length > 0) {
        patternsContainer.innerHTML = item.suspiciousPatterns.map(p => {
          return `<span class="pattern-chip"><i data-lucide="alert-circle"></i> ${UIManager.escapeHTML(p)}</span>`;
        }).join('');
      } else {
        patternsContainer.innerHTML = `<span class="pattern-chip pattern-chip-clean"><i data-lucide="check-check"></i> No suspicious signals flagged</span>`;
      }
    }

    const copyBtn = document.getElementById('modalCopyReportBtn');
    if (copyBtn) {
      copyBtn.onclick = () => {
        const text = generateReportMarkdown(item);
        UIManager.copyToClipboard(text, 'Scan report copied!');
      };
    }

    UIManager.showModal('modalScanDetail');
    initLucideIcons();
  }

  // ----------------------------------------------------
  // Settings Page Handlers
  // ----------------------------------------------------
  function setupSettingsEvents() {
    const resetDemoBtn = document.getElementById('btnResetDemoData');
    if (resetDemoBtn) {
      resetDemoBtn.addEventListener('click', () => {
        StorageManager.resetDemoData();
        updateDashboardOverview();
        renderHistoryTable();
        UIManager.showToast('Demo dataset has been restored.', 'success');
      });
    }

    const wipeDataBtn = document.getElementById('btnWipeAllData');
    if (wipeDataBtn) {
      wipeDataBtn.addEventListener('click', () => {
        UIManager.showModal('modalConfirmClear');
      });
    }
  }

  // ----------------------------------------------------
  // Utility Helpers
  // ----------------------------------------------------
  function setElementText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function getVerdictBadgeClass(verdict) {
    if (verdict === 'SAFE') return 'badge-safe';
    if (verdict === 'SUSPICIOUS') return 'badge-suspicious';
    return 'badge-phishing';
  }

  function getToastTypeForVerdict(verdict) {
    if (verdict === 'SAFE') return 'success';
    if (verdict === 'SUSPICIOUS') return 'warning';
    return 'error';
  }

  function formatRelativeTime(isoString) {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return 'Recently';

    const diffSec = Math.floor((Date.now() - date.getTime()) / 1000);
    if (diffSec < 60) return 'Just now';
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
  }

  function generateReportMarkdown(data) {
    return [
      `# PhishGuard Security Diagnostic Report`,
      `**Evaluated URL:** ${data.url}`,
      `**Verdict:** ${data.verdict} (${data.score}/100 - ${data.riskLevel})`,
      `**Timestamp:** ${new Date(data.timestamp).toUTCString()}`,
      ``,
      `### Executive Summary`,
      `${data.summary}`,
      ``,
      `### Recommended Action`,
      `${data.recommendation}`,
      ``,
      `### Identified Risk Patterns`,
      data.suspiciousPatterns && data.suspiciousPatterns.length > 0 
        ? data.suspiciousPatterns.map(p => `- ${p}`).join('\n')
        : `- None detected`,
      ``,
      `*Disclaimer: PhishGuard generates heuristic risk indicators for security awareness and education. It does not provide absolute guarantees of safety.*`
    ].join('\n');
  }

  function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  function initLucideIcons() {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }
  }
});
