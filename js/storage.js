/**
 * PhishGuard - Local Storage & Data Persistence Module
 * 
 * Manages scan records, statistics, user preferences, and CSV exports using localStorage.
 * Note: localStorage is client-side only and subject to browser cache clearing.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.StorageManager = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const STORAGE_KEYS = {
    HISTORY: 'phishguard_scan_history',
    THEME: 'phishguard_user_theme',
    SETTINGS: 'phishguard_app_settings'
  };

  // Realistic sample demonstration scans loaded on first launch
  const DEMO_HISTORY = [
    {
      id: 'demo-1',
      url: 'https://chase.com/personal/banking',
      score: 0,
      verdict: 'SAFE',
      riskLevel: 'Low Risk',
      timestamp: new Date(Date.now() - 3600000 * 2).toISOString(),
      summary: 'Legitimate financial institution portal using verified HTTPS and proper standard domain hierarchy.',
      recommendation: 'Safe to proceed under normal caution.',
      isDemo: true,
      checksCount: { passed: 14, warnings: 0, failed: 0 }
    },
    {
      id: 'demo-2',
      url: 'https://secure-login.paypa1-security-verification.xyz/signin?account=resolve',
      score: 88,
      verdict: 'PHISHING',
      riskLevel: 'High Risk',
      timestamp: new Date(Date.now() - 3600000 * 5).toISOString(),
      summary: 'Targeted brand spoofing of PayPal via typosquatting ("paypa1"), suspicious TLD (.xyz), and multiple credential-theft keywords.',
      recommendation: 'DO NOT CLICK or enter credentials. Immediate high-confidence phishing threat.',
      isDemo: true,
      checksCount: { passed: 6, warnings: 2, failed: 6 }
    },
    {
      id: 'demo-3',
      url: 'https://bit.ly/3xY8a9Q',
      score: 30,
      verdict: 'SUSPICIOUS',
      riskLevel: 'Medium Risk',
      timestamp: new Date(Date.now() - 3600000 * 12).toISOString(),
      summary: 'URL shortening service detected. True destination is obscured until opened.',
      recommendation: 'Expand and inspect destination using an unshortening preview tool before clicking.',
      isDemo: true,
      checksCount: { passed: 13, warnings: 1, failed: 0 }
    },
    {
      id: 'demo-4',
      url: 'http://192.168.1.105:8080/portal/update-credentials.php',
      score: 82,
      verdict: 'PHISHING',
      riskLevel: 'High Risk',
      timestamp: new Date(Date.now() - 3600000 * 22).toISOString(),
      summary: 'Raw IP address host combined with unencrypted HTTP, non-standard port 8080, and credential-harvesting tokens.',
      recommendation: 'Do not access or submit passwords over unencrypted IP endpoints.',
      isDemo: true,
      checksCount: { passed: 8, warnings: 1, failed: 5 }
    },
    {
      id: 'demo-5',
      url: 'https://github.com/security/advisories',
      score: 0,
      verdict: 'SAFE',
      riskLevel: 'Low Risk',
      timestamp: new Date(Date.now() - 3600000 * 30).toISOString(),
      summary: 'Legitimate developer platform advisory repository. Valid SSL certificate and clean URL syntax.',
      recommendation: 'Safe to proceed under standard caution.',
      isDemo: true,
      checksCount: { passed: 14, warnings: 0, failed: 0 }
    },
    {
      id: 'demo-6',
      url: 'https://accounts-google.security-challenge-resolution.top/auth',
      score: 75,
      verdict: 'PHISHING',
      riskLevel: 'High Risk',
      timestamp: new Date(Date.now() - 3600000 * 48).toISOString(),
      summary: 'Brand impersonation of Google Accounts hosted on high-abuse TLD (.top) with misleading subdomain structure.',
      recommendation: 'Phishing domain attempting to capture Google workspace credentials.',
      isDemo: true,
      checksCount: { passed: 8, warnings: 2, failed: 4 }
    },
    {
      id: 'demo-7',
      url: 'http://news-update-weekly.com/articles/2026/brief',
      score: 32,
      verdict: 'SUSPICIOUS',
      riskLevel: 'Medium Risk',
      timestamp: new Date(Date.now() - 3600000 * 60).toISOString(),
      summary: 'Unencrypted HTTP protocol with hyphenated news aggregation domain.',
      recommendation: 'Read-only content is acceptable, but never transmit confidential information.',
      isDemo: true,
      checksCount: { passed: 12, warnings: 2, failed: 0 }
    }
  ];

  let inMemoryHistory = [...DEMO_HISTORY];
  let inMemoryTheme = 'dark';

  class StorageManager {
    /**
     * Initialize storage and load demo data if history is empty
     */
    static init() {
      try {
        const existing = localStorage.getItem(STORAGE_KEYS.HISTORY);
        if (!existing) {
          this.saveHistory(DEMO_HISTORY);
        } else {
          inMemoryHistory = JSON.parse(existing);
        }
      } catch (err) {
        console.warn('localStorage is restricted or disabled; operating with in-memory persistence:', err);
      }
    }

    /**
     * Retrieve all scan records
     */
    static getHistory() {
      try {
        const raw = localStorage.getItem(STORAGE_KEYS.HISTORY);
        if (raw) return JSON.parse(raw);
      } catch (err) {
        // Fallback to in-memory store
      }
      return inMemoryHistory;
    }

    /**
     * Save full history array
     */
    static saveHistory(historyList) {
      inMemoryHistory = historyList;
      try {
        localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(historyList));
        return true;
      } catch (err) {
        return false;
      }
    }

    /**
     * Add a newly completed scan result
     */
    static addScan(scanResult) {
      const history = this.getHistory();
      const record = {
        id: 'scan-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6),
        url: scanResult.url,
        score: scanResult.score,
        verdict: scanResult.verdict,
        riskLevel: scanResult.riskLevel,
        timestamp: scanResult.timestamp || new Date().toISOString(),
        summary: scanResult.summary,
        recommendation: scanResult.recommendation,
        checks: scanResult.checks,
        suspiciousPatterns: scanResult.suspiciousPatterns,
        parsed: scanResult.parsed,
        isDemo: false,
        checksCount: {
          passed: scanResult.checks ? scanResult.checks.filter(c => c.status === 'pass').length : 0,
          warnings: scanResult.checks ? scanResult.checks.filter(c => c.status === 'warn').length : 0,
          failed: scanResult.checks ? scanResult.checks.filter(c => c.status === 'fail').length : 0
        }
      };

      // Keep at top of history (max 200 items)
      history.unshift(record);
      if (history.length > 200) {
        history.pop();
      }

      this.saveHistory(history);
      return record;
    }

    /**
     * Delete an individual scan record by ID
     */
    static deleteScan(id) {
      const history = this.getHistory();
      const filtered = history.filter(item => item.id !== id);
      this.saveHistory(filtered);
      return filtered;
    }

    /**
     * Clear all scans
     */
    static clearAllHistory() {
      this.saveHistory([]);
      return [];
    }

    /**
     * Reset to the original sample demo data
     */
    static resetDemoData() {
      this.saveHistory(DEMO_HISTORY);
      return DEMO_HISTORY;
    }

    /**
     * Calculate summary statistics across stored records
     */
    static getStatistics() {
      const history = this.getHistory();
      const total = history.length;
      let safe = 0;
      let suspicious = 0;
      let phishing = 0;

      history.forEach(item => {
        if (item.verdict === 'SAFE') safe++;
        else if (item.verdict === 'SUSPICIOUS') suspicious++;
        else if (item.verdict === 'PHISHING') phishing++;
      });

      const avgScore = total > 0 
        ? Math.round(history.reduce((acc, curr) => acc + (curr.score || 0), 0) / total) 
        : 0;

      return {
        total,
        safe,
        suspicious,
        phishing,
        avgScore,
        safePercent: total > 0 ? Math.round((safe / total) * 100) : 0,
        suspiciousPercent: total > 0 ? Math.round((suspicious / total) * 100) : 0,
        phishingPercent: total > 0 ? Math.round((phishing / total) * 100) : 0
      };
    }

    /**
     * Export history as formatted CSV file
     */
    static exportToCsv() {
      const history = this.getHistory();
      if (!history || history.length === 0) {
        throw new Error('No scan history available to export.');
      }

      const headers = ['ID', 'Scan Date (UTC)', 'URL', 'Verdict', 'Risk Score', 'Risk Level', 'Summary', 'Patterns Detected'];
      const rows = history.map(item => {
        const patterns = (item.suspiciousPatterns || []).join('; ');
        const cleanSummary = (item.summary || '').replace(/"/g, '""');
        const cleanUrl = (item.url || '').replace(/"/g, '""');
        return [
          `"${item.id}"`,
          `"${item.timestamp}"`,
          `"${cleanUrl}"`,
          `"${item.verdict}"`,
          item.score,
          `"${item.riskLevel}"`,
          `"${cleanSummary}"`,
          `"${patterns.replace(/"/g, '""')}"`
        ].join(',');
      });

      const csvContent = [headers.join(','), ...rows].join('\r\n');
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', `phishguard_scans_${new Date().toISOString().slice(0, 10)}.csv`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    }

    /**
     * Theme management
     */
    static getTheme() {
      try {
        return localStorage.getItem(STORAGE_KEYS.THEME) || inMemoryTheme;
      } catch (err) {
        return inMemoryTheme;
      }
    }

    static setTheme(theme) {
      inMemoryTheme = theme;
      try {
        localStorage.setItem(STORAGE_KEYS.THEME, theme);
      } catch (err) {}
    }
  }

  return StorageManager;
}));

