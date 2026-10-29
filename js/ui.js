/**
 * PhishGuard - UI Components & DOM Controller
 * 
 * Manages toast notifications, animated circular gauge, modals, and safe HTML rendering.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.UIManager = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  class UIManager {
    /**
     * Strictly sanitize any user-controlled string to prevent XSS
     */
    static escapeHTML(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    /**
     * Display a floating toast notification
     */
    static showToast(message, type = 'info', title = '') {
      const container = document.getElementById('toastContainer');
      if (!container) return;

      const toast = document.createElement('div');
      toast.className = `toast toast-${type}`;

      let iconName = 'info';
      if (type === 'success') iconName = 'check-circle-2';
      if (type === 'warning') iconName = 'alert-triangle';
      if (type === 'error') iconName = 'alert-octagon';

      toast.innerHTML = `
        <div class="toast-icon">
          <i data-lucide="${iconName}"></i>
        </div>
        <div class="toast-content">
          ${title ? `<div class="toast-title">${this.escapeHTML(title)}</div>` : ''}
          <div class="toast-message">${this.escapeHTML(message)}</div>
        </div>
        <button class="toast-close" aria-label="Close notification">&times;</button>
      `;

      container.appendChild(toast);
      if (window.lucide) {
        window.lucide.createIcons({ root: toast });
      }

      // Close handler
      const closeBtn = toast.querySelector('.toast-close');
      closeBtn.addEventListener('click', () => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 250);
      });

      // Auto dismiss after 4 seconds
      setTimeout(() => {
        if (toast.parentElement) {
          toast.classList.add('fade-out');
          setTimeout(() => toast.remove(), 250);
        }
      }, 4200);
    }

    /**
     * Animate Circular Risk Gauge SVG
     */
    static updateRiskGauge(score, verdict) {
      const circle = document.getElementById('gaugeProgressCircle');
      const text = document.getElementById('gaugeScoreText');
      const badge = document.getElementById('gaugeVerdictBadge');

      if (!circle || !text) return;

      const radius = 54;
      const circumference = 2 * Math.PI * radius; // ~339.29
      circle.style.strokeDasharray = `${circumference}`;

      // Calculate offset (100% score = 0 offset, 0% score = full offset)
      const offset = circumference - (score / 100) * circumference;
      
      // Determine color palette based on verdict / score
      let color = '#10b981'; // Green (Safe)
      let glow = 'rgba(16, 185, 129, 0.4)';
      let badgeClass = 'badge-safe';

      if (score >= 60) {
        color = '#ef4444'; // Red (Phishing)
        glow = 'rgba(239, 68, 68, 0.45)';
        badgeClass = 'badge-phishing';
      } else if (score >= 30) {
        color = '#f59e0b'; // Amber (Suspicious)
        glow = 'rgba(245, 158, 11, 0.4)';
        badgeClass = 'badge-suspicious';
      }

      circle.style.stroke = color;
      circle.style.filter = `drop-shadow(0 0 8px ${glow})`;
      circle.style.strokeDashoffset = offset;

      // Animate score number counter
      let current = 0;
      const duration = 600;
      const stepTime = 15;
      const steps = duration / stepTime;
      const increment = score / steps;

      const timer = setInterval(() => {
        current += increment;
        if (current >= score) {
          current = score;
          clearInterval(timer);
        }
        text.textContent = Math.round(current);
      }, stepTime);

      if (badge) {
        badge.className = `verdict-badge ${badgeClass}`;
        badge.textContent = verdict;
      }
    }

    /**
     * Show Modal
     */
    static showModal(modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.classList.add('active');
        document.body.style.overflow = 'hidden';
      }
    }

    /**
     * Hide Modal
     */
    static hideModal(modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.classList.remove('active');
        document.body.style.overflow = '';
      }
    }

    /**
     * Copy text to clipboard with fallback and toast confirmation
     */
    static copyToClipboard(text, successMsg = 'Copied to clipboard!') {
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
          .then(() => {
            this.showToast(successMsg, 'success');
          })
          .catch(() => {
            this.fallbackCopyText(text, successMsg);
          });
      } else {
        this.fallbackCopyText(text, successMsg);
      }
    }

    static fallbackCopyText(text, successMsg) {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      textArea.style.top = '-999999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      try {
        document.execCommand('copy');
        this.showToast(successMsg, 'success');
      } catch (err) {
        this.showToast('Unable to copy automatically. Please copy manually.', 'warning');
      }
      document.body.removeChild(textArea);
    }
  }

  return UIManager;
}));

