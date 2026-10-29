
/**
 * PhishGuard - Charts Controller Module
 * 
 * Configures and updates Chart.js charts for security distribution and scan activity.
 * Supports dynamic theme switching (Dark & Light) and responsive resizing.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ChartManager = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  let distributionChart = null;
  let activityChart = null;

  class ChartManager {
    /**
     * Get theme-aware styling parameters
     */
    static getThemeColors() {
      const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
      return {
        textColor: isDark ? '#94a3b8' : '#475569',
        gridColor: isDark ? 'rgba(255, 255, 255, 0.06)' : 'rgba(0, 0, 0, 0.06)',
        tooltipBg: isDark ? 'rgba(15, 23, 42, 0.95)' : 'rgba(255, 255, 255, 0.95)',
        tooltipBorder: isDark ? 'rgba(56, 189, 248, 0.3)' : 'rgba(14, 165, 233, 0.4)',
        tooltipText: isDark ? '#f8fafc' : '#0f172a',
        safeColor: '#10b981',
        suspiciousColor: '#f59e0b',
        phishingColor: '#ef4444'
      };
    }

    /**
     * Initialize or update the Security Distribution Donut Chart
     */
    static renderDistributionChart(canvasId, stats) {
      const ctx = document.getElementById(canvasId);
      if (!ctx || typeof Chart === 'undefined') return;

      try {
        const colors = this.getThemeColors();
        const dataValues = [stats.safe, stats.suspicious, stats.phishing];
        const hasData = stats.total > 0;

        if (distributionChart) {
          distributionChart.destroy();
        }

        distributionChart = new Chart(ctx, {
          type: 'doughnut',
          data: {
            labels: ['Safe', 'Suspicious', 'Phishing'],
            datasets: [{
              data: hasData ? dataValues : [1, 0, 0],
              backgroundColor: hasData 
                ? [colors.safeColor, colors.suspiciousColor, colors.phishingColor]
                : [isDark() ? '#334155' : '#e2e8f0'],
              borderColor: isDark() ? '#0f172a' : '#ffffff',
              borderWidth: 3,
              hoverOffset: 6
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: {
              legend: {
                position: 'bottom',
                labels: {
                  color: colors.textColor,
                  font: { family: 'Inter, sans-serif', size: 12, weight: '500' },
                  padding: 18,
                  usePointStyle: true,
                  pointStyle: 'circle'
                }
              },
              tooltip: {
                backgroundColor: colors.tooltipBg,
                borderColor: colors.tooltipBorder,
                borderWidth: 1,
                titleColor: colors.tooltipText,
                bodyColor: colors.tooltipText,
                padding: 12,
                boxPadding: 6,
                usePointStyle: true,
                callbacks: {
                  label: function (context) {
                    if (!hasData) return ' No scans recorded yet';
                    const value = context.raw || 0;
                    const total = stats.total || 1;
                    const pct = Math.round((value / total) * 100);
                    return ` ${context.label}: ${value} (${pct}%)`;
                  }
                }
              }
            },
            animation: {
              animateScale: true,
              animateRotate: true,
              duration: 900
            }
          }
        });
      } catch (err) {
        console.warn('Distribution chart render deferred:', err);
      }
    }

    /**
     * Initialize or update Recent Scan Activity Timeline Chart
     */
    static renderActivityChart(canvasId, history) {
      const ctx = document.getElementById(canvasId);
      if (!ctx || typeof Chart === 'undefined') return;

      try {
        const colors = this.getThemeColors();
        
        // Aggregate scans by last 7 days or chronologically
        const scans = [...history].reverse().slice(-10); // last 10 scans
        const labels = scans.map((item, index) => {
          const d = new Date(item.timestamp);
          return isNaN(d.getTime()) ? `Scan #${index + 1}` : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        });

        const scores = scans.map(item => item.score);
        const pointColors = scans.map(item => {
          if (item.verdict === 'SAFE') return colors.safeColor;
          if (item.verdict === 'SUSPICIOUS') return colors.suspiciousColor;
          return colors.phishingColor;
        });

        if (activityChart) {
          activityChart.destroy();
        }

        const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 260);
        gradient.addColorStop(0, 'rgba(56, 189, 248, 0.35)');
        gradient.addColorStop(1, 'rgba(56, 189, 248, 0.01)');

        activityChart = new Chart(ctx, {
          type: 'line',
          data: {
            labels: labels.length > 0 ? labels : ['No Data'],
            datasets: [{
              label: 'Risk Score (0 - 100)',
              data: scores.length > 0 ? scores : [0],
              borderColor: '#38bdf8',
              borderWidth: 2.5,
              pointBackgroundColor: pointColors.length > 0 ? pointColors : '#38bdf8',
              pointBorderColor: isDark() ? '#0f172a' : '#ffffff',
              borderWidth: 2,
              pointRadius: 5,
              pointHoverRadius: 7,
              tension: 0.35,
              fill: true,
              backgroundColor: gradient
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              y: {
                min: 0,
                max: 100,
                grid: { color: colors.gridColor },
                ticks: {
                  color: colors.textColor,
                  font: { family: 'Inter, sans-serif', size: 11 },
                  stepSize: 25
                }
              },
              x: {
                grid: { display: false },
                ticks: {
                  color: colors.textColor,
                  font: { family: 'Inter, sans-serif', size: 11 },
                  maxRotation: 45
                }
              }
            },
            plugins: {
              legend: { display: false },
              tooltip: {
                backgroundColor: colors.tooltipBg,
                borderColor: colors.tooltipBorder,
                borderWidth: 1,
                titleColor: colors.tooltipText,
                bodyColor: colors.tooltipText,
                padding: 12,
                callbacks: {
                  title: function(items) {
                    const idx = items[0].dataIndex;
                    return scans[idx] ? `URL: ${scans[idx].url.slice(0, 35)}...` : '';
                  },
                  label: function (context) {
                    const idx = context.dataIndex;
                    const item = scans[idx];
                    if (!item) return 'Risk Score: 0';
                    return `Verdict: ${item.verdict} | Risk Score: ${item.score}/100`;
                  }
                }
              }
            }
          }
        });
      } catch (err) {
        console.warn('Activity chart render deferred:', err);
      }
    }

    /**
     * Refresh charts on theme switch
     */
    static refreshTheme(stats, history) {
      this.renderDistributionChart('distributionChart', stats);
      this.renderActivityChart('activityChart', history);
    }
  }

  function isDark() {
    return document.documentElement.getAttribute('data-theme') !== 'light';
  }

  return ChartManager;
}));

