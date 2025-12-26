/**
 * Recent CVEs Template Module
 *
 * Generates HTML and JavaScript for the Recent CVEs tab with:
 * - Collapsible groups (by severity, vendor, week)
 * - Shadow DOM for performance isolation
 * - Client-side filtering
 */

import type { RecentCveData, CveGroup } from './types.js';

/**
 * Generate the Recent CVEs tab content (initially just a loading placeholder)
 * Actual content is lazy-loaded via JavaScript
 */
export function generateRecentTabHtml(): string {
  return `
    <div id="recent-content" class="tab-content" style="display: none;">
      <div id="recent-loading" class="loading-placeholder">
        <p>Loading recent CVEs...</p>
      </div>
      <div id="recent-loaded" style="display: none;">
        <div class="recent-header">
          <div class="recent-summary" id="recent-summary"></div>
          <div class="group-controls">
            <label>Group by:</label>
            <select id="group-select">
              <option value="severity" selected>Severity</option>
              <option value="vendor">Vendor</option>
              <option value="week">Week</option>
            </select>
          </div>
          <div class="filter-controls">
            <label>
              <input type="checkbox" id="filter-no-patch" />
              No patch available
            </label>
            <label>
              <input type="checkbox" id="filter-in-kev" />
              In KEV catalog
            </label>
          </div>
        </div>
        <div id="recent-groups"></div>
      </div>
    </div>
  `;
}

/**
 * Generate CSS for the Recent CVEs tab
 */
export function generateRecentCss(): string {
  return `
    /* Recent CVEs Tab Styles */
    .recent-header {
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      align-items: center;
      margin-bottom: 1rem;
      padding: 1rem;
      background: #f8f9fa;
      border-radius: 8px;
    }

    .recent-summary {
      flex: 1;
      min-width: 300px;
    }

    .recent-summary .stat-row {
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .recent-summary .stat {
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.875rem;
    }

    .recent-summary .stat.critical { background: #ffeef0; color: #9b2c2c; }
    .recent-summary .stat.high { background: #fff5eb; color: #c05621; }
    .recent-summary .stat.medium { background: #fefcbf; color: #975a16; }
    .recent-summary .stat.low { background: #e6fffa; color: #276749; }
    .recent-summary .stat.in-kev { background: #e2e8f0; color: #2d3748; }

    .group-controls, .filter-controls {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .filter-controls label {
      display: flex;
      align-items: center;
      gap: 0.25rem;
      font-size: 0.875rem;
      cursor: pointer;
    }

    #group-select {
      padding: 0.375rem 0.75rem;
      border: 1px solid #cbd5e0;
      border-radius: 4px;
      background: white;
    }

    .loading-placeholder {
      text-align: center;
      padding: 3rem;
      color: #718096;
    }

    /* CVE Group Styles */
    .cve-group {
      margin-bottom: 0.5rem;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      overflow: hidden;
    }

    .cve-group.hidden {
      display: none;
    }

    .group-header {
      width: 100%;
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.75rem 1rem;
      background: #f7fafc;
      border: none;
      cursor: pointer;
      text-align: left;
      font-size: 1rem;
      transition: background 0.15s;
    }

    .group-header:hover {
      background: #edf2f7;
    }

    .group-header .chevron {
      transition: transform 0.2s;
      color: #718096;
    }

    .cve-group.expanded .group-header .chevron {
      transform: rotate(90deg);
    }

    .group-header .severity-badge {
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }

    .severity-badge.critical { background: #fed7d7; color: #9b2c2c; }
    .severity-badge.high { background: #feebc8; color: #c05621; }
    .severity-badge.medium { background: #fefcbf; color: #975a16; }
    .severity-badge.low { background: #c6f6d5; color: #276749; }
    .severity-badge.none { background: #e2e8f0; color: #4a5568; }

    .group-header .label {
      flex: 1;
      font-weight: 500;
    }

    .group-header .count {
      color: #718096;
      font-size: 0.875rem;
    }

    .group-content {
      display: none;
      border-top: 1px solid #e2e8f0;
    }

    .cve-group.expanded .group-content {
      display: block;
    }

    /* Shadow DOM Table Styles (injected into shadow root) */
  `;
}

/**
 * Generate the shadow DOM styles for CVE tables
 */
function getShadowStyles(): string {
  return `
    <style>
      :host {
        display: block;
      }

      table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.875rem;
      }

      th, td {
        padding: 0.5rem 0.75rem;
        text-align: left;
        border-bottom: 1px solid #e2e8f0;
      }

      th {
        background: #f7fafc;
        font-weight: 600;
        color: #4a5568;
        position: sticky;
        top: 0;
      }

      tr:hover {
        background: #f7fafc;
      }

      .cve-id {
        font-family: monospace;
        font-weight: 500;
      }

      .cve-id a {
        color: #3182ce;
        text-decoration: none;
      }

      .cve-id a:hover {
        text-decoration: underline;
      }

      .severity {
        display: inline-block;
        padding: 0.125rem 0.375rem;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
      }

      .severity.critical { background: #fed7d7; color: #9b2c2c; }
      .severity.high { background: #feebc8; color: #c05621; }
      .severity.medium { background: #fefcbf; color: #975a16; }
      .severity.low { background: #c6f6d5; color: #276749; }
      .severity.none { background: #e2e8f0; color: #4a5568; }

      .badge {
        display: inline-block;
        padding: 0.125rem 0.375rem;
        border-radius: 4px;
        font-size: 0.625rem;
        font-weight: 600;
        text-transform: uppercase;
        margin-left: 0.25rem;
      }

      .badge.kev {
        background: #c53030;
        color: white;
      }

      .badge.patch {
        background: #38a169;
        color: white;
      }

      .description {
        max-width: 400px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .vendor-product {
        color: #4a5568;
      }

      .date {
        color: #718096;
        font-size: 0.8125rem;
      }
    </style>
  `;
}

/**
 * Generate JavaScript for the Recent CVEs tab functionality
 */
export function generateRecentJs(): string {
  const shadowStyles = getShadowStyles().replace(/`/g, '\\`').replace(/\$/g, '\\$');

  return `
    // Recent CVEs Tab JavaScript
    (function() {
      let recentData = null;
      let currentGrouping = 'severity';
      let filters = { noPatch: false, inKev: false };

      // Lazy load recent.json when tab is clicked
      window.loadRecentCves = async function() {
        if (recentData) {
          document.getElementById('recent-loading').style.display = 'none';
          document.getElementById('recent-loaded').style.display = 'block';
          return;
        }

        try {
          const response = await fetch('recent.json');
          recentData = await response.json();
          renderRecentCves();
        } catch (err) {
          document.getElementById('recent-loading').innerHTML =
            '<p style="color: #c53030;">Failed to load recent CVEs. Please try again.</p>';
          console.error('Failed to load recent.json:', err);
        }
      };

      function renderRecentCves() {
        document.getElementById('recent-loading').style.display = 'none';
        document.getElementById('recent-loaded').style.display = 'block';

        // Render summary
        const summary = recentData.summary;
        document.getElementById('recent-summary').innerHTML = \`
          <div class="stat-row">
            <span class="stat critical">Critical: \${summary.critical}</span>
            <span class="stat high">High: \${summary.high}</span>
            <span class="stat medium">Medium: \${summary.medium}</span>
            <span class="stat low">Low: \${summary.low}</span>
            <span class="stat in-kev">In KEV: \${summary.in_kev}</span>
          </div>
          <div style="margin-top: 0.5rem; font-size: 0.875rem; color: #718096;">
            \${recentData.total.toLocaleString()} CVEs from \${recentData.date_range.start} to \${recentData.date_range.end}
          </div>
        \`;

        renderGroups();
      }

      function renderGroups() {
        const container = document.getElementById('recent-groups');
        let groups;

        switch (currentGrouping) {
          case 'vendor':
            groups = recentData.by_vendor;
            break;
          case 'week':
            groups = recentData.by_week;
            break;
          default:
            groups = recentData.by_severity;
        }

        container.innerHTML = groups.map(group => {
          const filteredCves = filterCves(group.cves);
          const isHidden = filteredCves.length === 0;
          const severityClass = currentGrouping === 'severity' ? group.key : '';

          return \`
            <div class="cve-group\${isHidden ? ' hidden' : ''}" data-key="\${group.key}">
              <button class="group-header" onclick="toggleGroup(this)">
                <span class="chevron">▶</span>
                \${severityClass ? \`<span class="severity-badge \${severityClass}">\${group.label}</span>\` : \`<span class="label">\${group.label}</span>\`}
                <span class="count">\${filteredCves.length} CVEs</span>
              </button>
              <div class="group-content" data-cves='\${JSON.stringify(filteredCves)}'></div>
            </div>
          \`;
        }).join('');
      }

      function filterCves(cves) {
        return cves.filter(cve => {
          if (filters.noPatch && cve.has_patch) return false;
          if (filters.inKev && !cve.is_in_kev) return false;
          return true;
        });
      }

      window.toggleGroup = function(button) {
        const group = button.closest('.cve-group');
        const isExpanded = group.classList.contains('expanded');

        if (isExpanded) {
          group.classList.remove('expanded');
        } else {
          group.classList.add('expanded');

          // Render table in shadow DOM if not already done
          const content = group.querySelector('.group-content');
          if (!content.shadowRoot) {
            const cves = JSON.parse(content.dataset.cves);
            const shadow = content.attachShadow({ mode: 'open' });
            shadow.innerHTML = \`${shadowStyles}\` + renderCveTable(cves);
          }
        }
      };

      function renderCveTable(cves) {
        if (cves.length === 0) {
          return '<p style="padding: 1rem; color: #718096;">No CVEs match the current filters.</p>';
        }

        const rows = cves.map(cve => {
          const severityClass = (cve.cvss_severity || 'none').toLowerCase();
          const badges = [];
          if (cve.is_in_kev) badges.push('<span class="badge kev">KEV</span>');
          if (cve.has_patch) badges.push('<span class="badge patch">Patch</span>');

          return \`
            <tr>
              <td class="cve-id">
                <a href="https://nvd.nist.gov/vuln/detail/\${cve.cve_id}" target="_blank" rel="noopener">\${cve.cve_id}</a>
                \${badges.join('')}
              </td>
              <td>
                <span class="severity \${severityClass}">\${cve.cvss_severity || 'N/A'}</span>
                \${cve.cvss_score !== null ? \` (\${cve.cvss_score})\` : ''}
              </td>
              <td class="vendor-product">\${escapeHtml(cve.vendor)} / \${escapeHtml(cve.product)}</td>
              <td class="date">\${cve.published}</td>
              <td class="description" title="\${escapeHtml(cve.description)}">\${escapeHtml(cve.description)}</td>
            </tr>
          \`;
        }).join('');

        return \`
          <table>
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Severity</th>
                <th>Vendor / Product</th>
                <th>Published</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>\${rows}</tbody>
          </table>
        \`;
      }

      function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;')
                  .replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;')
                  .replace(/"/g, '&quot;');
      }

      // Event listeners
      document.getElementById('group-select')?.addEventListener('change', function(e) {
        currentGrouping = e.target.value;
        renderGroups();
      });

      document.getElementById('filter-no-patch')?.addEventListener('change', function(e) {
        filters.noPatch = e.target.checked;
        renderGroups();
      });

      document.getElementById('filter-in-kev')?.addEventListener('change', function(e) {
        filters.inKev = e.target.checked;
        renderGroups();
      });
    })();
  `;
}
