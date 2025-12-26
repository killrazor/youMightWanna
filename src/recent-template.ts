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
 * Generate CSS for the Recent CVEs tab - Dark Mode
 */
export function generateRecentCss(): string {
  return `
    /* Recent CVEs Tab Styles - Dark Mode */
    .recent-header {
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      align-items: center;
      margin-bottom: 1rem;
      padding: 1rem;
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
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

    .recent-summary .stat.critical { background: rgba(163, 113, 247, 0.2); color: var(--purple); }
    .recent-summary .stat.high { background: rgba(248, 81, 73, 0.2); color: var(--red); }
    .recent-summary .stat.medium { background: rgba(210, 153, 34, 0.2); color: var(--yellow); }
    .recent-summary .stat.low { background: rgba(63, 185, 80, 0.2); color: var(--green); }
    .recent-summary .stat.in-kev { background: rgba(139, 148, 158, 0.2); color: var(--text-secondary); }

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
      color: var(--text-primary);
    }

    #group-select {
      padding: 0.375rem 0.75rem;
      border: 1px solid var(--border-color);
      border-radius: 4px;
      background: var(--bg-secondary);
      color: var(--text-primary);
    }

    .loading-placeholder {
      text-align: center;
      padding: 3rem;
      color: var(--text-secondary);
    }

    /* CVE Group Styles */
    .cve-group {
      margin-bottom: 0.5rem;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      overflow: hidden;
      background: var(--bg-secondary);
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
      background: var(--bg-tertiary);
      border: none;
      cursor: pointer;
      text-align: left;
      font-size: 1rem;
      color: var(--text-primary);
      transition: background 0.15s;
    }

    .group-header:hover {
      background: #2d333b;
    }

    .group-header .chevron {
      transition: transform 0.2s;
      color: var(--text-secondary);
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

    .severity-badge.critical { background: rgba(163, 113, 247, 0.2); color: var(--purple); }
    .severity-badge.high { background: rgba(248, 81, 73, 0.2); color: var(--red); }
    .severity-badge.medium { background: rgba(210, 153, 34, 0.2); color: var(--yellow); }
    .severity-badge.low { background: rgba(63, 185, 80, 0.2); color: var(--green); }
    .severity-badge.none { background: rgba(139, 148, 158, 0.2); color: var(--text-secondary); }

    .group-header .label {
      flex: 1;
      font-weight: 500;
      color: var(--text-primary);
    }

    .group-header .count {
      color: var(--text-secondary);
      font-size: 0.875rem;
    }

    .group-content {
      display: none;
      border-top: 1px solid var(--border-color);
    }

    .cve-group.expanded .group-content {
      display: block;
    }
  `;
}

/**
 * Generate the shadow DOM styles for CVE tables - Dark Mode
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
        border-bottom: 1px solid #30363d;
      }

      th {
        background: #21262d;
        font-weight: 600;
        color: #c9d1d9;
        position: sticky;
        top: 0;
      }

      tr:hover {
        background: #21262d;
      }

      .cve-id {
        font-family: monospace;
        font-weight: 500;
      }

      .cve-id a {
        color: #58a6ff;
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

      .severity.critical { background: rgba(163, 113, 247, 0.2); color: #a371f7; }
      .severity.high { background: rgba(248, 81, 73, 0.2); color: #f85149; }
      .severity.medium { background: rgba(210, 153, 34, 0.2); color: #d29922; }
      .severity.low { background: rgba(63, 185, 80, 0.2); color: #3fb950; }
      .severity.none { background: rgba(139, 148, 158, 0.2); color: #8b949e; }

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
        background: #f85149;
        color: white;
      }

      .badge.patch {
        background: #3fb950;
        color: white;
      }

      .description {
        max-width: 400px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        color: #8b949e;
      }

      .vendor-product {
        color: #c9d1d9;
      }

      .date {
        color: #8b949e;
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
            '<p style="color: #f85149;">Failed to load recent CVEs. Please try again.</p>';
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
          <div style="margin-top: 0.5rem; font-size: 0.875rem; color: #8b949e;">
            \${recentData.total.toLocaleString()} CVEs from \${recentData.date_range.start} to \${recentData.date_range.end}
          </div>
        \`;

        renderGroups();
      }

      // Store CVE data in JS instead of HTML attributes to avoid escaping issues
      const groupCveData = new Map();

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

        // Clear previous data
        groupCveData.clear();

        container.innerHTML = groups.map((group, index) => {
          const filteredCves = filterCves(group.cves);
          const isHidden = filteredCves.length === 0;
          const severityClass = currentGrouping === 'severity' ? group.key : '';
          const groupId = currentGrouping + '-' + index;

          // Store CVE data in Map instead of HTML attribute
          groupCveData.set(groupId, filteredCves);

          return \`
            <div class="cve-group\${isHidden ? ' hidden' : ''}" data-group-id="\${groupId}">
              <button class="group-header" onclick="toggleGroup(this)">
                <span class="chevron">▶</span>
                \${severityClass ? \`<span class="severity-badge \${severityClass}">\${group.label}</span>\` : \`<span class="label">\${group.label}</span>\`}
                <span class="count">\${filteredCves.length} CVEs</span>
              </button>
              <div class="group-content"></div>
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
            const groupId = group.dataset.groupId;
            const cves = groupCveData.get(groupId) || [];
            const shadow = content.attachShadow({ mode: 'open' });
            shadow.innerHTML = \`${shadowStyles}\` + renderCveTable(cves);
          }
        }
      };

      function renderCveTable(cves) {
        if (cves.length === 0) {
          return '<p style="padding: 1rem; color: #8b949e;">No CVEs match the current filters.</p>';
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
