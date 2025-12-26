/**
 * Recent CVEs Template Module
 *
 * Generates HTML and JavaScript for the Recent CVEs tab with:
 * - Flat table view (consistent with KEV tab)
 * - Button toggle filters for severity, patch status, KEV status
 * - Shared search functionality
 */

import type { RecentCveData, CveGroup } from './types.js';

/**
 * Generate the Recent CVEs tab content
 */
export function generateRecentTabHtml(): string {
  return `
    <div id="recent-content" class="tab-content" style="display: none;">
      <div id="recent-loading" class="loading-placeholder">
        <p>Loading recent CVEs...</p>
      </div>
      <div id="recent-loaded" style="display: none;">
        <div class="recent-summary" id="recent-summary"></div>

        <div class="filter-controls" id="recent-filters">
          <div class="filter-group">
            <span class="filter-label">Severity:</span>
            <button class="filter-btn active" data-severity="all">All</button>
            <button class="filter-btn" data-severity="critical">Critical</button>
            <button class="filter-btn" data-severity="high">High</button>
            <button class="filter-btn" data-severity="medium">Medium</button>
            <button class="filter-btn" data-severity="low">Low</button>
          </div>
          <div class="filter-group">
            <span class="filter-label">Status:</span>
            <button class="filter-btn active" data-patch="all">All</button>
            <button class="filter-btn" data-patch="unpatched">No Patch</button>
            <button class="filter-btn" data-patch="patched">Has Patch</button>
          </div>
          <div class="filter-group">
            <button class="filter-btn" data-kev="true">In KEV Only</button>
          </div>
          <span class="results-count"><span id="recentVisibleCount">0</span> of <span id="recentTotalCount">0</span> shown</span>
        </div>

        <table id="recentTable">
          <thead>
            <tr>
              <th data-sort="cve">CVE <span class="sort-indicator">↕</span></th>
              <th data-sort="cvss" data-sort-type="number">CVSS <span class="sort-indicator">↕</span></th>
              <th data-sort="severity">Severity <span class="sort-indicator">↕</span></th>
              <th data-sort="vendor">Vendor <span class="sort-indicator">↕</span></th>
              <th data-sort="product">Product <span class="sort-indicator">↕</span></th>
              <th data-sort="published" class="sorted" data-sort-dir="desc">Published <span class="sort-indicator">↓</span></th>
              <th>Patch</th>
              <th>KEV</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody id="recentTableBody"></tbody>
        </table>

        <div class="no-results" id="recentNoResults" style="display: none;">
          No CVEs match your search criteria.
        </div>
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
    .recent-summary {
      margin-bottom: 20px;
      padding: 15px 20px;
      background: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
    }

    .recent-summary .stat-row {
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
      align-items: center;
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
    .recent-summary .stat.in-kev { background: rgba(88, 166, 255, 0.2); color: var(--blue); }

    .recent-summary .date-range {
      margin-left: auto;
      font-size: 0.875rem;
      color: var(--text-secondary);
    }

    .filter-group {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .filter-label {
      font-size: 0.875rem;
      color: var(--text-secondary);
      margin-right: 0.25rem;
    }

    .loading-placeholder {
      text-align: center;
      padding: 3rem;
      color: var(--text-secondary);
    }

    /* Badge styles for table */
    .badge {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
    }

    .badge.kev {
      background: rgba(248, 81, 73, 0.2);
      color: var(--red);
    }

    .badge.patch {
      background: rgba(63, 185, 80, 0.2);
      color: var(--green);
    }

    .badge.no-patch {
      background: rgba(139, 148, 158, 0.2);
      color: var(--text-secondary);
    }

    /* Severity badges */
    .severity-badge {
      padding: 4px 8px;
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
  `;
}

/**
 * Generate JavaScript for the Recent CVEs tab functionality
 */
export function generateRecentJs(): string {
  return `
    // Recent CVEs Tab JavaScript
    (function() {
      let recentData = null;
      let recentRows = [];
      let recentFilters = {
        severity: 'all',
        patch: 'all',
        kev: false
      };
      let recentSort = 'published';
      let recentSortDir = 'desc';

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

      function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;')
                  .replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;')
                  .replace(/"/g, '&quot;');
      }

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
            <span class="date-range">
              \${recentData.total.toLocaleString()} CVEs from \${recentData.date_range.start} to \${recentData.date_range.end}
            </span>
          </div>
        \`;

        document.getElementById('recentTotalCount').textContent = recentData.total;

        // Flatten all CVEs from severity groups
        const allCves = [];
        for (const group of recentData.by_severity) {
          allCves.push(...group.cves);
        }

        // Render table
        renderRecentTable(allCves);
        setupRecentFilters();
      }

      function renderRecentTable(cves) {
        const tbody = document.getElementById('recentTableBody');

        const html = cves.map(cve => {
          const severityClass = (cve.cvss_severity || 'none').toLowerCase();
          const cvssDisplay = cve.cvss_score !== null ? cve.cvss_score.toFixed(1) : 'N/A';

          return \`<tr
            data-cve="\${cve.cve_id.toLowerCase()}"
            data-cvss="\${cve.cvss_score ?? -1}"
            data-severity="\${severityClass}"
            data-vendor="\${escapeHtml((cve.vendor || '').toLowerCase())}"
            data-product="\${escapeHtml((cve.product || '').toLowerCase())}"
            data-published="\${cve.published}"
            data-patch="\${cve.has_patch ? 'patched' : 'unpatched'}"
            data-kev="\${cve.is_in_kev}"
          >
            <td><a href="https://nvd.nist.gov/vuln/detail/\${cve.cve_id}" class="cve-link" target="_blank" rel="noopener">\${cve.cve_id}</a></td>
            <td class="cvss-\${severityClass}">\${cvssDisplay}</td>
            <td><span class="severity-badge \${severityClass}">\${cve.cvss_severity || 'N/A'}</span></td>
            <td>\${escapeHtml(cve.vendor)}</td>
            <td>\${escapeHtml(cve.product)}</td>
            <td>\${cve.published}</td>
            <td>\${cve.has_patch ? '<span class="badge patch">Patch</span>' : '<span class="badge no-patch">None</span>'}</td>
            <td>\${cve.is_in_kev ? '<span class="badge kev">KEV</span>' : ''}</td>
            <td class="description-cell">
              <span class="description-text" title="\${escapeHtml(cve.description)}">\${escapeHtml((cve.description || '').substring(0, 60))}\${(cve.description || '').length > 60 ? '...' : ''}</span>
            </td>
          </tr>\`;
        }).join('');

        tbody.innerHTML = html;
        recentRows = Array.from(tbody.querySelectorAll('tr'));

        // Apply initial sort
        sortRecentTable(recentSort);
        applyRecentFilters();
      }

      function setupRecentFilters() {
        const filterContainer = document.getElementById('recent-filters');

        // Severity filters
        filterContainer.querySelectorAll('[data-severity]').forEach(btn => {
          btn.addEventListener('click', () => {
            filterContainer.querySelectorAll('[data-severity]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            recentFilters.severity = btn.dataset.severity;
            applyRecentFilters();
          });
        });

        // Patch filters
        filterContainer.querySelectorAll('[data-patch]').forEach(btn => {
          btn.addEventListener('click', () => {
            filterContainer.querySelectorAll('[data-patch]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            recentFilters.patch = btn.dataset.patch;
            applyRecentFilters();
          });
        });

        // KEV toggle
        filterContainer.querySelectorAll('[data-kev]').forEach(btn => {
          btn.addEventListener('click', () => {
            btn.classList.toggle('active');
            recentFilters.kev = btn.classList.contains('active');
            applyRecentFilters();
          });
        });

        // Sort headers
        const table = document.getElementById('recentTable');
        table.querySelectorAll('th[data-sort]').forEach(th => {
          th.addEventListener('click', () => sortRecentTable(th.dataset.sort));
        });
      }

      function applyRecentFilters() {
        let visibleCount = 0;
        const searchLower = (currentSearch || '').toLowerCase();

        recentRows.forEach(row => {
          const severity = row.dataset.severity;
          const patch = row.dataset.patch;
          const isKev = row.dataset.kev === 'true';
          const cve = row.dataset.cve;
          const vendor = row.dataset.vendor;
          const product = row.dataset.product;
          const text = row.textContent.toLowerCase();

          // Severity filter
          const matchesSeverity = recentFilters.severity === 'all' || severity === recentFilters.severity;

          // Patch filter
          const matchesPatch = recentFilters.patch === 'all' || patch === recentFilters.patch;

          // KEV filter
          const matchesKev = !recentFilters.kev || isKev;

          // Search filter
          const matchesSearch = searchLower === '' ||
            cve.includes(searchLower) ||
            vendor.includes(searchLower) ||
            product.includes(searchLower) ||
            text.includes(searchLower);

          const visible = matchesSeverity && matchesPatch && matchesKev && matchesSearch;
          row.style.display = visible ? '' : 'none';
          if (visible) visibleCount++;
        });

        document.getElementById('recentVisibleCount').textContent = visibleCount;
        document.getElementById('recentNoResults').style.display = visibleCount === 0 ? 'block' : 'none';
        document.getElementById('recentTable').style.display = visibleCount === 0 ? 'none' : '';
      }

      function sortRecentTable(column) {
        const table = document.getElementById('recentTable');
        const headers = table.querySelectorAll('th[data-sort]');
        const clickedHeader = table.querySelector(\`th[data-sort="\${column}"]\`);
        const isNumeric = clickedHeader?.dataset.sortType === 'number';
        const tbody = document.getElementById('recentTableBody');

        // Toggle direction if same column
        if (recentSort === column) {
          recentSortDir = recentSortDir === 'asc' ? 'desc' : 'asc';
        } else {
          recentSort = column;
          recentSortDir = column === 'published' || column === 'cvss' || column === 'cve' ? 'desc' : 'asc';
        }

        // Update header indicators
        headers.forEach(h => {
          h.classList.remove('sorted');
          const indicator = h.querySelector('.sort-indicator');
          if (indicator) indicator.textContent = '↕';
        });
        if (clickedHeader) {
          clickedHeader.classList.add('sorted');
          const indicator = clickedHeader.querySelector('.sort-indicator');
          if (indicator) indicator.textContent = recentSortDir === 'asc' ? '↑' : '↓';
        }

        // Sort rows
        recentRows.sort((a, b) => {
          let aVal = a.dataset[column] || '';
          let bVal = b.dataset[column] || '';

          if (isNumeric) {
            aVal = parseFloat(aVal) || -1;
            bVal = parseFloat(bVal) || -1;
            return recentSortDir === 'asc' ? aVal - bVal : bVal - aVal;
          }

          return recentSortDir === 'asc'
            ? aVal.localeCompare(bVal)
            : bVal.localeCompare(aVal);
        });

        // Re-append sorted rows
        recentRows.forEach(row => tbody.appendChild(row));
      }

      // Expose filter function for global search
      window.applyRecentFilters = applyRecentFilters;
    })();
  `;
}
