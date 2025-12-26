import type { CveResult, KevCatalog } from './types.js';
import { generateRecentTabHtml, generateRecentCss, generateRecentJs } from './recent-template.js';

const escapeHtml = (str: string): string =>
  String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

function getCvssClass(score: number | null): string {
  if (score === null) return '';
  if (score >= 9.0) return 'cvss-critical';
  if (score >= 7.0) return 'cvss-high';
  if (score >= 4.0) return 'cvss-medium';
  return 'cvss-low';
}

function getStatusLabel(status: string): string {
  const labels: Record<string, string> = {
    UNPATCHED: 'Unpatched',
    MITIGATION_ONLY: 'Mitigation',
    PATCHED: 'Patched',
    ERROR: 'Error',
  };
  return labels[status] || status;
}

export function generateHtml(results: CveResult[], kevData: KevCatalog): string {
  const total = results.length;
  const patched = results.filter((r) => r.status === 'PATCHED').length;
  const mitigationOnly = results.filter((r) => r.status === 'MITIGATION_ONLY').length;
  const unpatched = results.filter((r) => r.status === 'UNPATCHED').length;

  // Sort by date_added descending (newest first), then by status
  const statusOrder: Record<string, number> = { UNPATCHED: 0, MITIGATION_ONLY: 1, ERROR: 2, PATCHED: 3 };
  const sortedResults = [...results].sort((a, b) => {
    // First by date (newest first)
    const dateCompare = b.date_added.localeCompare(a.date_added);
    if (dateCompare !== 0) return dateCompare;
    // Then by status
    return (statusOrder[a.status] ?? 99) - (statusOrder[b.status] ?? 99);
  });

  const now = new Date().toISOString().replace('T', ' ').substring(0, 16) + ' UTC';
  const kevCount = kevData.vulnerabilities?.length || 0;

  // Generate table rows with all data attributes for sorting/filtering
  const tableRows = sortedResults
    .map((r) => {
      const statusClass = `status-${r.status.toLowerCase().replace('_', '-')}`;
      const ransomwareClass = r.known_ransomware === 'Known' ? 'ransomware-yes' : '';
      const cvssClass = getCvssClass(r.cvss_score);
      const cvssDisplay = r.cvss_score !== null ? r.cvss_score.toFixed(1) : 'N/A';

      return `<tr
        data-status="${r.status.toLowerCase().replace('_', '')}"
        data-kevadded="${r.date_added}"
        data-published="${r.nvd_published || ''}"
        data-cvss="${r.cvss_score ?? -1}"
        data-vendor="${escapeHtml(r.vendor.toLowerCase())}"
        data-product="${escapeHtml(r.product.toLowerCase())}"
        data-cve="${r.cve_id.toLowerCase()}"
        data-ransomware="${escapeHtml(r.known_ransomware.toLowerCase())}"
      >
        <td><a href="https://nvd.nist.gov/vuln/detail/${r.cve_id}" class="cve-link" target="_blank" rel="noopener">${r.cve_id}</a></td>
        <td class="${cvssClass}">${cvssDisplay}</td>
        <td>${escapeHtml(r.vendor)}</td>
        <td>${escapeHtml(r.product)}</td>
        <td><span class="status ${statusClass}">${getStatusLabel(r.status)}</span></td>
        <td class="${ransomwareClass}">${escapeHtml(r.known_ransomware)}</td>
        <td>${r.nvd_published || 'N/A'}</td>
        <td>${r.date_added}</td>
        <td class="description-cell">
          <span class="description-text" title="${escapeHtml(r.short_description)}">${escapeHtml(r.short_description.substring(0, 60))}${r.short_description.length > 60 ? '...' : ''}</span>
        </td>
      </tr>`;
    })
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <!-- SEO Meta Tags -->
  <title>KEV Unpatched Vulnerabilities | CISA Known Exploited CVEs Without Patches</title>
  <meta name="description" content="Track ${unpatched} actively exploited vulnerabilities from CISA's KEV catalog that have no vendor patch available. Updated daily with CVSS scores and patch status.">
  <meta name="keywords" content="CISA KEV, unpatched vulnerabilities, zero-day, CVE, security, exploited vulnerabilities, no patch available">
  <meta name="author" content="youmightwanna.org">
  <link rel="canonical" href="https://youmightwanna.org/">

  <!-- Open Graph / Social -->
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://youmightwanna.org/">
  <meta property="og:title" content="KEV Unpatched Vulnerabilities Tracker">
  <meta property="og:description" content="${unpatched} actively exploited vulnerabilities with no vendor patch. Track CISA KEV entries that can't be patched - only mitigated.">
  <meta property="og:image" content="https://youmightwanna.org/og-image.png">

  <!-- Twitter -->
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="KEV Unpatched Vulnerabilities Tracker">
  <meta name="twitter:description" content="${unpatched} actively exploited vulnerabilities with no vendor patch available.">

  <style>
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --text-primary: #c9d1d9;
      --text-secondary: #8b949e;
      --border-color: #30363d;
      --red: #f85149;
      --orange: #db6d28;
      --yellow: #d29922;
      --green: #3fb950;
      --blue: #58a6ff;
      --purple: #a371f7;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background-color: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 20px;
    }

    .container { max-width: 1600px; margin: 0 auto; }

    header {
      text-align: center;
      padding: 40px 20px;
      border-bottom: 1px solid var(--border-color);
      margin-bottom: 30px;
    }

    h1 { font-size: 2.5rem; margin-bottom: 10px; }
    .subtitle { color: var(--text-secondary); font-size: 1.1rem; }
    .last-updated { color: var(--text-secondary); font-size: 0.9rem; margin-top: 15px; }

    /* Search at top */
    .search-container {
      max-width: 600px;
      margin: 0 auto 30px;
    }

    .search-box {
      width: 100%;
      padding: 12px 20px;
      border: 1px solid var(--border-color);
      background-color: var(--bg-secondary);
      color: var(--text-primary);
      border-radius: 8px;
      font-size: 1rem;
    }

    .search-box:focus { outline: none; border-color: var(--blue); }
    .search-box::placeholder { color: var(--text-secondary); }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 20px;
      margin-bottom: 40px;
    }

    .stat-card {
      background-color: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }

    .stat-number { font-size: 2.5rem; font-weight: bold; }
    .stat-label { color: var(--text-secondary); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }

    .stat-card.unpatched .stat-number { color: var(--red); }
    .stat-card.mitigation .stat-number { color: var(--yellow); }
    .stat-card.patched .stat-number { color: var(--green); }
    .stat-card.total .stat-number { color: var(--blue); }

    /* Tab Navigation */
    .tab-nav {
      display: flex;
      gap: 0;
      margin-bottom: 30px;
      border-bottom: 2px solid var(--border-color);
    }

    .tab-btn {
      padding: 12px 24px;
      border: none;
      background: transparent;
      color: var(--text-secondary);
      font-size: 1rem;
      font-weight: 500;
      cursor: pointer;
      position: relative;
      transition: color 0.2s;
    }

    .tab-btn:hover {
      color: var(--text-primary);
    }

    .tab-btn.active {
      color: var(--blue);
    }

    .tab-btn.active::after {
      content: '';
      position: absolute;
      bottom: -2px;
      left: 0;
      right: 0;
      height: 2px;
      background: var(--blue);
    }

    .tab-content {
      display: none;
    }

    .tab-content.active {
      display: block;
    }

    ${generateRecentCss()}

    .filter-controls { margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }

    .filter-btn {
      padding: 8px 16px;
      border: 1px solid var(--border-color);
      background-color: var(--bg-secondary);
      color: var(--text-primary);
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s;
    }

    .filter-btn:hover { background-color: var(--bg-tertiary); }
    .filter-btn.active { background-color: var(--blue); border-color: var(--blue); color: white; }

    .results-count { color: var(--text-secondary); margin-left: auto; }

    table {
      width: 100%;
      border-collapse: collapse;
      background-color: var(--bg-secondary);
      border-radius: 8px;
      overflow: hidden;
    }

    th, td {
      padding: 12px 14px;
      text-align: left;
      border-bottom: 1px solid var(--border-color);
    }

    th {
      background-color: var(--bg-tertiary);
      font-weight: 600;
      position: sticky;
      top: 0;
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }

    th:hover { background-color: #2d333b; }

    th .sort-indicator {
      margin-left: 5px;
      opacity: 0.5;
    }

    th.sorted .sort-indicator { opacity: 1; }

    tr:hover { background-color: var(--bg-tertiary); }

    .cve-link { color: var(--blue); text-decoration: none; }
    .cve-link:hover { text-decoration: underline; }

    .status {
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 0.8rem;
      font-weight: 500;
      text-transform: uppercase;
    }

    .status-unpatched { background-color: rgba(248, 81, 73, 0.2); color: var(--red); }
    .status-mitigation-only { background-color: rgba(210, 153, 34, 0.2); color: var(--yellow); }
    .status-patched { background-color: rgba(63, 185, 80, 0.2); color: var(--green); }
    .status-error { background-color: rgba(139, 148, 158, 0.2); color: var(--text-secondary); }

    .ransomware-yes { color: var(--red); font-weight: bold; }

    /* CVSS colors */
    .cvss-critical { color: var(--purple); font-weight: bold; }
    .cvss-high { color: var(--red); font-weight: bold; }
    .cvss-medium { color: var(--orange); }
    .cvss-low { color: var(--yellow); }

    .description-cell { max-width: 300px; }
    .description-text {
      display: block;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: var(--text-secondary);
      font-size: 0.9rem;
      cursor: help;
    }

    /* Tooltip */
    .description-text:hover {
      position: relative;
    }

    footer {
      text-align: center;
      padding: 40px 20px;
      border-top: 1px solid var(--border-color);
      margin-top: 40px;
      color: var(--text-secondary);
    }

    footer a { color: var(--blue); }

    .disclaimer {
      background-color: var(--bg-secondary);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 30px;
      font-size: 0.9rem;
      color: var(--text-secondary);
    }

    .no-results {
      text-align: center;
      padding: 40px;
      color: var(--text-secondary);
    }

    @media (max-width: 1200px) {
      .description-cell { display: none; }
    }

    @media (max-width: 768px) {
      .stats { grid-template-columns: repeat(2, 1fr); }
      table { font-size: 0.85rem; }
      th, td { padding: 8px 10px; }
      h1 { font-size: 1.8rem; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>KEV Unpatched Vulnerabilities</h1>
      <p class="subtitle">CISA Known Exploited Vulnerabilities that may lack vendor patches</p>
      <p class="last-updated">Last updated: ${now} | Total KEV entries: ${kevCount}</p>
    </header>

    <div class="search-container">
      <input type="text" class="search-box" id="searchBox" placeholder="Search CVE, vendor, product, description..." autofocus>
    </div>

    <div class="stats">
      <div class="stat-card unpatched">
        <div class="stat-number">${unpatched}</div>
        <div class="stat-label">Likely Unpatched</div>
      </div>
      <div class="stat-card mitigation">
        <div class="stat-number">${mitigationOnly}</div>
        <div class="stat-label">Mitigation Only</div>
      </div>
      <div class="stat-card patched">
        <div class="stat-number">${patched}</div>
        <div class="stat-label">Now Patched</div>
      </div>
      <div class="stat-card total">
        <div class="stat-number">${total}</div>
        <div class="stat-label">Total Checked</div>
      </div>
    </div>

    <div class="disclaimer">
      <strong>Disclaimer:</strong> This tracker identifies CVEs from the CISA KEV catalog where the required action
      mentions "mitigations" rather than "updates", suggesting a full patch may not be available. Patch status
      is determined by checking NVD references. This is not a definitive source - always verify with vendor advisories.
    </div>

    <nav class="tab-nav">
      <button class="tab-btn active" data-tab="kev">KEV Tracker</button>
      <button class="tab-btn" data-tab="recent">Recent CVEs</button>
    </nav>

    <div id="kev-content" class="tab-content active">
    <div class="filter-controls">
      <button class="filter-btn active" data-filter="all">All</button>
      <button class="filter-btn" data-filter="unpatched">Unpatched</button>
      <button class="filter-btn" data-filter="mitigation">Mitigation Only</button>
      <button class="filter-btn" data-filter="patched">Patched</button>
      <span class="results-count"><span id="visibleCount">${total}</span> of ${total} shown</span>
    </div>

    <table id="resultsTable">
      <thead>
        <tr>
          <th data-sort="cve">CVE <span class="sort-indicator">↕</span></th>
          <th data-sort="cvss" data-sort-type="number">CVSS <span class="sort-indicator">↕</span></th>
          <th data-sort="vendor">Vendor <span class="sort-indicator">↕</span></th>
          <th data-sort="product">Product <span class="sort-indicator">↕</span></th>
          <th data-sort="status">Status <span class="sort-indicator">↕</span></th>
          <th data-sort="ransomware">Ransomware <span class="sort-indicator">↕</span></th>
          <th data-sort="published">Published <span class="sort-indicator">↕</span></th>
          <th data-sort="kevadded" class="sorted" data-sort-dir="desc">KEV Added <span class="sort-indicator">↓</span></th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        ${tableRows}
      </tbody>
    </table>

    <div class="no-results" id="noResults" style="display: none;">
      No vulnerabilities match your search criteria.
    </div>
    </div><!-- end #kev-content -->

    ${generateRecentTabHtml()}

    <footer>
      <p>Data sourced from <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">CISA KEV Catalog</a>
      and <a href="https://nvd.nist.gov/" target="_blank" rel="noopener">NIST NVD</a></p>
      <p style="margin-top: 10px;">This is an automated tracker. Verify all information with official vendor sources.</p>
      <p style="margin-top: 10px;"><a href="https://github.com/killrazor/youMightWanna" target="_blank" rel="noopener">View on GitHub</a></p>
    </footer>
  </div>

  <script>
    const table = document.getElementById('resultsTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const searchBox = document.getElementById('searchBox');
    const filterBtns = document.querySelectorAll('.filter-btn');
    const visibleCountEl = document.getElementById('visibleCount');
    const noResultsEl = document.getElementById('noResults');

    let currentFilter = 'all';
    let currentSearch = '';
    let currentSort = null;
    let sortDir = 'desc';

    function applyFilters() {
      let visibleCount = 0;
      const searchLower = currentSearch.toLowerCase();

      rows.forEach(row => {
        const status = row.dataset.status;
        const cve = row.dataset.cve;
        const vendor = row.dataset.vendor;
        const product = row.dataset.product;
        const text = row.textContent.toLowerCase();

        const matchesFilter = currentFilter === 'all' ||
          (currentFilter === 'unpatched' && status === 'unpatched') ||
          (currentFilter === 'mitigation' && status === 'mitigationonly') ||
          (currentFilter === 'patched' && status === 'patched');

        const matchesSearch = searchLower === '' ||
          cve.includes(searchLower) ||
          vendor.includes(searchLower) ||
          product.includes(searchLower) ||
          text.includes(searchLower);

        const visible = matchesFilter && matchesSearch;
        row.style.display = visible ? '' : 'none';
        if (visible) visibleCount++;
      });

      visibleCountEl.textContent = visibleCount;
      noResultsEl.style.display = visibleCount === 0 ? 'block' : 'none';
      table.style.display = visibleCount === 0 ? 'none' : '';
    }

    function sortTable(column) {
      const headers = table.querySelectorAll('th[data-sort]');
      const clickedHeader = table.querySelector(\`th[data-sort="\${column}"]\`);
      const isNumeric = clickedHeader?.dataset.sortType === 'number';

      // Toggle direction if same column
      if (currentSort === column) {
        sortDir = sortDir === 'asc' ? 'desc' : 'asc';
      } else {
        currentSort = column;
        sortDir = column === 'kevadded' || column === 'published' || column === 'cvss' || column === 'cve' ? 'desc' : 'asc';
      }

      // Update header indicators
      headers.forEach(h => {
        h.classList.remove('sorted');
        h.querySelector('.sort-indicator').textContent = '↕';
      });
      clickedHeader.classList.add('sorted');
      clickedHeader.querySelector('.sort-indicator').textContent = sortDir === 'asc' ? '↑' : '↓';

      // Sort rows
      rows.sort((a, b) => {
        let aVal = a.dataset[column] || '';
        let bVal = b.dataset[column] || '';

        if (isNumeric) {
          aVal = parseFloat(aVal) || -1;
          bVal = parseFloat(bVal) || -1;
          return sortDir === 'asc' ? aVal - bVal : bVal - aVal;
        }

        return sortDir === 'asc'
          ? aVal.localeCompare(bVal)
          : bVal.localeCompare(aVal);
      });

      // Re-append sorted rows
      rows.forEach(row => tbody.appendChild(row));
    }

    // Event listeners
    filterBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        filterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.filter;
        applyFilters();
      });
    });

    searchBox.addEventListener('input', (e) => {
      currentSearch = e.target.value;
      applyFilters();
    });

    table.querySelectorAll('th[data-sort]').forEach(th => {
      th.addEventListener('click', () => sortTable(th.dataset.sort));
    });

    // Keyboard shortcut: / to focus search
    document.addEventListener('keydown', (e) => {
      if (e.key === '/' && document.activeElement !== searchBox) {
        e.preventDefault();
        searchBox.focus();
      }
      if (e.key === 'Escape') {
        searchBox.blur();
      }
    });

    // Initial sort by KEV Added date descending (most recently added to KEV first)
    sortTable('kevadded');

    // Tab Navigation
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const tabId = btn.dataset.tab;

        // Update active tab button
        tabBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        // Show/hide tab content
        tabContents.forEach(content => {
          if (content.id === tabId + '-content') {
            content.classList.add('active');
            content.style.display = 'block';
          } else {
            content.classList.remove('active');
            content.style.display = 'none';
          }
        });

        // Lazy load recent CVEs when tab is clicked
        if (tabId === 'recent' && typeof loadRecentCves === 'function') {
          loadRecentCves();
        }
      });
    });

    ${generateRecentJs()}
  </script>
</body>
</html>`;
}
