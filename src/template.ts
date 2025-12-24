import type { CveResult, KevCatalog } from './types.js';

const escapeHtml = (str: string): string =>
  String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function renderCveRow(r: CveResult, includeDescription = false): string {
  const ransomwareClass = r.known_ransomware === 'Known' ? 'ransomware-yes' : '';
  const desc = escapeHtml(r.short_description?.substring(0, 150) || '');

  return `
    <tr data-status="${r.status.toLowerCase().replace('_', '')}">
      <td><a href="https://nvd.nist.gov/vuln/detail/${r.cve_id}" class="cve-link" target="_blank">${r.cve_id}</a></td>
      <td>${escapeHtml(r.vendor)}</td>
      <td>${escapeHtml(r.product)}</td>
      ${includeDescription ? '' : `<td><span class="status status-${r.status.toLowerCase().replace('_', '-')}">${getStatusLabel(r.status)}</span></td>`}
      <td class="${ransomwareClass}">${escapeHtml(r.known_ransomware)}</td>
      <td>${r.date_added}</td>
      ${includeDescription ? `<td class="description">${desc}...</td>` : ''}
    </tr>`;
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

function renderSection(
  title: string,
  emoji: string,
  badgeClass: string,
  badgeText: string,
  description: string,
  rows: CveResult[]
): string {
  if (rows.length === 0) return '';

  return `
    <div class="section">
      <div class="section-header">
        <h2 class="section-title">${emoji} ${title}</h2>
        <span class="badge ${badgeClass}">${badgeText}</span>
      </div>
      <p style="color: var(--text-secondary); margin-bottom: 15px;">${description}</p>
      <table>
        <thead>
          <tr>
            <th>CVE</th>
            <th>Vendor</th>
            <th>Product</th>
            <th>Ransomware</th>
            <th>Date Added</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map((r) => renderCveRow(r, true)).join('')}
        </tbody>
      </table>
    </div>`;
}

export function generateHtml(results: CveResult[], kevData: KevCatalog): string {
  const total = results.length;
  const patched = results.filter((r) => r.status === 'PATCHED').length;
  const mitigationOnly = results.filter((r) => r.status === 'MITIGATION_ONLY').length;
  const unpatched = results.filter((r) => r.status === 'UNPATCHED').length;

  const statusOrder: Record<string, number> = { UNPATCHED: 0, MITIGATION_ONLY: 1, ERROR: 2, PATCHED: 3 };
  const sortedResults = [...results].sort(
    (a, b) => (statusOrder[a.status] ?? 99) - (statusOrder[b.status] ?? 99) || a.cve_id.localeCompare(b.cve_id)
  );

  const unpatchedList = sortedResults.filter((r) => r.status === 'UNPATCHED');
  const mitigationList = sortedResults.filter((r) => r.status === 'MITIGATION_ONLY');

  const now = new Date().toISOString().replace('T', ' ').substring(0, 16) + ' UTC';
  const kevCount = kevData.vulnerabilities?.length || 0;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KEV Unpatched Vulnerabilities Tracker</title>
  <style>
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --text-primary: #c9d1d9;
      --text-secondary: #8b949e;
      --border-color: #30363d;
      --red: #f85149;
      --yellow: #d29922;
      --green: #3fb950;
      --blue: #58a6ff;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background-color: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      padding: 20px;
    }

    .container { max-width: 1400px; margin: 0 auto; }

    header {
      text-align: center;
      padding: 40px 20px;
      border-bottom: 1px solid var(--border-color);
      margin-bottom: 30px;
    }

    h1 { font-size: 2.5rem; margin-bottom: 10px; }
    .subtitle { color: var(--text-secondary); font-size: 1.1rem; }
    .last-updated { color: var(--text-secondary); font-size: 0.9rem; margin-top: 15px; }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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
    .stat-label { color: var(--text-secondary); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.5px; }

    .stat-card.unpatched .stat-number { color: var(--red); }
    .stat-card.mitigation .stat-number { color: var(--yellow); }
    .stat-card.patched .stat-number { color: var(--green); }
    .stat-card.total .stat-number { color: var(--blue); }

    .section { margin-bottom: 40px; }

    .section-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border-color);
    }

    .section-title { font-size: 1.5rem; }

    .badge { padding: 4px 12px; border-radius: 20px; font-size: 0.85rem; font-weight: 500; }
    .badge-red { background-color: rgba(248, 81, 73, 0.2); color: var(--red); }
    .badge-yellow { background-color: rgba(210, 153, 34, 0.2); color: var(--yellow); }

    table {
      width: 100%;
      border-collapse: collapse;
      background-color: var(--bg-secondary);
      border-radius: 8px;
      overflow: hidden;
    }

    th, td {
      padding: 12px 16px;
      text-align: left;
      border-bottom: 1px solid var(--border-color);
    }

    th {
      background-color: var(--bg-tertiary);
      font-weight: 600;
      position: sticky;
      top: 0;
    }

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

    .description { max-width: 400px; font-size: 0.9rem; color: var(--text-secondary); }

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

    .filter-controls { margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; }

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

    .search-box {
      padding: 8px 16px;
      border: 1px solid var(--border-color);
      background-color: var(--bg-secondary);
      color: var(--text-primary);
      border-radius: 6px;
      width: 250px;
    }

    .search-box:focus { outline: none; border-color: var(--blue); }

    @media (max-width: 768px) {
      .stats { grid-template-columns: repeat(2, 1fr); }
      table { font-size: 0.85rem; }
      th, td { padding: 8px 10px; }
      .description { display: none; }
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

    <div class="disclaimer">
      <strong>Disclaimer:</strong> This tracker identifies CVEs from the CISA KEV catalog where the required action
      mentions "mitigations" rather than "updates", suggesting a full patch may not be available. The patch status
      is determined by checking NVD references for "Patch" tags. This is not a definitive source - always verify
      with vendor security advisories.
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

    ${renderSection(
      'Likely Unpatched',
      '🚨',
      'badge-red',
      'Action Required',
      'These CVEs have no "Patch" reference in NVD. Consider taking affected systems offline or applying workarounds.',
      unpatchedList
    )}

    ${renderSection(
      'Mitigation Only',
      '⚠️',
      'badge-yellow',
      'Workarounds Available',
      'These CVEs have vendor advisories or mitigations but no explicit patch reference in NVD.',
      mitigationList
    )}

    <div class="section">
      <div class="section-header">
        <h2 class="section-title">All Checked CVEs</h2>
      </div>

      <div class="filter-controls">
        <input type="text" class="search-box" id="searchBox" placeholder="Search CVE, vendor, product...">
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="unpatched">Unpatched</button>
        <button class="filter-btn" data-filter="mitigation">Mitigation Only</button>
        <button class="filter-btn" data-filter="patched">Patched</button>
      </div>

      <table id="resultsTable">
        <thead>
          <tr>
            <th>CVE</th>
            <th>Vendor</th>
            <th>Product</th>
            <th>Status</th>
            <th>Ransomware</th>
            <th>Date Added</th>
          </tr>
        </thead>
        <tbody>
          ${sortedResults.map((r) => renderCveRow(r, false)).join('')}
        </tbody>
      </table>
    </div>

    <footer>
      <p>Data sourced from <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank">CISA KEV Catalog</a>
      and <a href="https://nvd.nist.gov/" target="_blank">NIST NVD</a></p>
      <p style="margin-top: 10px;">This is an automated tracker. Verify all information with official vendor sources.</p>
    </footer>
  </div>

  <script>
    const filterBtns = document.querySelectorAll('.filter-btn');
    const rows = document.querySelectorAll('#resultsTable tbody tr');
    const searchBox = document.getElementById('searchBox');

    let currentFilter = 'all';
    let currentSearch = '';

    function applyFilters() {
      rows.forEach(row => {
        const status = row.dataset.status;
        const text = row.textContent.toLowerCase();

        const matchesFilter = currentFilter === 'all' ||
          (currentFilter === 'unpatched' && status === 'unpatched') ||
          (currentFilter === 'mitigation' && status === 'mitigationonly') ||
          (currentFilter === 'patched' && status === 'patched');

        const matchesSearch = currentSearch === '' || text.includes(currentSearch.toLowerCase());

        row.style.display = matchesFilter && matchesSearch ? '' : 'none';
      });
    }

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
  </script>
</body>
</html>`;
}
