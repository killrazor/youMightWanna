#!/usr/bin/env node
/**
 * KEV Patch Status Checker
 *
 * Downloads the CISA KEV catalog, identifies CVEs that may be unpatched,
 * checks the NVD API for patch status, and generates a static HTML report.
 *
 * Usage:
 *   node check_patch_status.js [--limit N]
 *
 * Environment Variables:
 *   NVD_API_KEY: Optional NVD API key for faster rate limits (50 req/30s vs 5 req/30s)
 */

import { mkdir, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import pLimit from 'p-limit';

// Constants
const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const OUTPUT_DIR = 'docs';

// Rate limiting: NVD allows 50 req/30s with API key, 5 req/30s without
const API_KEY = process.env.NVD_API_KEY;
const CONCURRENCY = API_KEY ? 10 : 2; // concurrent requests
const DELAY_MS = API_KEY ? 600 : 6000; // delay between batches

/**
 * Sleep for specified milliseconds
 */
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Download the CISA KEV catalog
 */
async function downloadKev() {
    console.log('[1/5] Downloading CISA KEV catalog...');
    const response = await fetch(CISA_KEV_URL);
    if (!response.ok) throw new Error(`Failed to fetch KEV: ${response.status}`);
    const data = await response.json();
    console.log(`      Downloaded ${data.vulnerabilities?.length || 0} total CVEs`);
    return data;
}

/**
 * Filter KEV entries that have 'Apply mitigations' or 'discontinue use' in required action
 */
function filterMitigationCves(kevData) {
    console.log("[2/5] Filtering CVEs with 'Apply mitigations' or 'discontinue use'...");

    const filtered = (kevData.vulnerabilities || []).filter(vuln => {
        const action = (vuln.requiredAction || '').toLowerCase();
        return action.includes('apply mitigations') || action.includes('discontinue use');
    });

    console.log(`      Found ${filtered.length} CVEs to check`);
    return filtered;
}

/**
 * Check NVD API for a single CVE's patch status
 */
async function checkNvdPatchStatus(cveId) {
    const headers = {};
    if (API_KEY) headers['apiKey'] = API_KEY;

    try {
        const response = await fetch(`${NVD_API_URL}?cveId=${cveId}`, {
            headers,
            signal: AbortSignal.timeout(30000)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        let hasPatch = false;
        let hasVendorAdvisory = false;
        let hasMitigation = false;
        const patchUrls = [];

        const vulnerabilities = data.vulnerabilities || [];
        if (vulnerabilities.length > 0) {
            const cveData = vulnerabilities[0].cve || {};
            const references = cveData.references || [];

            for (const ref of references) {
                const tags = ref.tags || [];
                const url = ref.url || '';

                if (tags.includes('Patch')) {
                    hasPatch = true;
                    patchUrls.push(url);
                }
                if (tags.includes('Vendor Advisory')) {
                    hasVendorAdvisory = true;
                }
                if (tags.includes('Mitigation')) {
                    hasMitigation = true;
                }
            }
        }

        // Determine status
        let status;
        if (hasPatch) {
            status = 'PATCHED';
        } else if (hasVendorAdvisory || hasMitigation) {
            status = 'MITIGATION_ONLY';
        } else {
            status = 'UNPATCHED';
        }

        return {
            status,
            has_patch: hasPatch,
            has_vendor_advisory: hasVendorAdvisory,
            has_mitigation: hasMitigation,
            patch_urls: patchUrls,
            error: null
        };
    } catch (e) {
        return {
            status: 'ERROR',
            has_patch: false,
            has_vendor_advisory: false,
            has_mitigation: false,
            patch_urls: [],
            error: e.message
        };
    }
}

/**
 * Check all CVEs with controlled concurrency
 */
async function checkAllCves(cves) {
    console.log('[3/5] Checking NVD for patch status...');
    console.log(`      Using ${CONCURRENCY} concurrent requests with ${DELAY_MS}ms delay`);

    const total = cves.length;
    const estMinutes = (total / CONCURRENCY * DELAY_MS) / 60000;
    console.log(`      Estimated time: ${estMinutes.toFixed(1)} minutes`);

    const limit = pLimit(CONCURRENCY);
    const results = [];
    let completed = 0;

    // Process in batches to respect rate limits
    const batchSize = CONCURRENCY;
    for (let i = 0; i < cves.length; i += batchSize) {
        const batch = cves.slice(i, i + batchSize);

        const batchPromises = batch.map(cve => limit(async () => {
            const cveId = cve.cveID || '';
            const nvdResult = await checkNvdPatchStatus(cveId);

            completed++;
            const statusEmoji = {
                'PATCHED': '✓',
                'MITIGATION_ONLY': '⚠',
                'UNPATCHED': '✗',
                'ERROR': '!'
            }[nvdResult.status] || '?';

            process.stdout.write(`\r      [${completed}/${total}] ${statusEmoji} ${cveId}`);

            return {
                cve_id: cveId,
                vendor: cve.vendorProject || '',
                product: cve.product || '',
                vulnerability_name: cve.vulnerabilityName || '',
                date_added: cve.dateAdded || '',
                due_date: cve.dueDate || '',
                required_action: cve.requiredAction || '',
                known_ransomware: cve.knownRansomwareCampaignUse || 'Unknown',
                short_description: cve.shortDescription || '',
                notes: cve.notes || '',
                ...nvdResult
            };
        }));

        const batchResults = await Promise.all(batchPromises);
        results.push(...batchResults);

        // Delay between batches (except for last batch)
        if (i + batchSize < cves.length) {
            await sleep(DELAY_MS);
        }
    }

    console.log('\n');
    return results;
}

/**
 * Generate the HTML report (same output as Python version)
 */
function generateHtmlReport(results, kevData) {
    const total = results.length;
    const patched = results.filter(r => r.status === 'PATCHED').length;
    const mitigationOnly = results.filter(r => r.status === 'MITIGATION_ONLY').length;
    const unpatched = results.filter(r => r.status === 'UNPATCHED').length;

    // Sort: unpatched first, then mitigation only, then patched
    const statusOrder = { UNPATCHED: 0, MITIGATION_ONLY: 1, ERROR: 2, PATCHED: 3 };
    const sortedResults = [...results].sort((a, b) =>
        (statusOrder[a.status] ?? 99) - (statusOrder[b.status] ?? 99) || a.cve_id.localeCompare(b.cve_id)
    );

    const unpatchedList = sortedResults.filter(r => r.status === 'UNPATCHED');
    const mitigationList = sortedResults.filter(r => r.status === 'MITIGATION_ONLY');

    const now = new Date().toISOString().replace('T', ' ').substring(0, 16) + ' UTC';
    const kevCount = kevData.vulnerabilities?.length || 0;

    const escapeHtml = (str) => String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    let html = `<!DOCTYPE html>
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
        .status-mitigation { background-color: rgba(210, 153, 34, 0.2); color: var(--yellow); }
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
            <h1>🔓 KEV Unpatched Vulnerabilities</h1>
            <p class="subtitle">CISA Known Exploited Vulnerabilities that may lack vendor patches</p>
            <p class="last-updated">Last updated: ${now} | Total KEV entries: ${kevCount}</p>
        </header>

        <div class="disclaimer">
            <strong>⚠️ Disclaimer:</strong> This tracker identifies CVEs from the CISA KEV catalog where the required action
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
`;

    // Unpatched section
    if (unpatchedList.length > 0) {
        html += `
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">🚨 Likely Unpatched</h2>
                <span class="badge badge-red">Action Required</span>
            </div>
            <p style="color: var(--text-secondary); margin-bottom: 15px;">
                These CVEs have no "Patch" reference in NVD. Consider taking affected systems offline or applying workarounds.
            </p>
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
`;
        for (const r of unpatchedList) {
            const ransomwareClass = r.known_ransomware === 'Known' ? 'ransomware-yes' : '';
            const desc = escapeHtml(r.short_description?.substring(0, 150) || '');
            html += `
                    <tr>
                        <td><a href="https://nvd.nist.gov/vuln/detail/${r.cve_id}" class="cve-link" target="_blank">${r.cve_id}</a></td>
                        <td>${escapeHtml(r.vendor)}</td>
                        <td>${escapeHtml(r.product)}</td>
                        <td class="${ransomwareClass}">${escapeHtml(r.known_ransomware)}</td>
                        <td>${r.date_added}</td>
                        <td class="description">${desc}...</td>
                    </tr>
`;
        }
        html += `
                </tbody>
            </table>
        </div>
`;
    }

    // Mitigation Only section
    if (mitigationList.length > 0) {
        html += `
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">⚠️ Mitigation Only</h2>
                <span class="badge badge-yellow">Workarounds Available</span>
            </div>
            <p style="color: var(--text-secondary); margin-bottom: 15px;">
                These CVEs have vendor advisories or mitigations but no explicit patch reference in NVD.
            </p>
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
`;
        for (const r of mitigationList) {
            const ransomwareClass = r.known_ransomware === 'Known' ? 'ransomware-yes' : '';
            const desc = escapeHtml(r.short_description?.substring(0, 150) || '');
            html += `
                    <tr>
                        <td><a href="https://nvd.nist.gov/vuln/detail/${r.cve_id}" class="cve-link" target="_blank">${r.cve_id}</a></td>
                        <td>${escapeHtml(r.vendor)}</td>
                        <td>${escapeHtml(r.product)}</td>
                        <td class="${ransomwareClass}">${escapeHtml(r.known_ransomware)}</td>
                        <td>${r.date_added}</td>
                        <td class="description">${desc}...</td>
                    </tr>
`;
        }
        html += `
                </tbody>
            </table>
        </div>
`;
    }

    // Full table
    html += `
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">📋 All Checked CVEs</h2>
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
`;

    for (const r of sortedResults) {
        const statusClass = {
            UNPATCHED: 'status-unpatched',
            MITIGATION_ONLY: 'status-mitigation',
            PATCHED: 'status-patched',
            ERROR: 'status-error'
        }[r.status] || '';

        const statusLabel = {
            UNPATCHED: 'Unpatched',
            MITIGATION_ONLY: 'Mitigation',
            PATCHED: 'Patched',
            ERROR: 'Error'
        }[r.status] || r.status;

        const ransomwareClass = r.known_ransomware === 'Known' ? 'ransomware-yes' : '';

        html += `
                    <tr data-status="${r.status.toLowerCase().replace('_', '')}">
                        <td><a href="https://nvd.nist.gov/vuln/detail/${r.cve_id}" class="cve-link" target="_blank">${r.cve_id}</a></td>
                        <td>${escapeHtml(r.vendor)}</td>
                        <td>${escapeHtml(r.product)}</td>
                        <td><span class="status ${statusClass}">${statusLabel}</span></td>
                        <td class="${ransomwareClass}">${escapeHtml(r.known_ransomware)}</td>
                        <td>${r.date_added}</td>
                    </tr>
`;
    }

    html += `
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
</html>
`;

    return html;
}

/**
 * Main entry point
 */
async function main() {
    const args = process.argv.slice(2);
    const limitIndex = args.indexOf('--limit');
    const limit = limitIndex !== -1 ? parseInt(args[limitIndex + 1], 10) : null;

    console.log('='.repeat(50));
    console.log('KEV Patch Status Checker (Node.js)');
    console.log('='.repeat(50));
    console.log();

    // Download KEV
    const kevData = await downloadKev();

    // Filter for mitigation CVEs
    let cves = filterMitigationCves(kevData);

    // Apply limit if specified
    if (limit) {
        cves = cves.slice(0, limit);
        console.log(`      (Limited to ${limit} CVEs for testing)`);
    }

    // Check NVD for patch status
    const results = await checkAllCves(cves);

    // Create output directory
    console.log('[4/5] Generating output files...');
    if (!existsSync(OUTPUT_DIR)) {
        await mkdir(OUTPUT_DIR, { recursive: true });
    }

    // Generate HTML report
    const html = generateHtmlReport(results, kevData);
    await writeFile(`${OUTPUT_DIR}/index.html`, html, 'utf-8');
    console.log(`      HTML report: ${OUTPUT_DIR}/index.html`);

    // Save JSON data
    const jsonData = {
        last_updated: new Date().toISOString(),
        total_kev: kevData.vulnerabilities?.length || 0,
        total_checked: results.length,
        summary: {
            unpatched: results.filter(r => r.status === 'UNPATCHED').length,
            mitigation_only: results.filter(r => r.status === 'MITIGATION_ONLY').length,
            patched: results.filter(r => r.status === 'PATCHED').length,
            errors: results.filter(r => r.status === 'ERROR').length
        },
        vulnerabilities: results
    };
    await writeFile(`${OUTPUT_DIR}/data.json`, JSON.stringify(jsonData, null, 2), 'utf-8');
    console.log(`      JSON data: ${OUTPUT_DIR}/data.json`);

    // Summary
    console.log();
    console.log('[5/5] Summary');
    console.log('='.repeat(50));
    console.log(`   UNPATCHED:       ${jsonData.summary.unpatched}`);
    console.log(`   MITIGATION ONLY: ${jsonData.summary.mitigation_only}`);
    console.log(`   PATCHED:         ${jsonData.summary.patched}`);
    console.log(`   ERRORS:          ${jsonData.summary.errors}`);
    console.log();
    console.log('Done!');
}

main().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
