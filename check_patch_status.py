#!/usr/bin/env python3
"""
KEV Patch Status Checker

Downloads the CISA KEV catalog, identifies CVEs that may be unpatched,
checks the NVD API for patch status, and generates a static HTML report.

Usage:
    python check_patch_status.py [--api-key YOUR_NVD_API_KEY]

Environment Variables:
    NVD_API_KEY: Optional NVD API key for faster rate limits
"""

import os
import sys
import json
import time
import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from io import StringIO

try:
    import requests
except ImportError:
    print("Installing requests...")
    os.system(f"{sys.executable} -m pip install requests")
    import requests

# Constants
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_DIR = Path("docs")  # GitHub Pages default directory


def download_kev() -> dict:
    """Download the latest KEV catalog from CISA."""
    print("[1/5] Downloading CISA KEV catalog...")
    response = requests.get(CISA_KEV_URL, timeout=30)
    response.raise_for_status()
    data = response.json()
    print(f"      Downloaded {len(data.get('vulnerabilities', []))} total CVEs")
    return data


def filter_mitigation_cves(kev_data: dict) -> list:
    """Filter KEV entries that have 'Apply mitigations' or 'discontinue use' in required action."""
    print("[2/5] Filtering CVEs with 'Apply mitigations' or 'discontinue use'...")

    filtered = []
    for vuln in kev_data.get("vulnerabilities", []):
        action = vuln.get("requiredAction", "").lower()
        if "apply mitigations" in action or "discontinue use" in action:
            filtered.append(vuln)

    print(f"      Found {len(filtered)} CVEs to check")
    return filtered


def check_nvd_patch_status(cve_id: str, api_key: Optional[str] = None) -> dict:
    """Query NVD API to check if a CVE has patch references."""
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            f"{NVD_API_URL}?cveId={cve_id}",
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()

        has_patch = False
        has_vendor_advisory = False
        has_mitigation = False
        patch_urls = []

        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            cve_data = vulnerabilities[0].get("cve", {})
            references = cve_data.get("references", [])

            for ref in references:
                tags = ref.get("tags", [])
                url = ref.get("url", "")

                if "Patch" in tags:
                    has_patch = True
                    patch_urls.append(url)
                if "Vendor Advisory" in tags:
                    has_vendor_advisory = True
                if "Mitigation" in tags:
                    has_mitigation = True

        # Determine status
        if has_patch:
            status = "PATCHED"
        elif has_vendor_advisory or has_mitigation:
            status = "MITIGATION_ONLY"
        else:
            status = "UNPATCHED"

        return {
            "status": status,
            "has_patch": has_patch,
            "has_vendor_advisory": has_vendor_advisory,
            "has_mitigation": has_mitigation,
            "patch_urls": patch_urls,
            "error": None
        }

    except Exception as e:
        return {
            "status": "ERROR",
            "has_patch": False,
            "has_vendor_advisory": False,
            "has_mitigation": False,
            "patch_urls": [],
            "error": str(e)
        }


def check_all_cves(cves: list, api_key: Optional[str] = None) -> list:
    """Check patch status for all CVEs."""
    print("[3/5] Checking NVD for patch status...")

    # Rate limiting: 5 requests per 30 seconds without API key, 50 with
    delay = 0.7 if api_key else 6.5
    total = len(cves)

    if total > 0:
        est_minutes = (total * delay) / 60
        print(f"      Estimated time: {est_minutes:.1f} minutes")

    results = []

    for i, cve in enumerate(cves, 1):
        cve_id = cve.get("cveID", "")
        vendor = cve.get("vendorProject", "")
        product = cve.get("product", "")

        print(f"      [{i}/{total}] {cve_id} ({vendor})...", end="", flush=True)

        nvd_result = check_nvd_patch_status(cve_id, api_key)

        status = nvd_result["status"]
        if status == "PATCHED":
            print(" [PATCHED]")
        elif status == "MITIGATION_ONLY":
            print(" [MITIGATION ONLY]")
        elif status == "UNPATCHED":
            print(" [UNPATCHED]")
        else:
            print(f" [ERROR]: {nvd_result['error']}")

        results.append({
            "cve_id": cve_id,
            "vendor": vendor,
            "product": product,
            "vulnerability_name": cve.get("vulnerabilityName", ""),
            "date_added": cve.get("dateAdded", ""),
            "due_date": cve.get("dueDate", ""),
            "required_action": cve.get("requiredAction", ""),
            "known_ransomware": cve.get("knownRansomwareCampaignUse", "Unknown"),
            "short_description": cve.get("shortDescription", ""),
            "notes": cve.get("notes", ""),
            **nvd_result
        })

        # Rate limiting
        if i < total:
            time.sleep(delay)

    return results


def generate_html_report(results: list, kev_data: dict) -> str:
    """Generate a static HTML report."""

    # Count statistics
    total = len(results)
    patched = sum(1 for r in results if r["status"] == "PATCHED")
    mitigation_only = sum(1 for r in results if r["status"] == "MITIGATION_ONLY")
    unpatched = sum(1 for r in results if r["status"] == "UNPATCHED")
    errors = sum(1 for r in results if r["status"] == "ERROR")

    # Sort: unpatched first, then mitigation only, then patched
    status_order = {"UNPATCHED": 0, "MITIGATION_ONLY": 1, "ERROR": 2, "PATCHED": 3}
    sorted_results = sorted(results, key=lambda x: (status_order.get(x["status"], 99), x["cve_id"]))

    # Get unpatched and mitigation-only for summary
    unpatched_list = [r for r in sorted_results if r["status"] == "UNPATCHED"]
    mitigation_list = [r for r in sorted_results if r["status"] == "MITIGATION_ONLY"]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    kev_count = len(kev_data.get("vulnerabilities", []))

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KEV Unpatched Vulnerabilities Tracker</title>
    <style>
        :root {{
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
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        header {{
            text-align: center;
            padding: 40px 20px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }}

        h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}

        .subtitle {{
            color: var(--text-secondary);
            font-size: 1.1rem;
        }}

        .last-updated {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 15px;
        }}

        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}

        .stat-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}

        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .stat-card.unpatched .stat-number {{ color: var(--red); }}
        .stat-card.mitigation .stat-number {{ color: var(--yellow); }}
        .stat-card.patched .stat-number {{ color: var(--green); }}
        .stat-card.total .stat-number {{ color: var(--blue); }}

        .section {{
            margin-bottom: 40px;
        }}

        .section-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
        }}

        .section-title {{
            font-size: 1.5rem;
        }}

        .badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }}

        .badge-red {{ background-color: rgba(248, 81, 73, 0.2); color: var(--red); }}
        .badge-yellow {{ background-color: rgba(210, 153, 34, 0.2); color: var(--yellow); }}
        .badge-green {{ background-color: rgba(63, 185, 80, 0.2); color: var(--green); }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }}

        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background-color: var(--bg-tertiary);
            font-weight: 600;
            color: var(--text-primary);
            position: sticky;
            top: 0;
        }}

        tr:hover {{
            background-color: var(--bg-tertiary);
        }}

        .cve-link {{
            color: var(--blue);
            text-decoration: none;
        }}

        .cve-link:hover {{
            text-decoration: underline;
        }}

        .status {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
            text-transform: uppercase;
        }}

        .status-unpatched {{ background-color: rgba(248, 81, 73, 0.2); color: var(--red); }}
        .status-mitigation {{ background-color: rgba(210, 153, 34, 0.2); color: var(--yellow); }}
        .status-patched {{ background-color: rgba(63, 185, 80, 0.2); color: var(--green); }}
        .status-error {{ background-color: rgba(139, 148, 158, 0.2); color: var(--text-secondary); }}

        .ransomware-yes {{
            color: var(--red);
            font-weight: bold;
        }}

        .description {{
            max-width: 400px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}

        footer {{
            text-align: center;
            padding: 40px 20px;
            border-top: 1px solid var(--border-color);
            margin-top: 40px;
            color: var(--text-secondary);
        }}

        footer a {{
            color: var(--blue);
        }}

        .disclaimer {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}

        .filter-controls {{
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 8px 16px;
            border: 1px solid var(--border-color);
            background-color: var(--bg-secondary);
            color: var(--text-primary);
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .filter-btn:hover {{
            background-color: var(--bg-tertiary);
        }}

        .filter-btn.active {{
            background-color: var(--blue);
            border-color: var(--blue);
            color: white;
        }}

        .search-box {{
            padding: 8px 16px;
            border: 1px solid var(--border-color);
            background-color: var(--bg-secondary);
            color: var(--text-primary);
            border-radius: 6px;
            width: 250px;
        }}

        .search-box:focus {{
            outline: none;
            border-color: var(--blue);
        }}

        @media (max-width: 768px) {{
            .stats {{
                grid-template-columns: repeat(2, 1fr);
            }}

            table {{
                font-size: 0.85rem;
            }}

            th, td {{
                padding: 8px 10px;
            }}

            .description {{
                display: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔓 KEV Unpatched Vulnerabilities</h1>
            <p class="subtitle">CISA Known Exploited Vulnerabilities that may lack vendor patches</p>
            <p class="last-updated">Last updated: {now} | Total KEV entries: {kev_count}</p>
        </header>

        <div class="disclaimer">
            <strong>⚠️ Disclaimer:</strong> This tracker identifies CVEs from the CISA KEV catalog where the required action
            mentions "mitigations" rather than "updates", suggesting a full patch may not be available. The patch status
            is determined by checking NVD references for "Patch" tags. This is not a definitive source - always verify
            with vendor security advisories.
        </div>

        <div class="stats">
            <div class="stat-card unpatched">
                <div class="stat-number">{unpatched}</div>
                <div class="stat-label">Likely Unpatched</div>
            </div>
            <div class="stat-card mitigation">
                <div class="stat-number">{mitigation_only}</div>
                <div class="stat-label">Mitigation Only</div>
            </div>
            <div class="stat-card patched">
                <div class="stat-number">{patched}</div>
                <div class="stat-label">Now Patched</div>
            </div>
            <div class="stat-card total">
                <div class="stat-number">{total}</div>
                <div class="stat-label">Total Checked</div>
            </div>
        </div>
'''

    # Unpatched section
    if unpatched_list:
        html += '''
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
'''
        for r in unpatched_list:
            ransomware_class = "ransomware-yes" if r["known_ransomware"] == "Known" else ""
            html += f'''
                    <tr>
                        <td><a href="https://nvd.nist.gov/vuln/detail/{r['cve_id']}" class="cve-link" target="_blank">{r['cve_id']}</a></td>
                        <td>{r['vendor']}</td>
                        <td>{r['product']}</td>
                        <td class="{ransomware_class}">{r['known_ransomware']}</td>
                        <td>{r['date_added']}</td>
                        <td class="description">{r['short_description'][:150]}...</td>
                    </tr>
'''
        html += '''
                </tbody>
            </table>
        </div>
'''

    # Mitigation Only section
    if mitigation_list:
        html += '''
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
'''
        for r in mitigation_list:
            ransomware_class = "ransomware-yes" if r["known_ransomware"] == "Known" else ""
            html += f'''
                    <tr>
                        <td><a href="https://nvd.nist.gov/vuln/detail/{r['cve_id']}" class="cve-link" target="_blank">{r['cve_id']}</a></td>
                        <td>{r['vendor']}</td>
                        <td>{r['product']}</td>
                        <td class="{ransomware_class}">{r['known_ransomware']}</td>
                        <td>{r['date_added']}</td>
                        <td class="description">{r['short_description'][:150]}...</td>
                    </tr>
'''
        html += '''
                </tbody>
            </table>
        </div>
'''

    # Full table with all results
    html += '''
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
'''

    for r in sorted_results:
        status_class = {
            "UNPATCHED": "status-unpatched",
            "MITIGATION_ONLY": "status-mitigation",
            "PATCHED": "status-patched",
            "ERROR": "status-error"
        }.get(r["status"], "")

        status_label = {
            "UNPATCHED": "Unpatched",
            "MITIGATION_ONLY": "Mitigation",
            "PATCHED": "Patched",
            "ERROR": "Error"
        }.get(r["status"], r["status"])

        ransomware_class = "ransomware-yes" if r["known_ransomware"] == "Known" else ""

        html += f'''
                    <tr data-status="{r['status'].lower().replace('_', '')}">
                        <td><a href="https://nvd.nist.gov/vuln/detail/{r['cve_id']}" class="cve-link" target="_blank">{r['cve_id']}</a></td>
                        <td>{r['vendor']}</td>
                        <td>{r['product']}</td>
                        <td><span class="status {status_class}">{status_label}</span></td>
                        <td class="{ransomware_class}">{r['known_ransomware']}</td>
                        <td>{r['date_added']}</td>
                    </tr>
'''

    html += '''
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
        // Filter functionality
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
'''

    return html


def main():
    parser = argparse.ArgumentParser(description="Check KEV CVEs for patch status")
    parser.add_argument("--api-key", help="NVD API key for faster rate limits")
    parser.add_argument("--limit", type=int, help="Limit number of CVEs to check (for testing)")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("NVD_API_KEY")

    print("=" * 50)
    print("KEV Patch Status Checker")
    print("=" * 50)
    print()

    # Download KEV
    kev_data = download_kev()

    # Filter for mitigation CVEs
    cves = filter_mitigation_cves(kev_data)

    # Apply limit if specified
    if args.limit:
        cves = cves[:args.limit]
        print(f"      (Limited to {args.limit} CVEs for testing)")

    # Check NVD for patch status
    results = check_all_cves(cves, api_key)

    # Create output directory
    print("[4/5] Generating output files...")
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Generate HTML report
    html = generate_html_report(results, kev_data)
    html_path = OUTPUT_DIR / "index.html"
    html_path.write_text(html, encoding="utf-8")
    print(f"      HTML report: {html_path}")

    # Save JSON data
    json_path = OUTPUT_DIR / "data.json"
    json_data = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "total_kev": len(kev_data.get("vulnerabilities", [])),
        "total_checked": len(results),
        "summary": {
            "unpatched": sum(1 for r in results if r["status"] == "UNPATCHED"),
            "mitigation_only": sum(1 for r in results if r["status"] == "MITIGATION_ONLY"),
            "patched": sum(1 for r in results if r["status"] == "PATCHED"),
            "errors": sum(1 for r in results if r["status"] == "ERROR"),
        },
        "vulnerabilities": results
    }
    json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
    print(f"      JSON data: {json_path}")

    # Summary
    print()
    print("[5/5] Summary")
    print("=" * 50)
    print(f"   UNPATCHED:       {json_data['summary']['unpatched']}")
    print(f"   MITIGATION ONLY: {json_data['summary']['mitigation_only']}")
    print(f"   PATCHED:         {json_data['summary']['patched']}")
    print(f"   ERRORS:          {json_data['summary']['errors']}")
    print()
    print("Done!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
