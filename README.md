# KEV Unpatched Vulnerabilities Tracker

Automatically tracks CISA Known Exploited Vulnerabilities (KEV) that may lack vendor patches.

## 🔗 Live Site

**[View the tracker →](https://YOUR_USERNAME.github.io/kev-tracker/)**

## What This Does

1. **Downloads** the latest [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
2. **Filters** CVEs where the required action mentions "mitigations" rather than "updates" (suggesting no full patch)
3. **Checks** each CVE against the [NVD API](https://nvd.nist.gov/) for patch references
4. **Generates** a static HTML report showing:
   - 🚨 **Unpatched** - No patch reference found in NVD
   - ⚠️ **Mitigation Only** - Has vendor advisory but no explicit patch
   - ✅ **Patched** - Patch reference found (KEV may be outdated)

## Setup

### 1. Fork/Clone This Repository

```bash
git clone https://github.com/YOUR_USERNAME/kev-tracker.git
cd kev-tracker
```

### 2. Enable GitHub Pages

1. Go to **Settings** → **Pages**
2. Under "Build and deployment", select **GitHub Actions**

### 3. (Optional) Add NVD API Key

For faster updates (50 req/30s vs 5 req/30s):

1. Get a free API key at [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key)
2. Go to **Settings** → **Secrets and variables** → **Actions**
3. Add a new secret: `NVD_API_KEY` with your key

### 4. Run the Workflow

- **Automatic**: Runs daily at 6 AM UTC
- **Manual**: Go to **Actions** → **Update KEV Patch Status** → **Run workflow**

## Local Development

```bash
# Install dependencies
pip install requests

# Run the checker (use --limit for testing)
python check_patch_status.py --limit 10

# View the output
open docs/index.html
```

## Output Files

| File | Description |
|------|-------------|
| `docs/index.html` | Static HTML report with interactive filtering |
| `docs/data.json` | Machine-readable JSON data |

## How Patch Status is Determined

The script checks NVD references for these tags:

| NVD Reference Tag | Interpretation |
|-------------------|----------------|
| `Patch` | ✅ Vendor has released a patch |
| `Vendor Advisory` | ⚠️ Vendor has guidance (may or may not include patch) |
| `Mitigation` | ⚠️ Workaround available |
| None of the above | 🚨 Likely unpatched |

## ⚠️ Disclaimer

This tracker is for informational purposes only. The patch status is determined algorithmically and may not be accurate. **Always verify with official vendor security advisories** before making security decisions.

## Data Sources

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/)

## License

MIT License - See [LICENSE](LICENSE) for details.
