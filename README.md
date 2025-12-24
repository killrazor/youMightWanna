# KEV Unpatched Vulnerabilities Tracker

Automatically tracks CISA Known Exploited Vulnerabilities (KEV) that may lack vendor patches.

## Live Site

**[View the tracker → youmightwanna.org](https://youmightwanna.org)**

## What This Does

1. **Downloads** the latest [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
2. **Filters** CVEs where the required action mentions "mitigations" rather than "updates" (suggesting no full patch)
3. **Checks** each CVE against the [NVD API](https://nvd.nist.gov/) for patch references (concurrently for speed)
4. **Generates** a static HTML report showing:
   - **Unpatched** - No patch reference found in NVD
   - **Mitigation Only** - Has vendor advisory but no explicit patch
   - **Patched** - Patch reference found (KEV may be outdated)

## Local Development

```bash
# Install dependencies
npm install

# Run the checker (use --limit for testing)
npm run build -- --limit 10

# View the output
open docs/index.html
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `NVD_API_KEY` | Optional. NVD API key for faster rate limits (50 req/30s vs 5 req/30s). Get one at [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key) |

## Output Files

| File | Description |
|------|-------------|
| `docs/index.html` | Static HTML report with interactive filtering |
| `docs/data.json` | Machine-readable JSON data |

## How Patch Status is Determined

The script checks NVD references for these tags:

| NVD Reference Tag | Interpretation |
|-------------------|----------------|
| `Patch` | Vendor has released a patch |
| `Vendor Advisory` | Vendor has guidance (may or may not include patch) |
| `Mitigation` | Workaround available |
| None of the above | Likely unpatched |

## Infrastructure

This project uses:
- **AWS S3** - Static file hosting
- **AWS CloudFront** - CDN with HTTPS
- **AWS Route 53** - DNS for custom domain
- **Terraform** - Infrastructure as code (see `infra/`)
- **GitHub Actions** - CI/CD pipeline

## Disclaimer

This tracker is for informational purposes only. The patch status is determined algorithmically and may not be accurate. **Always verify with official vendor security advisories** before making security decisions.

## Data Sources

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/)

## License

MIT License
