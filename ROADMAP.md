# youMightWanna Roadmap

## Phase 1: KEV Unpatched Tracker ✅
Current implementation - tracks CISA KEV entries that lack vendor patches.

## Phase 2: Expanded CVE Coverage
Broaden scope beyond KEV to include recent unpatched CVEs from NVD.

### Features
- [ ] Display recent CVEs (configurable window, e.g., 30/90 days)
- [ ] Filter to unpatched CVEs only
- [ ] KEV badge for CVEs that are also in the KEV catalog
- [ ] Severity filtering (Critical, High, Medium, Low)

### Infrastructure
- [ ] **DynamoDB cache layer** - Cache NVD responses to handle rate limits
  - Store CVE data with TTL for freshness
  - Incremental updates vs full pulls
  - Reduces NVD API calls (50 req/30s with key, 5 req/30s without)
- [ ] Lambda or scheduled job for cache refresh

## Phase 3: Notification System
User-configurable alerts for new CVEs matching their stack.

### Features
- [ ] **Vendor/Product filtering** - Subscribe to specific vendors (e.g., "Microsoft", "Apache")
- [ ] **Version range matching** - Alert for CVEs affecting specific version ranges
  - Parse CPE strings: `cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`
  - Support version comparisons (e.g., "nginx < 1.25.0")
- [ ] Notification delivery (email, webhook, RSS?)

### Version Checking System
- [ ] CPE parser utility
- [ ] Semver comparison logic (handle non-semver versions gracefully)
- [ ] User-defined watch list (vendor + product + version constraint)
- [ ] Match incoming CVEs against watch list

## Technical Considerations

### NVD API
- Rate limits: 50 requests/30 seconds (with API key)
- CPE match criteria includes version ranges
- Pagination required for large result sets

### Data Model (DynamoDB)
```
CVE Cache Table:
  PK: CVE_ID (e.g., "CVE-2025-14303")
  published_date
  last_modified
  severity
  cpe_matches[] 
  patch_status
  kev_flag (boolean)
  ttl (for cache expiration)

User Subscriptions Table (Phase 3):
  PK: user_id
  SK: subscription_id
  vendor
  product
  version_constraint
  notification_method
```

### Open Questions
- [ ] How to handle CVEs with no CPE data yet (newly published)?
- [ ] Version comparison edge cases (non-semver, build metadata, etc.)
- [ ] Notification frequency (immediate vs digest?)
