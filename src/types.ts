export interface KevVulnerability {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
  knownRansomwareCampaignUse: string;
  shortDescription: string;
  notes: string;
}

export interface KevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevVulnerability[];
}

export interface NvdResult {
  status: 'PATCHED' | 'MITIGATION_ONLY' | 'UNPATCHED' | 'ERROR';
  has_patch: boolean;
  has_vendor_advisory: boolean;
  has_mitigation: boolean;
  patch_urls: string[];
  cvss_score: number | null;
  cvss_severity: string | null;
  nvd_published: string | null;
  error: string | null;
}

export interface CveResult extends NvdResult {
  cve_id: string;
  vendor: string;
  product: string;
  vulnerability_name: string;
  date_added: string;
  due_date: string;
  required_action: string;
  known_ransomware: string;
  short_description: string;
  notes: string;
}

export interface Summary {
  unpatched: number;
  mitigation_only: number;
  patched: number;
  errors: number;
}

export interface OutputData {
  last_updated: string;
  total_kev: number;
  total_checked: number;
  summary: Summary;
  vulnerabilities: CveResult[];
}

// Throttle state - persisted to S3 for tracking 429 errors
// Rate limiting is handled by sliding window algorithm in nvd.ts
// This state is used for concurrency control and adaptive behavior
export interface ThrottleState {
  concurrency: number;       // Number of concurrent requests allowed
  delay_ms: number;          // Legacy - no longer used for rate limiting
  last_429_at: string | null;
  last_success_at: string | null;
  consecutive_successes: number;
  consecutive_429s: number;
}

// Default throttle settings
// Rate limiting: 50 req/30s with API key, handled by sliding window in nvd.ts
// Concurrency: controls how many requests can be in-flight at once
export const DEFAULT_THROTTLE: ThrottleState = {
  concurrency: 2,            // Allow 2 concurrent requests
  delay_ms: 0,               // Not used - rate limiting is in nvd.ts
  last_429_at: null,
  last_success_at: null,
  consecutive_successes: 0,
  consecutive_429s: 0,
};

// Throttle bounds (for adaptive concurrency with S3 cache)
export const THROTTLE_BOUNDS = {
  min_concurrency: 1,
  max_concurrency: 3,
  min_delay_ms: 0,           // Not used
  max_delay_ms: 0,           // Not used
  // Speed up after N consecutive successful runs
  speedup_threshold: 3,
  // How much to adjust on success/failure
  concurrency_step: 1,
  delay_step_ms: 0,          // Not used
};

// ============================================
// Phase 2: Recent CVEs Types
// ============================================

// A CVE from bulk NVD query (lighter weight than CveResult)
export interface RecentCve {
  cve_id: string;
  cvss_score: number | null;
  cvss_severity: string | null; // CRITICAL, HIGH, MEDIUM, LOW
  vendor: string;
  product: string;
  published: string; // YYYY-MM-DD
  description: string; // Truncated to ~200 chars
  has_patch: boolean;
  is_in_kev: boolean; // Cross-referenced with KEV catalog
}

// A group of CVEs for UI rendering
export interface CveGroup {
  key: string;
  label: string;
  count: number;
  cves: RecentCve[];
}

// Summary statistics for recent CVEs
export interface RecentCveSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  none: number;
  in_kev: number;
  with_patch: number;
}

// Output structure for recent.json
export interface RecentCveData {
  last_updated: string;
  date_range: {
    start: string;
    end: string;
  };
  total: number;
  summary: RecentCveSummary;
  by_severity: CveGroup[];
  by_vendor: CveGroup[];
  by_week: CveGroup[];
}

// Options for bulk NVD fetch
export interface BulkNvdOptions {
  daysBack: number;
  maxResults: number;
  kevCveIds: Set<string>;
}
