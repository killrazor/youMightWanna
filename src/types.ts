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

// Adaptive throttle state - persisted to S3
export interface ThrottleState {
  concurrency: number;
  delay_ms: number;
  last_429_at: string | null;
  last_success_at: string | null;
  consecutive_successes: number;
  consecutive_429s: number;
}

// Default throttle settings
// With API key: 50 req/30s = 1 request per 600ms
// Without API key: 5 req/30s = 1 request per 6000ms
// Using concurrency=1 to ensure we respect rolling window limits
export const DEFAULT_THROTTLE: ThrottleState = {
  concurrency: 1,
  delay_ms: 650,
  last_429_at: null,
  last_success_at: null,
  consecutive_successes: 0,
  consecutive_429s: 0,
};

// Throttle bounds (for adaptive throttle with S3 cache)
// Conservative bounds since we're using concurrency=1
export const THROTTLE_BOUNDS = {
  min_concurrency: 1,
  max_concurrency: 1, // Keep at 1 to respect rolling window
  min_delay_ms: 650,
  max_delay_ms: 10000,
  // Speed up after N consecutive successful runs
  speedup_threshold: 3,
  // How much to adjust on success/failure
  concurrency_step: 0, // Don't adjust concurrency
  delay_step_ms: 50, // Small adjustments to delay
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
