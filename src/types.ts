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
