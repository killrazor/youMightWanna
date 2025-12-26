/**
 * NVD API Module
 *
 * Handles all NVD API interactions:
 * - Single CVE lookups (for KEV patch status checking)
 * - Bulk date-range queries (for recent CVEs)
 * - Vendor/product extraction from CPE strings
 */

import type { NvdResult, RecentCve, BulkNvdOptions } from './types.js';

const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const API_KEY = process.env.NVD_API_KEY;
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 5000;
const RESULTS_PER_PAGE = 2000; // NVD API maximum

// Rate limiting: 50 requests per 30 seconds with API key, 5 without
const RATE_LIMIT_WINDOW_MS = 30000;
const RATE_LIMIT_REQUESTS = API_KEY ? 50 : 5;

// Track request timestamps for sliding window rate limiting
const requestTimestamps: number[] = [];

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Wait if necessary to respect rate limits using sliding window algorithm
 * Returns immediately if we haven't hit the limit, otherwise waits until we can make a request
 */
async function waitForRateLimit(): Promise<void> {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW_MS;

  // Remove timestamps outside the window
  while (requestTimestamps.length > 0 && requestTimestamps[0] < windowStart) {
    requestTimestamps.shift();
  }

  // If we're at the limit, wait until the oldest request expires from the window
  if (requestTimestamps.length >= RATE_LIMIT_REQUESTS) {
    const oldestInWindow = requestTimestamps[0];
    const waitTime = oldestInWindow + RATE_LIMIT_WINDOW_MS - now + 100; // +100ms buffer
    if (waitTime > 0) {
      process.stdout.write(` [rate limit: waiting ${(waitTime / 1000).toFixed(1)}s]`);
      await sleep(waitTime);
    }
    // Clean up again after waiting
    const newNow = Date.now();
    const newWindowStart = newNow - RATE_LIMIT_WINDOW_MS;
    while (requestTimestamps.length > 0 && requestTimestamps[0] < newWindowStart) {
      requestTimestamps.shift();
    }
  }

  // Record this request
  requestTimestamps.push(Date.now());
}

/**
 * Check NVD patch status for a single CVE
 * Used by KEV tracker to check individual CVEs
 */
export async function checkNvdPatchStatus(cveId: string, retryCount = 0): Promise<NvdResult> {
  const headers: Record<string, string> = {};
  if (API_KEY) headers['apiKey'] = API_KEY;

  try {
    // Wait for rate limit before making request
    await waitForRateLimit();

    const response = await fetch(`${NVD_API_URL}?cveId=${cveId}`, {
      headers,
      signal: AbortSignal.timeout(30000),
    });

    // Handle rate limiting with retry
    if (response.status === 429) {
      if (retryCount < MAX_RETRIES) {
        const delay = RETRY_DELAY_MS * Math.pow(2, retryCount);
        process.stdout.write(` [429, retry in ${delay / 1000}s]`);
        await sleep(delay);
        return checkNvdPatchStatus(cveId, retryCount + 1);
      }
      throw new Error(`HTTP 429 after ${MAX_RETRIES} retries`);
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    return parseNvdCveResponse(data);
  } catch (e) {
    return {
      status: 'ERROR',
      has_patch: false,
      has_vendor_advisory: false,
      has_mitigation: false,
      patch_urls: [],
      cvss_score: null,
      cvss_severity: null,
      nvd_published: null,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

/**
 * Parse NVD CVE response data into NvdResult
 */
function parseNvdCveResponse(data: any): NvdResult {
  let hasPatch = false;
  let hasVendorAdvisory = false;
  let hasMitigation = false;
  const patchUrls: string[] = [];
  let cvssScore: number | null = null;
  let cvssSeverity: string | null = null;
  let nvdPublished: string | null = null;

  const vulnerabilities = data.vulnerabilities || [];
  if (vulnerabilities.length > 0) {
    const cveData = vulnerabilities[0].cve || {};
    const references = cveData.references || [];

    // Extract NVD published date
    nvdPublished = cveData.published ? cveData.published.split('T')[0] : null;

    // Extract CVSS score (prefer v3.1, fall back to v3.0, then v2.0)
    const metrics = cveData.metrics || {};
    if (metrics.cvssMetricV31?.[0]) {
      cvssScore = metrics.cvssMetricV31[0].cvssData?.baseScore ?? null;
      cvssSeverity = metrics.cvssMetricV31[0].cvssData?.baseSeverity ?? null;
    } else if (metrics.cvssMetricV30?.[0]) {
      cvssScore = metrics.cvssMetricV30[0].cvssData?.baseScore ?? null;
      cvssSeverity = metrics.cvssMetricV30[0].cvssData?.baseSeverity ?? null;
    } else if (metrics.cvssMetricV2?.[0]) {
      cvssScore = metrics.cvssMetricV2[0].cvssData?.baseScore ?? null;
      cvssSeverity = metrics.cvssMetricV2[0].baseSeverity ?? null;
    }

    for (const ref of references) {
      const tags: string[] = ref.tags || [];
      const url: string = ref.url || '';

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

  let status: NvdResult['status'];
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
    cvss_score: cvssScore,
    cvss_severity: cvssSeverity,
    nvd_published: nvdPublished,
    error: null,
  };
}

/**
 * Extract vendor and product from CPE string or description
 * CPE format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
 */
export function extractVendorProduct(
  cpeMatches: any[] | undefined,
  description: string
): { vendor: string; product: string } {
  // Try CPE first
  if (cpeMatches && cpeMatches.length > 0) {
    for (const match of cpeMatches) {
      const criteria = match.criteria || match.cpe23Uri || '';
      // cpe:2.3:a:vendor:product:version:...
      const parts = criteria.split(':');
      if (parts.length >= 5) {
        const vendor = parts[3] || '';
        const product = parts[4] || '';
        if (vendor && vendor !== '*') {
          return {
            vendor: formatVendorName(vendor),
            product: formatProductName(product),
          };
        }
      }
    }
  }

  // Fallback: extract from description using common patterns
  return extractFromDescription(description);
}

/**
 * Format vendor name for display (capitalize, handle underscores)
 */
function formatVendorName(vendor: string): string {
  return vendor
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
}

/**
 * Format product name for display
 */
function formatProductName(product: string): string {
  if (!product || product === '*') return 'Unknown';
  return product
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ');
}

/**
 * Extract vendor/product from description text using patterns
 */
function extractFromDescription(description: string): { vendor: string; product: string } {
  const desc = description.toLowerCase();

  // Common vendor patterns - check in order of specificity
  const vendorPatterns: [RegExp, string][] = [
    [/microsoft\s+(windows|office|edge|azure|exchange|sharepoint)/i, 'Microsoft'],
    [/microsoft/i, 'Microsoft'],
    [/apache\s+(tomcat|struts|http|kafka|spark)/i, 'Apache'],
    [/apache/i, 'Apache'],
    [/google\s+(chrome|android|cloud)/i, 'Google'],
    [/google/i, 'Google'],
    [/cisco\s+/i, 'Cisco'],
    [/adobe\s+(acrobat|reader|flash|photoshop)/i, 'Adobe'],
    [/adobe/i, 'Adobe'],
    [/oracle\s+(java|mysql|database|weblogic)/i, 'Oracle'],
    [/oracle/i, 'Oracle'],
    [/vmware\s+/i, 'VMware'],
    [/linux\s+kernel/i, 'Linux'],
    [/samsung\s+/i, 'Samsung'],
    [/apple\s+(ios|macos|safari|iphone)/i, 'Apple'],
    [/apple/i, 'Apple'],
    [/fortinet\s+/i, 'Fortinet'],
    [/palo\s+alto/i, 'Palo Alto'],
    [/juniper\s+/i, 'Juniper'],
    [/ibm\s+/i, 'IBM'],
    [/sap\s+/i, 'SAP'],
    [/wordpress/i, 'WordPress'],
    [/drupal/i, 'Drupal'],
    [/nginx/i, 'Nginx'],
    [/redis/i, 'Redis'],
    [/mongodb/i, 'MongoDB'],
    [/postgresql/i, 'PostgreSQL'],
    [/mysql/i, 'MySQL'],
  ];

  for (const [pattern, vendor] of vendorPatterns) {
    if (pattern.test(desc)) {
      // Try to extract product from the match
      const match = description.match(pattern);
      const product = match && match[1] ? formatProductName(match[1]) : 'Unknown';
      return { vendor, product };
    }
  }

  return { vendor: 'Unknown', product: 'Unknown' };
}

/**
 * Fetch recent CVEs in bulk using date-range query with pagination
 * Rate limiting is handled automatically by waitForRateLimit()
 */
export async function fetchRecentCves(
  options: BulkNvdOptions
): Promise<{ cves: RecentCve[]; had429: boolean }> {
  const { daysBack, maxResults, kevCveIds } = options;

  // Calculate date range
  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - daysBack);

  const startDateStr = startDate.toISOString().replace('Z', '');
  const endDateStr = endDate.toISOString().replace('Z', '');

  console.log(`      Date range: ${startDate.toISOString().split('T')[0]} to ${endDate.toISOString().split('T')[0]}`);

  const headers: Record<string, string> = {};
  if (API_KEY) headers['apiKey'] = API_KEY;

  const allCves: RecentCve[] = [];
  let startIndex = 0;
  let totalResults = 0;
  let had429 = false;
  let pageCount = 0;

  do {
    const url = `${NVD_API_URL}?pubStartDate=${startDateStr}&pubEndDate=${endDateStr}&resultsPerPage=${RESULTS_PER_PAGE}&startIndex=${startIndex}`;

    let response: Response | null = null;
    let retryCount = 0;

    // Retry loop for this page
    while (retryCount <= MAX_RETRIES) {
      try {
        // Wait for rate limit before making request
        await waitForRateLimit();

        response = await fetch(url, {
          headers,
          signal: AbortSignal.timeout(60000), // Longer timeout for bulk queries
        });

        if (response.status === 429) {
          had429 = true;
          if (retryCount < MAX_RETRIES) {
            const delay = RETRY_DELAY_MS * Math.pow(2, retryCount);
            console.log(`      [429 Rate limit - waiting ${delay / 1000}s before retry]`);
            await sleep(delay);
            retryCount++;
            continue;
          }
          throw new Error(`HTTP 429 after ${MAX_RETRIES} retries`);
        }

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        break; // Success, exit retry loop
      } catch (e) {
        if (retryCount >= MAX_RETRIES) {
          console.error(`      Error fetching page ${pageCount + 1}: ${e}`);
          throw e;
        }
        retryCount++;
        await sleep(RETRY_DELAY_MS * Math.pow(2, retryCount));
      }
    }

    if (!response) {
      throw new Error('Failed to fetch after retries');
    }

    const data = await response.json();
    totalResults = data.totalResults || 0;
    const vulnerabilities = data.vulnerabilities || [];

    pageCount++;
    console.log(
      `      Page ${pageCount}: fetched ${vulnerabilities.length} CVEs (${allCves.length + vulnerabilities.length}/${Math.min(totalResults, maxResults)})`
    );

    // Process each CVE
    for (const item of vulnerabilities) {
      if (allCves.length >= maxResults) break;

      const cve = item.cve || {};
      const recentCve = parseRecentCve(cve, kevCveIds);
      allCves.push(recentCve);
    }

    startIndex += RESULTS_PER_PAGE;
    // Rate limiting is now handled by waitForRateLimit() at the start of each request
  } while (startIndex < totalResults && allCves.length < maxResults);

  console.log(`      Total fetched: ${allCves.length} CVEs`);

  return { cves: allCves, had429 };
}

/**
 * Parse a single CVE from bulk NVD response into RecentCve format
 */
function parseRecentCve(cve: any, kevCveIds: Set<string>): RecentCve {
  const cveId = cve.id || '';

  // Extract CVSS score and severity
  let cvssScore: number | null = null;
  let cvssSeverity: string | null = null;
  const metrics = cve.metrics || {};

  if (metrics.cvssMetricV31?.[0]) {
    cvssScore = metrics.cvssMetricV31[0].cvssData?.baseScore ?? null;
    cvssSeverity = metrics.cvssMetricV31[0].cvssData?.baseSeverity ?? null;
  } else if (metrics.cvssMetricV30?.[0]) {
    cvssScore = metrics.cvssMetricV30[0].cvssData?.baseScore ?? null;
    cvssSeverity = metrics.cvssMetricV30[0].cvssData?.baseSeverity ?? null;
  } else if (metrics.cvssMetricV2?.[0]) {
    cvssScore = metrics.cvssMetricV2[0].cvssData?.baseScore ?? null;
    // V2 severity is at a different path
    cvssSeverity = metrics.cvssMetricV2[0].baseSeverity ?? null;
  }

  // Extract description (English preferred)
  const descriptions = cve.descriptions || [];
  let description = '';
  for (const desc of descriptions) {
    if (desc.lang === 'en') {
      description = desc.value || '';
      break;
    }
  }
  if (!description && descriptions.length > 0) {
    description = descriptions[0].value || '';
  }
  // Truncate to ~200 chars
  if (description.length > 200) {
    description = description.substring(0, 197) + '...';
  }

  // Extract vendor/product from CPE configurations
  const configurations = cve.configurations || [];
  let cpeMatches: any[] = [];
  for (const config of configurations) {
    const nodes = config.nodes || [];
    for (const node of nodes) {
      if (node.cpeMatch) {
        cpeMatches = cpeMatches.concat(node.cpeMatch);
      }
    }
  }

  const { vendor, product } = extractVendorProduct(cpeMatches, description);

  // Check for patch in references
  let hasPatch = false;
  const references = cve.references || [];
  for (const ref of references) {
    const tags: string[] = ref.tags || [];
    if (tags.includes('Patch')) {
      hasPatch = true;
      break;
    }
  }

  // Extract published date
  const published = cve.published ? cve.published.split('T')[0] : '';

  // Check if in KEV catalog
  const isInKev = kevCveIds.has(cveId);

  return {
    cve_id: cveId,
    cvss_score: cvssScore,
    cvss_severity: cvssSeverity,
    vendor,
    product,
    published,
    description,
    has_patch: hasPatch,
    is_in_kev: isInKev,
  };
}
