#!/usr/bin/env tsx
/**
 * KEV Patch Status Checker
 *
 * Downloads the CISA KEV catalog, identifies CVEs that may be unpatched,
 * checks the NVD API for patch status, and generates a static HTML report.
 *
 * Usage:
 *   npx tsx src/index.ts [--limit N]
 *
 * Environment Variables:
 *   NVD_API_KEY: Optional NVD API key for faster rate limits (50 req/30s vs 5 req/30s)
 *   S3_BUCKET: S3 bucket for caching throttle state (optional, enables adaptive throttle)
 *   AWS_REGION: AWS region (default: us-east-1)
 */

import { mkdir, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import pLimit from 'p-limit';
import type {
  KevCatalog,
  KevVulnerability,
  CveResult,
  OutputData,
  ThrottleState,
  RecentCveData,
  CveGroup,
  RecentCve,
} from './types.js';
import { DEFAULT_THROTTLE } from './types.js';
import { generateHtml } from './template.js';
import {
  initS3Cache,
  isCacheEnabled,
  loadThrottleState,
  saveThrottleState,
  throttleBackoff,
  throttleSpeedup,
} from './cache.js';
import { checkNvdPatchStatus, fetchRecentCves } from './nvd.js';

// Constants
const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const OUTPUT_DIR = 'docs';

// Rate limiting - API key allows 50 req/30s, without key allows 5 req/30s
const API_KEY = process.env.NVD_API_KEY;

// Adaptive throttle state - loaded from S3 or defaults
let throttleState: ThrottleState = { ...DEFAULT_THROTTLE };
let had429Error = false;

async function downloadKev(): Promise<KevCatalog> {
  console.log('[1/7] Downloading CISA KEV catalog...');
  const response = await fetch(CISA_KEV_URL);
  if (!response.ok) throw new Error(`Failed to fetch KEV: ${response.status}`);
  const data = (await response.json()) as KevCatalog;
  console.log(`      Downloaded ${data.vulnerabilities?.length || 0} total CVEs`);
  return data;
}

function filterMitigationCves(kevData: KevCatalog): KevVulnerability[] {
  console.log("[2/7] Filtering CVEs with 'Apply mitigations' or 'discontinue use'...");

  const filtered = (kevData.vulnerabilities || []).filter((vuln) => {
    const action = (vuln.requiredAction || '').toLowerCase();
    return action.includes('apply mitigations') || action.includes('discontinue use');
  });

  console.log(`      Found ${filtered.length} CVEs to check`);
  return filtered;
}


async function checkAllCves(cves: KevVulnerability[]): Promise<CveResult[]> {
  console.log('[3/7] Checking NVD for patch status...');
  // With API key: 50 requests per 30 seconds = ~600ms per request
  // With concurrency, effective rate: ~600ms / concurrency
  const apiKey = !!process.env.NVD_API_KEY;
  const rateLimit = apiKey ? 50 : 5;
  const windowSec = 30;
  const effectiveDelayMs = (windowSec * 1000) / rateLimit;
  console.log(`      Rate limit: ${rateLimit} requests per ${windowSec}s (${effectiveDelayMs.toFixed(0)}ms between requests)`);

  const total = cves.length;
  const estMinutes = (total * effectiveDelayMs) / 60000;
  console.log(`      Estimated time: ${estMinutes.toFixed(1)} minutes`);

  // Use p-limit for concurrency control, rate limiting is handled by waitForRateLimit() in nvd.ts
  const limit = pLimit(throttleState.concurrency);
  let completed = 0;

  const promises = cves.map((cve) =>
    limit(async () => {
      const cveId = cve.cveID || '';
      const nvdResult = await checkNvdPatchStatus(cveId);

      // Track 429 errors for adaptive throttle
      if (nvdResult.error?.includes('429')) {
        had429Error = true;
      }

      completed++;
      const statusEmoji: Record<string, string> = {
        PATCHED: '✓',
        MITIGATION_ONLY: '⚠',
        UNPATCHED: '✗',
        ERROR: '!',
      };

      process.stdout.write(`\r      [${completed}/${total}] ${statusEmoji[nvdResult.status] || '?'} ${cveId}`);

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
        ...nvdResult,
      };
    })
  );

  const results = await Promise.all(promises);
  console.log('\n');
  return results;
}

/**
 * Build the grouped output structure for recent CVEs
 */
function buildRecentCveOutput(cves: RecentCve[]): RecentCveData {
  const now = new Date();
  const sixtyDaysAgo = new Date();
  sixtyDaysAgo.setDate(sixtyDaysAgo.getDate() - 60);

  // Calculate summary
  const summary = {
    critical: cves.filter((c) => c.cvss_severity === 'CRITICAL').length,
    high: cves.filter((c) => c.cvss_severity === 'HIGH').length,
    medium: cves.filter((c) => c.cvss_severity === 'MEDIUM').length,
    low: cves.filter((c) => c.cvss_severity === 'LOW').length,
    none: cves.filter((c) => !c.cvss_severity).length,
    in_kev: cves.filter((c) => c.is_in_kev).length,
    with_patch: cves.filter((c) => c.has_patch).length,
  };

  // Group by severity
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', null];
  const bySeverity: CveGroup[] = severityOrder.map((severity) => {
    const groupCves = cves.filter((c) => c.cvss_severity === severity);
    return {
      key: severity?.toLowerCase() || 'none',
      label: severity || 'None/Unknown',
      count: groupCves.length,
      cves: groupCves,
    };
  }).filter((g) => g.count > 0);

  // Group by vendor (top 50 + Other)
  const vendorCounts = new Map<string, RecentCve[]>();
  for (const cve of cves) {
    const vendor = cve.vendor || 'Unknown';
    if (!vendorCounts.has(vendor)) {
      vendorCounts.set(vendor, []);
    }
    vendorCounts.get(vendor)!.push(cve);
  }

  const sortedVendors = [...vendorCounts.entries()]
    .sort((a, b) => b[1].length - a[1].length);

  const byVendor: CveGroup[] = [];
  const otherCves: RecentCve[] = [];

  for (let i = 0; i < sortedVendors.length; i++) {
    const [vendor, vendorCves] = sortedVendors[i];
    if (i < 50) {
      byVendor.push({
        key: vendor.toLowerCase().replace(/\s+/g, '-'),
        label: vendor,
        count: vendorCves.length,
        cves: vendorCves,
      });
    } else {
      otherCves.push(...vendorCves);
    }
  }

  if (otherCves.length > 0) {
    byVendor.push({
      key: 'other',
      label: 'Other',
      count: otherCves.length,
      cves: otherCves,
    });
  }

  // Group by week
  const byWeek: CveGroup[] = [];
  const weekGroups: { label: string; cves: RecentCve[] }[] = [
    { label: 'This Week', cves: [] },
    { label: 'Last Week', cves: [] },
    { label: '2 Weeks Ago', cves: [] },
    { label: 'Older', cves: [] },
  ];

  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const dayOfWeek = todayStart.getDay();
  const thisWeekStart = new Date(todayStart);
  thisWeekStart.setDate(todayStart.getDate() - dayOfWeek);

  for (const cve of cves) {
    const pubDate = new Date(cve.published);
    const daysAgo = Math.floor((todayStart.getTime() - pubDate.getTime()) / (1000 * 60 * 60 * 24));

    if (pubDate >= thisWeekStart) {
      weekGroups[0].cves.push(cve);
    } else if (daysAgo < 14) {
      weekGroups[1].cves.push(cve);
    } else if (daysAgo < 21) {
      weekGroups[2].cves.push(cve);
    } else {
      weekGroups[3].cves.push(cve);
    }
  }

  for (let i = 0; i < weekGroups.length; i++) {
    const { label, cves: weekCves } = weekGroups[i];
    if (weekCves.length > 0) {
      byWeek.push({
        key: `week-${i}`,
        label,
        count: weekCves.length,
        cves: weekCves,
      });
    }
  }

  return {
    last_updated: now.toISOString(),
    date_range: {
      start: sixtyDaysAgo.toISOString().split('T')[0],
      end: now.toISOString().split('T')[0],
    },
    total: cves.length,
    summary,
    by_severity: bySeverity,
    by_vendor: byVendor,
    by_week: byWeek,
  };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const limitIndex = args.indexOf('--limit');
  const limitArg = limitIndex !== -1 ? parseInt(args[limitIndex + 1], 10) : null;

  console.log('='.repeat(50));
  console.log('KEV Patch Status Checker');
  console.log('='.repeat(50));
  console.log();

  // Initialize S3 cache if bucket is configured
  const s3Bucket = process.env.S3_BUCKET;
  const awsRegion = process.env.AWS_REGION || 'us-east-1';
  if (s3Bucket) {
    initS3Cache(s3Bucket, awsRegion);
    throttleState = await loadThrottleState();
  } else {
    // Without S3 cache, use defaults based on API key presence
    // Rate limiting is handled by sliding window in nvd.ts, we just control concurrency
    if (API_KEY) {
      throttleState.concurrency = 2;
    } else {
      throttleState.concurrency = 1;
    }
    console.log(`      No S3 cache configured, using defaults: concurrency=${throttleState.concurrency} (API key: ${API_KEY ? 'yes' : 'no'})`);
  }

  const kevData = await downloadKev();
  let cves = filterMitigationCves(kevData);

  if (limitArg) {
    cves = cves.slice(0, limitArg);
    console.log(`      (Limited to ${limitArg} CVEs for testing)`);
  }

  const results = await checkAllCves(cves);

  // Phase 2: Fetch recent CVEs in bulk
  console.log('[4/7] Fetching recent CVEs in bulk...');
  const kevCveIds = new Set(kevData.vulnerabilities?.map((v) => v.cveID) || []);
  const recentResult = await fetchRecentCves({
    daysBack: 60,
    maxResults: limitArg ? Math.min(limitArg * 10, 500) : 5000, // Scale down for testing
    kevCveIds,
  });

  if (recentResult.had429) {
    had429Error = true;
  }

  // Build grouped recent CVE data
  console.log('[5/7] Building recent CVE groups...');
  const recentData = buildRecentCveOutput(recentResult.cves);

  console.log('[6/7] Generating output files...');
  if (!existsSync(OUTPUT_DIR)) {
    await mkdir(OUTPUT_DIR, { recursive: true });
  }

  const html = generateHtml(results, kevData);
  await writeFile(`${OUTPUT_DIR}/index.html`, html, 'utf-8');
  console.log(`      HTML report: ${OUTPUT_DIR}/index.html`);

  const outputData: OutputData = {
    last_updated: new Date().toISOString(),
    total_kev: kevData.vulnerabilities?.length || 0,
    total_checked: results.length,
    summary: {
      unpatched: results.filter((r) => r.status === 'UNPATCHED').length,
      mitigation_only: results.filter((r) => r.status === 'MITIGATION_ONLY').length,
      patched: results.filter((r) => r.status === 'PATCHED').length,
      errors: results.filter((r) => r.status === 'ERROR').length,
    },
    vulnerabilities: results,
  };

  await writeFile(`${OUTPUT_DIR}/data.json`, JSON.stringify(outputData, null, 2), 'utf-8');
  console.log(`      JSON data: ${OUTPUT_DIR}/data.json`);

  // Write recent CVE data
  await writeFile(`${OUTPUT_DIR}/recent.json`, JSON.stringify(recentData), 'utf-8');
  console.log(`      Recent CVEs: ${OUTPUT_DIR}/recent.json (${recentData.total} CVEs)`);

  // Generate sitemap.xml
  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://youmightwanna.org/</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>`;
  await writeFile(`${OUTPUT_DIR}/sitemap.xml`, sitemap, 'utf-8');
  console.log(`      Sitemap: ${OUTPUT_DIR}/sitemap.xml`);

  // Generate robots.txt
  const robots = `User-agent: *
Allow: /

Sitemap: https://youmightwanna.org/sitemap.xml`;
  await writeFile(`${OUTPUT_DIR}/robots.txt`, robots, 'utf-8');
  console.log(`      Robots: ${OUTPUT_DIR}/robots.txt`);

  console.log();
  console.log('[7/7] Summary');
  console.log('='.repeat(50));
  console.log('KEV Tracker:');
  console.log(`   UNPATCHED:       ${outputData.summary.unpatched}`);
  console.log(`   MITIGATION ONLY: ${outputData.summary.mitigation_only}`);
  console.log(`   PATCHED:         ${outputData.summary.patched}`);
  console.log(`   ERRORS:          ${outputData.summary.errors}`);
  console.log();
  console.log('Recent CVEs:');
  console.log(`   TOTAL:           ${recentData.total}`);
  console.log(`   CRITICAL:        ${recentData.summary.critical}`);
  console.log(`   HIGH:            ${recentData.summary.high}`);
  console.log(`   MEDIUM:          ${recentData.summary.medium}`);
  console.log(`   LOW:             ${recentData.summary.low}`);
  console.log(`   IN KEV:          ${recentData.summary.in_kev}`);

  // Update and save throttle state if S3 cache is enabled
  if (isCacheEnabled()) {
    if (had429Error) {
      console.log();
      console.log('      Detected 429 errors - backing off throttle for next run');
      throttleState = throttleBackoff(throttleState);
    } else {
      throttleState = throttleSpeedup(throttleState);
    }
    await saveThrottleState(throttleState);
  }

  console.log();
  console.log('Done!');
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
