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
 */

import { mkdir, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import pLimit from 'p-limit';
import type { KevCatalog, KevVulnerability, NvdResult, CveResult, OutputData } from './types.js';
import { generateHtml } from './template.js';

// Constants
const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const OUTPUT_DIR = 'docs';

// Rate limiting: NVD allows 50 req/30s with API key, 5 req/30s without
const API_KEY = process.env.NVD_API_KEY;
const CONCURRENCY = API_KEY ? 5 : 2; // Reduced from 10 to be safer
const DELAY_MS = API_KEY ? 1200 : 6500; // Increased delay
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 5000; // Base delay for retries (exponential backoff)

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function downloadKev(): Promise<KevCatalog> {
  console.log('[1/5] Downloading CISA KEV catalog...');
  const response = await fetch(CISA_KEV_URL);
  if (!response.ok) throw new Error(`Failed to fetch KEV: ${response.status}`);
  const data = (await response.json()) as KevCatalog;
  console.log(`      Downloaded ${data.vulnerabilities?.length || 0} total CVEs`);
  return data;
}

function filterMitigationCves(kevData: KevCatalog): KevVulnerability[] {
  console.log("[2/5] Filtering CVEs with 'Apply mitigations' or 'discontinue use'...");

  const filtered = (kevData.vulnerabilities || []).filter((vuln) => {
    const action = (vuln.requiredAction || '').toLowerCase();
    return action.includes('apply mitigations') || action.includes('discontinue use');
  });

  console.log(`      Found ${filtered.length} CVEs to check`);
  return filtered;
}

async function checkNvdPatchStatus(cveId: string, retryCount = 0): Promise<NvdResult> {
  const headers: Record<string, string> = {};
  if (API_KEY) headers['apiKey'] = API_KEY;

  try {
    const response = await fetch(`${NVD_API_URL}?cveId=${cveId}`, {
      headers,
      signal: AbortSignal.timeout(30000),
    });

    // Handle rate limiting with retry
    if (response.status === 429) {
      if (retryCount < MAX_RETRIES) {
        const delay = RETRY_DELAY_MS * Math.pow(2, retryCount); // Exponential backoff
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

    let hasPatch = false;
    let hasVendorAdvisory = false;
    let hasMitigation = false;
    const patchUrls: string[] = [];
    let cvssScore: number | null = null;
    let cvssSeverity: string | null = null;

    const vulnerabilities = data.vulnerabilities || [];
    if (vulnerabilities.length > 0) {
      const cveData = vulnerabilities[0].cve || {};
      const references = cveData.references || [];

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
      error: null,
    };
  } catch (e) {
    return {
      status: 'ERROR',
      has_patch: false,
      has_vendor_advisory: false,
      has_mitigation: false,
      patch_urls: [],
      cvss_score: null,
      cvss_severity: null,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

async function checkAllCves(cves: KevVulnerability[]): Promise<CveResult[]> {
  console.log('[3/5] Checking NVD for patch status...');
  console.log(`      Using ${CONCURRENCY} concurrent requests with ${DELAY_MS}ms delay`);

  const total = cves.length;
  const estMinutes = ((total / CONCURRENCY) * DELAY_MS) / 60000;
  console.log(`      Estimated time: ${estMinutes.toFixed(1)} minutes`);

  const limit = pLimit(CONCURRENCY);
  const results: CveResult[] = [];
  let completed = 0;

  const batchSize = CONCURRENCY;
  for (let i = 0; i < cves.length; i += batchSize) {
    const batch = cves.slice(i, i + batchSize);

    const batchPromises = batch.map((cve) =>
      limit(async () => {
        const cveId = cve.cveID || '';
        const nvdResult = await checkNvdPatchStatus(cveId);

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

    const batchResults = await Promise.all(batchPromises);
    results.push(...batchResults);

    if (i + batchSize < cves.length) {
      await sleep(DELAY_MS);
    }
  }

  console.log('\n');
  return results;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const limitIndex = args.indexOf('--limit');
  const limitArg = limitIndex !== -1 ? parseInt(args[limitIndex + 1], 10) : null;

  console.log('='.repeat(50));
  console.log('KEV Patch Status Checker');
  console.log('='.repeat(50));
  console.log();

  const kevData = await downloadKev();
  let cves = filterMitigationCves(kevData);

  if (limitArg) {
    cves = cves.slice(0, limitArg);
    console.log(`      (Limited to ${limitArg} CVEs for testing)`);
  }

  const results = await checkAllCves(cves);

  console.log('[4/5] Generating output files...');
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

  console.log();
  console.log('[5/5] Summary');
  console.log('='.repeat(50));
  console.log(`   UNPATCHED:       ${outputData.summary.unpatched}`);
  console.log(`   MITIGATION ONLY: ${outputData.summary.mitigation_only}`);
  console.log(`   PATCHED:         ${outputData.summary.patched}`);
  console.log(`   ERRORS:          ${outputData.summary.errors}`);
  console.log();
  console.log('Done!');
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
