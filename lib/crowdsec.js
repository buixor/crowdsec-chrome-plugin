// CrowdSec API wrappers.
// MVP: CTI /smoke/{ip}. CVE/LET is stubbed; to be filled in Phase 2.

import { getApiKeys } from './storage.js';
import { getCached, setCached } from './cache.js';

const CTI_BASE = 'https://cti.api.crowdsec.net/v2';
const IP_TTL_MS = 60 * 60 * 1000;              // 1 hour
const QUOTA_STORAGE_KEY = 'cs:quota:cti';
const BATCH_CONCURRENCY = 4;                   // polite fan-out for community tier

// Normalized error: { ok: false, status, message } / success: { ok: true, data, quota }
// `quota` shape: { remaining?: number, limit?: number, reset?: number, raw?: object }

export async function lookupIp(ip) {
  const cacheKey = ip;
  const cached = await getCached('ip', cacheKey);
  if (cached) {
    const quota = await getStoredQuota();
    return { ok: true, data: cached, quota, fromCache: true };
  }

  const { cti } = await getApiKeys();
  if (!cti) {
    return { ok: false, status: 0, message: 'No CTI API key configured. Open Options to paste your key.' };
  }

  let res;
  try {
    res = await fetch(`${CTI_BASE}/smoke/${encodeURIComponent(ip)}`, {
      headers: { 'x-api-key': cti, accept: 'application/json' },
    });
  } catch (err) {
    return { ok: false, status: 0, message: 'Network error reaching CrowdSec CTI. Check connectivity.' };
  }

  const quota = extractQuota(res.headers);
  if (quota) await setStoredQuota(quota);

  if (res.status === 404) {
    // The CTI API returns 404 for IPs it has never observed — useful info, not an error.
    // Cache the "clean" verdict for a shorter time in case the IP gets flagged later.
    const notSeen = { _notSeen: true, ip };
    await setCached('ip', cacheKey, notSeen, IP_TTL_MS);
    return { ok: true, data: notSeen, quota };
  }
  if (res.status === 401 || res.status === 403) {
    return { ok: false, status: res.status, message: 'Invalid or unauthorized CTI API key. Open Options to re-paste.' };
  }
  if (res.status === 429) {
    return {
      ok: false,
      status: 429,
      message: 'Rate-limit / daily quota reached. Community CTI keys are capped at 50 lookups/day.',
      quota,
    };
  }
  if (!res.ok) {
    return { ok: false, status: res.status, message: `CrowdSec CTI returned ${res.status}. Retry later.` };
  }

  let data;
  try {
    data = await res.json();
  } catch (err) {
    return { ok: false, status: res.status, message: 'CrowdSec CTI returned non-JSON body.' };
  }

  await setCached('ip', cacheKey, data, IP_TTL_MS);
  return { ok: true, data, quota };
}

/**
 * Look up a batch of IPs. Runs up to BATCH_CONCURRENCY parallel requests,
 * de-duplicates inputs, serves cache hits without hitting the network, and
 * bails out early if the API rate-limits us (status 429).
 *
 * `onProgress({ done, total, cached, lastIp, result })` fires after every IP.
 *
 * Returns an array of `{ ip, result }` in input order (de-duplicated).
 */
export async function lookupIps(ips, onProgress) {
  const unique = [];
  const seen = new Set();
  for (const raw of ips) {
    if (!raw) continue;
    if (seen.has(raw)) continue;
    seen.add(raw);
    unique.push(raw);
  }

  const results = new Array(unique.length);
  let done = 0;
  let cached = 0;
  let aborted = false;
  let cursor = 0;

  async function worker() {
    while (!aborted && cursor < unique.length) {
      const i = cursor++;
      const ip = unique[i];
      const cacheHit = await getCached('ip', ip);
      const result = cacheHit
        ? { ok: true, data: cacheHit, quota: await getQuota(), fromCache: true }
        : await lookupIp(ip);
      results[i] = { ip, result };
      done++;
      if (result.fromCache) cached++;
      onProgress?.({ done, total: unique.length, cached, lastIp: ip, result });
      if (result.status === 429) {
        aborted = true;
        break;
      }
    }
  }

  const workers = Array.from({ length: Math.min(BATCH_CONCURRENCY, unique.length) }, () => worker());
  await Promise.all(workers);

  return { results, aborted, total: unique.length, cached };
}

/**
 * Given a list of IPs, report how many are already in the cache (so the UI
 * can tell the user up-front how many quota units a lookup would burn).
 */
export async function countCached(ips) {
  let hit = 0;
  const miss = [];
  for (const ip of ips) {
    const c = await getCached('ip', ip);
    if (c) hit++;
    else miss.push(ip);
  }
  return { hit, miss };
}

// Phase 2 placeholder — kept so callers can already import it.
export async function lookupCve(cve) {
  return {
    ok: false,
    status: 501,
    message: 'CVE lookups coming in a later version.',
    link: `https://tracker.crowdsec.net/cves/${encodeURIComponent(cve)}`,
  };
}

// Issues a minimal request to validate the key without spending quota needlessly.
// Uses a well-known public IP so /smoke/ always yields a cacheable 200 or 404.
export async function testCtiKey(key) {
  try {
    const res = await fetch(`${CTI_BASE}/smoke/1.1.1.1`, {
      headers: { 'x-api-key': key, accept: 'application/json' },
    });
    const quota = extractQuota(res.headers);
    if (quota) await setStoredQuota(quota);
    if (res.ok || res.status === 404) return { ok: true, quota };
    if (res.status === 401 || res.status === 403) return { ok: false, message: 'Key rejected by CrowdSec (401/403).' };
    if (res.status === 429) return { ok: false, message: 'Rate-limited right now — the key looks valid, try again in a minute.', quota };
    return { ok: false, message: `CrowdSec returned HTTP ${res.status}.` };
  } catch (err) {
    return { ok: false, message: 'Network error reaching CrowdSec.' };
  }
}

// Header names for CrowdSec quota are not fully documented; we probe a few
// candidates and return whichever the response carries.
function extractQuota(headers) {
  const remainingHeaders = ['x-ratelimit-remaining', 'x-rate-limit-remaining', 'ratelimit-remaining'];
  const limitHeaders = ['x-ratelimit-limit', 'x-rate-limit-limit', 'ratelimit-limit'];
  const resetHeaders = ['x-ratelimit-reset', 'x-rate-limit-reset', 'ratelimit-reset'];

  const pick = (names) => {
    for (const n of names) {
      const v = headers.get(n);
      if (v != null && v !== '') return v;
    }
    return null;
  };

  const remaining = pick(remainingHeaders);
  const limit = pick(limitHeaders);
  const reset = pick(resetHeaders);
  if (remaining == null && limit == null) return null;
  return {
    remaining: remaining != null ? Number(remaining) : null,
    limit: limit != null ? Number(limit) : null,
    reset: reset != null ? Number(reset) : null,
    observedAt: Date.now(),
  };
}

async function getStoredQuota() {
  const out = await chrome.storage.local.get(QUOTA_STORAGE_KEY);
  return out[QUOTA_STORAGE_KEY] || null;
}

async function setStoredQuota(quota) {
  await chrome.storage.local.set({ [QUOTA_STORAGE_KEY]: quota });
}

export async function getQuota() {
  return getStoredQuota();
}
