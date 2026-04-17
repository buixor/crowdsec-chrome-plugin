// MV3 service worker: installs the context-menu entry and routes selections
// into the result window. Handles both single-IP/CVE lookups and batch mode
// (multi-IP extraction from log lines / CSV / paragraphs).

import { classify, extract } from './lib/detect.js';

const MENU_ID = 'cs-lookup';
const WINDOW_W = 520;
const WINDOW_H = 640;
const BATCH_WINDOW_W = 960;
const BATCH_WINDOW_H = 720;
const BATCH_STORAGE_PREFIX = 'cs:batch:';
const BATCH_TTL_MS = 10 * 60 * 1000; // 10 min — plenty for the user to act on it

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_ID,
    title: 'Lookup in CrowdSec CTI',
    contexts: ['selection'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_ID) return;
  const selection = info.selectionText || '';
  const source = {
    url: info.pageUrl || tab?.url || null,
    title: tab?.title || null,
  };
  await route(selection, source);
});

async function route(selection, source) {
  // First try whole-selection classification — handles the common case of a
  // single cleanly-selected token with surrounding punctuation.
  const single = classify(selection);
  if (single.kind === 'ip') return openSingle('ip', single.value, source);
  if (single.kind === 'cve') return openSingle('cve', single.value, source);

  // Otherwise, scan the text for any number of IPs/CVEs.
  const { ips, cves } = extract(selection);

  if (ips.length === 0 && cves.length === 0) {
    return openError('unrecognized', selection.slice(0, 96));
  }

  // Single IP embedded in prose — treat as single lookup.
  if (ips.length === 1 && cves.length === 0) return openSingle('ip', ips[0], source);
  // Single CVE embedded in prose — treat as single lookup.
  if (ips.length === 0 && cves.length === 1) return openSingle('cve', cves[0], source);

  // Batch mode: ≥ 2 IPs, or a mix of IPs and CVEs.
  await openBatch(ips, cves, source);
}

function openSingle(kind, value, source) {
  const qs = new URLSearchParams({ kind, value });
  if (source?.url) qs.set('src', source.url);
  if (source?.title) qs.set('srcTitle', source.title);
  const url = chrome.runtime.getURL(`result/result.html?${qs.toString()}`);
  return chrome.windows.create({ url, type: 'popup', width: WINDOW_W, height: WINDOW_H });
}

function openError(code, value) {
  const url = chrome.runtime.getURL(
    `result/result.html?error=${code}&value=${encodeURIComponent(value || '')}`,
  );
  return chrome.windows.create({ url, type: 'popup', width: WINDOW_W, height: WINDOW_H });
}

async function openBatch(ips, cves, source) {
  const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const key = BATCH_STORAGE_PREFIX + id;
  await chrome.storage.session.set({
    [key]: {
      ips,
      cves,
      sourceUrl: source?.url || null,
      sourceTitle: source?.title || null,
      createdAt: Date.now(),
      ttl: BATCH_TTL_MS,
    },
  });
  const url = chrome.runtime.getURL(`result/result.html?kind=batch&id=${encodeURIComponent(id)}`);
  return chrome.windows.create({
    url,
    type: 'popup',
    width: BATCH_WINDOW_W,
    height: BATCH_WINDOW_H,
  });
}

// Clean up old batch payloads periodically. The service worker may be killed
// between runs; that's fine — the next wake-up will tidy up.
chrome.alarms?.create?.('cs-cleanup', { periodInMinutes: 15 });
chrome.alarms?.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'cs-cleanup') return;
  const all = await chrome.storage.session.get(null);
  const now = Date.now();
  const stale = Object.entries(all)
    .filter(([k, v]) => k.startsWith(BATCH_STORAGE_PREFIX) && v?.createdAt && now - v.createdAt > (v.ttl || BATCH_TTL_MS))
    .map(([k]) => k);
  if (stale.length) await chrome.storage.session.remove(stale);
});
