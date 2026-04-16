import { classify, extract } from '../lib/detect.js';
import { lookupIp } from '../lib/crowdsec.js';
import { getApiKeys } from '../lib/storage.js';
import {
  renderIpCard,
  renderError,
  renderUnrecognized,
  renderCvePlaceholder,
} from '../lib/render.js';

const form = document.getElementById('lookup-form');
const input = document.getElementById('lookup-input');
const card = document.getElementById('card');
const intro = document.getElementById('intro');
const openOptions = document.getElementById('open-options');

openOptions.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage?.();
});

// Allow multi-line paste so users can drop in a log snippet.
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    form.requestSubmit();
  }
});

async function ensureKey() {
  const keys = await getApiKeys();
  return !!keys.cti;
}

function showLoading() {
  card.hidden = false;
  card.textContent = '';
  card.className = 'card';
  const loading = document.createElement('div');
  loading.className = 'loading';
  loading.textContent = 'Looking up…';
  card.append(loading);
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const raw = input.value;
  intro.hidden = true;
  card.hidden = false;

  // Single-token path first.
  const single = classify(raw);
  if (single.kind === 'ip') {
    if (!(await ensureKey())) {
      renderError(card, { status: 401, message: 'No CTI API key configured. Open Options to paste your key.' });
      return;
    }
    showLoading();
    const result = await lookupIp(single.value);
    if (result.ok) renderIpCard(card, single.value, result.data, result.quota);
    else renderError(card, result);
    return;
  }
  if (single.kind === 'cve') {
    renderCvePlaceholder(card, single.value);
    return;
  }

  // Multi-token / pasted-text path.
  const { ips, cves } = extract(raw);
  if (ips.length === 0 && cves.length === 0) {
    renderUnrecognized(card, raw);
    return;
  }
  if (ips.length === 1 && cves.length === 0) {
    if (!(await ensureKey())) {
      renderError(card, { status: 401, message: 'No CTI API key configured. Open Options to paste your key.' });
      return;
    }
    showLoading();
    const result = await lookupIp(ips[0]);
    if (result.ok) renderIpCard(card, ips[0], result.data, result.quota);
    else renderError(card, result);
    return;
  }
  if (ips.length === 0 && cves.length === 1) {
    renderCvePlaceholder(card, cves[0]);
    return;
  }

  // Batch: route to the full result window — the popup is too narrow to host
  // the summary comfortably.
  await openBatchWindow(ips, cves);
});

async function openBatchWindow(ips, cves) {
  const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const key = `cs:batch:${id}`;
  await chrome.storage.session.set({
    [key]: { ips, cves, createdAt: Date.now(), ttl: 10 * 60 * 1000 },
  });
  const url = chrome.runtime.getURL(`result/result.html?kind=batch&id=${encodeURIComponent(id)}`);
  await chrome.windows.create({ url, type: 'popup', width: 960, height: 720 });
  // Replace the popup's body with a short confirmation so the user knows
  // the window opened (chrome.windows.create doesn't raise the popup window).
  card.textContent = '';
  const wrap = document.createElement('div');
  wrap.className = 'loading';
  wrap.innerHTML = `Opened summary for <strong>${ips.length}</strong> IPs${cves.length ? ` (+${cves.length} CVEs)` : ''} in a new window.`;
  card.append(wrap);
}
