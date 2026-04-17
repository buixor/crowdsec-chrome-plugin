import { lookupIp, lookupIps, countCached, getQuota } from '../lib/crowdsec.js';
import {
  renderIpCard,
  renderError,
  renderUnrecognized,
  renderCvePlaceholder,
  renderSummaryCard,
  renderProgress,
  renderBatchConfirm,
  aggregate,
  summarizeForHistory,
  summarizeIpForHistory,
} from '../lib/render.js';
import { addEntry as addHistoryEntry } from '../lib/history.js';

const params = new URLSearchParams(location.search);
const kind = params.get('kind');
const value = params.get('value') || '';
const errorParam = params.get('error');
const batchId = params.get('id');
// Source page (captured by background.js from the context-menu tab) — may be null.
const paramSource = {
  url: params.get('src') || null,
  title: params.get('srcTitle') || null,
};
const card = document.getElementById('card');

// Batch lookups above this size prompt the user before burning quota.
const BATCH_CONFIRM_THRESHOLD = 3;

(async function main() {
  document.title = value ? `${value} — CrowdSec CTI` : 'CrowdSec CTI';

  if (errorParam === 'unrecognized') {
    renderUnrecognized(card, value);
    return;
  }

  if (kind === 'cve') {
    renderCvePlaceholder(card, value, null, paramSource);
    // Record CVE lookups too — useful breadcrumb even though the lookup is a placeholder.
    addHistoryEntry({
      kind: 'cve',
      query: value,
      sourceUrl: paramSource.url,
      sourceTitle: paramSource.title,
    }).catch(() => {});
    return;
  }

  if (kind === 'ip' && value) {
    const result = await lookupIp(value);
    if (result.ok) {
      renderIpCard(card, value, result.data, result.quota, paramSource);
      addHistoryEntry({
        kind: 'ip',
        query: value,
        sourceUrl: paramSource.url,
        sourceTitle: paramSource.title,
        summary: summarizeIpForHistory(result.data),
      }).catch(() => {});
    } else {
      renderError(card, result);
    }
    return;
  }

  if (kind === 'batch' && batchId) {
    await runBatch(batchId);
    return;
  }

  renderUnrecognized(card, value);
})();

async function runBatch(id) {
  const key = `cs:batch:${id}`;
  const out = await chrome.storage.session.get(key);
  const payload = out[key];
  if (!payload || !Array.isArray(payload.ips) || !payload.ips.length) {
    renderError(card, { status: 0, message: 'Batch payload missing or expired. Try re-selecting the text.' });
    return;
  }

  const { ips, cves = [] } = payload;
  const source = {
    url: payload.sourceUrl || null,
    title: payload.sourceTitle || null,
  };
  document.title = `${ips.length} IPs — CrowdSec CTI`;

  const { hit, miss } = await countCached(ips);

  const start = async () => {
    // Show a fresh container so the progress bar replaces the confirm dialog.
    card.textContent = '';
    renderProgress(card, { done: 0, total: ips.length, cached: 0 });

    const { results } = await lookupIps(ips, (p) => {
      renderProgress(card, p);
    });

    const quota = await getQuota();
    renderSummaryCard(card, { ips, results, quota, source });

    // Record this batch in history — store the IP list so a history click can
    // replay (most IPs will hit the response cache and consume no quota).
    const agg = aggregate(results);
    addHistoryEntry({
      kind: 'batch',
      ips,
      cves,
      sourceUrl: source.url,
      sourceTitle: source.title,
      summary: summarizeForHistory(agg),
    }).catch(() => {});

    // Clean up session storage — the payload has served its purpose.
    chrome.storage.session.remove(key).catch(() => {});
  };

  if (miss.length > BATCH_CONFIRM_THRESHOLD) {
    renderBatchConfirm(card, {
      ips,
      hit,
      miss,
      onConfirm: () => {
        start();
      },
    });
  } else {
    // Small batches auto-run.
    await start();
  }

  // cves are informational only in MVP; surface them at the bottom as chips
  // linking to the LET web UI.
  if (cves.length) {
    renderCvesFooter(cves);
  }
}

function renderCvesFooter(cves) {
  const footer = document.createElement('section');
  footer.className = 'section';
  const title = document.createElement('h3');
  title.className = 'section__title';
  title.textContent = `CVEs found in selection (${cves.length})`;
  footer.append(title);
  const chips = document.createElement('div');
  chips.className = 'tags';
  for (const c of cves) {
    const chip = document.createElement('span');
    chip.className = 'tag tag--cve';
    chip.textContent = c;
    chip.setAttribute('role', 'button');
    chip.setAttribute('tabindex', '0');
    chip.addEventListener('click', () => {
      window.open(`https://tracker.crowdsec.net/cves/${encodeURIComponent(c)}`, '_blank', 'noopener');
    });
    chips.append(chip);
  }
  footer.append(chips);
  const body = card.querySelector('.card__body');
  (body || card).append(footer);
}
