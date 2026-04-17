import { listEntries, removeEntry, clearHistory } from '../lib/history.js';

const list = document.getElementById('list');
const filterInput = document.getElementById('filter');
const clearBtn = document.getElementById('clear');

const WINDOW_W = 520;
const WINDOW_H = 640;
const BATCH_WINDOW_W = 960;
const BATCH_WINDOW_H = 720;

const KIND_LABELS = { ip: 'IP', cve: 'CVE', batch: 'Batch' };
const REP_LABELS = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  known: 'Known',
  safe: 'Safe',
  benign: 'Benign',
  unknown: 'Unknown',
};
const REP_TONE = {
  malicious: 'malicious',
  suspicious: 'suspicious',
  known: 'known',
  safe: 'clean',
  benign: 'clean',
  unknown: 'unknown',
};

let allEntries = [];
let filterText = '';

function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.class) node.className = opts.class;
  if (opts.text != null) node.textContent = opts.text;
  if (opts.attrs) {
    for (const [k, v] of Object.entries(opts.attrs)) {
      if (v === false || v == null) continue;
      node.setAttribute(k, v === true ? '' : String(v));
    }
  }
  if (opts.on) {
    for (const [k, fn] of Object.entries(opts.on)) node.addEventListener(k, fn);
  }
  for (const c of [].concat(children)) {
    if (c == null || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return node;
}

function relTime(ms) {
  if (!ms) return '—';
  const diffMs = ms - Date.now();
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  const units = [
    ['year', 365 * 86400e3],
    ['month', 30 * 86400e3],
    ['day', 86400e3],
    ['hour', 3600e3],
    ['minute', 60e3],
  ];
  for (const [unit, step] of units) {
    if (Math.abs(diffMs) >= step || unit === 'minute') {
      return rtf.format(Math.round(diffMs / step), unit);
    }
  }
  return new Date(ms).toLocaleString();
}

function hostnameOf(url) {
  if (!url) return null;
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function render() {
  const filtered = filterText
    ? allEntries.filter((e) => matchesFilter(e, filterText))
    : allEntries;

  list.textContent = '';

  if (!allEntries.length) {
    list.append(
      el('div', { class: 'history__empty' }, [
        el('p', {}, [
          el('strong', { text: 'No lookups yet.' }),
        ]),
        el('p', {
          text: "Right-click an IP on any page and choose \u201CLookup in CrowdSec CTI\u201D, or paste one into the toolbar popup.",
        }),
      ]),
    );
    return;
  }
  if (!filtered.length) {
    list.append(el('div', { class: 'history__empty' }, [
      el('p', { text: `No matches for "${filterText}".` }),
    ]));
    return;
  }

  const table = el('table', { class: 'ip-table history__table' }, [
    el('thead', {}, [
      el('tr', {}, [
        el('th', { text: 'When' }),
        el('th', { text: 'Kind' }),
        el('th', { text: 'Query / Summary' }),
        el('th', { text: 'Source' }),
        el('th', { text: '' }),
      ]),
    ]),
  ]);
  const tbody = el('tbody');
  for (const entry of filtered) tbody.append(renderRow(entry));
  table.append(tbody);
  list.append(table);
}

function matchesFilter(entry, q) {
  const hay = [
    entry.query,
    entry.sourceUrl,
    entry.sourceTitle,
    ...(entry.ips || []),
    ...(entry.cves || []),
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return hay.includes(q.toLowerCase());
}

function renderRow(entry) {
  const row = el('tr', {
    attrs: { 'data-id': entry.id },
    on: { click: () => replay(entry) },
  });

  // When
  row.append(el('td', {}, [
    el('span', {
      class: 'history__when',
      text: relTime(entry.createdAt),
      attrs: { title: new Date(entry.createdAt).toLocaleString() },
    }),
  ]));

  // Kind
  row.append(el('td', {}, [
    el('span', {
      class: `history__kind history__kind--${entry.kind}`,
      text: KIND_LABELS[entry.kind] || entry.kind,
    }),
  ]));

  // Query / Summary
  row.append(el('td', {}, [renderQueryCell(entry)]));

  // Source
  row.append(el('td', { class: 'history__source' }, [renderSourceCell(entry)]));

  // Actions
  row.append(el('td', {}, [
    el('span', { class: 'history__actions' }, [
      el('button', {
        class: 'history__action',
        text: '↗',
        attrs: { type: 'button', title: 'Re-open this lookup' },
        on: {
          click: (e) => {
            e.stopPropagation();
            replay(entry);
          },
        },
      }),
      el('button', {
        class: 'history__action history__action--danger',
        text: '✕',
        attrs: { type: 'button', title: 'Remove from history' },
        on: {
          click: async (e) => {
            e.stopPropagation();
            await removeEntry(entry.id);
            allEntries = allEntries.filter((x) => x.id !== entry.id);
            render();
          },
        },
      }),
    ]),
  ]));

  return row;
}

function renderQueryCell(entry) {
  const wrap = el('span', { class: 'history__query' });

  if (entry.kind === 'ip') {
    const rep = entry.summary?.reputation || 'unknown';
    const tone = REP_TONE[rep] || 'unknown';
    const label = entry.summary?.notSeenByCs
      ? 'Not seen'
      : REP_LABELS[rep] || 'Unknown';
    wrap.append(
      el('span', { class: 'mono', text: entry.query || '' }),
      el('span', { class: `rep rep--${tone}`, text: label }),
    );
    if (entry.summary?.country) {
      wrap.append(
        el('span', {
          class: 'muted',
          text: entry.summary.countryName || entry.summary.country,
        }),
      );
    }
    return wrap;
  }

  if (entry.kind === 'cve') {
    wrap.append(el('span', { class: 'tag tag--cve', text: entry.query || '' }));
    return wrap;
  }

  // batch
  const s = entry.summary || {};
  wrap.append(
    el('span', { class: 'mono', text: `${entry.ips?.length || s.total || 0} IPs` }),
    renderMini(s),
  );
  return wrap;
}

function renderMini(s) {
  const bits = el('span', { class: 'history__mini' });
  const add = (tone, label, n) => {
    if (!n) return;
    bits.append(
      el('span', { class: `history__mini-chip history__mini-chip--${tone}`, text: `${n} ${label}` }),
    );
  };
  add('malicious', 'mal', s.malicious);
  add('suspicious', 'susp', s.suspicious);
  add('clean', 'clean', s.clean);
  add('unseen', 'unseen', s.notSeenByCs);
  return bits;
}

function renderSourceCell(entry) {
  if (!entry.sourceUrl) return el('span', { class: 'muted', text: '—' });
  const host = hostnameOf(entry.sourceUrl);
  const title = [entry.sourceUrl, entry.sourceTitle].filter(Boolean).join(' — ');
  return el('a', {
    text: host || entry.sourceUrl,
    attrs: {
      href: entry.sourceUrl,
      target: '_blank',
      rel: 'noopener',
      title,
    },
    on: { click: (e) => e.stopPropagation() },
  });
}

async function replay(entry) {
  if (entry.kind === 'ip' || entry.kind === 'cve') {
    const qs = new URLSearchParams({ kind: entry.kind, value: entry.query || '' });
    if (entry.sourceUrl) qs.set('src', entry.sourceUrl);
    if (entry.sourceTitle) qs.set('srcTitle', entry.sourceTitle);
    const url = chrome.runtime.getURL(`result/result.html?${qs.toString()}`);
    chrome.windows.create({ url, type: 'popup', width: WINDOW_W, height: WINDOW_H });
    return;
  }
  if (entry.kind === 'batch') {
    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    const key = `cs:batch:${id}`;
    await chrome.storage.session.set({
      [key]: {
        ips: entry.ips || [],
        cves: entry.cves || [],
        sourceUrl: entry.sourceUrl || null,
        sourceTitle: entry.sourceTitle || null,
        createdAt: Date.now(),
        ttl: 10 * 60 * 1000,
      },
    });
    const url = chrome.runtime.getURL(`result/result.html?kind=batch&id=${encodeURIComponent(id)}`);
    chrome.windows.create({ url, type: 'popup', width: BATCH_WINDOW_W, height: BATCH_WINDOW_H });
  }
}

filterInput.addEventListener('input', () => {
  filterText = filterInput.value.trim();
  render();
});

clearBtn.addEventListener('click', async () => {
  if (!allEntries.length) return;
  if (!confirm(`Remove all ${allEntries.length} history entries? This cannot be undone.`)) return;
  await clearHistory();
  allEntries = [];
  render();
});

(async function init() {
  allEntries = await listEntries();
  render();
})();
