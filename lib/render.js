// Shared DOM renderer for CrowdSec CTI IP cards.
// Kept framework-free; accepts the raw /smoke/{ip} JSON and a quota object.
// Visual style aligned with ipdex-ui (see ~/github/crowdsec/ipdex-ui).

const COUNTRY_FLAGS = {
  // A tiny best-effort ISO-2 → emoji map. Anything missing falls back to the code itself.
  US: '🇺🇸', CA: '🇨🇦', MX: '🇲🇽', BR: '🇧🇷', AR: '🇦🇷',
  GB: '🇬🇧', IE: '🇮🇪', FR: '🇫🇷', DE: '🇩🇪', ES: '🇪🇸',
  IT: '🇮🇹', PT: '🇵🇹', NL: '🇳🇱', BE: '🇧🇪', LU: '🇱🇺',
  CH: '🇨🇭', AT: '🇦🇹', SE: '🇸🇪', NO: '🇳🇴', DK: '🇩🇰',
  FI: '🇫🇮', IS: '🇮🇸', PL: '🇵🇱', CZ: '🇨🇿', SK: '🇸🇰',
  HU: '🇭🇺', RO: '🇷🇴', BG: '🇧🇬', GR: '🇬🇷', TR: '🇹🇷',
  RU: '🇷🇺', UA: '🇺🇦', BY: '🇧🇾', MD: '🇲🇩', RS: '🇷🇸',
  HR: '🇭🇷', SI: '🇸🇮', BA: '🇧🇦', AL: '🇦🇱', MK: '🇲🇰',
  CN: '🇨🇳', HK: '🇭🇰', TW: '🇹🇼', JP: '🇯🇵', KR: '🇰🇷',
  IN: '🇮🇳', PK: '🇵🇰', BD: '🇧🇩', LK: '🇱🇰', NP: '🇳🇵',
  TH: '🇹🇭', VN: '🇻🇳', ID: '🇮🇩', MY: '🇲🇾', SG: '🇸🇬',
  PH: '🇵🇭', AU: '🇦🇺', NZ: '🇳🇿', ZA: '🇿🇦', EG: '🇪🇬',
  MA: '🇲🇦', NG: '🇳🇬', KE: '🇰🇪', IL: '🇮🇱', SA: '🇸🇦',
  AE: '🇦🇪', QA: '🇶🇦', IR: '🇮🇷', IQ: '🇮🇶',
};

// Reputation key → ipdex-ui tone class. Keeps the full set of reputation values
// but maps them to the four visual tones the UI draws (clean/known/suspicious/malicious/unknown).
const REPUTATION_TONE = {
  malicious: 'malicious',
  suspicious: 'suspicious',
  known: 'known',
  safe: 'clean',
  benign: 'clean',
  unknown: 'unknown',
};

const REPUTATION_LABELS = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  known: 'Known',
  safe: 'Safe',
  benign: 'Benign',
  unknown: 'Unknown',
};

function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.class) node.className = opts.class;
  if (opts.text != null) node.textContent = opts.text;
  if (opts.html != null) node.innerHTML = opts.html;
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

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    node.setAttribute(k, String(v));
  }
  return node;
}

function relTime(value) {
  if (!value) return '—';
  const then = new Date(value);
  if (Number.isNaN(then.getTime())) return '—';
  const diffMs = then.getTime() - Date.now();
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  const units = [
    ['year', 365 * 86400e3],
    ['month', 30 * 86400e3],
    ['day', 86400e3],
    ['hour', 3600e3],
    ['minute', 60e3],
  ];
  for (const [unit, ms] of units) {
    if (Math.abs(diffMs) >= ms || unit === 'minute') {
      return rtf.format(Math.round(diffMs / ms), unit);
    }
  }
  return then.toLocaleString();
}

function countryLabel(code, name) {
  if (!code && !name) return 'Unknown';
  const flag = code ? COUNTRY_FLAGS[code.toUpperCase()] || '' : '';
  return `${flag ? flag + ' ' : ''}${name || code || ''}`.trim();
}

function backgroundNoiseLabel(score) {
  if (score == null) return null;
  if (score >= 8) return 'Very Noisy';
  if (score >= 5) return 'Noisy';
  if (score >= 2) return 'Quiet';
  return 'Very Quiet';
}

function aggressivenessLabel(score) {
  if (score == null) return null;
  const t = typeof score === 'object' ? score.total ?? score.aggressiveness ?? null : score;
  if (t == null) return null;
  if (t >= 4) return 'Very aggressive';
  if (t >= 3) return 'Aggressive';
  if (t >= 2) return 'Moderate';
  if (t >= 1) return 'Low';
  return 'Quiet';
}

function reputationFrom(data) {
  const r = (data?.reputation || data?.classifications?.reputation || '').toLowerCase();
  if (REPUTATION_LABELS[r]) return r;
  // Fallback inference from classifications/scores if reputation field missing.
  const total = data?.scores?.overall?.total ?? 0;
  if (total >= 4) return 'malicious';
  if (total >= 2) return 'suspicious';
  if (total > 0) return 'known';
  return 'unknown';
}

function toTone(rep) {
  return REPUTATION_TONE[rep] || 'unknown';
}

function toScore(data) {
  const raw = data?.scores?.overall?.total;
  if (typeof raw !== 'number' || Number.isNaN(raw)) return null;
  return Math.max(0, Math.min(5, raw));
}

// ---------- Reusable visual bits -------------------------------------------

/** Circular SVG score ring (0–5) — mirrors ipdex-ui's scoreRing component. */
function scoreRing(tone, score) {
  if (score == null) return null;
  const radius = 14;
  const c = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(1, score / 5));
  const offset = c - pct * c;

  const svg = svgEl('svg', { viewBox: '0 0 36 36', width: '36', height: '36' });
  svg.append(
    svgEl('circle', { class: 'score-ring__base', cx: '18', cy: '18', r: String(radius) }),
    svgEl('circle', {
      class: `score-ring__fill score-ring__fill--${tone}`,
      cx: '18',
      cy: '18',
      r: String(radius),
      'stroke-dasharray': String(c),
      'stroke-dashoffset': String(offset),
    }),
  );
  const wrap = el('span', {
    class: 'score-ring',
    attrs: { title: `Score ${score.toFixed(1)} / 5` },
  });
  wrap.append(svg, el('span', { class: 'score-ring__value', text: `${Math.round(score)}` }));
  return wrap;
}

/** Three-bar confidence signal (low / medium / high). */
function confidenceSignal(score) {
  if (score == null) return null;
  const level = score >= 4 ? 'high' : score >= 2 ? 'medium' : 'low';
  const filled = level === 'high' ? 3 : level === 'medium' ? 2 : 1;
  const heights = [4, 7, 10];
  const bars = heights.map((h, i) =>
    el('span', {
      class: `confidence__bar${i < filled ? ' confidence__bar--filled-' + level : ''}`,
      attrs: { style: `height:${h}px` },
    }),
  );
  return el('span', { class: 'confidence', attrs: { title: `Confidence: ${level}` } }, [
    el('span', { class: 'confidence__bars' }, bars),
    el('span', { class: 'confidence__text', text: level }),
  ]);
}

function tag(text, opts = {}) {
  const variant = opts.variant || 'behavior';
  const attrs = opts.onClick ? { role: 'button', tabindex: '0' } : {};
  return el('span', {
    class: `tag tag--${variant}`,
    text,
    attrs,
    on: opts.onClick
      ? { click: opts.onClick, keydown: (e) => (e.key === 'Enter' ? opts.onClick(e) : null) }
      : {},
  });
}

function renderSource(source) {
  if (!source?.url) return null;
  let host = source.url;
  try {
    host = new URL(source.url).host || source.url;
  } catch {
    // leave as-is
  }
  const title = [source.url, source.title].filter(Boolean).join(' — ');
  return el('a', {
    class: 'source',
    text: `From ${host} ↗`,
    attrs: { href: source.url, target: '_blank', rel: 'noopener', title },
  });
}

function renderQuota(quota) {
  if (!quota || (quota.remaining == null && quota.limit == null)) return null;
  let level = 'ok';
  if (quota.remaining != null && quota.limit) {
    const ratio = quota.remaining / quota.limit;
    if (ratio <= 0.1) level = 'crit';
    else if (ratio <= 0.2) level = 'warn';
  }
  const label =
    quota.remaining != null && quota.limit != null
      ? `${quota.remaining}/${quota.limit} queries left`
      : quota.remaining != null
        ? `${quota.remaining} queries left`
        : `limit: ${quota.limit}`;
  return el('span', { class: `quota quota--${level}`, text: label, attrs: { title: 'CTI API quota' } });
}

// ---------- Header ---------------------------------------------------------

function renderHeader(ip, rep, data, quota, opts = {}) {
  const tone = toTone(rep);
  const score = opts.score ?? toScore(data);

  const copyBtn = el('button', {
    class: 'iconbtn',
    attrs: { type: 'button', title: 'Copy IP' },
    text: '⧉',
    on: { click: () => navigator.clipboard?.writeText(ip) },
  });
  const cons = el('a', {
    class: 'outlink',
    text: 'Open in CrowdSec Console ↗',
    attrs: {
      href: `https://app.crowdsec.net/cti/${encodeURIComponent(ip)}`,
      target: '_blank',
      rel: 'noopener',
    },
  });

  const titleBits = [
    el('span', { class: 'ip', text: ip }),
    copyBtn,
    el('span', {
      class: `rep rep--${tone}`,
      text: opts.labelOverride || REPUTATION_LABELS[rep] || 'Unknown',
    }),
  ];
  const ring = scoreRing(tone, score);
  if (ring) titleBits.push(ring);
  const conf = confidenceSignal(score);
  if (conf) titleBits.push(conf);

  return el('header', { class: `card__header card__header--${tone}` }, [
    el('div', { class: 'card__title' }, titleBits),
    el('div', { class: 'card__meta' }, [
      renderSource(opts.source),
      renderQuota(quota),
      cons,
    ].filter(Boolean)),
  ]);
}

// ---------- Facts ---------------------------------------------------------

function renderFacts(data) {
  const score = toScore(data);
  const confidenceLabel =
    score != null ? (score >= 4 ? 'High' : score >= 2 ? 'Medium' : score > 0 ? 'Low' : 'None') : '—';

  const country = countryLabel(data?.location?.country, data?.location?.country_name);
  const firstSeen = data?.history?.first_seen || data?.first_seen;
  const lastSeen = data?.history?.last_seen || data?.last_seen;
  const noise = backgroundNoiseLabel(data?.background_noise_score);

  return el('section', { class: 'facts' }, [
    el('div', { class: 'fact' }, [
      el('span', { class: 'fact__k', text: 'Crowd Confidence' }),
      el('span', { class: 'fact__v', text: confidenceLabel }),
    ]),
    el('div', { class: 'fact' }, [
      el('span', { class: 'fact__k', text: 'Location' }),
      el('span', { class: 'fact__v', text: country }),
    ]),
    el('div', { class: 'fact' }, [
      el('span', { class: 'fact__k', text: 'First Seen' }),
      el('span', { class: 'fact__v', text: relTime(firstSeen) }),
    ]),
    el('div', { class: 'fact' }, [
      el('span', { class: 'fact__k', text: 'Last Seen' }),
      el('span', { class: 'fact__v', text: relTime(lastSeen) }),
    ]),
    el('div', { class: 'fact' }, [
      el('span', { class: 'fact__k', text: 'Background Noise' }),
      el('span', { class: 'fact__v', text: noise || '—' }),
    ]),
  ]);
}

// ---------- Known For / MITRE --------------------------------------------

function renderKnownFor(data) {
  const behaviors = (data?.behaviors || []).map((b) => b.label || b.name).filter(Boolean);
  const cves = Array.from(
    new Set(
      []
        .concat(data?.cves || [])
        .concat(data?.target_countries?.cves || [])
        .map((v) => (typeof v === 'string' ? v : v?.name || v?.id))
        .filter((v) => typeof v === 'string' && /^CVE-\d{4}-\d+/i.test(v))
        .map((v) => v.toUpperCase()),
    ),
  );

  if (!behaviors.length && !cves.length) return null;

  const items = [];
  for (const b of behaviors) items.push(tag(b, { variant: 'behavior' }));
  for (const c of cves) {
    items.push(
      tag(c, {
        variant: 'cve',
        onClick: () =>
          window.open(`https://tracker.crowdsec.net/cves/${encodeURIComponent(c)}`, '_blank', 'noopener'),
      }),
    );
  }

  return el('section', { class: 'section' }, [
    el('h3', { class: 'section__title', text: 'Known For' }),
    el('div', { class: 'tags' }, items),
  ]);
}

function renderMitre(data) {
  const items = (data?.mitre_techniques || []).map((m) => m.label || m.name).filter(Boolean);
  if (!items.length) return null;
  return el('section', { class: 'section' }, [
    el('h3', { class: 'section__title', text: 'MITRE Techniques' }),
    el('div', { class: 'tags' }, items.map((t) => tag(t, { variant: 'mitre' }))),
  ]);
}

// ---------- KPI cards: IP Range / AS / rDNS / Classifications -------------

function renderKpis(data) {
  const ipRange = data?.ip_range || '—';
  const ipRangeScore = aggressivenessLabel(data?.ip_range_score);
  const asName = data?.as_name || data?.asn_name || null;
  const asNum = data?.asn || data?.asn_number || null;
  const reverseDns = data?.reverse_dns || null;
  const classifications = (data?.classifications?.classifications || data?.classifications || [])
    .map((c) => (typeof c === 'string' ? c : c.label || c.name))
    .filter(Boolean);

  return el('section', { class: 'kpi-grid' }, [
    el('div', { class: 'kpi kpi--primary' }, [
      el('div', { class: 'kpi__label', text: 'IP Range' }),
      el('div', { class: 'kpi__value' }, [
        el('span', { class: 'mono', text: ipRange }),
        ipRangeScore ? el('span', { class: 'badge badge--warn', text: ipRangeScore }) : null,
      ].filter(Boolean)),
      asName
        ? el('div', { class: 'kpi__sub', text: `AS: ${asName}${asNum ? ` (${asNum})` : ''}` })
        : null,
    ].filter(Boolean)),
    el('div', { class: 'kpi kpi--indigo' }, [
      el('div', { class: 'kpi__label', text: 'Reverse DNS' }),
      el('div', { class: 'kpi__value' }, [
        el('span', { class: reverseDns ? 'mono' : 'muted', text: reverseDns || 'Unknown' }),
      ]),
    ]),
    el('div', { class: 'kpi kpi--muted' }, [
      el('div', { class: 'kpi__label', text: 'Top Classifications' }),
      classifications.length
        ? el('ul', { class: 'bullets' }, classifications.slice(0, 3).map((c) => el('li', { text: c })))
        : el('span', { class: 'muted', text: 'None recorded' }),
    ]),
  ]);
}

/**
 * Build an IP card into `container` (cleared first). `data` is the raw CTI JSON
 * (or { _notSeen: true, ip } for 404s); `quota` is the optional quota object.
 */
export function renderIpCard(container, ip, data, quota, source) {
  container.textContent = '';

  if (data?._notSeen) {
    container.append(
      renderHeader(ip, 'safe', null, quota, {
        labelOverride: 'Not seen by CrowdSec',
        score: null,
        source,
      }),
      el('div', { class: 'card__body' }, [
        el('p', {
          class: 'empty',
          text: 'CrowdSec has no observations for this IP. That usually means it is clean — but absence of signal is not proof.',
        }),
        el('a', {
          class: 'outlink',
          text: 'Open in CrowdSec Console ↗',
          attrs: {
            href: `https://app.crowdsec.net/cti/${encodeURIComponent(ip)}`,
            target: '_blank',
            rel: 'noopener',
          },
        }),
      ]),
    );
    return;
  }

  const rep = reputationFrom(data);
  container.append(
    renderHeader(ip, rep, data, quota, { source }),
    el('div', { class: 'card__body' }, [
      renderFacts(data),
      renderKnownFor(data),
      renderMitre(data),
      renderKpis(data),
    ]),
  );
}

export function renderError(container, { status, message }) {
  container.textContent = '';
  const isAuth = status === 401 || status === 403;
  container.append(
    el('div', { class: 'error' }, [
      el('h3', { text: isAuth ? 'Authorization problem' : 'Lookup failed' }),
      el('p', { text: message }),
      isAuth
        ? el('a', {
            class: 'outlink',
            text: 'Open Options →',
            attrs: { href: '#' },
            on: {
              click: (e) => {
                e.preventDefault();
                chrome.runtime.openOptionsPage?.();
              },
            },
          })
        : null,
    ].filter(Boolean)),
  );
}

export function renderUnrecognized(container, raw) {
  container.textContent = '';
  container.append(
    el('div', { class: 'error' }, [
      el('h3', { text: 'Unrecognized IOC' }),
      el('p', { text: `"${raw || ''}" doesn't look like an IPv4/IPv6 address or a CVE identifier.` }),
      el('p', {
        class: 'muted',
        text: 'Tip: select only the IP or CVE before right-clicking — surrounding whitespace and punctuation are OK, but prose is not.',
      }),
    ]),
  );
}

// ---------- Batch summary --------------------------------------------------

export function aggregate(results) {
  const total = results.length;
  const reps = { malicious: 0, suspicious: 0, known: 0, safe: 0, unknown: 0 };
  const countries = new Map();
  const networks = new Map();
  const behaviors = new Map();
  const cves = new Map();
  const classifications = new Map();
  const unseen = [];
  const errored = [];
  let knownByCs = 0;
  let backgroundNoisy = 0;
  let targetingCves = 0;
  let onBlocklists = 0;

  const bump = (m, key, extra = {}) => {
    const prev = m.get(key) || { key, count: 0, ...extra };
    prev.count++;
    m.set(key, prev);
  };

  for (const entry of results) {
    if (!entry) continue;
    const { ip, result } = entry;
    if (!result?.ok) {
      errored.push({ ip, message: result?.message || 'failed' });
      continue;
    }
    const d = result.data;
    if (d?._notSeen) {
      unseen.push(ip);
      reps.unknown++;
      continue;
    }
    knownByCs++;

    const rep = reputationFrom(d);
    reps[rep] = (reps[rep] || 0) + 1;

    const cc = d?.location?.country;
    if (cc) bump(countries, cc.toUpperCase(), { name: d?.location?.country_name || cc });

    const asName = d?.as_name || d?.asn_name;
    if (asName) bump(networks, asName);

    for (const b of d?.behaviors || []) {
      const label = b.label || b.name;
      if (label) bump(behaviors, label);
    }

    const cveRefs = Array.from(
      new Set(
        []
          .concat(d?.cves || [])
          .map((v) => (typeof v === 'string' ? v : v?.name || v?.id))
          .filter((v) => typeof v === 'string' && /^CVE-\d{4}-\d+/i.test(v))
          .map((v) => v.toUpperCase()),
      ),
    );
    if (cveRefs.length) targetingCves++;
    for (const c of cveRefs) bump(cves, c);

    if ((d?.background_noise_score || 0) >= 5) backgroundNoisy++;

    const cls = (d?.classifications?.classifications || d?.classifications || [])
      .map((c) => (typeof c === 'string' ? c : c.label || c.name))
      .filter(Boolean);
    let isBlocklisted = false;
    for (const c of cls) {
      bump(classifications, c);
      if (/blocklist/i.test(c)) isBlocklisted = true;
    }
    if (isBlocklisted) onBlocklists++;
  }

  const sortDesc = (m) => [...m.values()].sort((a, b) => b.count - a.count);

  return {
    total,
    knownByCs,
    reps,
    countries: sortDesc(countries),
    networks: sortDesc(networks),
    behaviors: sortDesc(behaviors),
    cves: sortDesc(cves),
    classifications: sortDesc(classifications),
    backgroundNoisy,
    targetingCves,
    onBlocklists,
    unseen,
    errored,
  };
}

function pct(n, d) {
  if (!d) return 0;
  return Math.round((n / d) * 100);
}

/** Compact roll-up used by the history list (avoids re-fetching on render). */
export function summarizeForHistory(agg) {
  const cleanCount = (agg.reps.safe || 0) + (agg.reps.benign || 0) + (agg.reps.known || 0);
  return {
    total: agg.total,
    knownByCs: agg.knownByCs,
    malicious: agg.reps.malicious || 0,
    suspicious: agg.reps.suspicious || 0,
    known: agg.reps.known || 0,
    clean: cleanCount,
    notSeenByCs: agg.unseen?.length || 0,
    errored: agg.errored?.length || 0,
  };
}

/** Compact summary for a single-IP history entry. */
export function summarizeIpForHistory(data) {
  if (!data || data._notSeen) {
    return { reputation: 'unknown', score: null, country: null, notSeenByCs: !!data?._notSeen };
  }
  return {
    reputation: reputationFrom(data),
    score: toScore(data),
    country: data?.location?.country || null,
    countryName: data?.location?.country_name || null,
    notSeenByCs: false,
  };
}

function renderRepPills(agg) {
  const items = [
    { kind: 'malicious', label: 'malicious' },
    { kind: 'suspicious', label: 'suspicious' },
    { kind: 'known', label: 'known' },
    { kind: 'safe', label: 'safe', tone: 'clean' },
  ];
  const nodes = [];
  for (const it of items) {
    const n = agg.reps[it.kind] || 0;
    if (!n) continue;
    const tone = it.tone || it.kind;
    nodes.push(
      el('span', { class: `rep-pill rep-pill--${tone}` }, [
        el('span', { class: 'rep-pill__count', text: String(n) }),
        ' ',
        el('span', { text: it.label }),
      ]),
    );
  }
  if (!nodes.length) {
    nodes.push(
      el('span', { class: 'rep-pill rep-pill--unknown' }, [
        el('span', { class: 'rep-pill__count', text: String(agg.total) }),
        ' ',
        el('span', { text: 'IPs with no reputation data' }),
      ]),
    );
  }
  return el('div', { class: 'rep-pills' }, nodes);
}

function renderKnownBar(agg) {
  const percent = pct(agg.knownByCs, agg.total);
  return el('div', { class: 'known-bar' }, [
    el('div', { class: 'known-bar__label' }, [
      el('span', { class: 'known-bar__title', text: 'Known by CrowdSec' }),
      el('span', {
        class: 'known-bar__value',
        html: `<strong>${percent}%</strong> (${agg.knownByCs} / ${agg.total} IPs)`,
      }),
    ]),
    el('div', { class: 'known-bar__track' }, [
      el('div', { class: 'known-bar__fill', attrs: { style: `width:${percent}%` } }),
    ]),
  ]);
}

function renderInsights(agg) {
  const lines = [
    { pct: pct(agg.reps.malicious || 0, agg.total), text: 'malicious', tone: 'malicious' },
    { pct: pct(agg.reps.suspicious || 0, agg.total), text: 'suspicious', tone: 'suspicious' },
    { pct: pct(agg.backgroundNoisy, agg.total), text: 'background noise', tone: 'known' },
    { pct: pct(agg.targetingCves, agg.total), text: 'targeting CVEs', tone: 'cve' },
    { pct: pct(agg.onBlocklists, agg.total), text: 'on CrowdSec blocklists', tone: 'blocklist' },
  ];
  return el('div', { class: 'insights' },
    lines.map((l) =>
      el('div', { class: `insight insight--${l.tone}` }, [
        el('span', { text: `% of IPs are ${l.text}` }),
        el('span', { class: 'insight__num', text: `${l.pct}%` }),
      ]),
    ),
  );
}

function renderKpiRow(agg) {
  // ipdex-ui KPI row: clean / suspicious / malicious cards with colored top borders and mini bars.
  const cleanCount = (agg.reps.safe || 0) + (agg.reps.benign || 0) + (agg.reps.known || 0);
  const suspiciousCount = agg.reps.suspicious || 0;
  const maliciousCount = agg.reps.malicious || 0;
  const denom = agg.knownByCs || agg.total || 1;

  const card = (tone, label, count) => {
    const percent = pct(count, denom);
    return el('div', { class: `kpi kpi--${tone}` }, [
      el('div', { class: 'kpi__label', text: label }),
      el('div', { class: 'kpi__value' }, [
        el('span', { text: String(count) }),
        el('span', { class: 'kpi__fraction', text: ` / ${denom}` }),
      ]),
      el('div', { class: 'kpi__track' }, [
        el('div', {
          class: `kpi__fill--${tone}`,
          attrs: { style: `width:${percent}%` },
        }),
      ]),
    ]);
  };

  return el('section', { class: 'kpi-row' }, [
    card('clean', 'Clean / Known', cleanCount),
    card('suspicious', 'Suspicious', suspiciousCount),
    card('malicious', 'Malicious', maliciousCount),
  ]);
}

function facetColumn(title, items, total, opts = {}) {
  const top = items.slice(0, 5);
  const rest = items.length - top.length;
  const rows = top.map((item) => {
    const percent = pct(item.count, total);
    const name = opts.label ? opts.label(item) : item.key;
    const nameNode = opts.tagVariant
      ? el('span', { class: `tag tag--${opts.tagVariant}`, text: name })
      : el('span', { class: 'facet__name', text: name, attrs: { title: name } });
    return el('div', { class: 'facet__row' }, [
      nameNode,
      el('span', { class: 'facet__count', text: String(item.count) }),
      el('span', { class: 'facet__pct', text: `(${percent}%)` }),
    ]);
  });

  return el(
    'div',
    { class: 'facet' },
    [
      el('div', { class: 'facet__title', text: title }),
      el(
        'div',
        { class: 'facet__rows' },
        rows.length ? rows : [el('span', { class: 'muted', text: 'None' })],
      ),
      rest > 0 ? el('div', { class: 'facet__more', text: `+${rest} more` }) : null,
    ].filter(Boolean),
  );
}

function renderSummaryTop(agg) {
  return el('div', { class: 'summary__top' }, [
    el('div', { class: 'summary__top-left' }, [
      el('div', { class: 'summary__count' }, [
        el('span', { class: 'summary__num', text: String(agg.total) }),
        el('span', { class: 'summary__unit', text: 'IPs' }),
      ]),
      renderRepPills(agg),
      renderKnownBar(agg),
    ]),
    renderInsights(agg),
  ]);
}

function renderFacets(agg) {
  const denom = agg.knownByCs || agg.total;

  const countryCol = facetColumn('Countries', agg.countries, denom, {
    label: (c) => `${COUNTRY_FLAGS[c.key] || ''} ${c.name || c.key}`.trim(),
  });
  const networksCol = facetColumn('Networks', agg.networks, denom, {
    label: (n) => (n.key.length > 22 ? n.key.slice(0, 22) + '…' : n.key),
  });
  const behaviorsCol = facetColumn('Behaviors', agg.behaviors, denom, { tagVariant: 'behavior' });
  const cvesCol = facetColumn('CVEs', agg.cves, denom, { tagVariant: 'cve' });
  const classCol = facetColumn('Classifications', agg.classifications, denom, {
    tagVariant: 'classif',
  });

  return el('section', { class: 'summary__facets' }, [
    el('div', { class: 'summary__facets-head' }, [
      el('span', { class: 'section__title', text: 'Summary' }),
      el('div', { class: 'summary__counts' }, [
        el('span', { class: 'pill pill--muted', text: `${agg.countries.length} countries` }),
        el('span', { class: 'pill pill--muted', text: `${agg.networks.length} networks` }),
        el('span', { class: 'pill pill--muted', text: `${agg.behaviors.length} behaviors` }),
        el('span', { class: 'pill pill--muted', text: `${agg.cves.length} CVEs` }),
        el('span', { class: 'pill pill--muted', text: `${agg.classifications.length} classifications` }),
      ]),
    ]),
    el('div', { class: 'facet-grid' }, [countryCol, networksCol, behaviorsCol, cvesCol, classCol]),
  ]);
}

function renderIpTable(results) {
  if (!results?.length) return null;
  const table = el('table', { class: 'ip-table' }, [
    el('thead', {}, [
      el('tr', {}, [
        el('th', { text: 'IP' }),
        el('th', { text: 'Reputation' }),
        el('th', { text: 'Country' }),
        el('th', { text: 'AS' }),
      ]),
    ]),
  ]);
  const tbody = el('tbody');
  for (const { ip, result } of results) {
    if (!result?.ok) {
      tbody.append(
        el('tr', { class: 'ip-row ip-row--err' }, [
          el('td', {}, [ipCell(ip)]),
          el('td', { attrs: { colspan: '3' } }, [
            el('span', { class: 'muted', text: result?.message || 'error' }),
          ]),
        ]),
      );
      continue;
    }
    if (result.data?._notSeen) {
      tbody.append(
        el('tr', { class: 'ip-row' }, [
          el('td', {}, [ipCell(ip)]),
          el('td', {}, [el('span', { class: 'rep rep--clean', text: 'Not seen' })]),
          el('td', { class: 'muted', text: '—' }),
          el('td', { class: 'muted', text: '—' }),
        ]),
      );
      continue;
    }
    const d = result.data;
    const rep = reputationFrom(d);
    const tone = toTone(rep);
    tbody.append(
      el('tr', { class: 'ip-row' }, [
        el('td', {}, [ipCell(ip, { tone, asLink: true })]),
        el('td', {}, [
          el('span', {
            class: `rep rep--${tone}`,
            text: REPUTATION_LABELS[rep] || 'Unknown',
          }),
        ]),
        el('td', { text: countryLabel(d?.location?.country, d?.location?.country_name) || '—' }),
        el('td', { class: 'mono-sm', text: d?.as_name || d?.asn_name || '—' }),
      ]),
    );
  }
  table.append(tbody);

  const details = el('details', { class: 'ip-list', attrs: { open: true } }, [
    el('summary', { text: `All ${results.length} IPs` }),
    table,
  ]);
  return details;
}

function ipCell(ip, opts = {}) {
  const copyBtn = el('button', {
    class: 'ip-cell__copy',
    attrs: { type: 'button', title: 'Copy IP' },
    text: '⧉',
    on: {
      click: (e) => {
        e.preventDefault();
        e.stopPropagation();
        navigator.clipboard?.writeText(ip);
      },
    },
  });
  const children = [];
  if (opts.tone) children.push(el('span', { class: `dot dot--${opts.tone} dot--sm` }));
  children.push(
    opts.asLink
      ? el('a', {
          text: ip,
          attrs: {
            href: `https://app.crowdsec.net/cti/${encodeURIComponent(ip)}`,
            target: '_blank',
            rel: 'noopener',
          },
        })
      : el('span', { text: ip }),
  );
  children.push(copyBtn);
  return el('span', { class: 'ip-cell' }, children);
}

export function renderSummaryCard(container, { ips, results, quota, source }) {
  container.textContent = '';
  const agg = aggregate(results);

  container.append(
    el('header', { class: 'card__header summary__header' }, [
      el('div', { class: 'card__title' }, [
        el('span', { class: 'summary__label', text: 'Batch lookup' }),
        el('span', {
          class: 'muted',
          text: `${ips.length} selected, ${agg.total} unique`,
        }),
      ]),
      el('div', { class: 'card__meta' }, [
        renderSource(source),
        renderQuota(quota),
        el('button', {
          class: 'iconbtn',
          text: 'Copy JSON',
          attrs: { type: 'button', title: 'Copy summary as JSON' },
          on: {
            click: () => {
              const payload = {
                generatedAt: new Date().toISOString(),
                total: agg.total,
                knownByCs: agg.knownByCs,
                reps: agg.reps,
                countries: agg.countries.map((c) => ({ code: c.key, name: c.name, count: c.count })),
                networks: agg.networks.map((n) => ({ name: n.key, count: n.count })),
                behaviors: agg.behaviors.map((b) => ({ name: b.key, count: b.count })),
                cves: agg.cves.map((c) => ({ name: c.key, count: c.count })),
                classifications: agg.classifications.map((c) => ({ name: c.key, count: c.count })),
                unseen: agg.unseen,
                errored: agg.errored,
              };
              navigator.clipboard?.writeText(JSON.stringify(payload, null, 2));
            },
          },
        }),
      ].filter(Boolean)),
    ]),
    el('div', { class: 'card__body' }, [
      renderSummaryTop(agg),
      renderKpiRow(agg),
      renderFacets(agg),
      renderIpTable(results),
    ]),
  );
}

export function renderProgress(container, { done, total, cached }) {
  // Idempotent: called many times from the progress callback.
  let wrap = container.querySelector('.progress');
  if (!wrap) {
    container.textContent = '';
    const body = el('div', { class: 'card__body' }, [
      el('div', { class: 'progress' }, [
        el('div', { class: 'progress__label' }, [
          el('strong', { class: 'progress__done' }),
          el('span', { class: 'progress__slash', text: ' / ' }),
          el('span', { class: 'progress__total' }),
          el('span', { class: 'progress__cached' }),
        ]),
        el('div', { class: 'progress__track' }, [el('div', { class: 'progress__fill' })]),
        el('p', {
          class: 'progress__hint',
          text: 'Looking up IPs — cached IPs do not consume quota.',
        }),
      ]),
    ]);
    container.append(body);
    wrap = body.querySelector('.progress');
  }
  wrap.querySelector('.progress__done').textContent = String(done);
  wrap.querySelector('.progress__total').textContent = String(total);
  wrap.querySelector('.progress__cached').textContent = cached ? ` (${cached} from cache)` : '';
  const percent = total ? Math.round((done / total) * 100) : 0;
  wrap.querySelector('.progress__fill').style.width = `${percent}%`;
}

export function renderBatchConfirm(container, { ips, miss, hit, onConfirm }) {
  container.textContent = '';
  const msg = miss.length
    ? `Found ${ips.length} unique IPs. ${hit} are cached; this will consume up to ${miss.length} queries from your daily CTI quota.`
    : `Found ${ips.length} unique IPs — all served from cache, no quota impact.`;
  container.append(
    el('div', { class: 'card__body' }, [
      el('div', { class: 'confirm' }, [
        el('h3', { text: 'Batch lookup' }),
        el('p', { text: msg }),
        el('div', { class: 'confirm__actions' }, [
          el('button', {
            class: 'primary',
            text: 'Run lookup',
            attrs: { type: 'button' },
            on: { click: onConfirm },
          }),
        ]),
      ]),
    ]),
  );
}

export function renderCvePlaceholder(container, cve, quota, source) {
  container.textContent = '';
  container.append(
    el('header', { class: 'card__header card__header--suspicious' }, [
      el('div', { class: 'card__title' }, [
        el('span', { class: 'ip', text: cve }),
        el('span', { class: 'rep rep--suspicious', text: 'CVE' }),
      ]),
      el('div', { class: 'card__meta' }, [
        renderSource(source),
        renderQuota(quota),
      ].filter(Boolean)),
    ]),
    el('div', { class: 'card__body' }, [
      el('p', {
        class: 'empty',
        text: 'CVE lookups are coming in a later version of this extension. In the meantime, open the full page on CrowdSec Live Exploit Tracker:',
      }),
      el('a', {
        class: 'outlink',
        text: `View ${cve} on LET ↗`,
        attrs: {
          href: `https://tracker.crowdsec.net/cves/${encodeURIComponent(cve)}`,
          target: '_blank',
          rel: 'noopener',
        },
      }),
    ]),
  );
}
