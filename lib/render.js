// Shared DOM renderer for CrowdSec CTI IP cards.
// Kept framework-free; accepts the raw /smoke/{ip} JSON and a quota object.

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

const REPUTATION_COLORS = {
  malicious: 'red',
  suspicious: 'orange',
  known: 'yellow',
  safe: 'green',
  benign: 'green',
  unknown: 'grey',
};

const REPUTATION_LABELS = {
  malicious: 'Malicious IP',
  suspicious: 'Suspicious IP',
  known: 'Known IP',
  safe: 'Safe IP',
  benign: 'Benign IP',
  unknown: 'Unknown IP',
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
  const r = (data.reputation || data.classifications?.reputation || '').toLowerCase();
  if (REPUTATION_LABELS[r]) return r;
  // Fallback inference from classifications/scores if reputation field missing.
  const total = data?.scores?.overall?.total ?? 0;
  if (total >= 4) return 'malicious';
  if (total >= 2) return 'suspicious';
  if (total > 0) return 'known';
  return 'unknown';
}

function chip(text, opts = {}) {
  return el('span', {
    class: `chip${opts.variant ? ' chip--' + opts.variant : ''}`,
    text,
    attrs: opts.href ? { role: 'link', tabindex: '0' } : {},
    on: opts.onClick ? { click: opts.onClick, keydown: (e) => (e.key === 'Enter' ? opts.onClick(e) : null) } : {},
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

function renderHeader(ip, rep, quota) {
  const dot = el('span', { class: `dot dot--${REPUTATION_COLORS[rep] || 'grey'}` });
  const copyBtn = el('button', {
    class: 'iconbtn',
    attrs: { type: 'button', title: 'Copy IP' },
    text: '⧉',
    on: {
      click: () => {
        navigator.clipboard?.writeText(ip);
      },
    },
  });
  const console = el('a', {
    class: 'outlink',
    text: 'Open in CrowdSec Console ↗',
    attrs: { href: `https://app.crowdsec.net/cti/${encodeURIComponent(ip)}`, target: '_blank', rel: 'noopener' },
  });

  return el('header', { class: 'card__header' }, [
    el('div', { class: 'card__title' }, [
      dot,
      el('span', { class: 'ip', text: ip }),
      copyBtn,
      el('span', { class: `rep rep--${REPUTATION_COLORS[rep] || 'grey'}`, text: REPUTATION_LABELS[rep] || 'Unknown' }),
    ]),
    el('div', { class: 'card__meta' }, [renderQuota(quota), console].filter(Boolean)),
  ]);
}

function renderFacts(data) {
  const overall = data?.scores?.overall?.total;
  const confidenceBar = overall != null
    ? el('span', { class: 'bar' }, [
        el('span', { class: 'bar__fill', attrs: { style: `width:${Math.min(100, (overall / 5) * 100)}%` } }),
      ])
    : null;

  const confidenceLabel = overall != null
    ? overall >= 4 ? 'High' : overall >= 2 ? 'Medium' : overall > 0 ? 'Low' : 'None'
    : '—';

  const country = countryLabel(data?.location?.country, data?.location?.country_name);
  const firstSeen = data?.history?.first_seen || data?.first_seen;
  const lastSeen = data?.history?.last_seen || data?.last_seen;
  const noise = backgroundNoiseLabel(data?.background_noise_score);

  return el('section', { class: 'facts' }, [
    el('div', { class: 'facts__col' }, [
      el('div', { class: 'fact' }, [
        el('span', { class: 'fact__k', text: 'Crowd Confidence' }),
        el('span', { class: 'fact__v' }, [confidenceLabel, confidenceBar].filter(Boolean)),
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
    ]),
    el('div', { class: 'facts__col facts__col--right' }, [
      el('div', { class: 'fact' }, [
        el('span', { class: 'fact__k', text: 'Background Noise' }),
        el('span', { class: 'fact__v', text: noise || '—' }),
      ]),
    ]),
  ]);
}

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

  const chips = [];
  for (const b of behaviors) chips.push(chip(b));
  for (const c of cves) {
    chips.push(
      chip(c, {
        variant: 'cve',
        onClick: () => window.open(`https://tracker.crowdsec.net/cves/${encodeURIComponent(c)}`, '_blank', 'noopener'),
      }),
    );
  }

  return el('section', { class: 'section' }, [
    el('h3', { class: 'section__title', text: 'Known For' }),
    el('div', { class: 'chips' }, chips),
  ]);
}

function renderMitre(data) {
  const items = (data?.mitre_techniques || []).map((m) => m.label || m.name).filter(Boolean);
  if (!items.length) return null;
  return el('section', { class: 'section' }, [
    el('h3', { class: 'section__title', text: 'MITRE Techniques' }),
    el('div', { class: 'chips' }, items.map((t) => chip(t, { variant: 'mitre' }))),
  ]);
}

function renderPanels(data) {
  const ipRange = data?.ip_range || '—';
  const ipRangeScore = aggressivenessLabel(data?.ip_range_score);
  const asName = data?.as_name || data?.asn_name || null;
  const asNum = data?.asn || data?.asn_number || null;
  const reverseDns = data?.reverse_dns || null;
  const classifications = (data?.classifications?.classifications || data?.classifications || [])
    .map((c) => (typeof c === 'string' ? c : c.label || c.name))
    .filter(Boolean);

  return el('section', { class: 'panels' }, [
    el('div', { class: 'panel' }, [
      el('div', { class: 'panel__title', text: 'IP Range' }),
      el('div', { class: 'panel__body' }, [
        el('div', { class: 'panel__row' }, [
          el('span', { class: 'mono', text: ipRange }),
          ipRangeScore ? el('span', { class: 'badge badge--warn', text: ipRangeScore }) : null,
        ].filter(Boolean)),
        asName ? el('div', { class: 'panel__sub', text: `AS: ${asName}${asNum ? ` (${asNum})` : ''}` }) : null,
      ].filter(Boolean)),
    ]),
    el('div', { class: 'panel' }, [
      el('div', { class: 'panel__title', text: 'Reverse DNS' }),
      el('div', { class: 'panel__body' }, [
        el('span', { class: reverseDns ? 'mono' : 'muted', text: reverseDns || 'Unknown' }),
      ]),
    ]),
    el('div', { class: 'panel' }, [
      el('div', { class: 'panel__title', text: 'Top Classifications' }),
      el('div', { class: 'panel__body' }, [
        classifications.length
          ? el('ul', { class: 'bullets' }, classifications.slice(0, 3).map((c) => el('li', { text: c })))
          : el('span', { class: 'muted', text: 'None recorded' }),
      ]),
    ]),
  ]);
}

/**
 * Build an IP card into `container` (cleared first). `data` is the raw CTI JSON
 * (or { _notSeen: true, ip } for 404s); `quota` is the optional quota object.
 */
export function renderIpCard(container, ip, data, quota) {
  container.textContent = '';

  if (data?._notSeen) {
    container.append(
      el('header', { class: 'card__header' }, [
        el('div', { class: 'card__title' }, [
          el('span', { class: 'dot dot--green' }),
          el('span', { class: 'ip', text: ip }),
          el('span', { class: 'rep rep--green', text: 'Not seen by CrowdSec' }),
        ]),
        el('div', { class: 'card__meta' }, [renderQuota(quota)].filter(Boolean)),
      ]),
      el('p', { class: 'empty', text: 'CrowdSec has no observations for this IP. That usually means it is clean — but absence of signal is not proof.' }),
      el('a', {
        class: 'outlink',
        text: 'Open in CrowdSec Console ↗',
        attrs: { href: `https://app.crowdsec.net/cti/${encodeURIComponent(ip)}`, target: '_blank', rel: 'noopener' },
      }),
    );
    return;
  }

  const rep = reputationFrom(data);
  container.append(
    renderHeader(ip, rep, quota),
    renderFacts(data),
    renderKnownFor(data),
    renderMitre(data),
    renderPanels(data),
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
            attrs: { href: '#', },
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
      el('p', { class: 'muted', text: 'Tip: select only the IP or CVE before right-clicking — surrounding whitespace and punctuation are OK, but prose is not.' }),
    ]),
  );
}

// ---------- Batch summary --------------------------------------------------

function aggregate(results) {
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

function renderRepPills(agg) {
  const items = [
    { kind: 'malicious', label: 'malicious', color: 'red' },
    { kind: 'suspicious', label: 'suspicious', color: 'orange' },
    { kind: 'known', label: 'known', color: 'yellow' },
    { kind: 'safe', label: 'safe', color: 'green' },
  ];
  const nodes = [];
  for (const it of items) {
    const n = agg.reps[it.kind] || 0;
    if (!n) continue;
    nodes.push(el('span', { class: `rep-pill rep-pill--${it.color}`, text: `${n} ${it.label}` }));
  }
  if (!nodes.length) nodes.push(el('span', { class: 'rep-pill rep-pill--grey', text: `${agg.total} IPs with no reputation data` }));
  return el('div', { class: 'rep-pills' }, nodes);
}

function renderKnownBar(agg) {
  const percent = pct(agg.knownByCs, agg.total);
  return el('div', { class: 'known-bar' }, [
    el('div', { class: 'known-bar__label' }, [
      el('span', { class: 'known-bar__title', text: 'KNOWN BY CROWDSEC' }),
      el('span', { class: 'known-bar__value', html: `<strong>${percent}%</strong> (${agg.knownByCs} / ${agg.total} IPs)` }),
    ]),
    el('div', { class: 'known-bar__track' }, [
      el('div', { class: 'known-bar__fill', attrs: { style: `width:${percent}%` } }),
    ]),
  ]);
}

function renderHeadlineStats(agg) {
  const lines = [
    { pct: pct(agg.reps.malicious || 0, agg.total), text: 'of the IPs are malicious', tone: 'red' },
    { pct: pct(agg.reps.suspicious || 0, agg.total), text: 'of the IPs are suspicious', tone: 'orange' },
    { pct: pct(agg.backgroundNoisy, agg.total), text: 'of the IPs are background noise', tone: 'yellow' },
    { pct: pct(agg.targetingCves, agg.total), text: 'are targeting CVEs', tone: 'cve' },
    { pct: pct(agg.onBlocklists, agg.total), text: 'of the IPs are on CrowdSec blocklists', tone: 'blocklist' },
  ];
  return el('div', { class: 'headline-stats' }, lines.map((l) =>
    el('div', { class: `headline-stat headline-stat--${l.tone}` }, [
      el('span', { class: 'headline-stat__num', text: `${l.pct}%` }),
      el('span', { class: 'headline-stat__txt', text: l.text }),
    ]),
  ));
}

function facetColumn(title, items, total, opts = {}) {
  const top = items.slice(0, 5);
  const rest = items.length - top.length;
  const rows = top.map((item) => {
    const percent = pct(item.count, total);
    const name = opts.label ? opts.label(item) : item.key;
    const nameNode = opts.chip
      ? el('span', { class: `chip chip--${opts.chipVariant || ''}`, text: name })
      : el('span', { class: 'facet__name', text: name, attrs: { title: name } });
    return el('div', { class: 'facet__row' }, [
      nameNode,
      el('span', { class: 'facet__count', text: String(item.count) }),
      el('span', { class: 'facet__pct', text: `(${percent}%)` }),
    ]);
  });

  return el('div', { class: 'facet' }, [
    el('div', { class: 'facet__title', text: title }),
    el('div', { class: 'facet__rows' }, rows.length ? rows : [el('span', { class: 'muted', text: 'None' })]),
    rest > 0 ? el('div', { class: 'facet__more', text: `+${rest} more` }) : null,
  ].filter(Boolean));
}

function renderSummaryHeader(agg) {
  return el('div', { class: 'summary__top' }, [
    el('div', { class: 'summary__top-left' }, [
      el('div', { class: 'summary__count' }, [
        el('span', { class: 'summary__num', text: String(agg.total) }),
        el('span', { class: 'summary__unit', text: 'IPs' }),
      ]),
      renderRepPills(agg),
      renderKnownBar(agg),
    ]),
    renderHeadlineStats(agg),
  ]);
}

function renderFacets(agg) {
  const denom = agg.knownByCs || agg.total; // match the web UI: percentages over observed IPs

  const countryCol = facetColumn('COUNTRIES', agg.countries, denom, {
    label: (c) => `${COUNTRY_FLAGS[c.key] || ''} ${c.name || c.key}`.trim(),
  });
  const networksCol = facetColumn('NETWORKS', agg.networks, denom, {
    label: (n) => (n.key.length > 22 ? n.key.slice(0, 22) + '…' : n.key),
  });
  const behaviorsCol = facetColumn('BEHAVIORS', agg.behaviors, denom, {
    chip: true,
    chipVariant: '',
  });
  const cvesCol = facetColumn('CVES', agg.cves, denom, {
    chip: true,
    chipVariant: 'cve',
  });
  const classCol = facetColumn('CLASSIFICATIONS', agg.classifications, denom, {
    chip: true,
    chipVariant: 'mitre',
  });

  return el('section', { class: 'summary__facets' }, [
    el('div', { class: 'summary__facets-head' }, [
      el('span', { class: 'section__title', text: '> SUMMARY' }),
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
      tbody.append(el('tr', { class: 'ip-row ip-row--err' }, [
        el('td', { class: 'mono', text: ip }),
        el('td', { attrs: { colspan: '3' } }, [el('span', { class: 'muted', text: result?.message || 'error' })]),
      ]));
      continue;
    }
    if (result.data?._notSeen) {
      tbody.append(el('tr', { class: 'ip-row' }, [
        el('td', { class: 'mono', text: ip }),
        el('td', {}, [el('span', { class: 'rep rep--green', text: 'Not seen' })]),
        el('td', { class: 'muted', text: '—' }),
        el('td', { class: 'muted', text: '—' }),
      ]));
      continue;
    }
    const d = result.data;
    const rep = reputationFrom(d);
    const color = REPUTATION_COLORS[rep] || 'grey';
    tbody.append(el('tr', { class: 'ip-row' }, [
      el('td', { class: 'mono' }, [
        el('span', { class: `dot dot--${color} dot--sm` }),
        ' ',
        el('a', {
          text: ip,
          attrs: { href: `https://app.crowdsec.net/cti/${encodeURIComponent(ip)}`, target: '_blank', rel: 'noopener' },
        }),
      ]),
      el('td', {}, [el('span', { class: `rep rep--${color}`, text: REPUTATION_LABELS[rep] || 'Unknown' })]),
      el('td', { text: countryLabel(d?.location?.country, d?.location?.country_name) || '—' }),
      el('td', { class: 'mono-sm', text: d?.as_name || d?.asn_name || '—' }),
    ]));
  }
  table.append(tbody);

  const details = el('details', { class: 'ip-list' }, [
    el('summary', { text: `Show all ${results.length} IPs` }),
    table,
  ]);
  return details;
}

export function renderSummaryCard(container, { ips, results, quota }) {
  container.textContent = '';
  const agg = aggregate(results);

  container.append(
    el('header', { class: 'card__header summary__header' }, [
      el('div', { class: 'card__title' }, [
        el('span', { class: 'dot dot--orange' }),
        el('span', { class: 'summary__label', text: 'Batch lookup' }),
        el('span', { class: 'muted', text: `${ips.length} selected, ${agg.total} unique` }),
      ]),
      el('div', { class: 'card__meta' }, [
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
    renderSummaryHeader(agg),
    renderFacets(agg),
    renderIpTable(results),
  );
}

export function renderProgress(container, { done, total, cached }) {
  // Idempotent: called many times from the progress callback.
  let wrap = container.querySelector('.progress');
  if (!wrap) {
    container.textContent = '';
    wrap = el('div', { class: 'progress' }, [
      el('div', { class: 'progress__label' }, [
        el('strong', { class: 'progress__done' }),
        el('span', { class: 'progress__slash', text: ' / ' }),
        el('span', { class: 'progress__total' }),
        el('span', { class: 'muted progress__cached' }),
      ]),
      el('div', { class: 'progress__track' }, [el('div', { class: 'progress__fill' })]),
      el('p', { class: 'muted progress__hint', text: 'Looking up IPs — cached IPs do not consume quota.' }),
    ]);
    container.append(wrap);
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
  );
}

export function renderCvePlaceholder(container, cve, quota) {
  container.textContent = '';
  container.append(
    el('header', { class: 'card__header' }, [
      el('div', { class: 'card__title' }, [
        el('span', { class: 'dot dot--orange' }),
        el('span', { class: 'ip', text: cve }),
        el('span', { class: 'rep rep--orange', text: 'CVE' }),
      ]),
      el('div', { class: 'card__meta' }, [renderQuota(quota)].filter(Boolean)),
    ]),
    el('p', { class: 'empty', text: 'CVE lookups are coming in a later version of this extension. In the meantime, open the full page on CrowdSec Live Exploit Tracker:' }),
    el('a', {
      class: 'outlink',
      text: `View ${cve} on LET ↗`,
      attrs: {
        href: `https://tracker.crowdsec.net/cves/${encodeURIComponent(cve)}`,
        target: '_blank',
        rel: 'noopener',
      },
    }),
  );
}
