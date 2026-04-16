// Classifies a user-selected string as an IP, CVE, or unknown IOC.
// Keep this tiny and dependency-free; the service worker imports it.

const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;

// Covers full, compressed, and mixed-notation IPv6. Good enough for POC triage;
// we don't need to be RFC-perfect — the API is the source of truth.
const IPV6_RE = /^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))$/;

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

// Strips common surrounding punctuation (brackets, parens, quotes, trailing
// commas / periods) so selecting `[1.2.3.4]` or `"1.2.3.4",` still works.
function clean(raw) {
  if (typeof raw !== 'string') return '';
  return raw.trim().replace(/^[\s\[\](){}"'`]+|[\s\[\](){}"'`,.;:]+$/g, '');
}

export function classify(raw) {
  const value = clean(raw);
  if (!value) return { kind: 'unknown', value: '' };

  if (IPV4_RE.test(value)) return { kind: 'ip', value };
  if (IPV6_RE.test(value)) return { kind: 'ip', value };

  // `1.2.3.4:80` — tolerate IPv4 with port suffix common in log lines.
  const portMatch = value.match(/^((?:\d{1,3}\.){3}\d{1,3}):\d{1,5}$/);
  if (portMatch && IPV4_RE.test(portMatch[1])) return { kind: 'ip', value: portMatch[1] };

  // `[2001:db8::1]:80` — bracket-wrapped IPv6 with optional port. `clean()`
  // may have already stripped the leading `[`, so we also accept `ip]:port`.
  const v6Bracket = value.match(/^\[?([^\]]+)\](?::\d{1,5})?$/);
  if (v6Bracket && IPV6_RE.test(v6Bracket[1])) return { kind: 'ip', value: v6Bracket[1] };

  if (CVE_RE.test(value)) return { kind: 'cve', value: value.toUpperCase() };

  return { kind: 'unknown', value };
}

/**
 * Extract every IP and CVE found anywhere in `text`. Tokenises on whitespace
 * and common log delimiters, classifies each token, de-duplicates, and
 * preserves the order of first appearance.
 *
 * Returns `{ ips: string[], cves: string[] }`.
 */
export function extract(text) {
  if (typeof text !== 'string' || !text) return { ips: [], cves: [] };

  // Split on whitespace + a few delimiters that appear in logs/CSVs but never
  // inside an IP or CVE (comma, semicolon, pipe, tab). Keep brackets, colons
  // and dots — classify() handles them.
  const tokens = text.split(/[\s,;|\t]+/);
  const ips = new Set();
  const cves = new Set();

  for (const tok of tokens) {
    if (!tok) continue;
    const { kind, value } = classify(tok);
    if (kind === 'ip') ips.add(value);
    else if (kind === 'cve') cves.add(value);
  }

  return { ips: [...ips], cves: [...cves] };
}
