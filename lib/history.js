// LRU-capped lookup history backed by chrome.storage.local.
// Mirrors the pattern used by lib/cache.js (meta index + per-entry keys).

const PREFIX = 'cs:hist:';
const META_KEY = 'cs:hist:meta';
const MAX_ENTRIES = 200;

function makeId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function makeKey(id) {
  return `${PREFIX}${id}`;
}

/**
 * Store a new lookup history entry. `entry` should contain:
 *   - kind: 'ip' | 'cve' | 'batch'
 *   - query?, ips?, cves?
 *   - sourceUrl?, sourceTitle?
 *   - summary?  (small object shown in the history list)
 *
 * Returns the stored entry (with assigned id + createdAt).
 */
export async function addEntry(entry) {
  const stored = {
    id: makeId(),
    createdAt: Date.now(),
    ...entry,
  };
  const key = makeKey(stored.id);
  const out = await chrome.storage.local.get(META_KEY);
  const meta = out[META_KEY] || { ids: [] };
  meta.ids = [stored.id, ...meta.ids.filter((i) => i !== stored.id)];

  const removeKeys = [];
  if (meta.ids.length > MAX_ENTRIES) {
    const drop = meta.ids.slice(MAX_ENTRIES);
    meta.ids = meta.ids.slice(0, MAX_ENTRIES);
    removeKeys.push(...drop.map(makeKey));
  }

  await chrome.storage.local.set({ [key]: stored, [META_KEY]: meta });
  if (removeKeys.length) await chrome.storage.local.remove(removeKeys);
  return stored;
}

/** Returns newest-first array of entries. */
export async function listEntries({ limit } = {}) {
  const out = await chrome.storage.local.get(META_KEY);
  const ids = (out[META_KEY]?.ids || []).slice(0, limit || Infinity);
  if (!ids.length) return [];
  const keys = ids.map(makeKey);
  const rows = await chrome.storage.local.get(keys);
  // Preserve the meta order — the returned object has no ordering guarantee.
  return ids.map((id) => rows[makeKey(id)]).filter(Boolean);
}

export async function getEntry(id) {
  const key = makeKey(id);
  const out = await chrome.storage.local.get(key);
  return out[key] || null;
}

export async function removeEntry(id) {
  const key = makeKey(id);
  const out = await chrome.storage.local.get(META_KEY);
  const meta = out[META_KEY] || { ids: [] };
  meta.ids = meta.ids.filter((i) => i !== id);
  await chrome.storage.local.set({ [META_KEY]: meta });
  await chrome.storage.local.remove(key);
}

export async function clearHistory() {
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith(PREFIX) || k === META_KEY);
  if (keys.length) await chrome.storage.local.remove(keys);
}
