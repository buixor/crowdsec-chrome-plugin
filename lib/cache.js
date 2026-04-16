// TTL cache backed by chrome.storage.local.
// Purpose: respect the 50/day community quota and avoid redundant lookups.

const PREFIX = 'cs:cache:';
const META_KEY = 'cs:cache:meta';    // index of all cache keys for cleanup
const MAX_ENTRIES = 200;              // hard cap; oldest evicted when exceeded

function makeKey(kind, value) {
  return `${PREFIX}${kind}:${value.toLowerCase()}`;
}

export async function getCached(kind, value) {
  const key = makeKey(kind, value);
  const out = await chrome.storage.local.get(key);
  const entry = out[key];
  if (!entry) return null;
  if (entry.expiresAt && entry.expiresAt < Date.now()) {
    await chrome.storage.local.remove(key);
    return null;
  }
  return entry.data;
}

export async function setCached(kind, value, data, ttlMs) {
  const key = makeKey(kind, value);
  const entry = {
    data,
    expiresAt: ttlMs ? Date.now() + ttlMs : null,
    createdAt: Date.now(),
  };
  await chrome.storage.local.set({ [key]: entry });
  await trackAndEvict(key);
}

async function trackAndEvict(key) {
  const out = await chrome.storage.local.get(META_KEY);
  const meta = out[META_KEY] || { keys: [] };
  // Move this key to the head (most recently used).
  meta.keys = meta.keys.filter((k) => k !== key);
  meta.keys.unshift(key);
  if (meta.keys.length > MAX_ENTRIES) {
    const toRemove = meta.keys.slice(MAX_ENTRIES);
    meta.keys = meta.keys.slice(0, MAX_ENTRIES);
    await chrome.storage.local.remove(toRemove);
  }
  await chrome.storage.local.set({ [META_KEY]: meta });
}

export async function clearCache() {
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith(PREFIX));
  if (keys.length) await chrome.storage.local.remove(keys);
}
