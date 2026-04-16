// Thin wrapper around chrome.storage.local for API keys.
// Shape: { cti: string }. Reserved: { let: string } for Phase 2.

const KEYS_STORAGE_KEY = 'cs:apiKeys';

export async function getApiKeys() {
  const out = await chrome.storage.local.get(KEYS_STORAGE_KEY);
  return out[KEYS_STORAGE_KEY] || {};
}

export async function setApiKeys(keys) {
  const existing = await getApiKeys();
  const merged = { ...existing, ...keys };
  await chrome.storage.local.set({ [KEYS_STORAGE_KEY]: merged });
  return merged;
}
