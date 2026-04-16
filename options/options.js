import { getApiKeys, setApiKeys } from '../lib/storage.js';
import { testCtiKey, getQuota } from '../lib/crowdsec.js';

const $ = (id) => document.getElementById(id);
const ctiInput = $('cti-key');
const status = $('status');
const quotaBox = $('quota-box');
const quotaDetail = $('quota-detail');

async function hydrate() {
  const keys = await getApiKeys();
  if (keys.cti) ctiInput.value = keys.cti;
  await refreshQuota();
}

async function refreshQuota() {
  const q = await getQuota();
  if (!q || (q.remaining == null && q.limit == null)) {
    quotaBox.hidden = true;
    return;
  }
  quotaBox.hidden = false;
  const parts = [];
  if (q.remaining != null) parts.push(`<strong>${q.remaining}</strong> remaining`);
  if (q.limit != null) parts.push(`of <strong>${q.limit}</strong>`);
  if (q.reset) {
    const when = new Date(q.reset * (q.reset > 1e12 ? 1 : 1000));
    parts.push(`— resets ${when.toLocaleString()}`);
  }
  quotaDetail.innerHTML = parts.join(' ');
}

function setStatus(msg, kind) {
  status.textContent = msg;
  status.className = `status ${kind || ''}`;
}

$('save').addEventListener('click', async () => {
  const cti = ctiInput.value.trim();
  await setApiKeys({ cti });
  setStatus(cti ? 'Saved.' : 'Cleared.', 'ok');
});

$('test-cti').addEventListener('click', async () => {
  const cti = ctiInput.value.trim();
  if (!cti) {
    setStatus('Paste a key first.', 'err');
    return;
  }
  setStatus('Testing…');
  const result = await testCtiKey(cti);
  if (result.ok) {
    setStatus('✅ Key works.', 'ok');
    await setApiKeys({ cti });
    await refreshQuota();
  } else {
    setStatus(`❌ ${result.message}`, 'err');
    await refreshQuota();
  }
});

$('toggle-cti').addEventListener('click', () => {
  ctiInput.type = ctiInput.type === 'password' ? 'text' : 'password';
});

hydrate();
