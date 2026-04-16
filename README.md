# CrowdSec CTI Lookup — Chrome Extension

A zero-build Chrome extension (Manifest V3) that enriches any IP you see in
the browser with CrowdSec CTI threat-intelligence context.

- **Right-click** an IP (or select text containing one) → **Lookup in CrowdSec CTI** →
  a compact card opens with reputation, geo, ASN, attack behaviors, MITRE
  techniques, CVEs the IP has been seen targeting, and more.
- **Toolbar popup** lets you paste/type an IP (or CVE) for manual lookup.
- **CVE selections** deep-link to the
  [CrowdSec Live Exploit Tracker](https://tracker.crowdsec.net/) for now.
  Full in-extension CVE cards land in Phase 2.


## Disclaimer

This is fully vibe coded with little to no review, use at your own risk.

## Install (unpacked)

1. Clone / download this folder to your machine.
2. Visit `chrome://extensions` and enable **Developer mode** (top-right).
3. Click **Load unpacked** and select the `chrome-plugin/` directory.
4. The extension icon appears in the toolbar.

## Set up your API key

1. Get a free community API key from
   [app.crowdsec.net → Settings → API Keys](https://app.crowdsec.net/settings/cti-api-keys).
2. Right-click the extension icon → **Options** (or click it and follow the link).
3. Paste the key, click **Test CTI** to validate, then **Save**.

## Usage

- On any web page, highlight text containing some IPs, right-click, and pick
  **Lookup in CrowdSec CTI**. A detached popup window opens with the card.
- Click the toolbar icon for the manual-input popup.
- CVE chips in the "Known For" section open the matching LET page in a new tab.

## File layout

```
chrome-plugin/
├── manifest.json          # MV3 manifest
├── background.js          # service worker — context menu + routing
├── lib/
│   ├── crowdsec.js        # CTI API wrapper (+ stubbed CVE)
│   ├── detect.js          # IP / CVE classifier
│   ├── cache.js           # TTL cache backed by chrome.storage.local
│   ├── storage.js         # API-key helpers
│   └── render.js          # shared IP-card renderer
├── options/               # Options page (paste/test key)
├── popup/                 # Toolbar popup
├── result/                # Detached result window
└── icons/                 # Placeholder PNGs (16/32/48/128)
```

## Security notes

- API keys live in `chrome.storage.local` on your machine and are transmitted
  only to `cti.api.crowdsec.net` (enforced by `host_permissions`).
- No content script is injected on web pages — the extension only ever sees
  the text you explicitly right-click on, via `info.selectionText`.
- Cached lookups default to a 1-hour TTL to avoid burning community-tier quota.
