# DeltaShield

Real-time VirusTotal threat scanning for Chrome and Edge (Manifest V3).

DeltaShield checks every page you navigate to — and every file you download —
against the VirusTotal API. If enough engines flag the destination, it
intercepts the navigation and shows a warning page instead of loading it.

```
page / download  ->  VirusTotal lookup  ->  clean: open    ->  logged to the ledger
                                       ->  flagged: warn  ->  blocked, with the engine names
```

## What it does

- **Live URL checks** on `webNavigation` — including downloads (`downloads.onCreated`).
- **Interception page** with the detection stats, the engine names, and a VirusTotal permalink.
- **Scan ledger** — the last 100 verdicts, kept in `chrome.storage.local`.
- **Allow / deny lists** so your own sites are never scanned, and specific ones are always blocked.
- **Detection threshold** — how many engines must agree before a site is treated as malicious (default 1).
- **30-minute in-memory cache** so repeated visits don't burn API quota.

## Install (Chrome / Edge)

1. Download or clone this repo.
2. Open `chrome://extensions/` (or `edge://extensions/`) and turn on **Developer mode**.
3. **Load unpacked** → select the folder containing `manifest.json`.
4. Click the DeltaShield icon → **Open dashboard** (or right-click → Options).

## Set up the API key

DeltaShield ships with **no key** — you supply your own. Nothing is sent anywhere
until you do.

1. Make a free account at [virustotal.com](https://www.virustotal.com/).
2. Copy your API key from **Profile → API key**.
3. Paste it into DeltaShield's options page and **Save**.

The key is stored in `chrome.storage.sync` (your browser profile). It is never
committed here — see `.gitignore` and the note below.

## Privacy — what leaves your machine

- Each URL you visit is normalised and looked up at `www.virustotal.com` with
  **your** API key. If VirusTotal has never seen that URL, it is submitted for
  analysis (that is how the service works).
- Scan history, lists and settings stay in the extension's own storage.
- There is no DeltaShield server, no analytics and no telemetry.

## Limitations, honestly

- **Chromium only.** It is Manifest V3 with a `background.service_worker`, which
  Chrome and Edge run; Firefox does not support `service_worker` backgrounds.
- **Lookups, not uploads.** File downloads are matched by URL against VirusTotal's
  existing records, not by uploading the file.
- **Unknown URLs pass.** A URL VirusTotal has never seen is submitted and allowed
  while the analysis runs; it is not blocked until a verdict exists.
- The free VirusTotal tier is rate-limited (4 requests/minute); heavy browsing
  will hit it, and a failed lookup fails open (the page loads).

## Layout

| File | What it is |
|---|---|
| `manifest.json` | MV3 manifest — permissions, action, options page |
| `background.js` | Service worker: navigation/download checks, cache, ledger |
| `popup.html` / `popup.js` | Toolbar popup: key status, threat count, recent scans |
| `options.html` / `options.js` | Settings: API key, threshold, lists |
| `intercept.html` / `intercept.js` | The warning page shown instead of a flagged site |
| `icons/` | Shield icon (SVG source + 16/48/128 PNGs) |
| `README.md` | This file |

## Security note for forks

Never commit a real VirusTotal key. The default in `background.js` is deliberately
empty; if you hardcode one for a private build, rotate it before sharing the build.
A key inside a published ZIP is a key that belongs to whoever downloads it.

## License

MIT — see `LICENSE`.
