// DeltaShield Chrome Extension - Background Service Worker (Manifest V3)
const CACHE_EXPIRY_MS = 1000 * 60 * 30; // 30 minutes cache
const urlCache = new Map();
const bypassedUrls = new Set();

// Utility: Normalize and encode URL for VirusTotal v3 API
function getVirusTotalUrlId(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    // Ignore internal protocols
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    const cleanUrl = parsed.origin + parsed.pathname + parsed.search;
    const base64 = btoa(cleanUrl).replace(/=/g, '');
    return { urlId: base64, cleanUrl };
  } catch (e) {
    return null;
  }
}

// Retrieve settings from sync storage
async function getConfig() {
  const result = await chrome.storage.sync.get({
    apiKey: '',   // set your own in the options page - never commit a key
    detectionThreshold: 1,
    autoScanSites: true,
    autoScanDownloads: true,
    allowlist: ['google.com', 'virustotal.com', 'github.com', 'microsoft.com'],
    denylist: []
  });
  return result;
}

// Log scan report to local storage
async function logScanReport(report) {
  try {
    const { scanHistory = [] } = await chrome.storage.local.get({ scanHistory: [] });
    const updated = [report, ...scanHistory.filter(r => r.id !== report.id && r.target !== report.target)].slice(0, 100);
    await chrome.storage.local.set({ scanHistory: updated });
  } catch (err) {
    console.error('[DeltaShield] Failed to record report:', err);
  }
}

// VirusTotal URL lookup
async function checkUrlWithVirusTotal(targetUrl, apiKey, threshold) {
  const meta = getVirusTotalUrlId(targetUrl);
  if (!meta) return { safe: true };

  // Check in-memory cache
  if (urlCache.has(meta.cleanUrl)) {
    const cached = urlCache.get(meta.cleanUrl);
    if (Date.now() - cached.timestamp < CACHE_EXPIRY_MS) {
      return cached.result;
    }
  }

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${meta.urlId}`, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json'
      }
    });

    if (res.status === 404) {
      // Submit URL for async analysis
      fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(meta.cleanUrl)}`
      }).catch(() => {});

      const result = { safe: true, pending: true };
      urlCache.set(meta.cleanUrl, { timestamp: Date.now(), result });
      return result;
    }

    if (!res.ok) {
      return { safe: true, error: 'VT API returned ' + res.status };
    }

    const json = await res.json();
    const stats = json?.data?.attributes?.last_analysis_stats || { malicious: 0, suspicious: 0 };
    const threatNames = [];
    const results = json?.data?.attributes?.last_analysis_results || {};
    
    for (const [engine, info] of Object.entries(results)) {
      if ((info.category === 'malicious' || info.category === 'suspicious') && info.result) {
        if (!threatNames.includes(info.result)) threatNames.push(info.result);
      }
    }

    const isMalicious = stats.malicious >= threshold;
    const scanReport = {
      id: json?.data?.id || 'vt-' + Date.now(),
      type: 'url',
      target: meta.cleanUrl,
      timestamp: new Date().toISOString(),
      status: isMalicious ? 'malicious' : stats.suspicious > 0 ? 'suspicious' : 'clean',
      stats,
      threatNames: threatNames.slice(0, 5),
      engineCount: Object.keys(results).length || 85,
      permalink: `https://www.virustotal.com/gui/url/${meta.urlId}`,
      actionTaken: isMalicious ? 'blocked' : 'allowed'
    };

    await logScanReport(scanReport);

    const verdict = {
      safe: !isMalicious,
      stats,
      threatNames,
      reportId: json?.data?.id,
      permalink: scanReport.permalink
    };

    urlCache.set(meta.cleanUrl, { timestamp: Date.now(), result: verdict });
    return verdict;
  } catch (err) {
    console.warn('[DeltaShield] VT Query failed:', err);
    return { safe: true, error: err.message };
  }
}

// 1. Navigation Listener: Inspect visited URLs
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Only top-level main frame
  const url = details.url;
  
  // Ignore chrome://, extension URLs, and user bypassed URLs
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.includes('/intercept.html')) {
    return;
  }
  if (bypassedUrls.has(url)) {
    return;
  }

  const config = await getConfig();
  if (!config.autoScanSites || !config.apiKey) return;

  const urlObj = new URL(url);
  // Check domain allowlist
  if (config.allowlist.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain))) {
    return;
  }

  // Check domain denylist
  if (config.denylist.some(domain => urlObj.hostname === domain || urlObj.hostname.endsWith('.' + domain))) {
    const interceptUrl = chrome.runtime.getURL(`intercept.html?target=${encodeURIComponent(url)}&reason=denylist&engines=Denylist`);
    chrome.tabs.update(details.tabId, { url: interceptUrl });
    return;
  }

  const verdict = await checkUrlWithVirusTotal(url, config.apiKey, config.detectionThreshold);

  if (!verdict.safe) {
    const params = new URLSearchParams({
      target: url,
      malicious: verdict.stats?.malicious || 1,
      suspicious: verdict.stats?.suspicious || 0,
      engines: verdict.threatNames?.join(', ') || 'Known Malicious URL',
      permalink: verdict.permalink || ''
    });
    const interceptUrl = chrome.runtime.getURL(`intercept.html?${params.toString()}`);
    chrome.tabs.update(details.tabId, { url: interceptUrl });
  }
});

// 2. Download Listener: Inspect incoming downloads
chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const config = await getConfig();
  if (!config.autoScanDownloads || !config.apiKey) return;

  const downloadUrl = downloadItem.url || downloadItem.finalUrl;
  if (!downloadUrl) return;

  const verdict = await checkUrlWithVirusTotal(downloadUrl, config.apiKey, config.detectionThreshold);

  if (!verdict.safe) {
    // Pause malicious download immediately
    try {
      await chrome.downloads.pause(downloadItem.id);
    } catch (e) {}

    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'DeltaShield Download Blocked',
      message: `Malicious payload detected: ${downloadItem.filename || 'download'}. VirusTotal detections: ${verdict.stats?.malicious || 1}`,
      priority: 2
    });

    const params = new URLSearchParams({
      target: downloadItem.filename || downloadUrl,
      malicious: verdict.stats?.malicious || 1,
      suspicious: verdict.stats?.suspicious || 0,
      engines: verdict.threatNames?.join(', ') || 'Trojan / Exploit payload',
      permalink: verdict.permalink || '',
      type: 'download',
      downloadId: downloadItem.id
    });

    chrome.tabs.create({ url: chrome.runtime.getURL(`intercept.html?${params.toString()}`) });
  }
});

// Message handling for Bypass & Config from extension pages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'BYPASS_URL' && message.url) {
    bypassedUrls.add(message.url);
    // Allow for 15 minutes
    setTimeout(() => bypassedUrls.delete(message.url), 15 * 60 * 1000);
    sendResponse({ success: true });
  } else if (message.type === 'GET_STATUS') {
    sendResponse({ active: true, cacheSize: urlCache.size });
  }
  return true;
});
