document.addEventListener('DOMContentLoaded', async () => {
  const { apiKey } = await chrome.storage.sync.get({ apiKey: '' });
  const apiStatusEl = document.getElementById('api-status');
  if (!apiKey) {
    apiStatusEl.textContent = 'Key Required';
    apiStatusEl.style.color = '#f59e0b';
  }

  const { scanHistory = [] } = await chrome.storage.local.get({ scanHistory: [] });
  const threatsCount = scanHistory.filter(r => r.status === 'malicious').length;
  document.getElementById('threats-count').textContent = threatsCount;

  const recentList = document.getElementById('recent-scans');
  if (scanHistory.length > 0) {
    recentList.innerHTML = '';
    scanHistory.slice(0, 5).forEach(item => {
      const div = document.createElement('div');
      div.className = 'recent-item';
      const cleanTarget = item.target.replace(/^https?:\/\//, '');
      div.innerHTML = `
        <span class="recent-url" title="${item.target}">${cleanTarget}</span>
        <span style="color: ${item.status === 'malicious' ? '#ef4444' : '#10b981'}; font-weight: 600;">
          ${item.status === 'malicious' ? item.stats.malicious + ' threats' : 'Clean'}
        </span>
      `;
      recentList.appendChild(div);
    });
  }

  document.getElementById('open-dashboard').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('options.html') });
  });
});
