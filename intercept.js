const params = new URLSearchParams(window.location.search);
const target = params.get('target') || 'Unknown Destination';
const malicious = params.get('malicious') || '1+';
const engines = params.get('engines') || 'Security engine detection';
const permalink = params.get('permalink') || '';
const isDownload = params.get('type') === 'download';

document.getElementById('target-display').textContent = target;
document.getElementById('type-label').textContent = isDownload ? 'Malicious Download Payload' : 'Suspicious Target URL';
document.getElementById('malicious-count').textContent = malicious + ' Engines';
document.getElementById('threat-names').textContent = engines;

if (permalink) {
  const container = document.getElementById('permalink-container');
  const a = document.createElement('a');
  a.href = permalink;
  a.target = '_blank';
  a.className = 'permalink-link';
  a.textContent = 'View verified VirusTotal Intelligence Report →';
  container.appendChild(a);
}

document.getElementById('btn-back').addEventListener('click', () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = 'https://www.google.com';
  }
});

document.getElementById('btn-bypass').addEventListener('click', () => {
  const confirmBypass = confirm('Are you sure you want to bypass DeltaShield protection? This site or download contains confirmed malicious signatures.');
  if (confirmBypass) {
    chrome.runtime.sendMessage({ type: 'BYPASS_URL', url: target }, () => {
      window.location.href = target;
    });
  }
});
