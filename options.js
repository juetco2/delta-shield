document.addEventListener('DOMContentLoaded', async () => {
  const config = await chrome.storage.sync.get({ apiKey: '', detectionThreshold: 1 });
  document.getElementById('api-key').value = config.apiKey || '';
  document.getElementById('threshold').value = config.detectionThreshold || 1;

  document.getElementById('btn-save').addEventListener('click', async () => {
    const apiKey = document.getElementById('api-key').value.trim();
    const detectionThreshold = parseInt(document.getElementById('threshold').value, 10) || 1;

    await chrome.storage.sync.set({ apiKey, detectionThreshold });
    const msg = document.getElementById('saved-msg');
    msg.style.display = 'inline';
    setTimeout(() => { msg.style.display = 'none'; }, 2500);
  });
});
