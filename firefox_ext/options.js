document.addEventListener('DOMContentLoaded', async () => {
  const cfg = await browser.storage.local.get(['edc_url', 'edc_token', 'default_tool']);
  if (cfg.edc_url) document.getElementById('edc_url').value = cfg.edc_url;
  if (cfg.edc_token) document.getElementById('edc_token').value = cfg.edc_token;
  if (cfg.default_tool) document.getElementById('default_tool').value = cfg.default_tool;
});

document.getElementById('save').addEventListener('click', async () => {
  const edc_url = document.getElementById('edc_url').value.trim();
  const edc_token = document.getElementById('edc_token').value.trim();
  const default_tool = document.getElementById('default_tool').value.trim() || 'firefox-esr';

  await browser.storage.local.set({
    edc_url,
    edc_token,
    default_tool
  });

  const status = document.getElementById('status');
  status.textContent = 'Configuration saved.';
  setTimeout(() => { status.textContent = ''; }, 2500);
});