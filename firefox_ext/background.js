// In-memory cache for network headers
const tabTelemetry = {};

// Capture request headers
browser.webRequest.onSendHeaders.addListener(
  (details) => {
    if (details.tabId < 0) return;
    if (!tabTelemetry[details.tabId]) tabTelemetry[details.tabId] = {};
    if (details.type === "main_frame" || details.type === "xmlhttprequest") {
      tabTelemetry[details.tabId].lastRequest = {
        url: details.url,
        method: details.method,
        headers: details.requestHeaders
      };
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// 2. Capture incoming response headers
browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.tabId < 0) return;
    if (!tabTelemetry[details.tabId]) tabTelemetry[details.tabId] = {};
    if (details.type === "main_frame" || details.type === "xmlhttprequest") {
      tabTelemetry[details.tabId].lastResponse = {
        statusCode: details.statusCode,
        headers: details.responseHeaders
      };
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// Clean up memory on tab close
browser.tabs.onRemoved.addListener((tabId) => {
  delete tabTelemetry[tabId];
});

// Convert DataURL to a Blob
function dataURLtoBlob(dataurl) {
  const arr = dataurl.split(',');
  const mime = arr[0].match(/:(.*?);/)[1];
  const bstr = atob(arr[1]);
  let n = bstr.length;
  const u8arr = new Uint8Array(n);
  while (n--) {
    u8arr[n] = bstr.charCodeAt(n);
  }
  return new Blob([u8arr], { type: mime });
}

// Browser action click
browser.browserAction.onClicked.addListener(async (tab) => {
  // Ignore privileged browser pages
  if (!tab.url || tab.url.startsWith("about:") || tab.url.startsWith("chrome:")) {
    console.warn("Cannot capture internal browser page.");
    return;
  }

  // Load configuration
  const config = await browser.storage.local.get(['edc_url', 'edc_token', 'default_tool']);
  if (!config.edc_url || !config.edc_token) {
    alert("EDC Collector: Please set the API URL and Token in the extension options first.");
    browser.runtime.openOptionsPage();
    return;
  }

  try {
    // Capture visible tab as PNG
    const dataUrl = await browser.tabs.captureVisibleTab(tab.windowId, { format: "png" });
    const imageBlob = dataURLtoBlob(dataUrl);

    // Read cookies for current domain
    const cookies = await browser.cookies.getAll({ url: tab.url });
    const cookieList = cookies.map(c => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      httpOnly: c.httpOnly,
      secure: c.secure
    }));

    // Execute content script to read Storage (localStorage / sessionStorage)
    let clientStorage = {};
    try {
      const results = await browser.tabs.executeScript(tab.id, { file: "content.js" });
      if (results && results[0]) {
        clientStorage = results[0];
      }
    } catch (csErr) {
      clientStorage = { error: "Could not inject content script: " + csErr.message };
    }

    // Compile telemetry to output string
    const recentNet = tabTelemetry[tab.id] || {};
    const telemetryReport = {
      timestamp: new Date().toISOString(),
      page_title: clientStorage.pageTitle || tab.title,
      target_url: tab.url,
      network: {
        last_request: recentNet.lastRequest || null,
        last_response: recentNet.lastResponse || null
      },
      cookies: cookieList,
      local_storage: clientStorage.localStorage || {},
      session_storage: clientStorage.sessionStorage || {}
    };

    const outputText = JSON.stringify(telemetryReport, null, 2);

    // Prepare multiPart FormData payload for EDC API
    const formData = new FormData();
    formData.append("url", tab.url);
    formData.append("tool", config.default_tool || "firefox-esr");
    formData.append("command", `Browser snapshot: ${tab.url}`);
    formData.append("output", outputText);
    formData.append("notes", `Automated web capture: ${clientStorage.pageTitle || tab.title}`);

    // Append screenshot file using the name 'screenshots' supported by perform_create()
    const filename = `snap_${Date.now()}.png`;
    formData.append("screenshots", imageBlob, filename);

    // Send HTTP POST to EDC
    const response = await fetch(config.edc_url, {
      method: "POST",
      credentials: "omit",
      headers: {
        "Authorization": `Token ${config.edc_token}`
      },
      body: formData
    });

    if (response.ok) {
      // Brief visual success indicator (badge)
      browser.browserAction.setBadgeText({ text: "OK", tabId: tab.id });
      browser.browserAction.setBadgeBackgroundColor({ color: "#27ae60", tabId: tab.id });
      setTimeout(() => {
        browser.browserAction.setBadgeText({ text: "", tabId: tab.id });
      }, 3000);
    } else {
      const errText = await response.text();
      console.error("Upload error:", errText);
      alert(`EDC Upload Failed (${response.status}):\n${errText.slice(0, 300)}`);
      browser.browserAction.setBadgeText({ text: "ERR", tabId: tab.id });
      browser.browserAction.setBadgeBackgroundColor({ color: "#c0392b", tabId: tab.id });
    }
  } catch (err) {
    console.error("Extension execution error:", err);
    alert(`Error: ${err.message}`);
  }
});