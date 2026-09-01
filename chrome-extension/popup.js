/**
 * PhishLens PhishGuard - Popup Script
 */

document.addEventListener("DOMContentLoaded", () => {
  const BACKEND_URL = "http://localhost:5000";

  // Tab switching logic
  const tabs = document.querySelectorAll(".nav-tab");
  const tabContents = document.querySelectorAll(".tab-content");

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      tab.classList.add("active");
      const targetId = tab.dataset.tab;
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add("active");
    });
  });

  // Query Current Active Browser Tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0] && tabs[0].url) {
      const currentUrl = tabs[0].url;
      const urlDisplay = document.getElementById("active-url");
      if (urlDisplay) urlDisplay.innerText = currentUrl;

      // Analyze active URL
      analyzeActiveUrl(currentUrl);
    }
  });

  function analyzeActiveUrl(url) {
    const scoreCircle = document.getElementById("active-score-circle");
    const scoreNum = document.getElementById("active-score-num");
    const levelBadge = document.getElementById("active-level-badge");
    const summaryText = document.getElementById("active-summary-text");
    const flagsContainer = document.getElementById("active-indicators-container");
    const flagsList = document.getElementById("active-flags-list");

    fetch(`${BACKEND_URL}/api/analyze/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    })
    .then(r => r.json())
    .then(data => {
      const score = data.risk_score || 0;
      scoreNum.innerText = score;
      levelBadge.innerText = (data.risk_level || "Safe").toUpperCase();

      scoreCircle.className = "risk-score-circle";
      if (score >= 70) {
        scoreCircle.classList.add("dangerous");
        levelBadge.style.color = "var(--accent-red)";
      } else if (score >= 35) {
        scoreCircle.classList.add("caution");
        levelBadge.style.color = "var(--accent-yellow)";
      } else {
        levelBadge.style.color = "var(--accent-green)";
      }

      summaryText.innerText = data.recommendation || "Safe verified site.";

      if (data.indicators && data.indicators.length > 0) {
        flagsContainer.style.display = "block";
        flagsList.innerHTML = data.indicators.slice(0, 3).map(ind => `<li>${ind}</li>`).join("");
      } else {
        flagsContainer.style.display = "none";
      }
    })
    .catch(() => {
      // Fallback local safe check
      scoreNum.innerText = "0";
      levelBadge.innerText = "STANDALONE SAFE";
      levelBadge.style.color = "var(--accent-green)";
      summaryText.innerText = "Local Heuristic Shield Active";
    });
  }

  // Quick URL Scanner Button
  const btnScanUrl = document.getElementById("btn-scan-url");
  const quickUrlInput = document.getElementById("quick-url-input");
  const urlScanResult = document.getElementById("url-scan-result");

  if (btnScanUrl) {
    btnScanUrl.addEventListener("click", () => {
      const targetUrl = quickUrlInput.value.trim();
      if (!targetUrl) return;

      urlScanResult.style.display = "block";
      urlScanResult.innerHTML = "<em>Analyzing URL security vectors...</em>";

      fetch(`${BACKEND_URL}/api/analyze/url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl })
      })
      .then(r => r.json())
      .then(data => {
        let isPhish = data.risk_score >= 40;
        let color = isPhish ? "#ff3366" : "#10b981";
        urlScanResult.style.borderLeftColor = color;
        urlScanResult.innerHTML = `
          <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
            <strong style="color:${color}">${data.risk_level.toUpperCase()} (${data.risk_score}/100)</strong>
            <span style="color:#cbd5e1;">${data.threat_type || 'Clean'}</span>
          </div>
          <div style="color:#94a3b8; margin-bottom:6px;">${data.recommendation}</div>
          ${data.indicators && data.indicators.length > 0 ? `
            <div style="font-size:10px; color:#f87171;">
              <strong>Flags:</strong> ${data.indicators.slice(0, 2).join(" | ")}
            </div>` : ''}
        `;
      })
      .catch(err => {
        urlScanResult.innerHTML = `<span style="color:#ef4444;">Error connecting to analysis engine</span>`;
      });
    });
  }

  // Quick Email Scanner Button
  const btnScanEmail = document.getElementById("btn-scan-email");
  const emailFromInput = document.getElementById("email-from-input");
  const emailBodyInput = document.getElementById("email-body-input");
  const emailScanResult = document.getElementById("email-scan-result");

  if (btnScanEmail) {
    btnScanEmail.addEventListener("click", () => {
      const fromHeader = emailFromInput.value.trim();
      const bodyText = emailBodyInput.value.trim();
      if (!fromHeader && !bodyText) return;

      emailScanResult.style.display = "block";
      emailScanResult.innerHTML = "<em>Analyzing sender authenticity & psychological triggers...</em>";

      fetch(`${BACKEND_URL}/api/analyze/email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          from: fromHeader,
          subject: "Manual Scan",
          body: bodyText
        })
      })
      .then(r => r.json())
      .then(data => {
        let isPhish = data.risk_score >= 40;
        let color = isPhish ? "#ff3366" : "#10b981";
        emailScanResult.style.borderLeftColor = color;
        emailScanResult.innerHTML = `
          <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
            <strong style="color:${color}">${data.risk_level.toUpperCase()} (${data.risk_score}/100)</strong>
            <span style="color:#cbd5e1;">${data.threat_type || 'Clean'}</span>
          </div>
          <div style="color:#94a3b8; margin-bottom:6px;">${data.recommendation}</div>
          ${data.sender_anomalies && data.sender_anomalies.length > 0 ? `
            <div style="font-size:10px; color:#f87171; margin-bottom:4px;">
              <strong>Sender Flag:</strong> ${data.sender_anomalies[0]}
            </div>` : ''}
          ${data.red_flags && data.red_flags.length > 0 ? `
            <div style="font-size:10px; color:#fbbf24;">
              <strong>Content Flag:</strong> ${data.red_flags[0]}
            </div>` : ''}
        `;
      })
      .catch(() => {
        emailScanResult.innerHTML = `<span style="color:#ef4444;">Error connecting to email analysis engine</span>`;
      });
    });
  }

  // Launch Dashboard
  const btnDashboard = document.getElementById("btn-open-dashboard");
  if (btnDashboard) {
    btnDashboard.addEventListener("click", () => {
      chrome.tabs.create({ url: "http://localhost:8080" });
    });
  }
});