/**
 * PhishLens PhishGuard - Content Script
 * Real-time active link scanner, lookalike domain interceptor, and webmail protection shield.
 */

(function () {
  console.log("🛡️ PhishLens PhishGuard: Initializing Real-Time Guardian...");

  const BACKEND_URL = "http://localhost:5000";
  
  // Client-side quick brand & homoglyph definitions
  const TOP_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", "chase",
    "bankofamerica", "wellsfargo", "citi", "binance", "coinbase", "steam",
    "facebook", "instagram", "linkedin", "docusign", "outlook", "office365"
  ];
  
  const HOMOGLYPHS = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'ԁ': 'd',
    'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ո': 'n', 'υ': 'u', 'ѵ': 'v', 'ѡ': 'w', 'х': 'x',
    'у': 'y', 'т': 't', 'в': 'b', 'һ': 'h', 'к': 'k', 'м': 'm', 'н': 'h',
    'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'é': 'e', 'è': 'e', 'ê': 'e', 'í': 'i'
  };

  const SUSPICIOUS_TLDS = ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'live', 'loan', 'click', 'icu', 'buzz'];

  let cachedUrlRisks = new Map();
  let activeTooltip = null;

  // Initialize Page & Webmail Guard
  function init() {
    analyzeCurrentPageUrl();
    attachLinkInterceptors();
    initWebmailScanner();
    observeDomMutations();
  }

  // Fast Client-Side Heuristic URL Evaluation
  function evaluateUrlQuickly(url) {
    if (!url || url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('#')) {
      return { score: 0, level: 'Safe', isPhish: false, reason: 'Internal Link' };
    }

    try {
      const parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
      let host = parsed.hostname.toLowerCase();
      let score = 0;
      let reasons = [];
      let isLookalike = false;
      let targetBrand = null;

      // Check IP hostname
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
        score += 55;
        reasons.push("Direct IP address used as hostname");
      }

      // Check Homoglyphs
      let normalizedHost = "";
      let hasHomoglyph = false;
      for (let char of host) {
        if (HOMOGLYPHS[char]) {
          normalizedHost += HOMOGLYPHS[char];
          hasHomoglyph = true;
        } else {
          normalizedHost += char;
        }
      }

      if (hasHomoglyph) {
        score += 70;
        reasons.push("Deceptive Unicode homoglyphs detected in domain");
      }

      // Check Lookalikes & Brand Spoofing
      let sld = host.split('.').slice(-2, -1)[0] || host;
      let normalizedSld = normalizedHost.split('.').slice(-2, -1)[0] || normalizedHost;

      for (let brand of TOP_BRANDS) {
        let legitDomain = brand + ".com";
        // Homoglyph brand mimic
        if (normalizedSld === brand && sld !== brand) {
          isLookalike = true;
          targetBrand = brand;
          score += 90;
          reasons.push(`Lookalike: Homoglyph imitation of authentic '${legitDomain}'`);
        }
        // Subdomain brand spoofing (e.g. paypal.com.attacker.xyz)
        else if (host.includes(brand + ".") && !host.endsWith("." + legitDomain) && host !== legitDomain) {
          isLookalike = true;
          targetBrand = brand;
          score += 85;
          reasons.push(`Brand spoofing: '${brand}' placed in subdomain of '${host}'`);
        }
        // Combosquatting (e.g. paypal-security.xyz)
        else if ((host.includes(brand + "-") || host.includes("-" + brand)) && host !== legitDomain) {
          isLookalike = true;
          targetBrand = brand;
          score += 80;
          reasons.push(`Combosquatting: '${brand}' combined with security keywords`);
        }
      }

      // Suspicious TLD
      let tld = host.split('.').pop();
      if (SUSPICIOUS_TLDS.includes(tld)) {
        score += 25;
        reasons.push(`Suspicious TLD '.${tld}' commonly abused in phishing`);
      }

      // Credential lures in path
      let fullPath = parsed.pathname.toLowerCase() + parsed.search.toLowerCase();
      if (/[\/\-\_](login|signin|verify|account|banking|password|recover|update)[\/\.\_\=\&]?/.test(fullPath)) {
        score += 20;
        reasons.push("Sensitive credential harvesting keywords in URL path");
      }

      score = Math.min(100, score);
      let level = score >= 70 ? 'Dangerous' : (score >= 40 ? 'High Risk' : (score >= 20 ? 'Caution' : 'Safe'));
      let isPhish = score >= 40;

      return {
        url: url,
        domain: host,
        score: score,
        level: level,
        isPhish: isPhish,
        isLookalike: isLookalike,
        targetBrand: targetBrand,
        reasons: reasons
      };
    } catch (e) {
      return { score: 0, level: 'Safe', isPhish: false, reasons: [] };
    }
  }

  // Analyze Current Page URL and Notify Extension
  function analyzeCurrentPageUrl() {
    const currentUrl = window.location.href;
    const quickEval = evaluateUrlQuickly(currentUrl);

    // Also request deep scan from backend
    fetch(`${BACKEND_URL}/api/analyze/url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentUrl })
    })
    .then(r => r.json())
    .then(data => {
      chrome.runtime.sendMessage({ action: "pageAnalysisComplete", analysis: data });
    })
    .catch(() => {
      chrome.runtime.sendMessage({ action: "pageAnalysisComplete", analysis: quickEval });
    });
  }

  // Attach Hover Tooltip & Click Interceptors on All Links
  function attachLinkInterceptors() {
    document.querySelectorAll("a[href]").forEach(link => {
      if (link.dataset.phishguardAttached) return;
      link.dataset.phishguardAttached = "true";

      const href = link.getAttribute("href");
      if (!href || href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:")) return;

      // Hover Event: Quick Preview Tooltip
      link.addEventListener("mouseenter", (e) => {
        showLinkTooltip(link, href, e);
      });

      link.addEventListener("mouseleave", () => {
        hideLinkTooltip();
      });

      // Click Event: Active Interceptor for Dangerous Phishing Links
      link.addEventListener("click", (e) => {
        const fullUrl = link.href;
        const evaluation = cachedUrlRisks.get(fullUrl) || evaluateUrlQuickly(fullUrl);

        if (evaluation.isPhish || evaluation.score >= 50) {
          // Block immediate navigation!
          e.preventDefault();
          e.stopPropagation();
          showWarningModal(fullUrl, evaluation);
        }
      });
    });
  }

  // Floating Security Tooltip on Link Hover
  function showLinkTooltip(element, href, event) {
    hideLinkTooltip();

    const fullUrl = element.href || href;
    const evalResult = cachedUrlRisks.get(fullUrl) || evaluateUrlQuickly(fullUrl);
    cachedUrlRisks.set(fullUrl, evalResult);

    if (evalResult.score < 15) return; // Only show tooltip for noteworthy/suspicious links

    const tooltip = document.createElement("div");
    tooltip.id = "phishguard-link-tooltip";
    
    let badgeColor = evalResult.score >= 70 ? "#ff3366" : (evalResult.score >= 40 ? "#ff9900" : "#00d2ff");
    let badgeText = evalResult.score >= 70 ? "🚨 PHISHING DETECTED" : (evalResult.score >= 40 ? "⚠️ HIGH RISK LINK" : "ℹ️ CAUTION LINK");

    tooltip.innerHTML = `
      <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:6px; border-bottom:1px solid rgba(255,255,255,0.15); padding-bottom:4px;">
        <span style="font-weight:700; font-size:11px; letter-spacing:0.5px; color:${badgeColor};">${badgeText}</span>
        <span style="font-size:10px; background:${badgeColor}; color:#000; padding:2px 6px; border-radius:10px; font-weight:bold;">${evalResult.score}% Risk</span>
      </div>
      <div style="font-size:10px; color:#cbd5e1; word-break:break-all; margin-bottom:4px;">
        <strong>Target:</strong> ${evalResult.domain || fullUrl.substring(0, 40)}
      </div>
      ${evalResult.reasons.length > 0 ? `<div style="font-size:10px; color:#f87171;">• ${evalResult.reasons[0]}</div>` : ''}
    `;

    Object.assign(tooltip.style, {
      position: "fixed",
      zIndex: "2147483646",
      left: `${Math.min(event.clientX + 10, window.innerWidth - 260)}px`,
      top: `${Math.max(10, event.clientY - 75)}px`,
      width: "250px",
      background: "rgba(15, 23, 42, 0.95)",
      backdropFilter: "blur(12px)",
      color: "#ffffff",
      padding: "10px 12px",
      borderRadius: "8px",
      border: `1px solid ${badgeColor}`,
      boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.6), 0 0 15px rgba(255, 51, 102, 0.2)",
      fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
      pointerEvents: "none",
      transition: "opacity 0.2s ease"
    });

    document.body.appendChild(tooltip);
    activeTooltip = tooltip;
  }

  function hideLinkTooltip() {
    if (activeTooltip && activeTooltip.parentNode) {
      activeTooltip.parentNode.removeChild(activeTooltip);
      activeTooltip = null;
    }
  }

  // High-Impact In-Page Warning Modal
  function showWarningModal(targetUrl, evaluation) {
    // Remove existing modal if any
    const existing = document.getElementById("phishguard-warning-overlay");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.id = "phishguard-warning-overlay";
    
    overlay.innerHTML = `
      <div class="phishguard-modal-card">
        <div class="phishguard-alert-icon">⚠️</div>
        <h2 class="phishguard-title">CRITICAL PHISHING THREAT INTERCEPTED</h2>
        <p class="phishguard-subtitle">PhishLens blocked an attempt to navigate to a dangerous deceptive link.</p>

        <div class="phishguard-details-box">
          <div class="phishguard-detail-row">
            <span class="phishguard-label">Blocked URL:</span>
            <span class="phishguard-val" style="color:#f87171; word-break:break-all;">${targetUrl}</span>
          </div>
          <div class="phishguard-detail-row">
            <span class="phishguard-label">Threat Level:</span>
            <span class="phishguard-val" style="color:#ef4444; font-weight:bold;">${evaluation.level.toUpperCase()} (${evaluation.score}/100 Risk Score)</span>
          </div>
          ${evaluation.targetBrand ? `
          <div class="phishguard-detail-row">
            <span class="phishguard-label">Brand Impersonated:</span>
            <span class="phishguard-val" style="color:#fbbf24; font-weight:bold;">${evaluation.targetBrand.toUpperCase()}</span>
          </div>` : ''}
          <div class="phishguard-detail-row" style="flex-direction:column; align-items:flex-start; margin-top:8px;">
            <span class="phishguard-label" style="margin-bottom:4px;">Detection Indicators:</span>
            <ul style="margin:0; padding-left:18px; color:#e2e8f0; font-size:12px;">
              ${evaluation.reasons.map(r => `<li>${r}</li>`).join('')}
            </ul>
          </div>
        </div>

        <div class="phishguard-actions">
          <button id="phishguard-btn-safe" class="phishguard-btn phishguard-btn-primary">
            🛡️ Return to Safety (Recommended)
          </button>
          <button id="phishguard-btn-proceed" class="phishguard-btn phishguard-btn-secondary">
            Ignore Warning & Proceed
          </button>
        </div>
      </div>
    `;

    // Inject styling directly to ensure isolation
    const style = document.createElement("style");
    style.textContent = `
      #phishguard-warning-overlay {
        position: fixed !important;
        inset: 0 !important;
        background: rgba(8, 12, 22, 0.88) !important;
        backdrop-filter: blur(16px) !important;
        z-index: 2147483647 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        padding: 20px !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
      }
      .phishguard-modal-card {
        background: linear-gradient(145deg, #1e1b2e, #0f172a) !important;
        border: 2px solid #ef4444 !important;
        border-radius: 16px !important;
        padding: 32px !important;
        max-width: 580px !important;
        width: 100% !important;
        color: #ffffff !important;
        text-align: center !important;
        box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.4), 0 0 30px rgba(239, 68, 68, 0.2) !important;
        animation: phishguard-pop 0.3s cubic-bezier(0.16, 1, 0.3, 1) !important;
      }
      @keyframes phishguard-pop {
        from { opacity: 0; transform: scale(0.92); }
        to { opacity: 1; transform: scale(1); }
      }
      .phishguard-alert-icon {
        font-size: 48px !important;
        margin-bottom: 12px !important;
        animation: phishguard-pulse 1.5s infinite !important;
      }
      @keyframes phishguard-pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.1); }
      }
      .phishguard-title {
        color: #ef4444 !important;
        font-size: 20px !important;
        font-weight: 800 !important;
        margin: 0 0 8px 0 !important;
        letter-spacing: 0.5px !important;
      }
      .phishguard-subtitle {
        color: #94a3b8 !important;
        font-size: 14px !important;
        margin: 0 0 20px 0 !important;
      }
      .phishguard-details-box {
        background: rgba(0, 0, 0, 0.35) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        border-radius: 10px !important;
        padding: 16px !important;
        margin-bottom: 24px !important;
        text-align: left !important;
      }
      .phishguard-detail-row {
        display: flex !important;
        justify-content: space-between !important;
        font-size: 13px !important;
        margin-bottom: 8px !important;
      }
      .phishguard-label {
        color: #94a3b8 !important;
        font-weight: 600 !important;
        min-width: 140px !important;
      }
      .phishguard-actions {
        display: flex !important;
        gap: 12px !important;
        justify-content: center !important;
      }
      .phishguard-btn {
        padding: 12px 20px !important;
        border-radius: 8px !important;
        font-size: 14px !important;
        font-weight: 700 !important;
        cursor: pointer !important;
        transition: all 0.2s ease !important;
        border: none !important;
      }
      .phishguard-btn-primary {
        background: #10b981 !important;
        color: #ffffff !important;
        flex: 2 !important;
      }
      .phishguard-btn-primary:hover {
        background: #059669 !important;
        transform: translateY(-2px) !important;
      }
      .phishguard-btn-secondary {
        background: rgba(255, 255, 255, 0.1) !important;
        color: #94a3b8 !important;
        flex: 1 !important;
      }
      .phishguard-btn-secondary:hover {
        background: rgba(255, 255, 255, 0.2) !important;
        color: #ffffff !important;
      }
    `;

    document.head.appendChild(style);
    document.body.appendChild(overlay);

    document.getElementById("phishguard-btn-safe").onclick = () => {
      overlay.remove();
    };

    document.getElementById("phishguard-btn-proceed").onclick = () => {
      overlay.remove();
      window.location.href = targetUrl;
    };
  }

  // Webmail Real-Time Email Scanner (Gmail, Outlook, Yahoo)
  function initWebmailScanner() {
    const host = window.location.hostname;
    const isWebmail = host.includes("mail.google.com") || host.includes("outlook.live.com") || host.includes("mail.yahoo.com");
    if (!isWebmail) return;

    console.log("📧 PhishLens: Webmail client detected! Monitoring opened emails...");
    
    // Poll for opened email containers
    setInterval(scanOpenedEmailsInWebmail, 2500);
  }

  function scanOpenedEmailsInWebmail() {
    // Gmail selectors
    const gmailMessages = document.querySelectorAll(".h7, .adn.ads");
    gmailMessages.forEach(msg => {
      if (msg.dataset.phishguardScanned) return;
      msg.dataset.phishguardScanned = "true";

      let senderNode = msg.querySelector(".gD") || msg.querySelector("[email]");
      let fromHeader = senderNode ? `${senderNode.innerText} <${senderNode.getAttribute("email") || ""}>` : "";
      let subjectNode = document.querySelector("h2.hP");
      let subject = subjectNode ? subjectNode.innerText : "";
      let bodyNode = msg.querySelector(".a3s.aiL");
      let bodyHtml = bodyNode ? bodyNode.innerHTML : "";
      let bodyText = bodyNode ? bodyNode.innerText : "";

      if (fromHeader || bodyText) {
        analyzeAndInjectWebmailBanner(msg, {
          from: fromHeader,
          subject: subject,
          body: bodyText,
          body_html: bodyHtml
        });
      }
    });
  }

  function analyzeAndInjectWebmailBanner(containerElement, emailData) {
    fetch(`${BACKEND_URL}/api/analyze/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(emailData)
    })
    .then(r => r.json())
    .then(result => {
      if (result.risk_score >= 35) {
        injectEmailWarningBanner(containerElement, result);
      }
    })
    .catch(() => {
      // Fallback local check
      let hasUrgency = /urgent|24 hours|suspended|immediately/i.test(emailData.body);
      if (hasUrgency) {
        injectEmailWarningBanner(containerElement, {
          risk_score: 75,
          risk_level: "High Risk",
          threat_type: "Suspicious Urgency Triggers",
          red_flags: ["Artificial urgency detected in email message body"]
        });
      }
    });
  }

  function injectEmailWarningBanner(containerElement, result) {
    if (containerElement.querySelector(".phishguard-email-banner")) return;

    const banner = document.createElement("div");
    banner.className = "phishguard-email-banner";
    
    let isCrit = result.risk_score >= 70;
    let bgColor = isCrit ? "linear-gradient(135deg, rgba(239, 68, 68, 0.25), rgba(153, 27, 27, 0.35))" : "linear-gradient(135deg, rgba(245, 158, 11, 0.25), rgba(180, 83, 9, 0.35))";
    let borderColor = isCrit ? "#ef4444" : "#f59e0b";

    banner.innerHTML = `
      <div style="background:${bgColor}; border:1.5px solid ${borderColor}; border-radius:8px; padding:12px 16px; margin:10px 0; color:#fff; font-family:sans-serif; backdrop-filter:blur(8px);">
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:6px;">
          <strong style="color:${borderColor}; font-size:14px; display:flex; align-items:center; gap:6px;">
            ⚠️ PhishLens Security Alert: ${result.threat_type || 'Potential Phishing Threat'}
          </strong>
          <span style="background:${borderColor}; color:#000; font-weight:800; font-size:11px; padding:2px 8px; border-radius:12px;">
            Risk Score: ${result.risk_score}/100
          </span>
        </div>
        <div style="font-size:12px; color:#e2e8f0; margin-bottom:6px;">
          ${result.sender_anomalies && result.sender_anomalies.length > 0 ? result.sender_anomalies[0] : (result.red_flags ? result.red_flags[0] : 'Suspicious patterns detected in this message.')}
        </div>
        <div style="font-size:11px; color:#94a3b8;">
          🛡️ <em>Recommendation: Do not click any links, open attachments, or provide sensitive credentials.</em>
        </div>
      </div>
    `;

    containerElement.insertBefore(banner, containerElement.firstChild);
  }

  // Observe DOM for dynamic page changes
  function observeDomMutations() {
    const observer = new MutationObserver(() => {
      attachLinkInterceptors();
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // Start
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();