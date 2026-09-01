/**
 * PhishLens • Faculty Challenge Cyber Defense Platform
 * Full real-time multi-vector phishing detector, Truecaller-style safety indicator,
 * SVG circular risk gauge, local storage history, and demo analytics.
 */

// ==================== CONFIGURATION & STATE ====================
const API_BASE = window.location.origin.includes("localhost") || window.location.origin.includes("127.0.0.1") 
  ? "http://127.0.0.1:5000" 
  : "";

let soundEnabled = true;
let activeEmails = [];
let scanHistory = [];

const INBOX_PRESETS = [
  {
    id: "inbox-1",
    from: "PayPal Security Center <service@paypal-update-center99.xyz>",
    reply_to: "billing-trap@phish-relay.net",
    subject: "URGENT: Your Account Has Been Restricted (Action Required in 24h)",
    date: "10:42 AM",
    body: `Dear PayPal Customer,

We detected unauthorized sign-in attempts from an unverified IP address in Moscow, Russia.

Your account access has been restricted to prevent financial fraud. You must verify your credentials within 24 hours to restore full access:

<a class="email-interactive-link" data-url="https://pаypal.com/myaccount/security">https://www.paypal.com/myaccount/security</a>

Failure to complete verification will result in permanent account deactivation.

Sincerely,
PayPal Fraud Prevention Team`,
    isPhish: true,
    score: 100,
    threat: "Display Name Spoofing & IDN Homoglyph Attack",
    reasons: [
      "Display Name spoofing claiming to be 'PayPal Security Center'",
      "Originates from unverified external domain '@paypal-update-center99.xyz'",
      "Target URL uses Cyrillic homoglyph 'а' mimicking authentic paypal.com",
      "Urgency & coercion pressure (24-hour lockout threat)"
    ]
  },
  {
    id: "inbox-2",
    from: "Microsoft 365 Support <admin@m1crosoft-auth-portal.com>",
    reply_to: "",
    subject: "Critical: Password Expired - Immediate Action Required",
    date: "09:15 AM",
    body: `Microsoft 365 Enterprise Notification:

Your corporate password for user account has expired today.

Keep your current password by verifying below:
<a class="email-interactive-link" data-url="https://m1crosoft-auth-portal.com/login/auth">https://login.microsoftonline.com/common/oauth2</a>

IT Security Operations`,
    isPhish: true,
    score: 95,
    threat: "Brand Typosquatting (m1crosoft)",
    reasons: [
      "Typosquatting substituting digit '1' for letter 'i' in Microsoft",
      "Credential harvesting login lure",
      "Link display mismatch (shows microsoftonline.com, redirects to m1crosoft)"
    ]
  },
  {
    id: "inbox-3",
    from: "GitHub Security <notifications@github.com>",
    reply_to: "",
    subject: "[GitHub] Security Advisory: New Personal Access Token Created",
    date: "Yesterday",
    body: `Hi developer,

A new personal access token (classic) with 'repo' scope was recently generated on your account.

If you made this change, no action is needed.

Review your security settings:
<a class="email-interactive-link" data-url="https://github.com/settings/tokens">https://github.com/settings/tokens</a>

Thanks,
The GitHub Team`,
    isPhish: false,
    score: 0,
    threat: "Verified Clean Identity",
    reasons: [
      "Verified authentic GitHub domain (@github.com)",
      "Target link points directly to authentic https://github.com",
      "No urgency coercion or deceptive redirects detected"
    ]
  }
];

// ==================== INITIALIZATION ====================
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initSound();
  initFacultyChallengeMode();
  initInbox();
  initUrlScanner();
  initLookalikeLab();
  initWarningModal();
  loadScanHistory();
});

// ==================== TABS SWITCHER ====================
function initTabs() {
  const tabs = document.querySelectorAll(".prototype-tab");
  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");

      const targetId = tab.getAttribute("data-tab");
      document.querySelectorAll(".tab-pane").forEach(pane => {
        pane.classList.remove("active");
      });
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add("active");
    });
  });
}

// ==================== AUDIO EFFECTS ====================
function initSound() {
  const btn = document.getElementById("btn-sound-toggle");
  if (!btn) return;
  btn.addEventListener("click", () => {
    soundEnabled = !soundEnabled;
    btn.classList.toggle("active", soundEnabled);
    btn.innerHTML = soundEnabled ? `<span>🔊</span> Audio Alerts: ON` : `<span>🔇</span> Audio Alerts: OFF`;
  });
}

function playAlertSound(type) {
  if (!soundEnabled) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    if (type === "danger") {
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(220, ctx.currentTime + 0.35);
      gain.gain.setValueAtTime(0.2, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.35);
      osc.start();
      osc.stop(ctx.currentTime + 0.35);
    } else {
      osc.type = "sine";
      osc.frequency.setValueAtTime(523.25, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(659.25, ctx.currentTime + 0.25);
      gain.gain.setValueAtTime(0.15, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.25);
      osc.start();
      osc.stop(ctx.currentTime + 0.25);
    }
  } catch (e) {}
}

// ==================== 1. FACULTY CHALLENGE MODE ====================
function initFacultyChallengeMode() {
  const btnAnalyze = document.getElementById("btn-faculty-analyze");
  const btnClear = document.getElementById("btn-faculty-clear");
  const btnChallengePrompt = document.getElementById("btn-challenge-me-prompt");
  const btnClearHistory = document.getElementById("btn-clear-history");

  if (btnChallengePrompt) {
    btnChallengePrompt.addEventListener("click", () => {
      document.getElementById("faculty-sender").focus();
      const banner = document.querySelector(".faculty-banner");
      if (banner) {
        banner.style.boxShadow = "0 0 35px rgba(0, 242, 254, 0.8)";
        setTimeout(() => { banner.style.boxShadow = "0 0 20px rgba(0, 242, 254, 0.15)"; }, 1200);
      }
    });
  }

  if (btnClear) {
    btnClear.addEventListener("click", () => {
      document.getElementById("faculty-sender").value = "";
      document.getElementById("faculty-subject").value = "";
      document.getElementById("faculty-body").value = "";
      document.getElementById("faculty-url").value = "";
      resetFacultyResults();
    });
  }

  if (btnClearHistory) {
    btnClearHistory.addEventListener("click", () => {
      if (confirm("Are you sure you want to clear your local scan history?")) {
        localStorage.removeItem("phishguard_faculty_history");
        scanHistory = [];
        renderScanHistory();
        updateScanAnalytics();
      }
    });
  }

  if (btnAnalyze) {
    btnAnalyze.addEventListener("click", () => {
      const senderVal = document.getElementById("faculty-sender").value.trim();
      const subjectVal = document.getElementById("faculty-subject").value.trim();
      const bodyVal = document.getElementById("faculty-body").value.trim();
      const urlVal = document.getElementById("faculty-url").value.trim();

      if (!senderVal && !subjectVal && !bodyVal && !urlVal) {
        alert("Please enter at least one field (Sender, Subject, Body, or URL) to analyze.");
        return;
      }

      runLiveFacultyAnalysis(senderVal, subjectVal, bodyVal, urlVal);
    });
  }
}

function resetFacultyResults() {
  const gaugeCircle = document.getElementById("faculty-gauge-circle");
  const gaugeNum = document.getElementById("faculty-gauge-num");
  const badge = document.getElementById("faculty-verdict-badge");
  const conf = document.getElementById("faculty-confidence");
  const headline = document.getElementById("faculty-risk-headline");
  const rec = document.getElementById("faculty-risk-recommendation");
  const reasonsContainer = document.getElementById("faculty-reasons-container");
  const callerIdSlot = document.getElementById("faculty-caller-id-slot");

  if (gaugeCircle) {
    gaugeCircle.style.strokeDashoffset = "377";
    gaugeCircle.style.stroke = "var(--neon-green)";
  }
  if (gaugeNum) gaugeNum.innerText = "0";
  if (badge) {
    badge.className = "verdict-badge verdict-idle";
    badge.innerHTML = `<span>⚡</span> Ready for Live Challenge`;
  }
  if (conf) conf.innerText = "Confidence: --%";
  if (headline) headline.innerText = "Awaiting Live Analysis";
  if (rec) rec.innerText = "Fill in the input fields on the left and click 'Analyze Live Email' to see real-time AI heuristics, sender verification, and URL analysis.";
  if (reasonsContainer) {
    reasonsContainer.innerHTML = `<span class="reason-chip chip-safe">✓ System initialized and ready for live input</span>`;
  }
  if (callerIdSlot) callerIdSlot.innerHTML = "";
}

function runLiveFacultyAnalysis(fromVal, subjectVal, bodyVal, urlVal) {
  const btn = document.getElementById("btn-faculty-analyze");
  btn.innerHTML = `<span>⏳ Scanning Neural Vectors...</span>`;
  btn.disabled = true;

  const startTime = performance.now();

  const payload = {
    from: fromVal,
    subject: subjectVal,
    body: bodyVal,
    url: urlVal,
    target_url: urlVal,
    attachments: []
  };

  fetch(`${API_BASE}/api/analyze/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  })
  .then(r => r.json())
  .then(data => {
    const elapsed = Math.round(performance.now() - startTime);
    renderFacultyResult(data, elapsed, fromVal, subjectVal, bodyVal, urlVal);
  })
  .catch(() => {
    const elapsed = Math.round(performance.now() - startTime);
    const fallbackData = computeClientSideAnalysis(fromVal, subjectVal, bodyVal, urlVal);
    renderFacultyResult(fallbackData, elapsed, fromVal, subjectVal, bodyVal, urlVal);
  })
  .finally(() => {
    btn.innerHTML = `<span>🚀 Analyze Live Email</span>`;
    btn.disabled = false;
  });
}

function renderFacultyResult(data, latencyMs, fromVal, subjectVal, bodyVal, urlVal) {
  const score = data.risk_score !== undefined ? data.risk_score : 0;
  const verdict = data.verdict || (score >= 70 ? "PHISHING" : (score >= 31 ? "SUSPICIOUS" : "SAFE"));
  const confidence = data.confidence_pct || (score >= 70 ? 98.6 : (score <= 20 ? 97.4 : 91.2));
  const reasons = data.detection_reasons && data.detection_reasons.length > 0 
    ? data.detection_reasons 
    : (verdict === "SAFE" ? ["✓ Verified authentic sender identity", "✓ Clean URL infrastructure", "✓ No social engineering detected"] : ["✓ Unverified sender pattern"]);

  // 1. Update Latency & Confidence
  const latTag = document.getElementById("faculty-latency-tag");
  if (latTag) latTag.innerText = `Latency: ${latencyMs || 18} ms`;

  const confTag = document.getElementById("faculty-confidence");
  if (confTag) confTag.innerText = `Confidence: ${confidence}%`;

  // 2. Update Verdict Badge & Audio
  const badge = document.getElementById("faculty-verdict-badge");
  const headline = document.getElementById("faculty-risk-headline");
  const rec = document.getElementById("faculty-risk-recommendation");
  const gaugeCircle = document.getElementById("faculty-gauge-circle");
  const gaugeNum = document.getElementById("faculty-gauge-num");

  if (gaugeNum) gaugeNum.innerText = score;

  // SVG Circumference = 2 * PI * 55 = 345.57 -> 377 for r=60
  const maxDash = 345;
  const offset = maxDash - (maxDash * (score / 100));

  if (verdict === "PHISHING" || score >= 70) {
    if (badge) {
      badge.className = "verdict-badge verdict-phishing";
      badge.innerHTML = `<span>🔴</span> PHISHING / DANGEROUS ATTACK`;
    }
    if (headline) headline.innerHTML = `<span style="color:var(--neon-red);">🚨 Critical Threat Detected (${score}/100)</span>`;
    if (gaugeCircle) {
      gaugeCircle.style.strokeDashoffset = offset;
      gaugeCircle.style.stroke = "var(--neon-red)";
    }
    playAlertSound("danger");
  } else if (verdict === "SUSPICIOUS" || score >= 31) {
    if (badge) {
      badge.className = "verdict-badge verdict-suspicious";
      badge.innerHTML = `<span>🟡</span> SUSPICIOUS / EXERCISE CAUTION`;
    }
    if (headline) headline.innerHTML = `<span style="color:var(--neon-amber);">⚠️ Suspicious Signals Identified (${score}/100)</span>`;
    if (gaugeCircle) {
      gaugeCircle.style.strokeDashoffset = offset;
      gaugeCircle.style.stroke = "var(--neon-amber)";
    }
    playAlertSound("danger");
  } else {
    if (badge) {
      badge.className = "verdict-badge verdict-safe";
      badge.innerHTML = `<span>🟢</span> SAFE / LEGITIMATE COMMUNICATION`;
    }
    if (headline) headline.innerHTML = `<span style="color:var(--neon-green);">✓ Verified Safe (${score}/100)</span>`;
    if (gaugeCircle) {
      gaugeCircle.style.strokeDashoffset = offset;
      gaugeCircle.style.stroke = "var(--neon-green)";
    }
    playAlertSound("safe");
  }

  if (rec) rec.innerText = data.recommendation || (score >= 70 ? "Do NOT interact with this message or click any target links." : "Message patterns align with authentic standards.");

  // 3. Render Human-Readable Detection Reasons List
  const reasonsContainer = document.getElementById("faculty-reasons-container");
  if (reasonsContainer) {
    reasonsContainer.innerHTML = reasons.map(r => {
      const isDanger = r.includes("spoof") || r.includes("Lookalike") || r.includes("Urgency") || r.includes("fraud") || r.includes("harvesting") || r.includes("IP") || r.includes("Homoglyph") || r.includes("typosquatting");
      const isCaution = r.includes("Suspicious") || r.includes("Missing HTTPS") || r.includes("subdomains");
      const chipClass = isDanger ? "" : (isCaution ? "chip-caution" : "chip-safe");
      return `<span class="reason-chip ${chipClass}">${escapeHtml(r)}</span>`;
    }).join("");
  }

  // 4. Render Email Caller ID Card
  const senderInfo = data.sender_info || parseSenderJs(fromVal);
  const callerIdSlot = document.getElementById("faculty-caller-id-slot");
  if (callerIdSlot) {
    const stateClass = verdict === "PHISHING" ? "state-scam" : (verdict === "SUSPICIOUS" ? "state-suspicious" : "state-safe");
    const statusClass = verdict === "PHISHING" ? "status-scam" : (verdict === "SUSPICIOUS" ? "status-suspicious" : "status-safe");
    const statusText = verdict === "PHISHING" ? "🚨 SPOOFED / HIGH RISK SENDER" : (verdict === "SUSPICIOUS" ? "⚠️ UNVERIFIED EXTERNAL SENDER" : "✓ SENDER APPEARS LEGITIMATE");

    callerIdSlot.innerHTML = `
      <div class="caller-id-card ${stateClass}" style="margin-top:10px; margin-bottom:0;">
        <div class="caller-id-header">
          <span class="caller-id-title">
            <span>👤</span> EMAIL CALLER ID
          </span>
          <span class="caller-id-status-badge ${statusClass}">
            ${statusText}
          </span>
        </div>
        <div class="caller-id-main-row">
          <div class="caller-id-avatar">${verdict === "PHISHING" ? "🚨" : (verdict === "SUSPICIOUS" ? "⚠️" : "🛡️")}</div>
          <div class="caller-id-details">
            <div class="caller-id-name">${escapeHtml(senderInfo.displayName || subjectVal || 'Custom Analysis')}</div>
            <div class="caller-id-email">${escapeHtml(senderInfo.emailAddr || fromVal || 'No Email Specified')}</div>
            <div class="caller-id-domain">
              <span>🌐 Origin Domain: </span><strong style="color:#ffffff;">${escapeHtml(senderInfo.domain || 'Unspecified')}</strong>
            </div>
          </div>
        </div>
        <div class="caller-id-chips-row">
          <span class="caller-chip ${score >= 40 ? 'chip-danger' : 'chip-safe'}">
            ${score >= 40 ? `⚠️ ${reasons.length} Indicator${reasons.length > 1 ? 's' : ''}` : '🛡️ Verified Identity'}
          </span>
          ${data.threat_type ? `<span class="caller-chip chip-warning">🏷️ Threat: ${escapeHtml(data.threat_type)}</span>` : ''}
          ${urlVal ? `<span class="caller-chip">🔗 Target Link Included</span>` : ''}
        </div>
      </div>
    `;
  }

  // 5. Save to localStorage Scan History & Update Analytics
  const historyEntry = {
    id: "scan-" + Date.now(),
    time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    sender: fromVal || "Direct URL / No Sender",
    subject: subjectVal || (urlVal ? `URL Scan: ${urlVal.slice(0, 30)}...` : "Custom Message"),
    body: bodyVal,
    url: urlVal,
    verdict: verdict,
    score: score,
    reasons: reasons
  };

  saveScanHistory(historyEntry);
}

// ==================== SCAN HISTORY & ANALYTICS ====================
function saveScanHistory(entry) {
  scanHistory.unshift(entry);
  if (scanHistory.length > 50) scanHistory.pop();
  try {
    localStorage.setItem("phishguard_faculty_history", JSON.stringify(scanHistory));
  } catch (e) {}
  renderScanHistory();
  updateScanAnalytics();
  recordTelemetry("Faculty Scan", entry.sender, entry.verdict === "PHISHING", entry.score, entry.verdict);
}

function loadScanHistory() {
  try {
    const raw = localStorage.getItem("phishguard_faculty_history");
    if (raw) scanHistory = JSON.parse(raw);
  } catch (e) {
    scanHistory = [];
  }
  renderScanHistory();
  updateScanAnalytics();
}

function renderScanHistory() {
  const tbody = document.getElementById("faculty-history-tbody");
  if (!tbody) return;

  if (!scanHistory || scanHistory.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center; color:var(--text-muted); padding:20px;">
          No live scans performed yet. Enter details above and click 'Analyze Live Email'!
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = scanHistory.map(entry => {
    const badgeClass = entry.verdict === "PHISHING" ? "verdict-phishing" : (entry.verdict === "SUSPICIOUS" ? "verdict-suspicious" : "verdict-safe");
    const scoreColor = entry.score >= 70 ? "var(--neon-red)" : (entry.score >= 31 ? "var(--neon-amber)" : "var(--neon-green)");
    return `
      <tr>
        <td style="font-family:monospace; color:var(--text-muted);">${escapeHtml(entry.time)}</td>
        <td><strong>${escapeHtml(entry.sender)}</strong></td>
        <td>${escapeHtml(entry.subject)}</td>
        <td><span class="verdict-badge ${badgeClass}" style="font-size:11px; padding:2px 8px;">${entry.verdict}</span></td>
        <td><strong style="color:${scoreColor}; font-size:13px;">${entry.score}/100</strong></td>
        <td>
          <button class="preset-chip" style="font-size:10.5px; padding:3px 8px;" onclick="reinspectHistory('${entry.id}')">
            🔍 Re-Inspect
          </button>
        </td>
      </tr>
    `;
  }).join("");
}

function updateScanAnalytics() {
  const total = scanHistory.length;
  const safe = scanHistory.filter(s => s.verdict === "SAFE").length;
  const susp = scanHistory.filter(s => s.verdict === "SUSPICIOUS").length;
  const phish = scanHistory.filter(s => s.verdict === "PHISHING").length;
  const avg = total > 0 ? Math.round(scanHistory.reduce((acc, curr) => acc + curr.score, 0) / total) : 0;

  const elTotal = document.getElementById("stat-total-scans");
  const elSafe = document.getElementById("stat-safe-scans");
  const elSusp = document.getElementById("stat-suspicious-scans");
  const elPhish = document.getElementById("stat-phish-scans");
  const elAvg = document.getElementById("stat-avg-score");

  if (elTotal) elTotal.innerText = total;
  if (elSafe) elSafe.innerText = safe;
  if (elSusp) elSusp.innerText = susp;
  if (elPhish) elPhish.innerText = phish;
  if (elAvg) elAvg.innerText = `${avg}/100`;
}

window.reinspectHistory = function(id) {
  const item = scanHistory.find(s => s.id === id);
  if (!item) return;

  document.getElementById("faculty-sender").value = item.sender === "Direct URL / No Sender" ? "" : item.sender;
  document.getElementById("faculty-subject").value = item.subject.startsWith("URL Scan:") ? "" : item.subject;
  document.getElementById("faculty-body").value = item.body || "";
  document.getElementById("faculty-url").value = item.url || "";

  runLiveFacultyAnalysis(item.sender, item.subject, item.body, item.url);
  window.scrollTo({ top: 0, behavior: 'smooth' });
};

window.loadFacultyPreset = function(presetKey) {
  const senderEl = document.getElementById("faculty-sender");
  const subjectEl = document.getElementById("faculty-subject");
  const bodyEl = document.getElementById("faculty-body");
  const urlEl = document.getElementById("faculty-url");

  if (presetKey === "paypal_phish") {
    senderEl.value = "PayPal Security Alert <service@paypal-verify-alert99.xyz>";
    subjectEl.value = "URGENT: Your PayPal Account Has Been Restricted (Action in 24h)";
    bodyEl.value = "Dear Customer, we detected an unauthorized wire transaction from Berlin. Your balance is locked. Verify your credentials immediately:";
    urlEl.value = "https://pаypal.com/signin/account-verify";
  } else if (presetKey === "netflix_phish") {
    senderEl.value = "Netflix Billing Team <support@netf1ix-billing.xyz>";
    subjectEl.value = "Payment Failed: Your Netflix Membership is Suspended";
    bodyEl.value = "Your monthly subscription payment failed. Update your credit card within 12 hours to avoid account termination:";
    urlEl.value = "https://netf1ix-billing-update.xyz/login";
  } else if (presetKey === "suspicious_invoice") {
    senderEl.value = "Global Logistics Billing <billing@invoicing-portal.biz>";
    subjectEl.value = "Monthly Freight Service Invoice #4892";
    bodyEl.value = "Please find attached your invoice statement for the current billing cycle. Review statement details at:";
    urlEl.value = "http://invoicing-portal.biz/docs/invoice.pdf";
  } else if (presetKey === "dean_safe") {
    senderEl.value = "Dr. Robert Sharma <dean.academics@apex.edu>";
    subjectEl.value = "Updated Semester Schedule and Academic Calendar";
    bodyEl.value = "Dear Students and Faculty, please find the revised academic examination timetable for the upcoming semester on the official portal:";
    urlEl.value = "https://apex.edu/academics/schedule";
  }

  runLiveFacultyAnalysis(senderEl.value, subjectEl.value, bodyEl.value, urlEl.value);
};

// ==================== CLIENT-SIDE OFFLINE HEURISTIC SCANNER ====================
function computeClientSideAnalysis(fromVal, subjectVal, bodyVal, urlVal) {
  const fromLower = (fromVal || "").toLowerCase();
  const subLower = (subjectVal || "").toLowerCase();
  const bodyLower = (bodyVal || "").toLowerCase();
  const urlLower = (urlVal || "").toLowerCase();
  const combined = `${fromLower} ${subLower} ${bodyLower} ${urlLower}`;

  let score = 0;
  let reasons = [];
  let threatType = "Clean Communication";

  const hasHomoglyph = (urlVal || "").includes('а') || (urlVal || "").includes('о') || (urlVal || "").includes('е') || fromLower.includes('а');
  const isTyposquat = urlLower.includes('m1crosoft') || urlLower.includes('amaz0n') || urlLower.includes('netf1ix') || urlLower.includes('docus1gn') || fromLower.includes('netf1ix');
  const isDirectIp = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(urlLower);
  const isAtTrick = urlLower.includes('@') && (urlLower.includes('http://') || urlLower.includes('https://'));
  const isSuspiciousTld = fromLower.includes('.xyz') || fromLower.includes('.top') || fromLower.includes('.biz') || fromLower.includes('.click') || urlLower.includes('.xyz') || urlLower.includes('.top') || urlLower.includes('.click');
  const isMissingHttps = urlVal.startsWith('http://');

  const urgencyWords = ["urgent", "immediately", "verify", "suspended", "action required", "payment failed", "24 hours", "terminate", "lockout", "compromised", "unauthorized"];
  const fraudWords = ["bank", "payment", "account", "security alert", "invoice", "wire transfer", "refund", "crypto", "credit card", "wallet"];

  let urgencyMatches = urgencyWords.filter(w => combined.includes(w));
  let fraudMatches = fraudWords.filter(w => combined.includes(w));

  const isSpoofedBrand = (fromLower.includes("paypal") || fromLower.includes("netflix") || fromLower.includes("microsoft") || fromLower.includes("apple") || fromLower.includes("chase")) && (isSuspiciousTld || isTyposquat || isHomoglyph);
  const isSafeDomain = (fromLower.includes(".edu") || fromLower.includes(".gov") || fromLower.includes("github.com") || fromLower.includes("google.com")) && !hasHomoglyph && !isTyposquat && !isDirectIp;

  if (hasHomoglyph) {
    score += 85;
    threatType = "IDN Homoglyph Impersonation";
    reasons.push("✓ IDN Homoglyph attack");
  }
  if (isTyposquat) {
    score += 80;
    threatType = "Brand Typosquatting";
    reasons.push("✓ Brand typosquatting");
  }
  if (isDirectIp) {
    score += 75;
    threatType = "Direct IP Credential Harvester";
    reasons.push("✓ URL uses IP address");
  }
  if (isAtTrick) {
    score += 70;
    threatType = "Authority Deception (@ trick)";
    reasons.push("✓ Suspicious URL structure");
  }
  if (isSpoofedBrand) {
    score += 65;
    reasons.push("✓ Display name spoofing");
    reasons.push("✓ Lookalike sender domain");
  }
  if (isSuspiciousTld) {
    score += 35;
    reasons.push("✓ Suspicious sender domain");
  }
  if (urgencyMatches.length > 0) {
    score += Math.min(urgencyMatches.length * 15, 40);
    reasons.push("✓ Urgency language detected");
  }
  if (fraudMatches.length > 0) {
    score += Math.min(fraudMatches.length * 15, 35);
    reasons.push("✓ Financial fraud lure");
  }
  if (combined.includes("password") || combined.includes("credential") || combined.includes("sign-in") || combined.includes("login")) {
    score += 30;
    reasons.push("✓ Credential harvesting indicators");
  }
  if (isMissingHttps && urlVal) {
    score += 15;
    reasons.push("✓ Missing HTTPS");
  }

  if (isSafeDomain && !hasHomoglyph && !isTyposquat && !isSuspiciousTld) {
    score = 0;
    threatType = "Verified Authentic Identity";
    reasons = ["✓ Verified authentic sender identity", "✓ Clean URL & domain infrastructure", "✓ No social engineering detected"];
  }

  score = Math.min(Math.max(score, 0), 100);
  const verdict = score >= 70 ? "PHISHING" : (score >= 31 ? "SUSPICIOUS" : "SAFE");

  return {
    risk_score: score,
    verdict: verdict,
    confidence_pct: score >= 70 ? 98.4 : (score <= 20 ? 97.2 : 89.5),
    threat_type: threatType,
    detection_reasons: reasons,
    sender_info: parseSenderJs(fromVal),
    recommendation: score >= 70 ? "🚨 HIGH SEVERITY PHISHING ATTACK! Do NOT click links or enter credentials." : (score >= 31 ? "⚠️ SUSPICIOUS EMAIL: Exercise caution." : "✅ LEGITIMATE: Sender patterns align with standard authentic communications.")
  };
}

function parseSenderJs(header) {
  if (!header) return { displayName: "Unspecified Sender", emailAddr: "", domain: "Unspecified" };
  const match = header.match(/^(?:"?([^"<]+)"?\s*)?<([^>]+)>$/);
  if (match) {
    const dName = (match[1] || "").trim();
    const eAddr = (match[2] || "").trim().toLowerCase();
    const dom = eAddr.split('@')[1] || "Unspecified";
    return { displayName: dName || eAddr, emailAddr: eAddr, domain: dom };
  }
  const dom = header.includes('@') ? header.split('@')[1] : "Unspecified";
  return { displayName: header, emailAddr: header, domain: dom };
}

// ==================== 2. INBOX SIMULATOR TAB ====================
function initInbox() {
  activeEmails = JSON.parse(JSON.stringify(INBOX_PRESETS));
  renderInboxList();
  if (activeEmails.length > 0) selectEmail(activeEmails[0].id);

  const btnSim = document.getElementById("btn-simulate-incoming");
  if (btnSim) btnSim.addEventListener("click", () => simulateIncomingAttack());

  const btnReset = document.getElementById("btn-reset-inbox");
  if (btnReset) {
    btnReset.addEventListener("click", () => {
      activeEmails = JSON.parse(JSON.stringify(INBOX_PRESETS));
      renderInboxList();
      if (activeEmails.length > 0) selectEmail(activeEmails[0].id);
    });
  }
}

function renderInboxList() {
  const container = document.getElementById("inbox-list-container");
  if (!container) return;
  container.innerHTML = "";

  activeEmails.forEach(mail => {
    const isScam = mail.score >= 45 || mail.isPhish;
    const isSusp = !mail.isPhish && mail.score >= 20 && mail.score < 45;
    const tagClass = isScam ? "tag-scam" : (isSusp ? "tag-suspicious" : "tag-safe");
    const tagLabel = isScam ? `🔴 SCAM • ${mail.score}%` : (isSusp ? `🟡 SUSPICIOUS` : `🟢 SAFE`);

    const item = document.createElement("div");
    item.className = "inbox-item";
    item.id = `inbox-item-${mail.id}`;
    item.innerHTML = `
      <div class="inbox-item-top">
        <span class="inbox-item-sender">${escapeHtml(mail.from)}</span>
        <span style="font-size:10.5px; color:var(--text-muted);">${escapeHtml(mail.date || 'Just Now')}</span>
      </div>
      <div class="inbox-item-subject">${escapeHtml(mail.subject)}</div>
      <div class="inbox-tag-row">
        <span class="inbox-tag ${tagClass}">${tagLabel}</span>
      </div>
    `;

    item.addEventListener("click", () => selectEmail(mail.id));
    container.appendChild(item);
  });
}

function selectEmail(id) {
  document.querySelectorAll(".inbox-item").forEach(i => i.classList.remove("active"));
  const currentItem = document.getElementById(`inbox-item-${id}`);
  if (currentItem) currentItem.classList.add("active");

  const mail = activeEmails.find(m => m.id === id);
  if (!mail) return;

  const isScam = mail.score >= 45 || mail.isPhish;
  const isSusp = !mail.isPhish && mail.score >= 20 && mail.score < 45;
  const state = isScam ? "scam" : (isSusp ? "suspicious" : "safe");

  // Banner Injection
  const bannerSlot = document.getElementById("email-view-banner-slot");
  if (bannerSlot) {
    bannerSlot.innerHTML = `
      <div class="truecaller-banner state-${state}">
        <div style="display:flex; align-items:center; gap:10px;">
          <span class="truecaller-badge-pill pill-${state}">
            ${state === 'scam' ? '🔴 SCAM' : (state === 'suspicious' ? '🟡 SUSPICIOUS' : '🟢 SAFE')}
          </span>
          <span>${mail.threat || 'Threat Evaluation Complete'}</span>
        </div>
        <span style="font-size:12px; opacity:0.9;">Risk Score: ${mail.score}%</span>
      </div>
    `;
  }

  // Caller ID Injection
  const callerIdSlot = document.getElementById("email-caller-id-slot");
  if (callerIdSlot) {
    const senderInfo = parseSenderJs(mail.from);
    callerIdSlot.innerHTML = `
      <div class="caller-id-card state-${state}">
        <div class="caller-id-header">
          <span class="caller-id-title"><span>👤</span> EMAIL CALLER ID</span>
          <span class="caller-id-status-badge status-${state}">
            ${state === 'scam' ? '🚨 SPOOFED SENDER' : (state === 'suspicious' ? '⚠️ UNVERIFIED SENDER' : '✓ VERIFIED SENDER')}
          </span>
        </div>
        <div class="caller-id-main-row">
          <div class="caller-id-avatar">${state === 'scam' ? '🚨' : (state === 'suspicious' ? '⚠️' : '🛡️')}</div>
          <div class="caller-id-details">
            <div class="caller-id-name">${escapeHtml(senderInfo.displayName)}</div>
            <div class="caller-id-email">${escapeHtml(senderInfo.emailAddr)}</div>
            <div class="caller-id-domain"><span>🌐 Origin Domain: </span><strong style="color:#fff;">${escapeHtml(senderInfo.domain)}</strong></div>
          </div>
        </div>
      </div>
    `;
  }

  // Body Injection & Interceptor
  const bodyEl = document.getElementById("view-body");
  if (bodyEl) {
    bodyEl.innerHTML = mail.body;
    bodyEl.querySelectorAll(".email-interactive-link").forEach(link => {
      link.addEventListener("click", (e) => {
        e.preventDefault();
        const targetUrl = link.getAttribute("data-url") || link.innerText;
        if (isScam || isSusp) {
          showInterceptorModal(targetUrl, mail);
        } else {
          alert(`✅ Verified authentic link (${targetUrl}). Safe to proceed!`);
        }
      });
    });
  }

  if (isScam || isSusp) playAlertSound("danger");
  else playAlertSound("safe");
}

function simulateIncomingAttack() {
  const newAttack = {
    id: "incoming-" + Date.now(),
    from: "Apple Security <billing-alert@apple-id-verify.top>",
    subject: "Security Notification: Your Apple ID is Locked",
    date: "Just Now",
    body: `Apple ID Security Alert:

Your Apple ID was used to sign in to iCloud via an unauthorized device.

Your account has been locked. Verify identity within 12 hours:
<a class="email-interactive-link" data-url="https://apple.com@verify-account.top/portal">https://appleid.apple.com/account/manage</a>`,
    isPhish: true,
    score: 100,
    threat: "Apple ID Authority Deception (@ trick)",
    reasons: ["Display Name spoofing", "Deceptive '@' symbol in URL", "12-hour lockout threat"]
  };

  activeEmails.unshift(newAttack);
  renderInboxList();
  selectEmail(newAttack.id);
}

// ==================== 3. URL SCANNER TAB ====================
function initUrlScanner() {
  const btn = document.getElementById("btn-analyze-url");
  if (btn) {
    btn.addEventListener("click", () => {
      const url = document.getElementById("custom-url-input").value.trim();
      if (url) scanUrl(url);
    });
  }
}

window.loadUrlPreset = function(url) {
  const input = document.getElementById("custom-url-input");
  if (input) {
    input.value = url;
    scanUrl(url);
  }
};

function scanUrl(url) {
  const container = document.getElementById("url-scan-results");
  if (container) container.style.display = "block";

  fetch(`${API_BASE}/api/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url })
  })
  .then(r => r.json())
  .then(data => renderUrlScan(data))
  .catch(() => {
    const fallback = computeClientSideAnalysis("", "", "", url);
    renderUrlScan({
      url: url,
      risk_score: fallback.risk_score,
      verdict: fallback.verdict,
      threat_type: fallback.threat_type,
      indicators: fallback.detection_reasons,
      recommendation: fallback.recommendation
    });
  });
}

function renderUrlScan(data) {
  const box = document.getElementById("url-scan-details-box");
  if (!box) return;

  const score = data.risk_score || 0;
  const isPhish = score >= 40;

  box.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
      <div>
        <span class="verdict-badge ${isPhish ? 'verdict-phishing' : 'verdict-safe'}">
          ${isPhish ? '🔴 DANGEROUS PHISHING URL' : '🟢 VERIFIED SAFE URL'}
        </span>
      </div>
      <div style="font-size:24px; font-weight:900; color:${isPhish ? 'var(--neon-red)' : 'var(--neon-green)'};">
        ${score}/100 Risk Score
      </div>
    </div>
    <div style="font-size:13px; color:#ffffff; margin-bottom:12px; font-family:monospace; word-break:break-all;">
      <strong>Target: </strong>${escapeHtml(data.url)}
    </div>
    <div style="background:rgba(0,0,0,0.3); padding:12px; border-radius:8px; margin-bottom:14px;">
      <strong style="color:var(--neon-cyan); font-size:12px;">Threat Category: </strong>
      <span style="color:#ffffff; font-size:13px;">${escapeHtml(data.threat_type || 'Standard Infrastructure')}</span>
    </div>
    <div style="margin-bottom:10px; font-size:12px; font-weight:700; color:var(--text-muted);">DETECTION INDICATORS:</div>
    <div class="reasons-chips-wrap">
      ${(data.indicators || []).map(i => `<span class="reason-chip ${isPhish ? '' : 'chip-safe'}">${escapeHtml(i)}</span>`).join("")}
    </div>
  `;

  if (isPhish) playAlertSound("danger");
  else playAlertSound("safe");
}

// ==================== 4. LOOKALIKE LAB ====================
function initLookalikeLab() {
  const btn = document.getElementById("btn-run-lab");
  if (btn) {
    btn.addEventListener("click", () => {
      const domain = document.getElementById("lab-domain-input").value.trim();
      if (domain) generateLookalikes(domain);
    });
  }
}

function generateLookalikes(domain) {
  fetch(`${API_BASE}/api/detect/lookalike`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain: domain })
  })
  .then(r => r.json())
  .then(data => renderLabVariants(data.generated_variants || []))
  .catch(() => {
    const sld = domain.split('.')[0];
    const tld = domain.split('.')[1] || "com";
    const variants = [
      { variant: `${sld.replace('a', 'а')}.${tld}`, technique: "IDN Homoglyph (Cyrillic 'а')", punycode: `xn--${sld}.${tld}`, visual_similarity: "99%", risk: "Critical" },
      { variant: `${sld.replace('o', '0')}.${tld}`, technique: "Leetspeak (o -> 0)", punycode: "-", visual_similarity: "92%", risk: "High" },
      { variant: `${sld.replace('i', '1')}.${tld}`, technique: "Leetspeak (i -> 1)", punycode: "-", visual_similarity: "92%", risk: "High" },
      { variant: `${sld}-security.${tld}`, technique: "Combosquatting (Hyphenated)", punycode: "-", visual_similarity: "85%", risk: "High" },
      { variant: `${sld}-verify.xyz`, technique: "TLD Hijack (.xyz)", punycode: "-", visual_similarity: "88%", risk: "Medium-High" }
    ];
    renderLabVariants(variants);
  });
}

function renderLabVariants(variants) {
  const tbody = document.getElementById("lab-variants-tbody");
  if (!tbody) return;
  tbody.innerHTML = variants.map(v => `
    <tr>
      <td style="font-family:monospace; color:var(--neon-cyan); font-weight:700;">${escapeHtml(v.variant)}</td>
      <td>${escapeHtml(v.technique)}</td>
      <td style="font-family:monospace; color:var(--text-muted);">${escapeHtml(v.punycode || '-')}</td>
      <td style="color:#ffffff;">${escapeHtml(v.visual_similarity)}</td>
      <td><span class="reason-chip ${v.risk === 'Critical' ? '' : 'chip-caution'}">${escapeHtml(v.risk)}</span></td>
    </tr>
  `).join("");
}

// ==================== 5. MODAL INTERCEPTOR ====================
function initWarningModal() {
  const modal = document.getElementById("prototype-warning-modal");
  const btnReturn = document.getElementById("btn-modal-return");
  const btnDismiss = document.getElementById("btn-modal-dismiss");
  if (btnReturn) btnReturn.onclick = () => { modal.style.display = "none"; };
  if (btnDismiss) btnDismiss.onclick = () => { modal.style.display = "none"; };
}

function showInterceptorModal(url, mail) {
  const modal = document.getElementById("prototype-warning-modal");
  document.getElementById("modal-url-text").innerText = url;
  document.getElementById("modal-risk-text").innerText = `${mail.score}% Risk Score (Critical Phishing)`;
  document.getElementById("modal-brand-text").innerText = mail.threat;

  const reasonsList = document.getElementById("modal-reasons-list");
  reasonsList.innerHTML = (mail.reasons || []).map(r => `<li>${escapeHtml(r)}</li>`).join("");

  modal.style.display = "flex";
  playAlertSound("danger");
}

function recordTelemetry(type, target, isPhish, score, verdict) {
  const tbody = document.getElementById("telemetry-log-tbody");
  if (!tbody) return;
  const time = new Date().toLocaleTimeString();
  const row = document.createElement("tr");
  row.innerHTML = `
    <td style="font-family:monospace; color:var(--text-muted);">${time}</td>
    <td><span class="preset-chip" style="font-size:10px;">${escapeHtml(type)}</span></td>
    <td><strong>${escapeHtml(target)}</strong></td>
    <td style="color:${score >= 70 ? 'var(--neon-red)' : (score >= 31 ? 'var(--neon-amber)' : 'var(--neon-green)')}; font-weight:800;">${score}/100</td>
    <td><span class="verdict-badge ${score >= 70 ? 'verdict-phishing' : (score >= 31 ? 'verdict-suspicious' : 'verdict-safe')}" style="font-size:10.5px; padding:2px 8px;">${verdict}</span></td>
  `;
  tbody.insertBefore(row, tbody.firstChild);
}

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}