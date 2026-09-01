/**
 * PhishLens PhishGuard - Prototype Defense Logic & Interactive Simulation Center
 */

// Automatically detect API host:
// When deployed on Vercel, use relative paths to the same domain.
// When running locally on port 8080 or from local file, fallback to http://localhost:5000.
const API_BASE = (window.location.hostname === "localhost" && window.location.port === "8080")
  ? "http://localhost:5000"
  : (window.location.protocol.startsWith("http") ? "" : "http://localhost:5000");

// Sound synthesis using Web Audio API
let audioCtx = null;
let soundEnabled = true;

function playAlertSound(type = "danger") {
  if (!soundEnabled) return;
  try {
    if (!audioCtx) audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain);
    gain.connect(audioCtx.destination);

    if (type === "danger") {
      // Dual-tone urgent alert
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(880, audioCtx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.25);
      gain.gain.setValueAtTime(0.12, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.25);
    } else {
      // Soft pleasant confirmation chime
      osc.type = "sine";
      osc.frequency.setValueAtTime(587.33, audioCtx.currentTime); // D5
      osc.frequency.setValueAtTime(880, audioCtx.currentTime + 0.1); // A5
      gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.3);
    }
  } catch (e) {
    // Audio context may be restricted before user interaction
  }
}

// Global In-Memory Data
let activeEmails = [];
let telemetryStats = {
  total: 0,
  phish: 0,
  lookalikes: 0,
  spoofs: 0,
  logs: []
};

// Curated realistic emails for live simulation
const INBOX_PRESETS = [
  {
    id: "mail-paypal-1",
    from: "PayPal Security Center <service@paypal-update-center99.xyz>",
    reply_to: "recovery@inbox-portal.top",
    subject: "URGENT: Your PayPal Account Has Been Restricted (Action Required in 24 Hours)",
    date: "Just Now",
    body: `Dear Customer,

We detected unauthorized sign-in activity on your PayPal account from an unrecognized location. To safeguard your balance, your account has been temporarily restricted.

You have 24 hours to confirm your identity, or your account will be permanently closed.

Please verify your account credentials immediately:
<a class="email-interactive-link" data-url="https://pаypal.com/signin/account-verify">https://www.paypal.com/myaccount/security</a>

Thank you,
PayPal Security Team`,
    isPhish: true,
    score: 100,
    threat: "Display Name Spoofing & IDN Homoglyph",
    reasons: [
      "Display Name claims to be 'PayPal Security' but sender domain is '@paypal-urgent-update99.xyz'",
      "Embedded link uses Cyrillic homoglyph ('а' instead of Latin 'a') to mimic paypal.com",
      "Artificial urgency triggers ('restricted in 24 hours') designed to force impulsive action"
    ]
  },
  {
    id: "mail-m365-2",
    from: "Microsoft 365 IT Helpdesk <it-admin@m1crosoft-security.xyz>",
    reply_to: "",
    subject: "Final Notice: Your Microsoft 365 Password Expires Today",
    date: "5 mins ago",
    body: `IT Helpdesk Alert:

Your corporate Microsoft 365 password is scheduled to expire in 3 hours. Failure to update your password will result in immediate disconnection from company VPN and Outlook email.

Click below to keep your current password:
<a class="email-interactive-link" data-url="https://m1crosoft-login-auth.xyz/oauth2">https://login.microsoftonline.com/auth/update</a>

Global IT Services`,
    isPhish: true,
    score: 95,
    threat: "Typosquatting (m1crosoft) & Credential Harvester",
    reasons: [
      "Lookalike typosquatting: 'm1crosoft' substitutes digit '1' for letter 'i'",
      "Mismatched link text: displays 'login.microsoftonline.com' but target is 'm1crosoft-login-auth.xyz'",
      "High domain entropy indicating an automated malicious landing page"
    ]
  },
  {
    id: "mail-chase-3",
    from: "Chase Fraud Prevention <chase.fraud.alert@gmail.com>",
    reply_to: "",
    subject: "Security Alert: Unauthorized Wire Transfer of $3,450.00",
    date: "12 mins ago",
    body: `Chase Online Fraud Alert:

A wire transfer of $3,450.00 was requested from your checking account. If you did not authorize this transaction, click below immediately to dispute the charge:

<a class="email-interactive-link" data-url="http://192.168.1.100/chase-online/auth/login.php">http://chase.com/fraud-resolution</a>

Chase Fraud Department`,
    isPhish: true,
    score: 100,
    threat: "Free Webmail Impersonation & Direct IP Phishing",
    reasons: [
      "Institutional impersonation: Bank claims sent from a free public webmail address (@gmail.com)",
      "Link points directly to a raw numerical IP address (192.168.1.100) instead of authentic chase.com",
      "Manufactures financial panic to induce immediate credential submission"
    ]
  },
  {
    id: "mail-github-4",
    from: "GitHub Security <notifications@github.com>",
    reply_to: "support@github.com",
    subject: "[GitHub] Security advisory published for repository",
    date: "25 mins ago",
    body: `Hello,

A new security advisory has been published for a repository on your watchlist. You can review the vulnerability details, affected packages, and recommended upgrades directly on GitHub.

View advisory details:
<a class="email-interactive-link" data-url="https://github.com/security/advisories">https://github.com/security/advisories</a>

Thanks,
The GitHub Team`,
    isPhish: false,
    score: 0,
    threat: "Clean Authentic Notification",
    reasons: [
      "Sender domain matches verified authentic GitHub infrastructure (github.com)",
      "No urgency coercion, credential lures, or link discrepancies detected"
    ]
  }
];

// Initialize on Load
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initSoundToggle();
  initInbox();
  initUrlScanner();
  initLookalikeLab();
  initWarningModal();
});

// Prototype Navigation Tabs
function initTabs() {
  document.querySelectorAll(".prototype-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".prototype-tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      tab.classList.add("active");
      const target = document.getElementById(tab.dataset.tab);
      if (target) target.classList.add("active");
    });
  });
}

function initSoundToggle() {
  const btn = document.getElementById("btn-sound-toggle");
  btn.addEventListener("click", () => {
    soundEnabled = !soundEnabled;
    btn.className = `sound-toggle-btn ${soundEnabled ? 'active' : ''}`;
    btn.innerHTML = soundEnabled ? "<span>🔊</span> Audio Alerts: ON" : "<span>🔇</span> Audio Alerts: OFF";
  });
}

// ==================== INBOX SIMULATOR ====================
function initInbox() {
  activeEmails = JSON.parse(JSON.stringify(INBOX_PRESETS));
  renderInboxList();
  if (activeEmails.length > 0) {
    selectEmail(activeEmails[0].id);
  }

  // Incoming Attack Trigger Button
  document.getElementById("btn-simulate-incoming").addEventListener("click", () => {
    simulateIncomingAttack();
  });

  // Reset Inbox
  document.getElementById("btn-reset-inbox").addEventListener("click", () => {
    activeEmails = JSON.parse(JSON.stringify(INBOX_PRESETS));
    renderInboxList();
    if (activeEmails.length > 0) selectEmail(activeEmails[0].id);
  });

  // Live Real-Time Target URL Inspector Listener
  const craftLinkInput = document.getElementById("craft-link");
  if (craftLinkInput) {
    craftLinkInput.addEventListener("input", (e) => {
      inspectTargetUrlLive(e.target.value);
    });
    inspectTargetUrlLive(craftLinkInput.value);
  }

  // Custom Attack / Real Email Analyzer & Injector
  document.getElementById("btn-inject-custom").addEventListener("click", () => {
    const fromVal = document.getElementById("craft-from").value.trim();
    const subjectVal = document.getElementById("craft-subject").value.trim();
    const linkVal = document.getElementById("craft-link").value.trim();

    if (!fromVal || !subjectVal) return;

    const payload = {
      from: fromVal,
      reply_to: "",
      subject: subjectVal,
      body: `Notice:\n\nPlease check the following reference link:\n${linkVal}`,
      body_html: linkVal ? `<a href="${linkVal}">${linkVal}</a>` : "",
      attachments: []
    };

    fetch(`${API_BASE}/api/analyze/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
    .then(res => res.json())
    .then(data => {
      const newMail = {
        id: "custom-" + Date.now(),
        from: fromVal,
        reply_to: "",
        subject: subjectVal,
        date: "Just Now",
        body: `Notice: Real-Time Evaluated Message.\n\nTarget Link Reference:\n<a class="email-interactive-link" data-url="${linkVal}">${linkVal || 'No Link Specified'}</a>`,
        isPhish: data.is_phishing,
        score: data.risk_score,
        threat: data.threat_type || "Custom Email Analysis",
        threat_categories: data.threat_categories || [],
        sender_info: data.sender_info,
        reasons: (data.red_flags && data.red_flags.length > 0) ? data.red_flags : ["✓ Standard sender patterns verified", "✓ No malicious payloads or urgency triggers detected"]
      };

      activeEmails.unshift(newMail);
      renderInboxList();
      selectEmail(newMail.id);
      recordTelemetry("Email Message", fromVal, data.is_phishing, data.risk_score, data.threat_type);
    })
    .catch(() => {
      // Client-side fallback analyzer
      const fallback = clientSideEmailScan(fromVal, subjectVal, linkVal);
      activeEmails.unshift(fallback);
      renderInboxList();
      selectEmail(fallback.id);
      recordTelemetry("Email Message", fromVal, fallback.isPhish, fallback.score, fallback.threat);
    });
  });
}

function inspectTargetUrlLive(url) {
  const statusEl = document.getElementById("craft-link-status");
  if (!statusEl) return;

  if (!url || url.trim() === "") {
    statusEl.innerHTML = `<span style="color:var(--text-muted);">ℹ️ Enter any target URL to detect whether it is authentic or a duplicate threat</span>`;
    return;
  }

  const u = url.toLowerCase().trim();
  const hasHomoglyph = url.includes('а') || url.includes('о') || url.includes('е') || url.includes('р') || url.includes('с');
  const isTyposquat = u.includes('m1crosoft') || u.includes('amaz0n') || u.includes('netf1ix') || u.includes('docus1gn') || u.includes('paypa1') || u.includes('paypai');
  const isDirectIp = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(u);
  const isAuthorityAt = u.includes('@') && (u.includes('http://') || u.includes('https://'));
  const isCombosquat = (u.includes('paypal') || u.includes('netflix') || u.includes('microsoft') || u.includes('apple') || u.includes('chase') || u.includes('google')) && (u.includes('.xyz') || u.includes('.top') || u.includes('.biz') || u.includes('verify') || u.includes('update') || u.includes('security') || u.includes('support'));
  const isAuthentic = (u.startsWith('https://paypal.com') || u.startsWith('https://www.paypal.com') || u.startsWith('https://google.com') || u.startsWith('https://www.google.com') || u.startsWith('https://github.com') || u.startsWith('https://apple.com') || u.startsWith('https://microsoft.com') || u.includes('.edu') || u.includes('.gov')) && !hasHomoglyph && !isTyposquat && !isCombosquat;

  if (hasHomoglyph) {
    statusEl.innerHTML = `<span style="color:var(--neon-red);">🚨 Duplicate / IDN Homoglyph Attack: Hidden Cyrillic character mimicking authentic brand domain</span>`;
  } else if (isTyposquat) {
    statusEl.innerHTML = `<span style="color:var(--neon-red);">🚨 Duplicate / Typosquatting Attack: Deceptive character substitution (e.g. digit '1' for 'i' / '0' for 'o')</span>`;
  } else if (isDirectIp) {
    statusEl.innerHTML = `<span style="color:var(--neon-red);">🚨 Raw IP Address Threat: URL points directly to unverified numerical server IP</span>`;
  } else if (isAuthorityAt) {
    statusEl.innerHTML = `<span style="color:var(--neon-red);">🚨 Authority '@' Deception Attack: Misleading prefix attempting to mask actual server host</span>`;
  } else if (isCombosquat) {
    statusEl.innerHTML = `<span style="color:var(--neon-red);">🚨 Combosquatting / Deceptive Domain: Brand name combined with suspicious TLD/keywords</span>`;
  } else if (isAuthentic) {
    statusEl.innerHTML = `<span style="color:var(--neon-green);">🟢 Authentic Original URL: Verified genuine domain and infrastructure</span>`;
  } else if (u.includes('.xyz') || u.includes('.top') || u.includes('.biz') || u.includes('.tk')) {
    statusEl.innerHTML = `<span style="color:var(--neon-amber);">🟡 Suspicious Domain: High-risk top-level domain (.xyz/.top/.biz) with no brand verification</span>`;
  } else {
    statusEl.innerHTML = `<span style="color:var(--neon-cyan);">🔍 Standard URL: Will be deeply evaluated with 29-feature ML Classifier and Sender Match</span>`;
  }
}

window.loadEmailPreset = function(type) {
  const fromEl = document.getElementById("craft-from");
  const subEl = document.getElementById("craft-subject");
  const linkEl = document.getElementById("craft-link");

  if (type === "scam") {
    fromEl.value = "PayPal Security <service@paypal-urgent-update99.xyz>";
    subEl.value = "URGENT: Your PayPal Account Has Been Restricted (Action in 24h)";
    linkEl.value = "https://pаypal.com/signin/account-verify";
  } else if (type === "suspicious") {
    fromEl.value = "Global Vendor Invoicing <billing@invoicing-portal.biz>";
    subEl.value = "Monthly Service Fee Invoice #4892";
    linkEl.value = "https://invoicing-portal.biz/docs/invoice.pdf";
  } else if (type === "safe") {
    fromEl.value = "Dr. Robert Sharma <dean.academics@apex.edu>";
    subEl.value = "Updated Semester Schedule and Academic Calendar";
    linkEl.value = "https://apex.edu/academics/schedule";
  }

  inspectTargetUrlLive(linkEl.value);
};

function clientSideEmailScan(fromVal, subjectVal, linkVal) {
  const fromLower = fromVal.toLowerCase();
  const subLower = subjectVal.toLowerCase();
  const linkLower = (linkVal || "").toLowerCase();

  const hasHomoglyph = (linkVal || "").includes('а') || (linkVal || "").includes('о') || (linkVal || "").includes('е');
  const isTyposquat = linkLower.includes('m1crosoft') || linkLower.includes('amaz0n') || linkLower.includes('netf1ix') || linkLower.includes('docus1gn');
  const isDirectIp = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(linkLower);
  const isAtTrick = linkLower.includes('@');
  const isPhishDomain = fromLower.includes(".xyz") || fromLower.includes(".top") || fromLower.includes("update") || fromLower.includes("verify") || linkLower.includes(".xyz") || linkLower.includes(".top");
  const isSpoofedBrand = (fromLower.includes("paypal") || fromLower.includes("netflix") || fromLower.includes("microsoft") || fromLower.includes("apple") || fromLower.includes("chase")) && isPhishDomain;
  const isUrgent = subLower.includes("urgent") || subLower.includes("restricted") || subLower.includes("suspended") || subLower.includes("24h") || subLower.includes("action required");
  const isSafeDomain = (fromLower.includes(".edu") || fromLower.includes(".gov") || fromLower.includes("github.com") || fromLower.includes("google.com")) && !hasHomoglyph && !isTyposquat;

  let score = 0;
  let threat = "Clean Verified Communication";
  let reasons = ["✓ Standard sender patterns verified", "✓ No malicious payloads or urgency triggers detected"];

  if (hasHomoglyph || isTyposquat || isDirectIp || isAtTrick || (isSpoofedBrand && isUrgent)) {
    score = 100;
    threat = hasHomoglyph ? "IDN Homoglyph Duplicate URL Attack" : (isTyposquat ? "Typosquatting Duplicate URL Attack" : (isDirectIp ? "Direct IP Credential Harvester" : "Display Name Spoofing & Phishing Lure"));
    reasons = [
      hasHomoglyph ? "Target URL uses Cyrillic homoglyph characters mimicking an authentic brand" : (isTyposquat ? "Target URL substitutes leetspeak characters (e.g. '1' for 'i')" : `Display Name claims brand identity from external mailbox '@${fromLower.split('@')[1] || 'unrecognized.xyz'}'`),
      "Coercive urgency and credential harvesting intent identified"
    ];
  } else if (isSafeDomain && !isPhishDomain) {
    score = 0;
    threat = "Verified Authentic Communication";
    reasons = ["✓ Verified authentic educational / corporate infrastructure", "✓ Sender identity and target URL match legitimate domain"];
  } else if (isPhishDomain || isUrgent || fromLower.includes(".biz") || linkLower.includes(".biz")) {
    score = 35;
    threat = "Unverified External Sender & Target Link";
    reasons = ["Unfamiliar external top-level domain (.biz/.xyz)", "Unusual inbound subject line characteristics"];
  }

  return {
    id: "custom-" + Date.now(),
    from: fromVal,
    reply_to: "",
    subject: subjectVal,
    date: "Just Now",
    body: `Notice: Evaluated Message Content.\n\nTarget Reference Link:\n<a class="email-interactive-link" data-url="${linkVal}">${linkVal || 'No Link Provided'}</a>`,
    isPhish: score >= 45,
    score: score,
    threat: threat,
    threat_categories: score >= 45 ? ["Malicious / Phishing Links", "Display Name Spoofing"] : (score >= 20 ? ["Unusual Sender Domain"] : []),
    reasons: reasons
  };
}

function renderInboxList() {
  const container = document.getElementById("inbox-list-container");
  container.innerHTML = "";

  let phishCount = 0;
  activeEmails.forEach(mail => {
    const isScam = mail.isPhish || mail.score >= 45;
    const isSuspicious = !mail.isPhish && mail.score >= 20 && mail.score < 45;
    const isSafe = !mail.isPhish && mail.score < 20;

    if (isScam) phishCount++;

    let tagClass = "danger";
    let tagText = `🔴 SCAM • ${mail.score}% Risk`;

    if (isSuspicious) {
      tagClass = "warning";
      tagText = `🟡 SUSPICIOUS • ${mail.score}% Risk`;
    } else if (isSafe) {
      tagClass = "safe";
      tagText = `🟢 SAFE • Verified Sender`;
    }

    const row = document.createElement("div");
    row.className = `inbox-item-row ${isScam ? 'phish-flagged' : (isSuspicious ? 'suspicious-flagged' : '')}`;
    row.dataset.id = mail.id;

    row.innerHTML = `
      <div class="inbox-item-top">
        <span class="inbox-item-sender">${escapeHtml(mail.from)}</span>
        <span class="inbox-item-time">${mail.date}</span>
      </div>
      <div class="inbox-item-subject">${escapeHtml(mail.subject)}</div>
      <div class="inbox-item-snippet">${escapeHtml(mail.body.replace(/<[^>]*>/g, '').substring(0, 55))}...</div>
      <div>
        <span class="inbox-tag-pill ${tagClass}">
          ${tagText}
        </span>
      </div>
    `;

    row.addEventListener("click", () => {
      selectEmail(mail.id);
    });

    container.appendChild(row);
  });

  document.getElementById("inbox-unread-count").innerText = `${phishCount} Threats Caught`;
}

// ==================== EMAIL CALLER ID HELPERS ====================
function parseSenderDetails(fromStr) {
  let displayName = "";
  let emailAddr = "";
  let domain = "";

  if (fromStr) {
    const match = fromStr.match(/^(?:"?([^"<]+)"?\s*)?<([^>]+)>$/);
    if (match) {
      displayName = (match[1] || "").trim();
      emailAddr = (match[2] || "").trim();
    } else {
      if (fromStr.includes("@")) {
        displayName = fromStr.split("@")[0].trim();
        emailAddr = fromStr.trim();
      } else {
        displayName = fromStr.trim();
        emailAddr = "";
      }
    }
    if (emailAddr.includes("@")) {
      domain = emailAddr.split("@").pop().trim();
    }
  }
  return {
    displayName: displayName || "Unknown Sender",
    emailAddr: emailAddr,
    domain: domain
  };
}

function extractImpersonatedBrand(mail) {
  if (mail.sender_info && mail.sender_info.impersonated_brand) {
    return mail.sender_info.impersonated_brand;
  }
  const fullText = `${mail.threat || ''} ${(mail.reasons || []).join(' ')} ${mail.from || ''}`.toLowerCase();
  const knownBrands = [
    "paypal", "microsoft", "apple", "amazon", "netflix", "chase", 
    "bank of america", "wells fargo", "citibank", "docusign", "binance", 
    "coinbase", "google", "meta", "instagram", "facebook", "whatsapp", 
    "zoom", "slack", "dhl", "fedex", "usps", "ups", "spotify", "steam", "playstation"
  ];
  
  for (const b of knownBrands) {
    if (fullText.includes(b)) {
      return b.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
    }
  }
  return null;
}

function hasLookalikeWarning(mail) {
  const fullText = `${mail.threat || ''} ${(mail.reasons || []).join(' ')}`.toLowerCase();
  return fullText.includes("lookalike") || fullText.includes("typosquat") || fullText.includes("homoglyph") || fullText.includes("spoofing");
}

function selectEmail(id) {
  document.querySelectorAll(".inbox-item-row").forEach(r => {
    r.classList.toggle("active", r.dataset.id === id);
  });

  const mail = activeEmails.find(m => m.id === id);
  if (!mail) return;

  // Render Meta
  document.getElementById("view-subject").innerText = mail.subject;
  document.getElementById("view-from").innerText = mail.from;
  document.getElementById("view-replyto").innerText = mail.reply_to || "None specified";
  document.getElementById("view-date").innerText = mail.date;

  // Render Body & Attach Interactive Link Handlers
  const bodyEl = document.getElementById("view-body");
  bodyEl.innerHTML = mail.body.replace(/\n/g, '<br>');

  // Add Hover Badges and Click Interceptors to Links inside the Email
  bodyEl.querySelectorAll(".email-interactive-link").forEach(link => {
    const targetUrl = link.dataset.url || link.innerText;
    
    // Add risk badge next to link
    if (mail.isPhish) {
      const tag = document.createElement("span");
      tag.className = "link-risk-tag";
      tag.innerText = "🚨 SUSPICIOUS LINK";
      link.parentNode.insertBefore(tag, link.nextSibling);
    }

    link.addEventListener("click", (e) => {
      e.preventDefault();
      if (mail.isPhish) {
        showInterceptorModal(targetUrl, mail);
      } else {
        alert(`✅ Verified Safe Link: ${targetUrl}\nNavigating safely.`);
      }
    });
  });

  // Helper: Extract sender parts (Display Name, Email Address, Domain)
  const senderInfo = parseSenderDetails(mail.from || "");
  const impersonatedBrand = extractImpersonatedBrand(mail);
  const lookalikeWarning = hasLookalikeWarning(mail);
  const threatCount = (mail.threat_categories && mail.threat_categories.length) || 
                      (mail.reasons && mail.reasons.length) || 
                      (mail.isPhish ? 1 : 0);

  // Determine Truecaller 3-State Visual Safety Indicator & Caller ID Status
  let safetyState = "safe";
  let safetyTag = "SAFE";
  let safetyIcon = "🟢";
  let safetySubtitle = "No major threats detected. The sender appears legitimate.";
  let callerIdStatusText = "✓ SENDER APPEARS LEGITIMATE";

  if (mail.isPhish || mail.score >= 45) {
    safetyState = "scam";
    safetyTag = "SCAM";
    safetyIcon = "🔴";
    safetySubtitle = "This email appears dangerous. Do not click links or share sensitive information.";
    callerIdStatusText = "🚨 SPOOFED / HIGH RISK SENDER";
  } else if (!mail.isPhish && mail.score >= 20 && mail.score < 45) {
    safetyState = "suspicious";
    safetyTag = "SUSPICIOUS";
    safetyIcon = "🟡";
    safetySubtitle = "This email has unusual characteristics. Verify the sender before taking action.";
    callerIdStatusText = "⚠️ VERIFY SENDER";
  }

  // 1. Inject Truecaller Identity Badge & PhishGuard Threat Analysis Banner
  const bannerSlot = document.getElementById("email-view-banner-slot");
  bannerSlot.innerHTML = `
    <!-- Top Truecaller-Style Identity Tag -->
    <div class="truecaller-safety-card state-${safetyState}">
      <div class="truecaller-header-row">
        <div class="truecaller-badge">
          <span>${safetyIcon}</span> ${safetyTag}
        </div>
        <span class="truecaller-score-pill">
          ${safetyState === 'safe' ? 'Verified Safe (0-19% Risk)' : `${mail.score}/100 Risk Score`}
        </span>
      </div>
      <div class="truecaller-subtitle">
        ${safetySubtitle}
      </div>
    </div>

    <!-- Underlying Detailed Risk Analysis Card -->
    <div class="phishguard-alert-banner ${safetyState === 'safe' ? 'safe-banner' : (safetyState === 'suspicious' ? 'suspicious-banner' : '')}">
      <div class="banner-top-row">
        <span class="banner-threat-title" style="${safetyState === 'suspicious' ? 'color:#f59e0b;' : ''}">
          <span>${safetyIcon}</span> ${safetyState === 'safe' ? 'PhishGuard: Legitimate Verified Communication' : `PhishGuard Threat Analysis: ${mail.threat}`}
        </span>
        <span class="banner-risk-badge" style="${safetyState === 'suspicious' ? 'background:#f59e0b; color:#000;' : ''}">
          ${mail.score}/100 Risk Score
        </span>
      </div>
      <ul class="banner-reasons-list" style="${safetyState === 'suspicious' ? 'color:#fef08a;' : ''}">
        ${mail.reasons.map(r => `<li>${safetyState === 'safe' ? '✓ ' : ''}${r}</li>`).join('')}
      </ul>
      ${safetyState === 'scam' ? `
        <div style="font-size:11px; color:#fca5a5; margin-top:6px; font-weight:700;">
          🛡️ DO NOT click any links, enter credentials, or open attachments.
        </div>
      ` : (safetyState === 'suspicious' ? `
        <div style="font-size:11px; color:#fef08a; margin-top:6px; font-weight:700;">
          ⚠️ CAUTION: Inspect links and verify sender identity before replying.
        </div>
      ` : '')}
    </div>
  `;

  // 2. Inject Compact Email Caller ID Card (between banner and body)
  const callerIdSlot = document.getElementById("email-caller-id-slot");
  if (callerIdSlot) {
    callerIdSlot.innerHTML = `
      <div class="caller-id-card state-${safetyState}">
        <div class="caller-id-header">
          <span class="caller-id-title">
            <span>👤</span> EMAIL CALLER ID
          </span>
          <span class="caller-id-status-badge status-${safetyState}">
            ${callerIdStatusText}
          </span>
        </div>

        <div class="caller-id-main-row">
          <div class="caller-id-avatar">
            ${safetyState === 'safe' ? '🛡️' : (safetyState === 'suspicious' ? '⚠️' : '🚨')}
          </div>
          <div class="caller-id-details">
            <div class="caller-id-name">${escapeHtml(senderInfo.displayName)}</div>
            <div class="caller-id-email">${escapeHtml(senderInfo.emailAddr || mail.from)}</div>
            <div class="caller-id-domain">
              <span>🌐 Origin Domain: </span><strong style="color:#ffffff;">${escapeHtml(senderInfo.domain || 'Direct Domain / Unspecified')}</strong>
            </div>
          </div>
        </div>

        <div class="caller-id-chips-row">
          <span class="caller-chip ${threatCount > 0 ? 'chip-danger' : 'chip-safe'}">
            ${threatCount > 0 ? `⚠️ ${threatCount} Threat${threatCount > 1 ? 's' : ''} Detected` : '🛡️ 0 Threats Detected'}
          </span>
          ${impersonatedBrand ? `
            <span class="caller-chip chip-danger">
              🏷️ Impersonating: <strong>${escapeHtml(impersonatedBrand)}</strong>
            </span>
          ` : ''}
          ${lookalikeWarning ? `
            <span class="caller-chip chip-warning">
              ⚠️ Lookalike domain detected
            </span>
          ` : ''}
          <span class="caller-chip">
            📅 ${escapeHtml(mail.date || 'Just Now')}
          </span>
          ${mail.reply_to ? `
            <span class="caller-chip chip-warning">
              ↩️ Reply-To: ${escapeHtml(mail.reply_to)}
            </span>
          ` : ''}
          <span class="caller-chip">
            🔒 Protocol: PhishGuard Real-Time
          </span>
        </div>
      </div>
    `;
  }

  if (safetyState === "scam" || safetyState === "suspicious") {
    playAlertSound("danger");
  } else {
    playAlertSound("safe");
  }

  recordTelemetry("Email Message", mail.subject, mail.isPhish, mail.score, mail.threat);
}

function simulateIncomingAttack() {
  const simulatedAttacks = [
    {
      id: "incoming-" + Date.now(),
      from: "Apple Security <billing-alert@apple-id-verify.top>",
      reply_to: "auth@inbox-relay.xyz",
      subject: "Security Notification: Your Apple ID is Locked",
      date: "Just Now",
      body: `Apple ID Security Alert:

Your Apple ID was used to sign in to iCloud via an unauthorized device in Berlin, Germany.

Your account has been locked for your protection. You have 12 hours to verify your identity:
<a class="email-interactive-link" data-url="https://apple.com@verify-account.top/portal">https://appleid.apple.com/account/manage</a>

Apple Support`,
      isPhish: true,
      score: 100,
      threat: "Apple ID Authority Deception (@ trick)",
      reasons: [
        "Display Name spoofing claiming to be 'Apple Security'",
        "Deceptive '@' symbol in URL attempting to trick user into seeing 'apple.com'",
        "High-urgency 12-hour lockout threat"
      ]
    },
    {
      id: "incoming-docusign-" + Date.now(),
      from: "DocuSign Signature <service@docus1gn-review.com>",
      reply_to: "",
      subject: "Please Review & Sign: Confidential Wire Transfer Invoice",
      date: "Just Now",
      body: `DocuSign Electronic Signature:

Accounting sent you a document for signature: 'Wire_Transfer_Invoice_8492.pdf'.

Review and sign document:
<a class="email-interactive-link" data-url="https://docus1gn-review.com/auth/sign">https://docusign.net/Member/PowerFormSigning.aspx</a>

DocuSign Inc.`,
      isPhish: true,
      score: 95,
      threat: "DocuSign Typosquatting (docus1gn)",
      reasons: [
        "Brand typosquatting substituting digit '1' for 'i' in DocuSign",
        "Financial lure regarding wire transfer"
      ]
    }
  ];

  const randomAttack = simulatedAttacks[Math.floor(Math.random() * simulatedAttacks.length)];
  activeEmails.unshift(randomAttack);
  renderInboxList();
  selectEmail(randomAttack.id);
}

// ==================== WARNING MODAL INTERCEPTOR ====================
function initWarningModal() {
  const modal = document.getElementById("prototype-warning-modal");
  document.getElementById("btn-modal-return").onclick = () => { modal.style.display = "none"; };
  document.getElementById("btn-modal-dismiss").onclick = () => { modal.style.display = "none"; };
}

function showInterceptorModal(url, mail) {
  const modal = document.getElementById("prototype-warning-modal");
  document.getElementById("modal-url-text").innerText = url;
  document.getElementById("modal-risk-text").innerText = `${mail.score}% Risk Score (Critical Phishing)`;
  document.getElementById("modal-brand-text").innerText = mail.threat;

  const reasonsList = document.getElementById("modal-reasons-list");
  reasonsList.innerHTML = mail.reasons.map(r => `<li>${r}</li>`).join("");

  modal.style.display = "flex";
  playAlertSound("danger");
}

// ==================== URL SCANNER ====================
function initUrlScanner() {
  const btn = document.getElementById("btn-analyze-url");
  btn.addEventListener("click", () => {
    const url = document.getElementById("custom-url-input").value.trim();
    if (url) scanUrl(url);
  });
}

window.loadUrlPreset = function(url) {
  document.getElementById("custom-url-input").value = url;
  scanUrl(url);
};

function scanUrl(url) {
  const container = document.getElementById("url-scan-results");
  container.style.display = "grid";

  // Try backend first with instant fallback
  fetch(`${API_BASE}/api/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url })
  })
  .then(r => r.json())
  .then(data => {
    renderUrlScan(data);
  })
  .catch(() => {
    // Client-side fallback calculation
    const fallback = clientSideUrlScan(url);
    renderUrlScan(fallback);
  });
}

function clientSideUrlScan(url) {
  let isHomoglyph = url.includes('а') || url.includes('о') || url.includes('е');
  let isTypo = url.includes('m1crosoft') || url.includes('amaz0n') || url.includes('netf1ix') || url.includes('docus1gn');
  let isIp = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);
  let isAt = url.includes('@');
  let isCombosquat = url.includes('netflix-billing') || url.includes('paypal-security');
  let isSafe = url.includes('google.com') || url.includes('github.com');

  let score = isSafe ? 5 : (isHomoglyph || isIp || isAt || isTypo || isCombosquat ? 100 : 25);
  let level = score >= 70 ? "Dangerous" : (score >= 40 ? "High Risk" : "Safe");

  return {
    url: url,
    risk_score: score,
    risk_level: level,
    is_phishing: score >= 40,
    threat_type: isHomoglyph ? "IDN Homoglyph Attack" : (isIp ? "Direct IP Hostname" : (isTypo ? "Brand Typosquatting" : (isSafe ? "Clean Domain" : "Suspicious Syntax"))),
    lookalike_analysis: {
      is_lookalike: !isSafe,
      target_brand: isHomoglyph ? "PayPal" : (isTypo ? "Microsoft" : (isSafe ? "None" : "Brand Target")),
      deception_type: isHomoglyph ? "IDN Unicode Confusable" : (isTypo ? "Leetspeak Typosquatting" : "None")
    },
    structural_metrics: {
      domain_entropy: 3.85,
      is_ip: isIp,
      subdomain_count: 2
    },
    indicators: isSafe ? ["✓ Verified authentic domain"] : [
      "Deceptive domain syntax targeting user credentials",
      "High probability of malicious credential harvesting portal"
    ],
    ai_intelligence: {
      summary: isSafe ? "Verified authentic domain with standard security architecture." : "High-confidence phishing attack designed to impersonate trusted platforms and intercept passwords.",
      mitigation_steps: isSafe ? ["Safe to proceed."] : ["Do NOT enter passwords or payment credentials", "Navigate to official domain directly"]
    },
    recommendation: isSafe ? "Verified safe domain." : "🚨 DANGEROUS PHISHING LINK! Navigation blocked."
  };
}

function renderUrlScan(data) {
  const score = data.risk_score || 0;
  const level = data.risk_level || "Safe";

  const ring = document.getElementById("proto-gauge-ring");
  const num = document.getElementById("proto-gauge-num");
  const title = document.getElementById("proto-risk-title");
  const rec = document.getElementById("proto-risk-rec");

  num.innerText = score;
  title.innerText = level.toUpperCase();
  rec.innerText = data.recommendation;

  ring.className = "gauge-ring";
  if (score >= 70) {
    ring.classList.add("danger");
    title.style.color = "var(--neon-red)";
    playAlertSound("danger");
  } else if (score >= 35) {
    ring.classList.add("caution");
    title.style.color = "var(--neon-amber)";
  } else {
    title.style.color = "var(--neon-green)";
    playAlertSound("safe");
  }

  // Lookalike & Metrics
  const lookalike = data.lookalike_analysis || {};
  document.getElementById("proto-lookalike-flag").innerText = lookalike.is_lookalike ? "YES (SPOOF)" : "No";
  document.getElementById("proto-target-brand").innerText = lookalike.target_brand || "None";
  document.getElementById("proto-deception-technique").innerText = lookalike.deception_type || "None";

  const metrics = data.structural_metrics || {};
  document.getElementById("proto-entropy-score").innerText = `${metrics.domain_entropy || 2.1} / 5.0`;
  document.getElementById("proto-is-ip").innerText = metrics.is_ip ? "Yes (High Risk)" : "No";
  document.getElementById("proto-subdomain-count").innerText = `${metrics.subdomain_count || 1} level(s)`;

  // ML Model Analysis
  const ml = data.ml_analysis || {};
  const mlProb = (ml.ml_phishing_probability !== undefined) ? Math.round(ml.ml_phishing_probability * 100) : 0;
  const isMlPhish = ml.is_phishing_predicted || mlProb >= 50;
  const mlVerdictEl = document.getElementById("proto-ml-verdict");
  if (mlVerdictEl) {
    mlVerdictEl.innerText = isMlPhish ? "🚨 PHISHING" : "✅ LEGITIMATE";
    mlVerdictEl.style.color = isMlPhish ? "var(--neon-red)" : "var(--neon-green)";
  }
  const mlProbEl = document.getElementById("proto-ml-prob");
  if (mlProbEl) mlProbEl.innerText = `${mlProb}%`;
  const mlModelEl = document.getElementById("proto-ml-model");
  if (mlModelEl) mlModelEl.innerText = ml.model_name || "ExtraTrees Ensemble";
  const mlFeatEl = document.getElementById("proto-ml-features");
  if (mlFeatEl) {
    const activeFeats = ml.active_threat_features || [];
    mlFeatEl.innerText = activeFeats.length > 0 ? activeFeats.join(", ") : "None (Clean Structural Profile)";
    mlFeatEl.style.color = activeFeats.length > 0 ? "#fca5a5" : "#a7f3d0";
  }

  // Indicators
  const indList = document.getElementById("proto-indicators-list");
  indList.innerHTML = (data.indicators || []).map(i => `<li>${i}</li>`).join("");

  // AI Summary
  const ai = data.ai_intelligence || {};
  document.getElementById("proto-ai-summary").innerText = ai.summary || data.recommendation;
  document.getElementById("proto-ai-actions").innerHTML = (ai.mitigation_steps || []).map(s => `<div>• ${s}</div>`).join("");

  recordTelemetry("URL Scan", data.url, data.is_phishing, score, data.threat_type);
}

// ==================== LOOKALIKE LAB ====================
function initLookalikeLab() {
  document.getElementById("btn-run-lab").addEventListener("click", () => {
    const domain = document.getElementById("lab-domain-input").value.trim();
    if (domain) generateLookalikes(domain);
  });
}

function generateLookalikes(domain) {
  fetch(`${API_BASE}/api/detect/lookalike`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain: domain })
  })
  .then(r => r.json())
  .then(data => {
    renderLabVariants(data.generated_variants || []);
  })
  .catch(() => {
    // Client-side fallback generator
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
  tbody.innerHTML = variants.map(v => `
    <tr>
      <td style="font-family:monospace; font-weight:700; color:#fca5a5;">${escapeHtml(v.variant)}</td>
      <td>${escapeHtml(v.technique)}</td>
      <td style="font-family:monospace; color:#94a3b8;">${escapeHtml(v.punycode || '-')}</td>
      <td style="font-weight:700; color:#38bdf8;">${escapeHtml(v.visual_similarity)}</td>
      <td><span class="inbox-tag-pill danger">${escapeHtml(v.risk)}</span></td>
    </tr>
  `).join("");
}

// ==================== TELEMETRY & LOGGING ====================
function recordTelemetry(type, target, isPhish, score, threat) {
  telemetryStats.total++;
  if (isPhish) {
    telemetryStats.phish++;
    if (threat.includes("Lookalike") || threat.includes("Homoglyph") || threat.includes("Typosquat")) telemetryStats.lookalikes++;
    if (threat.includes("Spoof") || threat.includes("Sender")) telemetryStats.spoofs++;
  }

  document.getElementById("count-total").innerText = telemetryStats.total;
  document.getElementById("count-phish").innerText = telemetryStats.phish;
  document.getElementById("count-lookalikes").innerText = telemetryStats.lookalikes;
  document.getElementById("count-spoofs").innerText = telemetryStats.spoofs;

  const logEntry = {
    timestamp: new Date().toLocaleTimeString(),
    type: type,
    target: target.substring(0, 55),
    score: score,
    level: score >= 70 ? "Dangerous" : (score >= 40 ? "High Risk" : "Safe"),
    threat: threat,
    isPhish: isPhish
  };

  telemetryStats.logs.unshift(logEntry);

  // Render logs table
  const tbody = document.getElementById("logs-tbody");
  tbody.innerHTML = telemetryStats.logs.slice(0, 15).map(log => `
    <tr>
      <td style="font-family:monospace; color:var(--text-muted);">${log.timestamp}</td>
      <td><span class="preset-chip" style="font-size:10px;">${log.type}</span></td>
      <td style="font-family:monospace;">${escapeHtml(log.target)}</td>
      <td><span class="inbox-tag-pill ${log.isPhish ? 'danger' : 'safe'}">${log.score}% (${log.level})</span></td>
      <td>${log.threat}</td>
      <td style="color:${log.isPhish ? 'var(--neon-red)' : 'var(--neon-green)'}; font-weight:700;">
        ${log.isPhish ? '🚫 Blocked & Warned' : '✓ Permitted'}
      </td>
    </tr>
  `).join("");
}

document.getElementById("btn-export-log").addEventListener("click", () => {
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(telemetryStats, null, 2));
  const dlAnchor = document.createElement("a");
  dlAnchor.setAttribute("href", dataStr);
  dlAnchor.setAttribute("download", `phishguard_telemetry_${Date.now()}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
});

function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}