# 🛡️ PhishLens PhishGuard - Real-Time Phishing URL & Email Threat Guardian

**State-of-the-art real-time phishing defense engine that intercepts malicious links and deceptive emails as they arrive, detects lookalike domains & spoofed senders, and protects users before compromise.**

---

## 🌟 Key Features

### 🔍 1. Real-Time URL & Lookalike Domain Engine
- **IDN Homoglyph Attack Detector**: Identifies Unicode confusables (e.g. Cyrillic `а` in `pаypal.com`, Greek variations, accents).
- **Typosquatting & Leetspeak Matcher**: Compares incoming domains against **150+ high-profile target brands** (Google, Microsoft, Apple, Amazon, PayPal, Netflix, Chase, Bank of America, Steam, Binance, DocuSign, etc.) using Levenshtein distance and character mapping.
- **Combosquatting & Subdomain Deception**: Flags domains embedding authentic brand names in subdomains or pairing them with urgency keywords (`paypal-security.xyz`, `login.microsoft.com.attacker.net`).
- **Structural Entropy & Syntax Anomalies**: Detects Shannon entropy spikes (DGA domains), IP-based hostnames (`http://192.168.1.1/login`), `@` authority tricks, suspicious TLDs (`.xyz`, `.top`, `.tk`), and double-extension executables (`invoice.pdf.exe`).

### 📧 2. Email Threat & Sender Pattern Inspector
- **Display Name Spoofing**: Identifies when a sender's display name claims institutional authority (e.g., `"PayPal Support"` or `"Microsoft IT"`) while originating from an unrelated domain.
- **Free Webmail Impersonation**: Flags public webmail accounts (`@gmail.com`, `@yahoo.com`) pretending to be corporate, financial, or security departments.
- **Reply-To Mismatch**: Alerts when replies are routed to a different destination server than the sender.
- **Psychological Urgency & Social Engineering NLP**: Extracts artificial time pressure ("within 24 hours", "account suspended", "unauthorized access"), credential harvesting prompts, and financial lures.
- **Embedded Link Discrepancy Comparator**: Flags links where display text (`https://bankofamerica.com`) masks a different destination URL.

### 🛡️ 3. Active Real-Time Chrome Extension (Manifest V3)
- **Active Click Interceptor**: Halts browser navigation and displays an unmissable in-page warning modal before navigating to high-risk phishing links.
- **Hover Threat Tooltips**: Displays real-time risk scores and safety badges when hovering over hyperlinks.
- **Webmail Live Shield**: Automatically inspects opened messages in **Gmail, Outlook Web, and Yahoo Mail**, injecting a live security alert banner at the top of suspicious emails.
- **Cyberpunk HUD Popup**: Quick URL scanner, email checker, and live protection toggles.

### 📊 4. Cyber Defense Operations Dashboard
- **Live URL Deep Scanner**: Visual circular risk gauge (0-100%), entropy metrics, and AI threat breakdown.
- **Email Message Analyzer**: Header inspector, psychological trigger radar, and link discrepancy table.
- **Real-Time Incoming Stream Simulator**: Live animated simulation of an incoming inbox receiving safe and phishing threats in real-time.
- **Lookalike & Typosquat Domain Lab**: Generates and inspects attack variations for any domain.
- **Threat Telemetry Hub**: Real-time stats, incident logs, and JSON export.

---

## 🚀 Quick Start

### 1. Prerequisites & Environment Setup
Python 3.8+ is supported.

```bash
# Install dependencies
pip install flask flask-cors requests beautifulsoup4 python-dotenv google-generativeai
```

### 2. Start the Backend API & Dashboard Servers
```powershell
# On Windows PowerShell:
.\start_servers.ps1

# Or run separately:
python backend/app.py       # API Server on http://localhost:5000
python dashboard/server.py  # Dashboard on http://localhost:8080
```

### 3. Open the Cyber Defense Dashboard
Open your browser and visit:
```
http://localhost:8080
```

### 4. Install the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** in the top right.
3. Click **Load unpacked** and select the `chrome-extension/` directory.
4. Pin the **PhishLens** icon in your browser toolbar.

---

## 🧪 Running Automated Tests & CLI Demo

### Run Full Test Suite (100% Pass Rate)
```bash
python test_phishing_detector.py
```

### Run Interactive CLI Tool & Showcase
```bash
# Interactive menu:
python demo.py

# Automated showcase:
python demo.py --showcase
```

---

## 🌐 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | API health check and capability manifest |
| `POST` | `/api/analyze/url` | Deep URL phishing, entropy, and lookalike analysis |
| `POST` | `/api/analyze/email` | Full email header, sender pattern, urgency NLP, and link scan |
| `POST` | `/api/analyze/quick` | Low-latency heuristic scan for extension tooltips |
| `POST` | `/api/detect/lookalike` | Lookalike domain detection and attack variation generator |
| `GET` | `/api/samples` | Realistic attack presets and legitimate verification samples |
| `GET` | `/api/stats` | Real-time threat telemetry metrics and scan history |

---

## 📋 Architecture Overview

```
shadowlens-main/
├── backend/
│   ├── app.py                 # Flask REST API & telemetry
│   ├── lookalike_engine.py    # 150+ brand homoglyph & typosquat engine
│   ├── url_analyzer.py        # Structural entropy & phishing heuristics
│   ├── email_analyzer.py      # Sender spoofing, NLP, and link extractor
│   └── ai_threat_analyzer.py  # AI contextual threat explanations
├── chrome-extension/
│   ├── manifest.json          # Manifest V3 configuration
│   ├── content.js             # Active click interceptor & webmail shield
│   ├── background.js          # Service worker & badge manager
│   ├── popup.html             # Cyber defense HUD popup
│   ├── popup.js               # HUD tab controller & quick scanner
│   └── icons/                 # Extension icons
├── dashboard/
│   ├── index.html             # SOC Dashboard interface
│   ├── dashboard.js           # Live stream simulator & analytics logic
│   └── server.py              # Standalone HTTP dashboard server (:8080)
├── test_phishing_detector.py  # 20-point automated test suite
├── demo.py                    # Interactive CLI threat inspector
└── start_servers.ps1          # One-click startup script
```

---

## 🔒 Security & Privacy Notice
PhishLens analyzes link structures, domain patterns, and message headers client-side and via local backend heuristics. No sensitive credentials or passwords are ever stored or forwarded to third parties.