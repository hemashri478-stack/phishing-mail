#!/usr/bin/env python3
"""
ShadowLens PhishGuard - Real-Time Phishing URL & Email Threat Detection API Server
"""

import os
import sys
import time
import logging
from typing import Dict, List, Any
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Ensure backend directory is in Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lookalike_engine import LookalikeEngine, TARGET_BRANDS
from url_analyzer import URLAnalyzer
from email_analyzer import EmailAnalyzer
from ai_threat_analyzer import AIThreatAnalyzer
try:
    from ml_url_detector import ml_detector
except Exception:
    ml_detector = None

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PhishGuard")

app = Flask(__name__)
CORS(app)

# Initialize engines
ai_threat_analyzer = AIThreatAnalyzer(os.getenv("GEMINI_API_KEY"))

# In-memory telemetry storage for live dashboard stats
telemetry = {
    "total_scans": 0,
    "phishing_detected": 0,
    "lookalikes_blocked": 0,
    "emails_analyzed": 0,
    "urls_analyzed": 0,
    "recent_scans": [],
    "threat_distribution": {
        "Lookalike Spoofing": 0,
        "Credential Harvesting": 0,
        "Display Name Spoofing": 0,
        "High Urgency Extortion": 0,
        "Malicious Attachment": 0,
        "Direct IP Phish": 0,
        "Clean": 0
    }
}

# Pre-loaded realistic phishing and legitimate samples for one-click testing
SAMPLE_DATA = {
    "urls": [
        {
            "id": "url-paypal-homoglyph",
            "name": "PayPal IDN Homoglyph Attack (Cyrillic 'а')",
            "url": "https://pаypal.com/signin/account-verify",
            "category": "Homoglyph Lookalike",
            "expected": "Dangerous Phishing"
        },
        {
            "id": "url-m1crosoft-typo",
            "name": "Microsoft 365 Typosquatting (1 instead of i)",
            "url": "https://m1crosoft-login-auth.xyz/oauth2/authorize?client_id=update",
            "category": "Typosquat & Suspicious TLD",
            "expected": "Dangerous Phishing"
        },
        {
            "id": "url-ip-chase",
            "name": "Chase Bank Direct IP Credential Harvester",
            "url": "http://192.168.1.100/chase-online/auth/login.php?session=secure",
            "category": "IP Hostname & Credential Lure",
            "expected": "Dangerous Phishing"
        },
        {
            "id": "url-at-trick",
            "name": "Apple ID Authority Deception (@ trick)",
            "url": "https://apple.com@security-verification-portal.top/account/unlock",
            "category": "Authority Deception",
            "expected": "Dangerous Phishing"
        },
        {
            "id": "url-combosquat-netflix",
            "name": "Netflix Billing Combosquatting",
            "url": "https://netflix-billing-update-service.com/payment/retry",
            "category": "Combosquatting",
            "expected": "Dangerous Phishing"
        },
        {
            "id": "url-legit-google",
            "name": "Legitimate Google Account Settings",
            "url": "https://myaccount.google.com/security",
            "category": "Legitimate Domain",
            "expected": "Safe"
        },
        {
            "id": "url-legit-github",
            "name": "Legitimate GitHub Repository",
            "url": "https://github.com/security/advisories",
            "category": "Legitimate Domain",
            "expected": "Safe"
        }
    ],
    "emails": [
        {
            "id": "email-paypal-spoof",
            "name": "PayPal Security - Account Limitation & Urgency",
            "from": "PayPal Security Center <service-alert@paypal-update-center99.xyz>",
            "reply_to": "verification@inbox-recover.top",
            "subject": "URGENT: Your PayPal Account Has Been Restricted (Action Required in 24 Hours)",
            "body": """Dear Customer,

We detected unusual sign-in activity on your PayPal account from an unrecognized IP address. To protect your funds, your account features have been temporarily restricted.

You have 24 hours to verify your identity, otherwise your account will be permanently closed and pending transfers canceled.

Please verify your account immediately:
https://pаypal.com/signin/account-verify

Thank you for choosing PayPal.
PayPal Security Team""",
            "body_html": """<p>Dear Customer,</p>
<p>We detected unusual sign-in activity on your PayPal account. To prevent permanent suspension within <strong>24 hours</strong>, please confirm your credentials:</p>
<p><a href="http://paypal-security-update.xyz/login.php">https://www.paypal.com/myaccount/security</a></p>
<p>PayPal Security Team</p>""",
            "attachments": [],
            "category": "Display Name Spoof & Mismatched Link",
            "expected": "Dangerous Phishing"
        },
        {
            "id": "email-m365-password",
            "name": "Microsoft 365 IT Helpdesk - Password Expiry Lure",
            "from": "Microsoft 365 Admin <it-support@m1crosoft-security.xyz>",
            "reply_to": "admin@external-relay.net",
            "subject": "Final Notice: Your Microsoft 365 Password Expires Today",
            "body": """IT Helpdesk Notification:
Your corporate Office 365 password is set to expire in 4 hours. Failure to update your password will result in loss of email access and disconnected VPN credentials.

Click here to keep your same password:
https://m1crosoft-login-auth.xyz/oauth2/authorize?client_id=update

Global IT Support Department""",
            "body_html": """<p><strong>IT Helpdesk Notification:</strong></p>
<p>Your password expires in <strong>4 hours</strong>. Action required immediately.</p>
<p><a href="http://192.168.1.55/microsoft/login">Keep Current Password</a></p>""",
            "attachments": [],
            "category": "Credential Harvesting & Urgency",
            "expected": "Dangerous Phishing"
        },
        {
            "id": "email-chase-fraud",
            "name": "Chase Bank - Free Webmail Impersonation & Malicious PDF",
            "from": "Chase Fraud Prevention <chase.fraud.alert.team@gmail.com>",
            "reply_to": "",
            "subject": "Security Alert: Unauthorized Wire Transfer of $3,450.00",
            "body": """Chase Fraud Alert:
A wire transfer of $3,450.00 was requested from your checking account. If you did not authorize this payment, open the attached transaction dispute document immediately and follow the verification steps.

Attached: Transaction_Dispute_Form.pdf.exe""",
            "body_html": "<p>Chase Fraud Alert: A wire transfer was attempted. Review the attached form immediately.</p>",
            "attachments": [{"name": "Transaction_Dispute_Form.pdf.exe"}],
            "category": "Free Webmail Spoof & Double Extension Attachment",
            "expected": "Dangerous Phishing"
        },
        {
            "id": "email-legit-receipt",
            "name": "Legitimate GitHub Security Advisory Notice",
            "from": "GitHub Security <notifications@github.com>",
            "reply_to": "support@github.com",
            "subject": "[GitHub] Security advisory published for repository",
            "body": """Hello,
A new security advisory has been published for a repository you watch. You can review the details and recommended package updates directly on GitHub.

View advisory: https://github.com/security/advisories

Thanks,
The GitHub Team""",
            "body_html": """<p>Hello,</p><p>A new security advisory has been published. <a href="https://github.com/security/advisories">View advisory on GitHub</a>.</p>""",
            "attachments": [],
            "category": "Legitimate Verified Email",
            "expected": "Safe"
        }
    ]
}


def record_scan_telemetry(scan_type: str, item_name: str, result: Dict[str, Any]):
    """Records real-time telemetry stats for dashboard"""
    telemetry["total_scans"] += 1
    if scan_type == "url":
        telemetry["urls_analyzed"] += 1
    else:
        telemetry["emails_analyzed"] += 1

    if result.get("is_phishing"):
        telemetry["phishing_detected"] += 1

    lookalike = result.get("lookalike_analysis") or (result.get("links_analyzed", [{}])[0].get("lookalike") if result.get("links_analyzed") else None)
    if lookalike and lookalike.get("is_lookalike"):
        telemetry["lookalikes_blocked"] += 1

    threat_type = result.get("threat_type", "Clean")
    if threat_type in telemetry["threat_distribution"]:
        telemetry["threat_distribution"][threat_type] += 1
    else:
        telemetry["threat_distribution"]["Clean"] += 1

    # Keep last 50 scans
    scan_entry = {
        "id": f"scan-{int(time.time() * 1000)}",
        "timestamp": time.strftime("%H:%M:%S"),
        "type": scan_type,
        "target": item_name[:60],
        "risk_score": result.get("risk_score", 0),
        "risk_level": result.get("risk_level", "Safe"),
        "threat_type": threat_type,
        "is_phishing": result.get("is_phishing", False)
    }
    telemetry["recent_scans"].insert(0, scan_entry)
    if len(telemetry["recent_scans"]) > 50:
        telemetry["recent_scans"].pop()


# --- API Routes ---

@app.route("/", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def root_index_handler():
    """Serves the dashboard HTML or health status to prevent any 404 on Vercel"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for candidate in [
        os.path.join(base_dir, "public", "index.html"),
        os.path.join(base_dir, "dashboard", "index.html"),
        os.path.join(base_dir, "index.html")
    ]:
        if os.path.exists(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    return f.read(), 200, {"Content-Type": "text/html; charset=utf-8"}
            except Exception:
                pass
    return health_check()


@app.route("/dashboard.js", methods=["GET"])
def dashboard_js_handler():
    """Serves the dashboard.js file to ensure complete standalone operation"""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for candidate in [
        os.path.join(base_dir, "public", "dashboard.js"),
        os.path.join(base_dir, "dashboard", "dashboard.js"),
        os.path.join(base_dir, "dashboard.js")
    ]:
        if os.path.exists(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    return f.read(), 200, {"Content-Type": "application/javascript; charset=utf-8"}
            except Exception:
                pass
    return "console.error('dashboard.js not found');", 404


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "ShadowLens PhishGuard",
        "version": "2.0.0",
        "ai_engine": "Gemini AI" if ai_threat_analyzer.model else "Neural Heuristic Engine",
        "ml_engine": "Trained ExtraTrees Ensemble Classifier" if (ml_detector and ml_detector.model) else "Heuristic Fallback",
        "ml_model_loaded": bool(ml_detector and ml_detector.model),
        "monitored_brands_count": len(TARGET_BRANDS),
        "capabilities": [
            "Real-Time URL Phishing Detection",
            "Machine Learning URL Phishing Classifier (29 Structural Features)",
            "IDN Homoglyph & Punycode Analysis",
            "Typosquatting & Combosquatting Matcher",
            "Email Sender Pattern & Display Name Spoofing",
            "Free Webmail Impersonation Guard",
            "Psychological Urgency & Social Engineering NLP",
            "Embedded Link Mismatch Comparator",
            "Malicious Attachment Inspector",
            "AI Threat Explanation & Mitigation"
        ]
    })


@app.route("/api/analyze/ml", methods=["POST"])
def analyze_ml_endpoint():
    """Machine Learning URL Phishing analysis endpoint"""
    try:
        data = request.json or {}
        url = data.get("url") or data.get("text") or ""
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        if not ml_detector:
            return jsonify({"error": "ML detector module not initialized"}), 500

        ml_result = ml_detector.predict_url(url)
        return jsonify(ml_result)
    except Exception as e:
        logger.error(f"Error in ML URL analysis: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze/url", methods=["POST"])
def analyze_url_endpoint():
    """Deep URL analysis endpoint"""
    try:
        data = request.json or {}
        url = data.get("url") or data.get("text") or ""
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Perform URL analysis
        url_report = URLAnalyzer.analyze_url(url)
        
        # Get AI explanation / contextual intelligence
        ai_explanation = ai_threat_analyzer.explain_url_threat(url_report)
        url_report["ai_intelligence"] = ai_explanation

        # Record telemetry
        record_scan_telemetry("url", url, url_report)

        return jsonify(url_report)
    except Exception as e:
        logger.error(f"Error in URL analysis: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze/email", methods=["POST"])
def analyze_email_endpoint():
    """Deep Email analysis endpoint"""
    try:
        data = request.json or {}
        if not data:
            return jsonify({"error": "No email data provided"}), 400

        # Perform Email analysis
        email_report = EmailAnalyzer.analyze_email(data)

        # Get AI explanation / contextual intelligence
        ai_explanation = ai_threat_analyzer.explain_email_threat(email_report)
        email_report["ai_intelligence"] = ai_explanation

        # Record telemetry
        target_name = f"{data.get('from', 'Unknown')} - {data.get('subject', 'No Subject')}"
        record_scan_telemetry("email", target_name, email_report)

        return jsonify(email_report)
    except Exception as e:
        logger.error(f"Error in Email analysis: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze/quick", methods=["POST"])
def analyze_quick_endpoint():
    """Low-latency quick heuristic check for Chrome Extension live tooltips"""
    try:
        data = request.json or {}
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Fast URL check
        report = URLAnalyzer.analyze_url(url)
        return jsonify({
            "url": url,
            "risk_score": report["risk_score"],
            "risk_level": report["risk_level"],
            "is_phishing": report["is_phishing"],
            "threat_type": report["threat_type"],
            "lookalike": report["lookalike_analysis"]["is_lookalike"],
            "recommendation": report["recommendation"]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/detect/lookalike", methods=["POST"])
def detect_lookalike_endpoint():
    """Lookalike domain detection & variant generator endpoint"""
    try:
        data = request.json or {}
        domain = data.get("domain", "")
        if not domain:
            return jsonify({"error": "No domain provided"}), 400

        analysis = LookalikeEngine.detect_lookalike(domain)
        variants = LookalikeEngine.generate_lookalike_variants(domain)

        return jsonify({
            "domain": domain,
            "analysis": analysis,
            "generated_variants": variants,
            "monitored_brands": list(TARGET_BRANDS.keys())
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/samples", methods=["GET"])
def get_samples_endpoint():
    """Returns curated realistic test samples"""
    return jsonify(SAMPLE_DATA)


@app.route("/api/stats", methods=["GET"])
def get_stats_endpoint():
    """Returns real-time telemetry stats for dashboard"""
    return jsonify(telemetry)


@app.route("/analyze", methods=["POST"])
def legacy_analyze_endpoint():
    """Backwards-compatible endpoint for extension and legacy scripts"""
    try:
        data = request.json or {}
        url = data.get("url", "")
        text = data.get("text", "")

        # If data looks like an email (contains from/subject or email keywords)
        if "from" in data or "subject" in data:
            result = EmailAnalyzer.analyze_email(data)
            ai_exp = ai_threat_analyzer.explain_email_threat(result)
            result["ai_intelligence"] = ai_exp
            result["student_summary"] = ai_exp["summary"]
            result["privacy_threats"] = result["red_flags"]
            return jsonify(result)

        # Standard URL analysis
        if url:
            result = URLAnalyzer.analyze_url(url)
            ai_exp = ai_threat_analyzer.explain_url_threat(result)
            result["ai_intelligence"] = ai_exp
            result["student_summary"] = ai_exp["summary"]
            result["privacy_threats"] = result["indicators"]
            result["features_used"] = ["Lookalike Engine", "Entropy Analyzer", "PhishGuard AI"]
            return jsonify(result)

        # Fallback text check
        return jsonify({"risk_score": 0, "risk_level": "Safe", "message": "No actionable URL or email found"})
    except Exception as e:
        logger.error(f"Legacy analyze error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    logger.info(f"🚀 Starting ShadowLens PhishGuard on port {port}...")
    logger.info(f"🛡️ Monitored Target Brands: {len(TARGET_BRANDS)}")
    app.run(host="0.0.0.0", port=port, debug=False)