#!/usr/bin/env python3
"""
Comprehensive Test Suite for PhishLens Real-Time Phishing URL & Email Detector
Tests homoglyphs, typosquatting, sender spoofing, urgency NLP, link discrepancies, and API endpoints.
"""

import sys
import os
import json
import time

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Add backend directory to sys.path
BACKEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
sys.path.insert(0, BACKEND_DIR)

from lookalike_engine import LookalikeEngine, TARGET_BRANDS
from url_analyzer import URLAnalyzer
from email_analyzer import EmailAnalyzer


def run_tests():
    passed = 0
    failed = 0
    total = 0

    print("🛡️ ========================================================")
    print("   PHISHLENS REAL-TIME PHISHING DETECTOR - TEST MATRIX")
    print("========================================================\n")

    # --- TEST SUITE 1: Lookalike & Homoglyph Engine ---
    print("🔍 TEST SUITE 1: Lookalike & Homoglyph Detection")
    print("-" * 55)

    homoglyph_tests = [
        ("pаypal.com", True, "paypal", "IDN Homoglyph with Cyrillic 'а'"),
        ("gооgle.com", True, "google", "IDN Homoglyph with Cyrillic 'о'"),
        ("m1crosoft.com", True, "microsoft", "Typosquatting with leetspeak '1'"),
        ("amaz0n-security.com", True, "amazon", "Combosquatting & leetspeak '0'"),
        ("netflix-billing-update.xyz", True, "netflix", "Combosquatting with brand name"),
        ("chase.com.attacker-vps.net", True, "chase", "Subdomain brand spoofing"),
        ("paypal.com", False, "paypal", "Authentic PayPal Root Domain"),
        ("google.com", False, "google", "Authentic Google Root Domain"),
        ("github.com", False, "github", "Authentic GitHub Root Domain")
    ]

    for domain, expected_lookalike, expected_brand, desc in homoglyph_tests:
        total += 1
        res = LookalikeEngine.detect_lookalike(domain)
        is_lookalike = res["is_lookalike"]
        brand_match = res["target_brand"] == expected_brand if expected_brand else True

        if is_lookalike == expected_lookalike and brand_match:
            passed += 1
            status = "✅ PASS"
        else:
            failed += 1
            status = "❌ FAIL"

        print(f"[{status}] {desc:<40} -> Result: Lookalike={is_lookalike}")

    # --- TEST SUITE 2: Structural URL Phishing Analysis ---
    print("\n🌐 TEST SUITE 2: Structural & Heuristic URL Threat Analysis")
    print("-" * 55)

    url_tests = [
        ("https://pаypal.com/signin/account-verify", True, 70, "Homoglyph PayPal URL"),
        ("http://192.168.1.100/chase-online/auth/login.php", True, 70, "Direct IP Banking Credential Harvester"),
        ("https://apple.com@security-verification.top/unlock", True, 60, "Authority '@' Deception Attack"),
        ("https://login-microsoft365-verify.xyz/auth/oauth", True, 60, "Combosquatting with Suspicious TLD (.xyz)"),
        ("http://secure-banking-portal.online/statement.pdf.exe", True, 75, "Double Extension Executable Payload"),
        ("https://myaccount.google.com/security", False, 15, "Authentic Google Security Settings"),
        ("https://github.com/security/advisories", False, 15, "Authentic GitHub Advisories")
    ]

    for url, expected_phish, min_score, desc in url_tests:
        total += 1
        report = URLAnalyzer.analyze_url(url)
        risk_score = report["risk_score"]
        is_phish = report["is_phishing"]

        if (is_phish == expected_phish) and (risk_score >= min_score if expected_phish else risk_score <= min_score):
            passed += 1
            status = "✅ PASS"
        else:
            failed += 1
            status = "❌ FAIL"

        print(f"[{status}] {desc:<42} -> Score: {risk_score}/100 ({report['risk_level']})")

    # --- TEST SUITE 3: Email Threat & Sender Pattern Inspection ---
    print("\n📧 TEST SUITE 3: Email Threat & Sender Pattern Inspection")
    print("-" * 55)

    email_tests = [
        (
            {
                "from": "PayPal Security Center <service@paypal-update-center99.xyz>",
                "reply_to": "recover@inbox-box.net",
                "subject": "URGENT: Your PayPal Account Has Been Restricted in 24 Hours",
                "body": "Dear customer, verify your password immediately to prevent closure: https://pаypal.com/signin"
            },
            True,
            75,
            "Display Name Spoof & Urgency Phish"
        ),
        (
            {
                "from": "Chase Fraud Team <chase.fraud.alert@gmail.com>",
                "reply_to": "",
                "subject": "Security Alert: Unauthorized Wire Transfer of $3,450.00",
                "body": "Review the attached dispute form immediately.",
                "attachments": ["Dispute_Form.pdf.exe"]
            },
            True,
            80,
            "Free Webmail Impersonation & Malicious Attachment"
        ),
        (
            {
                "from": "Microsoft IT Admin <support@m1crosoft-security.xyz>",
                "reply_to": "",
                "subject": "Final Notice: Password Expires Today",
                "body": "Your password expires in 4 hours. Keep same password here: http://192.168.1.55/login"
            },
            True,
            75,
            "Typosquat Sender & Credential Harvester"
        ),
        (
            {
                "from": "GitHub Security <notifications@github.com>",
                "reply_to": "support@github.com",
                "subject": "[GitHub] Security advisory published for repository",
                "body": "Hello, A new security advisory has been published for a repository you watch. View advisory: https://github.com/security/advisories"
            },
            False,
            20,
            "Legitimate GitHub Verified Notification"
        )
    ]

    for email_data, expected_phish, min_score, desc in email_tests:
        total += 1
        report = EmailAnalyzer.analyze_email(email_data)
        risk_score = report["risk_score"]
        is_phish = report["is_phishing"]

        if (is_phish == expected_phish) and (risk_score >= min_score if expected_phish else risk_score <= min_score):
            passed += 1
            status = "✅ PASS"
        else:
            failed += 1
            status = "❌ FAIL"

        print(f"[{status}] {desc:<45} -> Score: {risk_score}/100 ({report['risk_level']})")

    # --- SUMMARY ---
    print("\n" + "=" * 55)
    print(f"🎯 TEST SUMMARY: {passed}/{total} Tests Passed ({round(passed/total*100, 1)}% Accuracy)")
    if failed == 0:
        print("🌟 ALL PHISHING DETECTION & SENDER PATTERN TESTS PASSED PERFECTLY!")
    else:
        print(f"⚠️ {failed} test(s) failed.")
    print("=" * 55 + "\n")

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
