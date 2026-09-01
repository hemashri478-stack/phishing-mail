#!/usr/bin/env python3
"""
PhishLens PhishGuard - Interactive CLI Demonstration Tool
Inspects URLs and Emails in real-time, generates lookalike domain simulations, and runs threat benchmarks.
"""

import sys
import os
import time
import json

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

from lookalike_engine import LookalikeEngine, TARGET_BRANDS
from url_analyzer import URLAnalyzer
from email_analyzer import EmailAnalyzer


def print_banner():
    print("""
========================================================================
   🛡️  PHISHLENS PHISHGUARD - REAL-TIME CYBER THREAT DETECTOR 🛡️
   Active Lookalike Blocker • Sender Pattern Guard • Link Inspector
========================================================================
    """)


def demo_url_scan(url: str):
    print(f"\n🔍 [DEEP URL INSPECTION] -> {url}")
    print("-" * 65)
    report = URLAnalyzer.analyze_url(url)
    
    score = report["risk_score"]
    level = report["risk_level"]
    is_phish = report["is_phishing"]
    lookalike = report.get("lookalike_analysis", {})

    status_icon = "🚨 DANGEROUS PHISHING" if is_phish else "✅ VERIFIED SAFE"
    print(f"Verdict:           {status_icon}")
    print(f"Risk Score:        {score}/100 ({level})")
    print(f"Primary Threat:    {report['threat_type']}")
    print(f"Domain:            {report['domain']}")
    
    if lookalike.get("is_lookalike"):
        print(f"Lookalike Spoof:   Impersonating authentic '{lookalike.get('legitimate_domain')}' ({lookalike.get('target_brand', '').title()})")
        print(f"Deception Type:    {lookalike.get('deception_type')}")
        print(f"Visual Similarity: {lookalike.get('similarity_score')}%")

    if report.get("indicators"):
        print("\nThreat Indicators:")
        for ind in report["indicators"]:
            print(f"  • {ind}")

    print(f"\nRecommendation:    {report['recommendation']}\n")


def demo_email_scan(from_hdr: str, subject: str, body: str, attachments=None):
    print(f"\n📧 [EMAIL THREAT INSPECTION] -> From: {from_hdr}")
    print(f"Subject: {subject}")
    print("-" * 65)

    payload = {
        "from": from_hdr,
        "subject": subject,
        "body": body,
        "attachments": attachments or []
    }
    report = EmailAnalyzer.analyze_email(payload)

    score = report["risk_score"]
    level = report["risk_level"]
    is_phish = report["is_phishing"]

    status_icon = "🚨 PHISHING ATTACK DETECTED" if is_phish else "✅ AUTHENTIC MESSAGE"
    print(f"Verdict:           {status_icon}")
    print(f"Risk Score:        {score}/100 ({level})")
    print(f"Threat Vector:     {report['threat_type']}")

    if report.get("sender_anomalies"):
        print("\nSender Authenticity Anomalies:")
        for a in report["sender_anomalies"]:
            print(f"  • {a}")

    if report.get("red_flags"):
        print("\nRed Flags & Psychological Triggers:")
        for rf in report["red_flags"]:
            print(f"  • {rf}")

    if report.get("links_analyzed"):
        print(f"\nExtracted Links ({len(report['links_analyzed'])}):")
        for link in report["links_analyzed"]:
            mismatch_tag = " [MISMATCH!]" if link["is_mismatch"] else ""
            print(f"  • {link['href']} -> Risk: {link['risk_score']}%{mismatch_tag}")

    print(f"\nRecommendation:    {report['recommendation']}\n")


def demo_automated_showcase():
    print("🚀 Running Automated Real-Time Threat Detection Showcase...\n")

    # Case 1: Homoglyph PayPal
    demo_url_scan("https://pаypal.com/signin/account-verify")
    time.sleep(1)

    # Case 2: Microsoft Typosquatting
    demo_url_scan("https://m1crosoft-login-auth.xyz/oauth2/authorize")
    time.sleep(1)

    # Case 3: Chase Bank Direct IP
    demo_url_scan("http://192.168.1.100/chase-online/auth/login.php")
    time.sleep(1)

    # Case 4: Display Name Spoof Email
    demo_email_scan(
        from_hdr="PayPal Security Team <support@paypal-urgent-update9.xyz>",
        subject="URGENT: Your Account Has Been Restricted in 24 Hours",
        body="Suspicious login detected from Russia. Verify your password now: https://pаypal.com/signin"
    )
    time.sleep(1)

    # Case 5: Chase Webmail Spoof with Malicious Attachment
    demo_email_scan(
        from_hdr="Chase Fraud Prevention <chase.fraud.alert@gmail.com>",
        subject="Unauthorized Wire Transfer of $3,450.00",
        body="A transfer was initiated. Review attached dispute form immediately.",
        attachments=["Dispute_Form.pdf.exe"]
    )
    time.sleep(1)

    # Case 6: Authentic GitHub Email
    demo_email_scan(
        from_hdr="GitHub Security <notifications@github.com>",
        subject="[GitHub] Security advisory published for repository",
        body="A new security advisory has been published: https://github.com/security/advisories"
    )


def interactive_menu():
    print_banner()
    while True:
        print("\nSelect an Operation:")
        print("1. 🌐 Scan Custom URL")
        print("2. 📧 Scan Custom Email")
        print("3. 🔬 Generate Lookalike & Typosquat Variations for a Brand")
        print("4. 🚀 Run Automated Threat Showcase")
        print("5. 🚪 Exit")

        choice = input("\nEnter choice (1-5): ").strip()

        if choice == "1":
            target_url = input("\nEnter URL to analyze: ").strip()
            if target_url:
                demo_url_scan(target_url)
        elif choice == "2":
            from_hdr = input("\nEnter Sender (From Header, e.g. PayPal <support@fake.xyz>): ").strip()
            subj = input("Enter Subject Line: ").strip()
            body = input("Enter Message Content / Body: ").strip()
            demo_email_scan(from_hdr, subj, body)
        elif choice == "3":
            domain = input("\nEnter brand domain (e.g. apple.com, paypal.com, netflix.com): ").strip()
            if domain:
                variants = LookalikeEngine.generate_lookalike_variants(domain)
                print(f"\nGenerated {len(variants)} Lookalike Variations for '{domain}':")
                print(f"{'Variant':<32} {'Technique':<30} {'Similarity':<12} {'Risk'}")
                print("-" * 80)
                for v in variants:
                    print(f"{v['variant']:<32} {v['technique']:<30} {v['visual_similarity']:<12} {v['risk']}")
        elif choice == "4":
            demo_automated_showcase()
        elif choice == "5":
            print("\nExiting PhishLens PhishGuard. Stay secure!\n")
            break
        else:
            print("Invalid option. Please choose 1-5.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--showcase":
        print_banner()
        demo_automated_showcase()
    else:
        interactive_menu()