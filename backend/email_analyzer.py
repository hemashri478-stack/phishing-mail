"""
Email Threat & Sender Pattern Analyzer
Analyzes email headers, display name spoofing, sender-reply mismatch, urgency/psychological triggers, embedded links, and attachments.
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
from bs4 import BeautifulSoup
try:
    from .url_analyzer import URLAnalyzer
    from .lookalike_engine import TARGET_BRANDS, LookalikeEngine
except (ImportError, ValueError):
    from url_analyzer import URLAnalyzer
    from lookalike_engine import TARGET_BRANDS, LookalikeEngine

# Common free webmail domains
FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "mail.com", "zoho.com", "yandex.com", "icloud.com",
    "gmx.com", "live.com", "msn.com"
}

# Psychological urgency & fear triggers
URGENCY_TRIGGERS = [
    r'\b(immediate(ly)?|urgent|urgently|right away|asap|without delay)\b',
    r'\b(within\s+\d+\s+(hours?|minutes?|days?)|in\s+\d+\s+hours?|24\s+hours?|48\s+hours?)\b',
    r'\b(account\s+(has been\s+)?(suspended|terminated|disabled|restricted|locked|closed|flagged))\b',
    r'\b(unauthorized\s+(access|activity|transaction|login|attempt|charge))\b',
    r'\b(action\s+required|final\s+notice|final\s+warning|last\s+reminder)\b',
    r'\b(security\s+alert|security\s+breach|compromised|suspicious\s+activity)\b',
    r'\b(failure\s+to\s+(respond|verify|update)|legal\s+action|law\s+enforcement)\b',
    r'\b(prevent\s+(suspension|deactivation|closure|loss\s+of\s+access))\b'
]

# Credential & data harvesting lures
CREDENTIAL_LURES = [
    r'\b(verify|confirm|validate|update|upgrade)\s+(your\s+)?(account|identity|password|credential|profile|information|details)\b',
    r'\b(click\s+(here|below|the link)|follow\s+the\s+link|log\s*in\s+to\s+(continue|review|verify))\b',
    r'\b(reset\s+(your\s+)?password|enter\s+(your\s+)?(pin|passcode|2fa|otp|code))\b',
    r'\b(update\s+(your\s+)?(billing|payment|credit\s+card|bank)\s+(details|method|info))\b',
    r'\b(re-?authenticate|session\s+expired|sign\s*in\s+again)\b'
]

# Financial / scam lures
FINANCIAL_LURES = [
    r'\b(invoice|receipt|statement|remittance|payment\s+overdue|past\s+due)\b',
    r'\b(wire\s+transfer|fund\s+transfer|direct\s+deposit|ach\s+payment)\b',
    r'\b(claim\s+(your\s+)?(reward|prize|refund|compensation|inheritance|grant|settlement))\b',
    r'\b(bitcoin|crypto|ethereum|usdt|wallet\s+credited|crypto\s+bonus)\b',
    r'\b(order\s+(confirmed|processed|placed)\s+for\s+\$\d+)\b'
]

# Dangerous attachment extensions
HIGH_RISK_EXTENSIONS = {
    "exe": "Executable Binary",
    "scr": "Screensaver Executable",
    "vbs": "VBScript Executable",
    "js": "JavaScript Executable",
    "bat": "Batch Script",
    "cmd": "Command Script",
    "ps1": "PowerShell Script",
    "iso": "Disk Image Container (Malware Delivery)",
    "img": "Disk Image Container",
    "hta": "HTML Application Executable",
    "docm": "Macro-Enabled Word Document",
    "xlsm": "Macro-Enabled Excel Document",
    "pptm": "Macro-Enabled PowerPoint Document",
    "jar": "Java Archive Executable",
    "html": "HTML / SVG Phishing Redirect",
    "htm": "HTML Phishing Redirect",
    "svg": "SVG Vector (Potential Script Embedding)",
    "zip": "Compressed Archive (May contain obfuscated payloads)",
    "rar": "Compressed Archive",
    "7z": "Compressed Archive",
    "ace": "Compressed Archive",
    "gz": "Compressed Archive"
}


class EmailAnalyzer:
    """Real-Time Email Threat, Sender Pattern, and Content Analyzer"""

    @staticmethod
    def parse_sender_header(from_header: str) -> Dict[str, str]:
        """Parses 'Display Name <email@domain.com>' or plain 'email@domain.com'"""
        if not from_header:
            return {"display_name": "", "email_address": "", "domain": ""}
            
        header = from_header.strip()
        # Pattern: "Display Name" <user@domain.com> or Display Name <user@domain.com>
        match = re.match(r'^(?:"?([^"<]+)"?\s*)?<([^>]+)>$', header)
        if match:
            display_name = (match.group(1) or "").strip()
            email_address = (match.group(2) or "").strip().lower()
        else:
            # Plain email or name
            if "@" in header:
                display_name = ""
                email_address = header.strip().lower()
            else:
                display_name = header.strip()
                email_address = ""

        domain = email_address.split("@")[-1] if "@" in email_address else ""
        return {
            "display_name": display_name,
            "email_address": email_address,
            "domain": domain
        }

    @staticmethod
    def extract_links_from_content(body_html: str, body_text: str) -> List[Dict[str, Any]]:
        """Extracts and compares anchor text vs target hrefs from email content"""
        extracted_links = []
        seen_urls = set()

        # 1. Extract from HTML
        if body_html:
            try:
                soup = BeautifulSoup(body_html, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href'].strip()
                    anchor_text = a_tag.get_text().strip()
                    if href and href not in seen_urls and not href.startswith(("mailto:", "tel:", "javascript:")):
                        seen_urls.add(href)
                        extracted_links.append({
                            "href": href,
                            "anchor_text": anchor_text,
                            "source": "HTML Link"
                        })
            except Exception:
                pass

        # 2. Extract plain text URLs
        combined_text = (body_text or "") + " " + (body_html or "")
        raw_urls = re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', combined_text)
        for u in raw_urls:
            u_clean = u.rstrip(".,;!?)")
            if u_clean not in seen_urls:
                seen_urls.add(u_clean)
                extracted_links.append({
                    "href": u_clean,
                    "anchor_text": u_clean,
                    "source": "Plain Text URL"
                })

        # 3. Analyze Link Discrepancies & Run through URLAnalyzer
        analyzed_links = []
        for item in extracted_links:
            href = item["href"]
            anchor = item["anchor_text"]
            
            # Check if anchor text pretends to be a different URL
            is_mismatch = False
            mismatch_details = None
            if re.match(r'https?://[^\s]+|www\.[^\s]+', anchor):
                anchor_parsed = urlparse(anchor if anchor.startswith("http") else "http://" + anchor)
                href_parsed = urlparse(href if href.startswith("http") else "http://" + href)
                if anchor_parsed.netloc and href_parsed.netloc:
                    anchor_sld = LookalikeEngine.extract_sld(anchor_parsed.netloc)
                    href_sld = LookalikeEngine.extract_sld(href_parsed.netloc)
                    if anchor_sld != href_sld:
                        is_mismatch = True
                        mismatch_details = f"Display text shows '{anchor_parsed.netloc}', but actual destination is '{href_parsed.netloc}'!"

            # Analyze URL via URLAnalyzer
            url_report = URLAnalyzer.analyze_url(href)
            
            analyzed_links.append({
                "href": href,
                "anchor_text": anchor,
                "is_mismatch": is_mismatch,
                "mismatch_details": mismatch_details,
                "risk_score": url_report["risk_score"],
                "risk_level": url_report["risk_level"],
                "is_phishing": url_report["is_phishing"],
                "threat_type": url_report["threat_type"],
                "lookalike": url_report["lookalike_analysis"],
                "indicators": url_report["indicators"]
            })

        return analyzed_links

    @staticmethod
    def analyze_email(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive Real-Time Email Threat Analysis:
        - Sender display name spoofing
        - Free webmail impersonation of corporate entities
        - Reply-To mismatch
        - Psychological urgency, fear, and credential lures
        - Embedded links scanning and anchor text discrepancies
        - Malicious attachment detection
        """
        from_header = data.get("from", "")
        reply_to_header = data.get("reply_to", "")
        subject = data.get("subject", "")
        body_text = data.get("body", "") or data.get("text", "")
        body_html = data.get("body_html", "") or data.get("html", "")
        attachments = data.get("attachments", [])

        # Parse sender
        sender_info = EmailAnalyzer.parse_sender_header(from_header)
        reply_to_info = EmailAnalyzer.parse_sender_header(reply_to_header)
        
        display_name = sender_info["display_name"]
        sender_address = sender_info["email_address"]
        sender_domain = sender_info["domain"]
        reply_to_domain = reply_to_info["domain"]

        score = 0
        red_flags: List[str] = []
        sender_anomalies: List[str] = []
        threat_categories: List[str] = []
        
        # 1. SENDER ANALYSIS: Display Name Spoofing Check
        # Check if Display Name impersonates a known brand while Domain is unrelated
        display_name_lower = display_name.lower()
        impersonated_brand = None
        
        for brand, b_info in TARGET_BRANDS.items():
            legit_domain = b_info["domain"]
            legit_sld = LookalikeEngine.extract_sld(legit_domain)
            
            # If display name explicitly mentions the target brand (whole word match, min length 2)
            brand_in_display = len(brand) >= 2 and bool(re.search(rf'\b{re.escape(brand)}\b', display_name_lower))
            if brand_in_display:
                # Check if sender domain matches legitimate brand domain
                if sender_domain and not (sender_domain == legit_domain or sender_domain.endswith("." + legit_domain)):
                    impersonated_brand = brand
                    score += 65
                    threat_categories.append("Display Name Spoofing")
                    sender_anomalies.append(
                        f"🚨 DISPLAY NAME SPOOFING: Display Name claims to be '{display_name}' ({brand.title()}), "
                        f"but actual sender domain is '@{sender_domain}'!"
                    )
                    break

        # 2. SENDER ANALYSIS: Free Webmail Impersonation of Corporate/Financial Services
        if sender_domain in FREE_WEBMAIL_DOMAINS:
            # Check if display name or subject mentions corporate/bank/security terms
            corporate_indicators = ["support", "security", "helpdesk", "billing", "service", "admin", "fraud", "team", "bank", "payroll", "official"]
            if any(ci in display_name_lower for ci in corporate_indicators) or impersonated_brand:
                score += 50
                threat_categories.append("Free Webmail Impersonation")
                sender_anomalies.append(
                    f"⚠️ FREE WEBMAIL MISUSE: Sender claims institutional authority ('{display_name}') from a free public webmail provider (@{sender_domain})"
                )

        # 3. SENDER ANALYSIS: Lookalike Sender Domain
        if sender_domain:
            sender_lookalike = LookalikeEngine.detect_lookalike(sender_domain)
            if sender_lookalike["is_lookalike"]:
                score += sender_lookalike["risk_score_boost"]
                threat_categories.append("Lookalike Sender Domain")
                sender_anomalies.append(
                    f"🚨 SENDER LOOKALIKE DOMAIN: Email originates from '{sender_domain}' which impersonates '{sender_lookalike['legitimate_domain']}'"
                )

        # 4. SENDER ANALYSIS: From vs Reply-To Mismatch
        if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
            # If Reply-To has a completely different SLD
            sender_sld = LookalikeEngine.extract_sld(sender_domain)
            reply_sld = LookalikeEngine.extract_sld(reply_to_domain)
            if sender_sld != reply_sld:
                score += 40
                threat_categories.append("Reply-To Mismatch")
                sender_anomalies.append(
                    f"⚠️ SENDER/REPLY-TO MISMATCH: Responses will be routed to a different domain '@{reply_to_domain}' instead of '@{sender_domain}'"
                )

        # 5. CONTENT NLP: Urgency, Fear, and Psychological Triggers
        full_content = f"{subject} {body_text} {body_html}".lower()
        
        urgency_matches = []
        for pattern in URGENCY_TRIGGERS:
            matches = re.findall(pattern, full_content, re.IGNORECASE)
            if matches:
                urgency_matches.append(pattern)

        if urgency_matches:
            urgency_score = min(len(urgency_matches) * 15, 45)
            score += urgency_score
            threat_categories.append("High Urgency & Fear Triggers")
            red_flags.append(f"⚠️ Artificial Urgency & Coercion: Found {len(urgency_matches)} time-pressure and suspension triggers")

        credential_matches = []
        for pattern in CREDENTIAL_LURES:
            matches = re.findall(pattern, full_content, re.IGNORECASE)
            if matches:
                credential_matches.append(pattern)

        if credential_matches:
            cred_score = min(len(credential_matches) * 15, 45)
            score += cred_score
            threat_categories.append("Credential Harvesting Intent")
            red_flags.append(f"⚠️ Credential Harvesting Language: Requests immediate password/account verification or login")

        financial_matches = []
        for pattern in FINANCIAL_LURES:
            matches = re.findall(pattern, full_content, re.IGNORECASE)
            if matches:
                financial_matches.append(pattern)

        if financial_matches:
            score += min(len(financial_matches) * 12, 30)
            threat_categories.append("Financial / Fraud Lure")
            red_flags.append(f"ℹ️ Financial Lures: Contains references to invoices, wire transfers, crypto, or cash refunds")

        # 6. EMBEDDED LINKS ANALYSIS
        links_report = EmailAnalyzer.extract_links_from_content(body_html, body_text)
        phishing_links_count = sum(1 for link in links_report if link["is_phishing"])
        mismatched_links_count = sum(1 for link in links_report if link["is_mismatch"])

        if phishing_links_count > 0:
            score += min(phishing_links_count * 40, 75)
            threat_categories.append("Malicious / Phishing Links")
            red_flags.append(f"🚨 CRITICAL: Email contains {phishing_links_count} dangerous phishing or lookalike link(s)!")

        if mismatched_links_count > 0:
            score += min(mismatched_links_count * 35, 60)
            threat_categories.append("Mismatched Link Destination")
            red_flags.append(f"🚨 DECEPTIVE LINK TEXT: {mismatched_links_count} link(s) display a legitimate URL but redirect to an attacker server")

        # 7. ATTACHMENTS ANALYSIS
        dangerous_attachments = []
        for att in attachments:
            name = att if isinstance(att, str) else att.get("name", "")
            ext = name.split(".")[-1].lower() if "." in name else ""
            if ext in HIGH_RISK_EXTENSIONS:
                desc = HIGH_RISK_EXTENSIONS[ext]
                dangerous_attachments.append({"name": name, "extension": ext, "description": desc})

        if dangerous_attachments:
            score += min(len(dangerous_attachments) * 45, 80)
            threat_categories.append("High-Risk Attachment")
            for da in dangerous_attachments:
                red_flags.append(f"🚨 DANGEROUS ATTACHMENT: '{da['name']}' ({da['description']}) detected")

        # Cap score 0-100
        final_score = min(100, max(0, score))
        score_10 = round(final_score / 10, 1)

        # Risk Classification & Actionable Recommendations
        if final_score >= 70:
            risk_level = "Dangerous"
            is_phishing = True
            rec = "🚨 HIGH SEVERITY PHISHING ATTACK! Do NOT click any links, open attachments, or reply. Report this email immediately."
        elif final_score >= 45:
            risk_level = "High Risk"
            is_phishing = True
            rec = "⚠️ SUSPICIOUS EMAIL: Exhibits strong signs of social engineering or sender spoofing. Verify through out-of-band channels."
        elif final_score >= 20:
            risk_level = "Caution"
            is_phishing = False
            rec = "⚠️ CAUTION: Minor marketing or urgency triggers detected. Inspect links carefully before proceeding."
        else:
            risk_level = "Safe"
            is_phishing = False
            rec = "✅ LEGITIMATE: Sender authentication and content patterns align with standard authentic communications."

        primary_threat = threat_categories[0] if threat_categories else "Clean"

        return {
            "from": from_header,
            "sender_info": sender_info,
            "reply_to_info": reply_to_info,
            "subject": subject,
            "risk_score": final_score,
            "risk_score_10": score_10,
            "risk_level": risk_level,
            "is_phishing": is_phishing,
            "threat_type": primary_threat,
            "threat_categories": list(set(threat_categories)),
            "sender_anomalies": sender_anomalies,
            "red_flags": red_flags,
            "psychological_triggers": {
                "urgency_count": len(urgency_matches),
                "credential_count": len(credential_matches),
                "financial_count": len(financial_matches)
            },
            "links_analyzed": links_report,
            "links_count": len(links_report),
            "phishing_links_count": phishing_links_count,
            "mismatched_links_count": mismatched_links_count,
            "dangerous_attachments": dangerous_attachments,
            "recommendation": rec
        }
