"""
URL Phishing & Structural Threat Analyzer
Analyzes URLs for structural anomalies, suspicious TLDs, entropy, IP hostnames, deceptive keywords, and lookalike domains.
"""

import re
import math
from urllib.parse import urlparse, unquote
from typing import Dict, List, Tuple, Any, Optional
try:
    from .lookalike_engine import LookalikeEngine, TARGET_BRANDS
except (ImportError, ValueError):
    from lookalike_engine import LookalikeEngine, TARGET_BRANDS

try:
    from .ml_url_detector import ml_detector
except (ImportError, ValueError):
    try:
        from ml_url_detector import ml_detector
    except Exception:
        ml_detector = None

# High-risk / Abused TLDs commonly seen in phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz": 25, "top": 30, "tk": 35, "ml": 35, "ga": 35, "cf": 35, "gq": 35,
    "work": 20, "live": 20, "loan": 30, "click": 25, "icu": 30, "buzz": 25,
    "fit": 20, "surf": 20, "rest": 20, "monster": 25, "vip": 20, "kim": 25,
    "country": 25, "stream": 25, "gdn": 25, "mom": 20, "date": 25, "racing": 25,
    "bid": 25, "win": 25, "accountant": 25, "download": 25, "review": 20, "link": 15
}

# Known legitimate top-tier domains (Whitelisted root domains)
VERIFIED_SAFE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "github.com", "netflix.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "youtube.com", "wikipedia.org", "linkedin.com", "twitter.com", "x.com",
    "instagram.com", "facebook.com", "reddit.com", "cloudflare.com", "openai.com",
    "coursera.org", "edx.org", "harvard.edu", "mit.edu", "stanford.edu"
}

# Known URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly",
    "rb.gy", "tiny.cc", "shorturl.at", "rebrand.ly", "soo.gd", "s.id"
}

# Sensitive Phishing Keywords
PHISHING_KEYWORDS = {
    "login": 15, "signin": 15, "sign-in": 15, "log-in": 15,
    "verify": 18, "verification": 18, "verif": 15,
    "secure": 12, "security": 15, "auth": 14, "authenticate": 16,
    "account": 12, "update": 14, "upgrade": 12, "validate": 15,
    "banking": 20, "wallet": 18, "recover": 16, "recovery": 16,
    "password": 20, "credential": 22, "2fa": 20, "mfa": 18,
    "billing": 16, "invoice": 15, "payment": 16, "confirm": 14,
    "suspension": 22, "suspended": 22, "unlock": 18, "unlocked": 16,
    "support": 10, "helpdesk": 12, "portal": 10, "identity": 18
}


class URLAnalyzer:
    """Multi-vector Real-Time URL Phishing and Threat Analyzer"""

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculates Shannon Entropy of a string to detect randomized/DGA strings"""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        for count in char_counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 2)

    @staticmethod
    def is_ip_address(hostname: str) -> Tuple[bool, Optional[str]]:
        """Detects if hostname is a raw IP address (IPv4, Hex, or Integer)"""
        # Clean port
        host = hostname.split(":")[0].strip()
        
        # Standard IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, host):
            parts = host.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                return True, "IPv4 Hostname"

        # Hexadecimal IP (e.g. 0x7f000001)
        if host.startswith("0x") and len(host) <= 10:
            try:
                int(host, 16)
                return True, "Hexadecimal IP Hostname"
            except ValueError:
                pass

        # Pure Dword / Integer IP
        if host.isdigit() and len(host) > 6:
            return True, "Integer/Dword IP Hostname"

        return False, None

    @staticmethod
    def analyze_url(url: str) -> Dict[str, Any]:
        """
        Deep analysis of a URL for phishing, lookalikes, structural deception, and entropy anomalies.
        """
        if not url:
            return {
                "url": "",
                "risk_score": 0,
                "risk_level": "Safe",
                "is_phishing": False,
                "threat_type": "None",
                "indicators": [],
                "recommendation": "Empty URL provided."
            }

        raw_url = url.strip()
        # Add default scheme if missing for proper parsing
        if not raw_url.startswith(("http://", "https://", "ftp://")):
            parsed_url = "http://" + raw_url
        else:
            parsed_url = raw_url

        try:
            parsed = urlparse(parsed_url)
        except Exception:
            return {
                "url": raw_url,
                "risk_score": 85,
                "risk_level": "Dangerous",
                "is_phishing": True,
                "threat_type": "Malformed URL Attack",
                "indicators": ["Malformed URL syntax designed to evade parsers"],
                "recommendation": "Do not open this URL; it cannot be safely parsed."
            }

        hostname = (parsed.netloc or parsed.path.split("/")[0]).lower()
        if "@" in hostname:
            # Handle @ credential trick: http://google.com@evil.com
            auth_part, actual_host = hostname.split("@", 1)
        else:
            auth_part, actual_host = None, hostname

        # Strip port
        host_no_port = actual_host.split(":")[0]
        port = parsed.port

        path = unquote(parsed.path or "")
        query = unquote(parsed.query or "")
        full_path = path + ("?" + query if query else "")

        # Initialize scoring & indicators
        score = 0
        indicators: List[str] = []
        threat_categories: List[str] = []

        # 1. Check Verified Safe Whitelist (Direct Exact Root Match)
        is_whitelisted = False
        for safe_dom in VERIFIED_SAFE_DOMAINS:
            if host_no_port == safe_dom or host_no_port.endswith("." + safe_dom):
                is_whitelisted = True
                break

        # 2. Lookalike & Homoglyph Engine Check
        lookalike_res = LookalikeEngine.detect_lookalike(host_no_port)
        if lookalike_res["is_lookalike"]:
            score += lookalike_res["risk_score_boost"]
            threat_categories.append("Lookalike / Brand Impersonation")
            for detail in lookalike_res["details"]:
                indicators.append(f"🚨 {detail}")

        if lookalike_res["has_homoglyphs"] and not lookalike_res["is_lookalike"]:
            score += 70
            threat_categories.append("IDN Homoglyph Attack")
            indicators.append("⚠️ Domain contains suspicious non-Latin / Cyrillic homoglyphs")

        # 3. IP Address Hostname Detection
        is_ip, ip_type = URLAnalyzer.is_ip_address(host_no_port)
        if is_ip:
            score += 50
            threat_categories.append("Direct IP Access")
            indicators.append(f"⚠️ URL uses a raw {ip_type} ({host_no_port}) instead of a registered domain name")

        # 4. @ Symbol Authentication Deception
        if auth_part:
            score += 55
            threat_categories.append("Authority Deception (@ trick)")
            indicators.append(f"🚨 Deceptive '@' symbol in URL: attempts to trick users into seeing '{auth_part}' while destination is '{host_no_port}'")

        # 5. Suspicious TLD Analysis
        tld = host_no_port.split(".")[-1] if "." in host_no_port else ""
        if tld in SUSPICIOUS_TLDS:
            tld_risk = SUSPICIOUS_TLDS[tld]
            score += tld_risk
            indicators.append(f"⚠️ High-risk Top Level Domain '.{tld}' (+{tld_risk} risk points)")

        # 6. Subdomain Depth & Multiple Subdomain Exploits
        subdomain_parts = host_no_port.split(".")
        if len(subdomain_parts) >= 4:
            score += 25
            threat_categories.append("Excessive Subdomains")
            indicators.append(f"⚠️ Excessive subdomain hierarchy ({len(subdomain_parts)} levels) used to conceal true domain")

        # 7. Phishing & Credential Keywords in Subdomain or Path
        found_keywords = []
        full_url_lower = (host_no_port + full_path).lower()
        for kw, kw_score in PHISHING_KEYWORDS.items():
            # Check standalone keyword in domain or path
            if re.search(r'[\.\-\_\/\?\=]' + re.escape(kw) + r'[\.\-\_\/\&\=\d]?', full_url_lower):
                found_keywords.append(kw)
                score += kw_score

        if found_keywords:
            score += min(len(found_keywords) * 8, 35)
            threat_categories.append("Credential / Phishing Keywords")
            indicators.append(f"⚠️ Sensitive credential/urgency lures found in URL: {', '.join(set(found_keywords))}")

        # 8. Shannon Entropy Calculation (DGA / High Randomness)
        domain_entropy = URLAnalyzer.calculate_entropy(LookalikeEngine.extract_sld(host_no_port))
        path_entropy = URLAnalyzer.calculate_entropy(path)
        
        if domain_entropy > 3.8 and len(LookalikeEngine.extract_sld(host_no_port)) > 8:
            score += 25
            threat_categories.append("High Domain Entropy (DGA)")
            indicators.append(f"⚠️ High domain entropy ({domain_entropy}/5.0): indicates an algorithmically generated or random domain name")

        if path_entropy > 4.2 and len(path) > 20:
            score += 15
            indicators.append(f"⚠️ High path entropy ({path_entropy}/5.0): randomized tracking or payload delivery path")

        # 9. URL Shortener Detection
        if host_no_port in URL_SHORTENERS:
            score += 15
            indicators.append(f"ℹ️ URL Shortener detected ({host_no_port}): obscures the final destination URL")

        # 10. Abnormal Port Numbers
        if port and port not in [80, 443, 8080]:
            score += 20
            indicators.append(f"⚠️ Non-standard web port (:{port}) detected")

        # 11. Excessively Long URL (> 100 chars)
        if len(raw_url) > 120:
            score += 12
            indicators.append(f"ℹ️ Abnormally long URL ({len(raw_url)} chars) often used in token obfuscation")

        # 12. Double Extension / Executable file in URL path
        if re.search(r'\.(pdf|doc|docx|xls|xlsx|jpg|png)\.(exe|scr|vbs|bat|cmd|ps1|iso|zip|hta)$', path, re.I):
            score += 65
            threat_categories.append("Malicious Double Extension")
            indicators.append("🚨 Critical: URL points to an executable masquerading as a document (Double Extension attack)")

        # Whitelist suppression if genuinely verified domain and no lookalike/homoglyph trick
        if is_whitelisted and not lookalike_res["is_lookalike"] and not lookalike_res["has_homoglyphs"] and not auth_part:
            score = max(0, min(score, 5))
            threat_categories = []
            indicators = [f"✅ Verified authentic domain ({host_no_port})"]

        # Cap score between 0 and 100
        final_score = min(100, max(0, score))
        score_10 = round(final_score / 10, 1)

        # Classify Risk Level
        if final_score >= 70:
            risk_level = "Dangerous"
            is_phishing = True
            rec = "🚨 DANGEROUS PHISHING / MALICIOUS LINK! Do NOT click or enter credentials. This link shows high-confidence indicators of cyber attack."
        elif final_score >= 45:
            risk_level = "High Risk"
            is_phishing = True
            rec = "⚠️ HIGH RISK: This link exhibits multiple suspicious patterns (lookalike traits, abnormal TLD, or credential lures). Proceed with extreme caution."
        elif final_score >= 25:
            risk_level = "Caution"
            is_phishing = False
            rec = "⚠️ CAUTION: Minor anomalies detected (shortener or keyword triggers). Verify the destination before entering personal information."
        elif final_score >= 10:
            risk_level = "Moderate"
            is_phishing = False
            rec = "ℹ️ MODERATE: Generally standard structure with low-level anomalies."
        else:
            risk_level = "Safe"
            is_phishing = False
            rec = "✅ SAFE: No significant phishing, lookalike, or structural deception indicators detected."

        primary_threat = threat_categories[0] if threat_categories else ("Lookalike Spoof" if lookalike_res["is_lookalike"] else "Clean")

        # 13. Machine Learning Ensemble Signal
        ml_res = {}
        if ml_detector:
            try:
                ml_res = ml_detector.predict_url(raw_url)
                if ml_res.get("is_phishing_predicted") and not is_whitelisted:
                    indicators.append(f"🤖 ML Ensemble Model: High probability of phishing ({ml_res.get('ml_phishing_probability', 0)*100:.1f}%) based on 29 trained structural features")
            except Exception:
                pass

        return {
            "url": raw_url,
            "domain": host_no_port,
            "risk_score": final_score,
            "risk_score_10": score_10,
            "risk_level": risk_level,
            "is_phishing": is_phishing,
            "threat_type": primary_threat,
            "threat_categories": list(set(threat_categories)),
            "lookalike_analysis": lookalike_res,
            "ml_analysis": ml_res,
            "structural_metrics": {
                "url_length": len(raw_url),
                "domain_length": len(host_no_port),
                "subdomain_count": len(subdomain_parts),
                "domain_entropy": domain_entropy,
                "path_entropy": path_entropy,
                "is_ip": is_ip,
                "has_at_symbol": bool(auth_part),
                "tld": tld,
                "port": port
            },
            "indicators": indicators,
            "recommendation": rec
        }
