"""
Lookalike & Homoglyph Detection Engine
Analyzes domains for IDN homograph attacks, typosquatting, brand spoofing, and generates lookalike variations.
"""

import re
import unicodedata
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Any, Optional

# Comprehensive database of top targeted brands & authoritative domains
TARGET_BRANDS: Dict[str, Dict[str, Any]] = {
    # Tech Giants & Cloud
    "google": {"domain": "google.com", "category": "Tech & Search", "importance": 10},
    "microsoft": {"domain": "microsoft.com", "category": "Tech & Enterprise", "importance": 10},
    "apple": {"domain": "apple.com", "category": "Tech & Hardware", "importance": 10},
    "amazon": {"domain": "amazon.com", "category": "E-Commerce & Cloud", "importance": 10},
    "meta": {"domain": "meta.com", "category": "Social Media", "importance": 9},
    "facebook": {"domain": "facebook.com", "category": "Social Media", "importance": 10},
    "instagram": {"domain": "instagram.com", "category": "Social Media", "importance": 9},
    "twitter": {"domain": "twitter.com", "category": "Social Media", "importance": 8},
    "x": {"domain": "x.com", "category": "Social Media", "importance": 8},
    "linkedin": {"domain": "linkedin.com", "category": "Professional Network", "importance": 9},
    "netflix": {"domain": "netflix.com", "category": "Streaming & Media", "importance": 9},
    "spotify": {"domain": "spotify.com", "category": "Streaming & Media", "importance": 8},
    "adobe": {"domain": "adobe.com", "category": "Software", "importance": 8},
    "github": {"domain": "github.com", "category": "Developer Tools", "importance": 8},
    "dropbox": {"domain": "dropbox.com", "category": "Cloud Storage", "importance": 8},
    "onedrive": {"domain": "onedrive.live.com", "category": "Cloud Storage", "importance": 8},
    "docusign": {"domain": "docusign.com", "category": "E-Signature", "importance": 9},
    "zoom": {"domain": "zoom.us", "category": "Communication", "importance": 8},
    "slack": {"domain": "slack.com", "category": "Communication", "importance": 8},
    "yahoo": {"domain": "yahoo.com", "category": "Web Portal & Email", "importance": 8},
    "outlook": {"domain": "outlook.com", "category": "Email", "importance": 9},
    "office365": {"domain": "office.com", "category": "Enterprise Suite", "importance": 10},
    
    # Financial Institutions & Banking
    "paypal": {"domain": "paypal.com", "category": "Payment Processor", "importance": 10},
    "chase": {"domain": "chase.com", "category": "Banking", "importance": 10},
    "bankofamerica": {"domain": "bankofamerica.com", "category": "Banking", "importance": 10},
    "wellsfargo": {"domain": "wellsfargo.com", "category": "Banking", "importance": 10},
    "citi": {"domain": "citi.com", "category": "Banking", "importance": 9},
    "citibank": {"domain": "citibank.com", "category": "Banking", "importance": 9},
    "capitalone": {"domain": "capitalone.com", "category": "Banking & Credit", "importance": 9},
    "americanexpress": {"domain": "americanexpress.com", "category": "Financial Services", "importance": 9},
    "amex": {"domain": "americanexpress.com", "category": "Financial Services", "importance": 8},
    "stripe": {"domain": "stripe.com", "category": "Payment Gateway", "importance": 9},
    "square": {"domain": "squareup.com", "category": "Payment Gateway", "importance": 8},
    "venmo": {"domain": "venmo.com", "category": "Payment Service", "importance": 8},
    "zelle": {"domain": "zellepay.com", "category": "Payment Service", "importance": 8},
    "westernunion": {"domain": "westernunion.com", "category": "Money Transfer", "importance": 8},
    "hsbc": {"domain": "hsbc.com", "category": "Banking", "importance": 9},
    "barclays": {"domain": "barclays.co.uk", "category": "Banking", "importance": 8},
    
    # Cryptocurrency & Exchanges
    "binance": {"domain": "binance.com", "category": "Crypto Exchange", "importance": 10},
    "coinbase": {"domain": "coinbase.com", "category": "Crypto Exchange", "importance": 10},
    "kraken": {"domain": "kraken.com", "category": "Crypto Exchange", "importance": 8},
    "metamask": {"domain": "metamask.io", "category": "Crypto Wallet", "importance": 9},
    "blockchain": {"domain": "blockchain.com", "category": "Crypto Platform", "importance": 8},
    "crypto": {"domain": "crypto.com", "category": "Crypto Exchange", "importance": 8},
    "kucoin": {"domain": "kucoin.com", "category": "Crypto Exchange", "importance": 8},
    "bybit": {"domain": "bybit.com", "category": "Crypto Exchange", "importance": 8},
    
    # E-Commerce & Retail & Logistics
    "ebay": {"domain": "ebay.com", "category": "E-Commerce", "importance": 8},
    "walmart": {"domain": "walmart.com", "category": "Retail", "importance": 8},
    "aliexpress": {"domain": "aliexpress.com", "category": "E-Commerce", "importance": 8},
    "fedex": {"domain": "fedex.com", "category": "Logistics & Shipping", "importance": 9},
    "dhl": {"domain": "dhl.com", "category": "Logistics & Shipping", "importance": 9},
    "ups": {"domain": "ups.com", "category": "Logistics & Shipping", "importance": 9},
    "usps": {"domain": "usps.com", "category": "Postal Service", "importance": 9},
    
    # Gaming & Entertainment
    "steam": {"domain": "steampowered.com", "category": "Gaming Platform", "importance": 9},
    "roblox": {"domain": "roblox.com", "category": "Gaming Platform", "importance": 8},
    "epicgames": {"domain": "epicgames.com", "category": "Gaming Platform", "importance": 8},
    "playstation": {"domain": "playstation.com", "category": "Gaming Platform", "importance": 8},
    "xbox": {"domain": "xbox.com", "category": "Gaming Platform", "importance": 8},
    "discord": {"domain": "discord.com", "category": "Gaming & Chat", "importance": 9}
}

# Homoglyph Confusables Map (Unicode lookalikes -> Latin equivalent)
HOMOGLYPHS_MAP: Dict[str, str] = {
    # Cyrillic
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q',
    'і': 'i', 'ј': 'j', 'ӏ': 'l', 'ո': 'n', 'υ': 'u', 'ѵ': 'v', 'ѡ': 'w', 'х': 'x',
    'у': 'y', 'т': 't', 'в': 'b', 'һ': 'h', 'к': 'k', 'м': 'm', 'н': 'h',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K',
    'М': 'M', 'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'Ү': 'Y',
    
    # Greek
    'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o',
    'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N',
    'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
    
    # Latin variations & accents
    'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a', 'ā': 'a',
    'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 'ē': 'e',
    'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i', 'ī': 'i', 'ı': 'i',
    'ó': 'o', 'ò': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o', 'ō': 'o', 'ø': 'o',
    'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ū': 'u',
    'ç': 'c', 'ñ': 'n', 'ý': 'y', 'ÿ': 'y'
}

# Number to Letter substitutes common in Leetspeak / Typosquatting
LEET_MAP: Dict[str, List[str]] = {
    '0': ['o'],
    '1': ['l', 'i', '1'],
    '3': ['e'],
    '4': ['a'],
    '5': ['s'],
    '7': ['t'],
    '8': ['b'],
    '@': ['a'],
    '$': ['s'],
    'vv': ['w'],
    'rn': ['m'],
    'cl': ['d']
}


class LookalikeEngine:
    """Engine for detecting and generating lookalike/typosquatting domains"""
    
    @staticmethod
    def normalize_homoglyphs(text: str) -> Tuple[str, bool, List[Dict[str, str]]]:
        """
        Replaces homoglyphs with their Latin counterparts.
        Returns: (normalized_text, has_homoglyphs, list_of_detected_homoglyphs)
        """
        normalized_chars = []
        has_homoglyphs = False
        detected = []
        
        # Check if IDN punycode
        if text.startswith("xn--"):
            try:
                decoded = text.encode("ascii").decode("idna")
                text = decoded
                has_homoglyphs = True
                detected.append({
                    "char": "punycode",
                    "original": text,
                    "latin": text,
                    "script": "Punycode (IDN)"
                })
            except Exception:
                pass

        for i, char in enumerate(text):
            if char in HOMOGLYPHS_MAP:
                has_homoglyphs = True
                latin_equiv = HOMOGLYPHS_MAP[char]
                normalized_chars.append(latin_equiv)
                try:
                    script = unicodedata.name(char, "UNKNOWN")
                except Exception:
                    script = "Unicode Confusable"
                detected.append({
                    "index": i,
                    "char": char,
                    "latin": latin_equiv,
                    "script": script
                })
            else:
                normalized_chars.append(char)
                
        return "".join(normalized_chars), has_homoglyphs, detected

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Calculates Levenshtein edit distance between two strings"""
        if len(s1) < len(s2):
            return LookalikeEngine.levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    @staticmethod
    def extract_sld(domain: str) -> str:
        """Extracts second-level domain name (e.g. 'paypal' from 'paypal.com' or 'login.paypal.com')"""
        clean_domain = domain.lower().strip()
        # Remove port if present
        if ":" in clean_domain:
            clean_domain = clean_domain.split(":")[0]
            
        parts = clean_domain.split(".")
        if len(parts) >= 2:
            # Handle common multi-part TLDs like co.uk, com.au, edu.in
            if parts[-2] in ["co", "com", "edu", "gov", "org", "net"] and len(parts) >= 3:
                return parts[-3]
            return parts[-2]
        return clean_domain

    @staticmethod
    def detect_lookalike(domain: str) -> Dict[str, Any]:
        """
        Analyzes a domain to see if it is impersonating or typosquatting a known brand.
        """
        domain_lower = domain.lower().strip()
        # Strip scheme and path if full URL was passed
        if "://" in domain_lower:
            parsed = urlparse(domain_lower)
            domain_lower = parsed.netloc
        if "/" in domain_lower:
            domain_lower = domain_lower.split("/")[0]
        if ":" in domain_lower:
            domain_lower = domain_lower.split(":")[0]

        # 1. Homoglyph check
        normalized_domain, has_homoglyphs, homoglyph_details = LookalikeEngine.normalize_homoglyphs(domain_lower)
        target_sld = LookalikeEngine.extract_sld(normalized_domain)
        original_sld = LookalikeEngine.extract_sld(domain_lower)

        result: Dict[str, Any] = {
            "is_lookalike": False,
            "target_brand": None,
            "legitimate_domain": None,
            "similarity_score": 0.0,
            "deception_type": None,
            "has_homoglyphs": has_homoglyphs,
            "homoglyphs_detected": homoglyph_details,
            "normalized_domain": normalized_domain,
            "risk_score_boost": 0,
            "details": []
        }

        # Skip lookalike edit-distance matching if domain is a raw IP address
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain_lower) or domain_lower.replace('.', '').isdigit():
            return result

        # Check if the domain is EXACTLY the legitimate domain
        for brand, info in TARGET_BRANDS.items():
            legit_domain = info["domain"]
            if domain_lower == legit_domain or domain_lower.endswith("." + legit_domain):
                # Authentic domain!
                result["is_lookalike"] = False
                result["target_brand"] = brand
                result["legitimate_domain"] = legit_domain
                result["details"].append(f"Authentic {brand.title()} domain verified ({legit_domain})")
                return result

        # If homoglyphs were used to mimic a known brand
        if has_homoglyphs:
            for brand, info in TARGET_BRANDS.items():
                legit_sld = LookalikeEngine.extract_sld(info["domain"])
                if target_sld == legit_sld or (len(brand) >= 3 and (target_sld.startswith(brand) or target_sld.endswith(brand) or f"-{brand}-" in target_sld)):
                    result["is_lookalike"] = True
                    result["target_brand"] = brand
                    result["legitimate_domain"] = info["domain"]
                    result["similarity_score"] = 98.0
                    result["deception_type"] = "IDN Homograph / Unicode Confusable Attack"
                    result["risk_score_boost"] = 95
                    result["details"].append(
                        f"CRITICAL: Domain uses Unicode homoglyphs to imitate '{info['domain']}'! "
                        f"Visual characters were substituted with lookalike characters."
                    )
                    return result

        # Sort brands by name length descending so specific brands (netflix) are prioritized over single-letter brands (x)
        sorted_brands = sorted(TARGET_BRANDS.items(), key=lambda x: len(x[0]), reverse=True)

        # 2. Check for Subdomain Spoofing (e.g., paypal.com.attacker-domain.xyz or login-paypal.account.com)
        for brand, info in sorted_brands:
            legit_domain = info["domain"]
            legit_sld = LookalikeEngine.extract_sld(legit_domain)
            
            # Case A: Brand name as a distinct subdomain label (e.g., paypal.attacker.xyz or login.paypal.account.com)
            is_subdomain_label = (domain_lower.startswith(f"{legit_sld}.") or f".{legit_sld}." in domain_lower)
            if is_subdomain_label and len(legit_sld) >= 3 and not (domain_lower == legit_domain or domain_lower.endswith(f".{legit_domain}")):
                result["is_lookalike"] = True
                result["target_brand"] = brand
                result["legitimate_domain"] = legit_domain
                result["similarity_score"] = 90.0
                result["deception_type"] = "Subdomain Brand Spoofing"
                result["risk_score_boost"] = 85
                result["details"].append(
                    f"Brand '{brand}' appears as a deceptive subdomain label, but actual root domain is '{target_sld}'."
                )
                return result

            # Case B: Compound Brand-Keyword domain (e.g. paypal-security-update.com, amaz0n-security.com)
            leet_normalized_sld = target_sld
            for leet_char, replacements in LEET_MAP.items():
                for r in replacements:
                    leet_normalized_sld = leet_normalized_sld.replace(leet_char, r)

            # Skip single-character brands like 'x' for combosquatting unless strictly hyphen-bounded
            if len(brand) < 3 and not (target_sld.startswith(f"{brand}-") or f"-{brand}-" in target_sld or target_sld.endswith(f"-{brand}")):
                continue

            suspicious_keywords = ["login", "verify", "secure", "security", "support", "account", "update", "service", "billing", "auth", "signin", "portal", "help", "alert", "official"]
            for kw in suspicious_keywords:
                pattern1 = f"{brand}-{kw}"
                pattern2 = f"{kw}-{brand}"
                pattern3 = f"{brand}{kw}"
                pattern4 = f"{kw}{brand}"
                
                matches_orig = (pattern1 in target_sld or pattern2 in target_sld or 
                                target_sld.startswith(pattern3) or target_sld.endswith(pattern4))
                matches_leet = (pattern1 in leet_normalized_sld or pattern2 in leet_normalized_sld or 
                                leet_normalized_sld.startswith(pattern3) or leet_normalized_sld.endswith(pattern4))

                if (matches_orig or matches_leet) and target_sld != legit_sld and leet_normalized_sld != legit_sld:
                    result["is_lookalike"] = True
                    result["target_brand"] = brand
                    result["legitimate_domain"] = legit_domain
                    result["similarity_score"] = 88.0
                    result["deception_type"] = "Keyword Squatting / Combosquatting"
                    result["risk_score_boost"] = 80
                    result["details"].append(
                        f"Brand '{brand}' is combined with high-urgency keyword '{kw}' in '{domain_lower}'."
                    )
                    return result

        # 3. Levenshtein / Edit Distance Typosquatting Check
        # Example: paypa1.com, netf1ix.com, m1crosoft.com, amaz0n.com, app1e.com
        
        # Also check leetspeak normalized version
        leet_normalized = original_sld
        for leet_char, replacements in LEET_MAP.items():
            for r in replacements:
                leet_normalized = leet_normalized.replace(leet_char, r)

        for brand, info in TARGET_BRANDS.items():
            legit_sld = LookalikeEngine.extract_sld(info["domain"])
            
            # Distance against original SLD and leet-normalized SLD
            dist1 = LookalikeEngine.levenshtein_distance(original_sld, legit_sld)
            dist2 = LookalikeEngine.levenshtein_distance(leet_normalized, legit_sld)
            min_dist = min(dist1, dist2)
            
            # Length considerations
            max_len = max(len(original_sld), len(legit_sld))
            if max_len == 0:
                continue
                
            similarity = (1 - (min_dist / max_len)) * 100

            # Distance threshold based on word length
            is_match = False
            deception_reason = ""

            if len(legit_sld) <= 4 and min_dist == 1:
                # Short words (e.g. meta, ebay) with 1 edit
                is_match = True
                deception_reason = "1-character variation of short brand name"
            elif len(legit_sld) > 4 and min_dist in [1, 2]:
                # Longer words (e.g. microsoft, paypal, netflix) with 1-2 edits
                is_match = True
                deception_reason = f"{min_dist}-character typo/edit distance variation"
            elif dist2 == 0 and dist1 > 0:
                is_match = True
                deception_reason = "Leetspeak character substitution (e.g. 0->o, 1->l/i)"

            if is_match and original_sld != legit_sld:
                result["is_lookalike"] = True
                result["target_brand"] = brand
                result["legitimate_domain"] = info["domain"]
                result["similarity_score"] = round(similarity, 1)
                result["deception_type"] = f"Typosquatting ({deception_reason})"
                result["risk_score_boost"] = 85
                result["details"].append(
                    f"Lookalike detected: '{domain_lower}' is visually {round(similarity, 1)}% similar to authentic '{info['domain']}' ({brand.title()})."
                )
                return result

        return result

    @staticmethod
    def generate_lookalike_variants(domain: str) -> List[Dict[str, Any]]:
        """
        Generates simulated lookalike & typosquatting variations for security testing & threat hunting.
        """
        sld = LookalikeEngine.extract_sld(domain)
        tld = domain.split(".")[-1] if "." in domain else "com"
        variants = []
        
        # 1. Homoglyphs (Cyrillic substitution)
        for char, repl in [('a', 'а'), ('o', 'о'), ('e', 'е'), ('p', 'р'), ('c', 'с'), ('i', 'і')]:
            if char in sld:
                fake_sld = sld.replace(char, repl, 1)
                try:
                    puny = fake_sld.encode('idna').decode('ascii')
                except Exception:
                    puny = f"xn--{fake_sld}"
                variants.append({
                    "variant": f"{fake_sld}.{tld}",
                    "punycode": f"{puny}.{tld}",
                    "technique": "IDN Homoglyph (Cyrillic)",
                    "risk": "Critical",
                    "visual_similarity": "99%"
                })

        # 2. Character Omission
        for i in range(len(sld)):
            omitted = sld[:i] + sld[i+1:]
            if len(omitted) >= 3:
                variants.append({
                    "variant": f"{omitted}.{tld}",
                    "technique": "Character Omission",
                    "risk": "High",
                    "visual_similarity": "90%"
                })

        # 3. Leetspeak / Substitution
        leet_swaps = [('o', '0'), ('l', '1'), ('i', '1'), ('e', '3'), ('a', '4'), ('s', '5')]
        for orig, sub in leet_swaps:
            if orig in sld:
                variants.append({
                    "variant": f"{sld.replace(orig, sub, 1)}.{tld}",
                    "technique": f"Leetspeak ({orig} -> {sub})",
                    "risk": "High",
                    "visual_similarity": "92%"
                })

        # 4. Combosquatting / Keyword addition
        for kw in ["security", "login", "verify", "support", "billing"]:
            variants.append({
                "variant": f"{sld}-{kw}.{tld}",
                "technique": "Combosquatting (Hyphenated)",
                "risk": "High",
                "visual_similarity": "85%"
            })

        # 5. Suspicious TLD Swap
        for fake_tld in ["xyz", "top", "online", "live", "site"]:
            variants.append({
                "variant": f"{sld}.{fake_tld}",
                "technique": f"TLD Hijack (.{fake_tld})",
                "risk": "Medium-High",
                "visual_similarity": "88%"
            })

        return variants[:20]  # Return top 20 variants
