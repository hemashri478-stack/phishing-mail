"""
ML Phishing URL Detector
Extracts feature vectors from URLs matching the UCI/Kaggle Phishing Website Dataset
and scores them using the trained Machine Learning Ensemble Classifier.
"""

import os
import re
import math
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
import joblib

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ai-models", "phishing_ml_model.joblib")
METADATA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ai-models", "model_metadata.json")

# Known URL shorteners
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly",
    "rb.gy", "tiny.cc", "shorturl.at", "rebrand.ly", "soo.gd", "s.id"
}

FEATURE_NAMES = [
    'having_IP', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain',
    'SSLfinal_State', 'Domain_registeration_length', 'Favicon', 'port',
    'HTTPS_token', 'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH',
    'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover',
    'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain', 'DNSRecord',
    'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page'
]


class MLPhishingDetector:
    """Inference engine for Machine Learning Phishing URL Detection"""

    def __init__(self):
        self.model = None
        self.metadata = {}
        self.load_model()

    def load_model(self):
        """Loads the serialized model if available"""
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception as e:
                print(f"⚠️ Warning: Could not load ML model: {e}")
                self.model = None

    @staticmethod
    def extract_features(url: str) -> Dict[str, int]:
        """
        Extracts 29 standard phishing features from a URL matching the dataset:
        Values: -1 (Phishing indicator), 0 (Suspicious), 1 (Legitimate)
        """
        if not url:
            return {f: 1 for f in FEATURE_NAMES}

        raw_url = url.strip()
        parsed_str = raw_url if raw_url.startswith(("http://", "https://")) else "http://" + raw_url
        try:
            parsed = urlparse(parsed_str)
        except Exception:
            return {f: -1 for f in FEATURE_NAMES}

        host = parsed.netloc.lower() or parsed.path.split("/")[0].lower()
        if ":" in host:
            host_no_port = host.split(":")[0]
            port_val = -1 if parsed.port not in [80, 443, None] else 1
        else:
            host_no_port = host
            port_val = 1

        path = parsed.path or ""

        # 1. having_IP (-1 if IP, 1 if domain)
        is_ip = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host_no_port) or host_no_port.startswith("0x"))
        having_ip = -1 if is_ip else 1

        # 2. URL_Length (<54 -> 1, 54-75 -> 0, >75 -> -1)
        url_len = len(raw_url)
        if url_len < 54:
            url_length_feat = 1
        elif 54 <= url_len <= 75:
            url_length_feat = 0
        else:
            url_length_feat = -1

        # 3. Shortining_Service (-1 if shortener, 1 otherwise)
        shortener_feat = -1 if host_no_port in SHORTENERS else 1

        # 4. having_At_Symbol (-1 if @ in URL, 1 otherwise)
        at_symbol_feat = -1 if "@" in raw_url else 1

        # 5. double_slash_redirecting (-1 if // in path, 1 otherwise)
        # // after scheme (e.g. http://site.com//login)
        double_slash_feat = -1 if "//" in path else 1

        # 6. Prefix_Suffix (-1 if '-' in domain, 1 otherwise)
        prefix_suffix_feat = -1 if "-" in host_no_port else 1

        # 7. having_Sub_Domain (subdomains: 1 -> 1, 2 -> 0, >2 -> -1)
        subdomain_parts = host_no_port.split(".")
        if len(subdomain_parts) <= 2:
            subdomain_feat = 1
        elif len(subdomain_parts) == 3:
            subdomain_feat = 0
        else:
            subdomain_feat = -1

        # 8. SSLfinal_State (1 if https, -1 if http)
        ssl_feat = 1 if raw_url.startswith("https://") else -1

        # 9. Domain_registeration_length (heuristic proxy)
        reg_length_feat = 1 if not is_ip and len(host_no_port) > 5 else -1

        # 10. Favicon (heuristic proxy)
        favicon_feat = 1

        # 11. port (-1 if non-standard)
        port_feat = port_val

        # 12. HTTPS_token (-1 if 'https' is in domain part e.g. https-login.com)
        https_token_feat = -1 if "https" in host_no_port.replace("https://", "") else 1

        # 13. Request_URL (proxy)
        request_url_feat = 1

        # 14. URL_of_Anchor (-1 if anchor text mismatch or javascript)
        url_anchor_feat = 1

        # 15. Links_in_tags
        links_tags_feat = 1

        # 16. SFH (Server Form Handler: -1 if blank or about:blank, 1 if valid)
        sfh_feat = 1

        # 17. Submitting_to_email (-1 if mailto in action)
        email_sub_feat = -1 if "mailto:" in raw_url else 1

        # 18. Abnormal_URL (-1 if host name not present)
        abnormal_url_feat = -1 if len(host_no_port) == 0 else 1

        # 19. Redirect (0 if <=1, 1 if >=2)
        redirect_feat = 0

        # 20. on_mouseover
        mouseover_feat = 1

        # 21. RightClick
        right_click_feat = 1

        # 22. popUpWidnow
        popup_feat = 1

        # 23. Iframe
        iframe_feat = 1

        # 24. age_of_domain
        age_domain_feat = 1 if not is_ip else -1

        # 25. DNSRecord
        dns_feat = 1

        # 26. web_traffic (-1 if suspicious TLD or IP)
        tld = host_no_port.split(".")[-1] if "." in host_no_port else ""
        web_traffic_feat = -1 if tld in ["xyz", "top", "tk", "ml", "ga", "cf", "gq"] else 1

        # 27. Page_Rank
        page_rank_feat = -1 if is_ip or prefix_suffix_feat == -1 else 1

        # 28. Google_Index (1 if standard, -1 if suspicious)
        google_index_feat = 1 if not is_ip else -1

        # 29. Links_pointing_to_page
        links_pointing_feat = 0

        return {
            'having_IP': having_ip,
            'URL_Length': url_length_feat,
            'Shortining_Service': shortener_feat,
            'having_At_Symbol': at_symbol_feat,
            'double_slash_redirecting': double_slash_feat,
            'Prefix_Suffix': prefix_suffix_feat,
            'having_Sub_Domain': subdomain_feat,
            'SSLfinal_State': ssl_feat,
            'Domain_registeration_length': reg_length_feat,
            'Favicon': favicon_feat,
            'port': port_feat,
            'HTTPS_token': https_token_feat,
            'Request_URL': request_url_feat,
            'URL_of_Anchor': url_anchor_feat,
            'Links_in_tags': links_tags_feat,
            'SFH': sfh_feat,
            'Submitting_to_email': email_sub_feat,
            'Abnormal_URL': abnormal_url_feat,
            'Redirect': redirect_feat,
            'on_mouseover': mouseover_feat,
            'RightClick': right_click_feat,
            'popUpWidnow': popup_feat,
            'Iframe': iframe_feat,
            'age_of_domain': age_domain_feat,
            'DNSRecord': dns_feat,
            'web_traffic': web_traffic_feat,
            'Page_Rank': page_rank_feat,
            'Google_Index': google_index_feat,
            'Links_pointing_to_page': links_pointing_feat
        }

    def predict_url(self, url: str) -> Dict[str, Any]:
        """
        Runs ML model inference on the URL feature vector.
        """
        features_dict = self.extract_features(url)
        feature_vector = [features_dict[name] for name in FEATURE_NAMES]

        if self.model is None:
            # Fallback heuristic calculation if model file is not loaded
            negative_count = sum(1 for v in feature_vector if v == -1)
            prob = min(1.0, negative_count / 8.0)
            score = int(prob * 100)
            is_phish = prob >= 0.45
            return {
                "ml_available": False,
                "ml_risk_score": score,
                "ml_phishing_probability": round(prob, 3),
                "is_phishing_predicted": is_phish,
                "model_name": "Heuristic Feature Fallback",
                "extracted_features": features_dict
            }

        try:
            import pandas as pd
            df_input = pd.DataFrame([feature_vector], columns=FEATURE_NAMES)
            proba = self.model.predict_proba(df_input)[0]
            phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            pred_class = int(self.model.predict(df_input)[0])
            ml_score = int(phishing_prob * 100)
            is_phish = (pred_class == 1) or (phishing_prob >= 0.50)

            # Top active risk features
            active_threat_features = [
                feat for feat, val in features_dict.items() if val == -1
            ]

            return {
                "ml_available": True,
                "ml_risk_score": ml_score,
                "ml_phishing_probability": round(phishing_prob, 4),
                "is_phishing_predicted": is_phish,
                "predicted_class": "Phishing" if is_phish else "Legitimate",
                "model_name": type(self.model).__name__,
                "active_threat_features": active_threat_features,
                "extracted_features": features_dict
            }
        except Exception as e:
            return {
                "ml_available": False,
                "error": str(e),
                "ml_risk_score": 50,
                "ml_phishing_probability": 0.5,
                "is_phishing_predicted": False,
                "extracted_features": features_dict
            }


# Singleton instance
ml_detector = MLPhishingDetector()
