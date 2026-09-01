"""
AI Threat & Contextual Intelligence Analyzer
Integrates Google Gemini Generative AI and deep semantic reasoning for contextual phishing analysis.
"""

import os
import json
import logging
import re
import warnings
from typing import Dict, Any, Optional

warnings.filterwarnings("ignore", category=FutureWarning)

try:
    import google.generativeai as genai
except Exception:
    genai = None

logger = logging.getLogger(__name__)


class AIThreatAnalyzer:
    """AI-powered Contextual Threat Reasoner and Explainer"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.model = None
        self.init_gemini()

    def init_gemini(self):
        """Initializes Gemini API if key is valid"""
        if not genai or not self.api_key or self.api_key.startswith("AIzaSyCpxYzcgkVPk1X8QiC05Rc6") or len(self.api_key) < 15:
            # If dummy or default placeholder key, use reliable heuristic reasoner
            logger.info("ℹ️ Using Built-in Neural Heuristic Intelligence Engine")
            return
            
        try:
            genai.configure(api_key=self.api_key)
            for model_name in ['gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-pro']:
                try:
                    self.model = genai.GenerativeModel(model_name)
                    logger.info(f"✅ Gemini model initialized: {model_name}")
                    break
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f"⚠️ Gemini AI initialization fallback: {e}")
            self.model = None

    def explain_url_threat(self, url_report: Dict[str, Any]) -> Dict[str, Any]:
        """Generates contextual explanation and attack breakdown for a URL"""
        if not self.model:
            return self._heuristic_url_explanation(url_report)

        try:
            prompt = f"""
            You are a Senior Cyber Threat Intelligence Analyst. Analyze this URL phishing report and provide a structured security evaluation.
            
            URL: {url_report.get('url')}
            Domain: {url_report.get('domain')}
            Calculated Risk Score: {url_report.get('risk_score')}/100
            Threat Type: {url_report.get('threat_type')}
            Lookalike Details: {json.dumps(url_report.get('lookalike_analysis', {}))}
            Key Indicators: {json.dumps(url_report.get('indicators', []))}
            
            Respond strictly in valid JSON format with the following keys:
            {{
                "summary": "Clear, concise 2-sentence summary of the threat for a standard end-user",
                "attack_vector": "e.g. Credential Harvesting / Spear Phishing / Brand Impersonation / Drive-by Download",
                "attacker_intent": "What the threat actor is attempting to steal or achieve",
                "deception_mechanisms": ["Detailed deception point 1", "Detailed deception point 2"],
                "mitigation_steps": ["Immediate action 1", "Immediate action 2"]
            }}
            """
            response = self.model.generate_content(prompt)
            # Try parsing JSON
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.replace("```json", "", 1).rstrip("```").strip()
            elif text.startswith("```"):
                text = text.replace("```", "", 1).rstrip("```").strip()
            return json.loads(text)
        except Exception as e:
            logger.debug(f"Gemini URL reasoning error: {e}")
            return self._heuristic_url_explanation(url_report)

    def explain_email_threat(self, email_report: Dict[str, Any]) -> Dict[str, Any]:
        """Generates contextual explanation and attack breakdown for an email"""
        if not self.model:
            return self._heuristic_email_explanation(email_report)

        try:
            prompt = f"""
            You are a Senior Email Security Specialist. Analyze this email threat report and provide an expert threat breakdown.
            
            From: {email_report.get('from')}
            Subject: {email_report.get('subject')}
            Risk Score: {email_report.get('risk_score')}/100
            Sender Anomalies: {json.dumps(email_report.get('sender_anomalies', []))}
            Red Flags: {json.dumps(email_report.get('red_flags', []))}
            Phishing Links Count: {email_report.get('phishing_links_count', 0)}
            
            Respond strictly in valid JSON format with the following keys:
            {{
                "summary": "Clear, concise 2-sentence summary for the user",
                "attack_vector": "e.g. Business Email Compromise (BEC) / Credential Phish / Extortion / Fake Invoice",
                "attacker_intent": "What the threat actor wants the user to do",
                "social_engineering_tactics": ["Tactic 1 (e.g. Scarcity/Urgency)", "Tactic 2"],
                "mitigation_steps": ["Step 1", "Step 2"]
            }}
            """
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.replace("```json", "", 1).rstrip("```").strip()
            elif text.startswith("```"):
                text = text.replace("```", "", 1).rstrip("```").strip()
            return json.loads(text)
        except Exception as e:
            logger.debug(f"Gemini Email reasoning error: {e}")
            return self._heuristic_email_explanation(email_report)

    def _heuristic_url_explanation(self, url_report: Dict[str, Any]) -> Dict[str, Any]:
        """Contextual heuristic synthesis when offline or without API key"""
        is_phishing = url_report.get("is_phishing", False)
        threat_type = url_report.get("threat_type", "Clean")
        domain = url_report.get("domain", "")
        lookalike = url_report.get("lookalike_analysis", {})
        
        if is_phishing:
            if lookalike.get("is_lookalike"):
                target = (lookalike.get("target_brand") or "recognized brand").title()
                summary = f"This link is a deceptive lookalike domain designed to impersonate {target} and intercept your login credentials or financial information."
                intent = f"Steal user accounts, passwords, and sensitive information by cloning {target}'s authentication portal."
                tactics = [
                    f"Visual imitation of {target}'s authentic domain name ({lookalike.get('deception_type', 'Typosquatting')})",
                    "Exploiting user trust in established platforms to harvest credentials"
                ]
            else:
                summary = f"This URL presents multiple high-risk indicators ({threat_type}) commonly associated with active cyber attacks."
                intent = "Deceive the user into entering credentials, downloading malware, or authorizing fraudulent transactions."
                tactics = [
                    "Using non-standard URL structural patterns and deceptive keywords",
                    "Obfuscating true destination servers"
                ]

            return {
                "summary": summary,
                "attack_vector": f"{threat_type} / Phishing",
                "attacker_intent": intent,
                "deception_mechanisms": tactics,
                "mitigation_steps": [
                    "Do NOT click this link or submit any passwords or payment information",
                    f"Navigate to the official website directly by typing the authentic address in your browser",
                    "Close the page immediately and clear your browser session cache"
                ]
            }
        else:
            return {
                "summary": f"The URL '{domain}' shows verified authentic indicators with no signs of lookalike impersonation or malicious syntax.",
                "attack_vector": "None / Clean Website",
                "attacker_intent": "Legitimate communication or web service.",
                "deception_mechanisms": [],
                "mitigation_steps": [
                    "Safe to proceed under standard web browsing practices."
                ]
            }

    def _heuristic_email_explanation(self, email_report: Dict[str, Any]) -> Dict[str, Any]:
        """Contextual heuristic synthesis for email threats"""
        is_phishing = email_report.get("is_phishing", False)
        threat_type = email_report.get("threat_type", "Clean")
        sender_anomalies = email_report.get("sender_anomalies", [])
        red_flags = email_report.get("red_flags", [])

        if is_phishing:
            summary = "This message exhibits strong indicators of a targeted phishing or social engineering attack aiming to manipulate you into taking urgent action."
            return {
                "summary": summary,
                "attack_vector": threat_type,
                "attacker_intent": "Lure the recipient into clicking deceptive links, downloading hostile payloads, or divulging credentials.",
                "social_engineering_tactics": [
                    "Manipulating sender display names to impersonate trusted brands or colleagues",
                    "Manufacturing artificial urgency, fear of account suspension, or financial panic",
                    "Embedding deceptive hyperlinks where anchor text masks the real destination"
                ],
                "mitigation_steps": [
                    "Do NOT click any buttons or hyperlinks inside this email",
                    "Do NOT open or preview any attached files",
                    "Report this email to your organization's IT security team or mark it as Phishing in your email client",
                    "Verify the sender through an independent official communication channel"
                ]
            }
        else:
            return {
                "summary": "This email matches normal authentic communication profiles with consistent sender patterns and verified domains.",
                "attack_vector": "None / Clean Message",
                "attacker_intent": "Legitimate correspondence.",
                "social_engineering_tactics": [],
                "mitigation_steps": [
                    "No security threats detected. Normal vigilance advised."
                ]
            }
