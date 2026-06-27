import json
import re
from typing import Dict, Optional, Any

from backend.llm.nvidia_client import nvidia_client
from backend.llm.prompt_builder import PromptBuilder
from loguru import logger


class RouterAgent:
    """
    Fast-path router that classifies alerts into:
    - dismiss: false positive, no action needed
    - enrich: suspicious, needs parallel investigation
    - escalate: confirmed threat, immediate response required

    Production hardening:
    - NEVER escalate purely based on severity.
    - Escalate only when confirmed/high-confidence evidence patterns exist.
    - Webshell indicators (even "detected") are treated as HIGH-PRIORITY ENRICH by default
      unless you have explicit corroborated telemetry in the deterministic pipeline.
    """

    FALSE_POSITIVE_PATTERNS = [
        "vulnerability scanner", "nessus", "qualys", "authorized scan",
        "penetration test", "pentest", "red team authorized",
        "backup process", "monitoring agent"
    ]

    # Suspicious keywords => ENRICH (not confirmed)
    SUSPICIOUS_PATTERNS = [
        "data exfiltration", "c2 beacon", "command and control",
        "privilege escalation", "lateral movement", "mimikatz", "cobalt strike",
        "credential dump", "persistence mechanism",

        # web exploitation indicators (common in intel narratives; not proof alone)
        "webshell", "web shell", "human2.aspx", "x-silock", "lemurloot",
        "sql injection", "rce", "remote code execution"
    ]
    
    APT_PATTERNS = [
    "plugx",
    "dll side-loading",
    "dll sideloading",
    "spearphishing",
    "state-sponsored",
    "nation-state",
    "government think tank",
    "classified research",
    "usb lateral movement",
    "c2 over https",
    "masquerading as microsoft",
    "rar archives",
    "exfiltration",
    "volt typhoon",
    "fast reverse proxy",
    "frp",
    "brightmetricagent",
    "smsvcservice",
    "ntds.dit",
    "log clearing",
    "credential compromise",
    "stealth persistence",
    "proxy tunneling",
    ]

    # Confirmed (non-webshell) => allowed to ESCALATE
    CONFIRMED_THREAT_REGEX_ESCALATE = [
        # ransomware confirmation-ish
        r"\b(files?\s+encrypted|file\s+encryption|ransom\s+note)\b",
        r"\b(mass\s+file\s+rename|mass\s+rename)\b",
        r"\b(vssadmin\s+delete\s+shadows|shadow\s+copy\s+deletion)\b",
        r"\b(wevtutil\s+cl|wbadmin\s+delete|bcdedit\s+/set)\b",

        # confirmed beacon/C2 language
        r"\b(beaconing\s+confirmed|confirmed\s+c2|c2\s+communication\s+established)\b",

        # explicit "compromise confirmed"
        r"\b(compromise\s+confirmed|confirmed\s+compromise)\b",
    ]

    # Webshell "confirmation" => HIGH-PRIORITY ENRICH (not escalate)
    CONFIRMED_THREAT_REGEX_WEBSHELL = [
        r"\b(web\s*shell|webshell)\b.*\b(detected|confirmed|found|present|dropped|written|uploaded|created)\b",
        r"\b(detected|confirmed|found|present|dropped|written|uploaded|created)\b.*\b(web\s*shell|webshell)\b",
    ]

    def __init__(self):
        self.client = nvidia_client
        self.prompt_builder = PromptBuilder()

    def route(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        alert_xml = self.prompt_builder.build_alert_xml(alert_data)

        rule_decision = self._rule_based_screen(alert_data)
        if rule_decision and float(rule_decision.get("confidence") or 0.0) > 0.90:
            logger.info(f"[Router] Rule-based decision: {rule_decision['decision']}")
            return rule_decision

        try:
            messages = self.prompt_builder.build_router_prompt(alert_xml)
            response = self.client.chat(messages, temperature=0.0, max_tokens=200)
            result = self._parse_json_response(response)

            gated = self._gate_llm_decision(alert_data, result)

            logger.info(
                f"[Router] LLM decision: {result['decision']} (conf: {result.get('confidence')}) "
                f"=> gated: {gated['decision']} (conf: {gated.get('confidence')})"
            )
            return gated

        except Exception as e:
            logger.error(f"[Router] LLM routing failed: {e}, falling back to rules")
            return rule_decision or {
                "decision": "enrich",
                "reason": "Routing failed; defaulting to enrichment for safety",
                "confidence": 0.5
            }

    # -------------------------
    # Internal helpers
    # -------------------------

    def _build_text(self, alert_data: Dict[str, Any]) -> str:
        return " ".join([
            str(alert_data.get("description", "")),
            str(alert_data.get("additional_context", "")),
            str(alert_data.get("alert_source", "")),
            str(alert_data.get("ioc_list", "")),
        ]).lower()

    def _contains_any(self, text: str, patterns: list[str]) -> Optional[str]:
        for p in patterns:
            if p in text:
                return p
        return None

    def _match_regex(self, text: str, regexes: list[str]) -> Optional[str]:
        for rx in regexes:
            if re.search(rx, text, flags=re.IGNORECASE):
                return rx
        return None

    def _rule_based_screen(self, alert_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        text = self._build_text(alert_data)

        # 1) Dismiss first
        fp = self._contains_any(text, self.FALSE_POSITIVE_PATTERNS)
        if fp:
            return {
                "decision": "dismiss",
                "reason": f"Known false positive pattern: '{fp}'",
                "confidence": 0.92,
                "match": {"type": "false_positive_pattern", "value": fp}
            }
            
        # APT / espionage indicators
        apt_hits = [
            p for p in self.APT_PATTERNS
            if p in text
        ]
        
        if len(apt_hits) >= 2:
            return {
                "decision": "enrich",
                "reason": (
                    "APT / espionage tradecraft indicators detected: "
                    + ", ".join(apt_hits[:4])
                ),
                "confidence": 0.94,
                "match": {
                    "type": "apt_tradecraft",
                    "value": apt_hits[:6]
                }
            }

        # 2) Escalate only for non-webshell confirmed evidence
        rx_escalate = self._match_regex(text, self.CONFIRMED_THREAT_REGEX_ESCALATE)
        if rx_escalate:
            return {
                "decision": "escalate",
                "reason": "Confirmed threat indicator present in alert text (non-webshell).",
                "confidence": 0.93,
                "match": {"type": "confirmed_regex_escalate", "value": rx_escalate}
            }

        # 3) Webshell confirmations -> high-priority ENRICH (not escalate)
        rx_webshell = self._match_regex(text, self.CONFIRMED_THREAT_REGEX_WEBSHELL)
        if rx_webshell:
            return {
                "decision": "enrich",
                "reason": "Webshell indicator appears in alert text; treat as high-priority enrichment pending corroboration.",
                "confidence": 0.90,
                "match": {"type": "webshell_regex_enrich", "value": rx_webshell}
            }

        # 4) Suspicious patterns => enrich
        susp = self._contains_any(text, self.SUSPICIOUS_PATTERNS)
        if susp:
            return {
                "decision": "enrich",
                "reason": f"Suspicious indicator detected: '{susp}' (needs corroboration).",
                "confidence": 0.85,
                "match": {"type": "suspicious_pattern", "value": susp}
            }

        # 5) Severity influences priority, not confirmation
        severity = str(alert_data.get("severity", "")).upper().strip()
        if severity == "CRITICAL":
            return {
                "decision": "enrich",
                "reason": "Critical severity: prioritize enrichment; escalate only with corroborated evidence.",
                "confidence": 0.80,
                "match": {"type": "severity", "value": "CRITICAL"}
            }

        if severity == "INFO":
            return {
                "decision": "enrich",
                "reason": "Informational severity — needs context.",
                "confidence": 0.70,
                "match": {"type": "severity", "value": "INFO"}
            }

        return None

    def _gate_llm_decision(self, alert_data: Dict[str, Any], llm_result: Dict[str, Any]) -> Dict[str, Any]:
        decision = str(llm_result.get("decision") or "enrich").strip().lower()

        conf = llm_result.get("confidence", 0.5)
        try:
            conf = float(conf)
        except Exception:
            conf = 0.5
        conf = max(0.0, min(conf, 1.0))

        text = self._build_text(alert_data)

        rx_escalate = self._match_regex(text, self.CONFIRMED_THREAT_REGEX_ESCALATE)
        rx_webshell = self._match_regex(text, self.CONFIRMED_THREAT_REGEX_WEBSHELL)

        # If LLM says escalate but only webshell regex matched => downgrade
        if decision == "escalate" and (not rx_escalate) and rx_webshell:
            return {
                "decision": "enrich",
                "reason": "LLM suggested escalation, but evidence indicates webshell-style alert text requiring corroboration; downgraded to enrich.",
                "confidence": min(conf, 0.80),
                "match": {"type": "llm_escalate_downgraded_webshell", "value": rx_webshell}
            }

        # If LLM says escalate but no confirmed evidence => downgrade
        if decision == "escalate" and not rx_escalate and not rx_webshell:
            return {
                "decision": "enrich",
                "reason": "LLM suggested escalation, but no confirmed threat indicators passed evidence gates; downgraded to enrich.",
                "confidence": min(conf, 0.75),
                "match": {"type": "llm_escalate_downgraded_no_evidence", "value": None}
            }

        # If LLM says dismiss but regex escalation evidence exists => upgrade
        if decision == "dismiss" and rx_escalate:
            return {
                "decision": "escalate",
                "reason": "LLM suggested dismiss, but confirmed non-webshell threat indicators exist; upgraded to escalate.",
                "confidence": max(conf, 0.90),
                "match": {"type": "llm_dismiss_upgraded_confirmed", "value": rx_escalate}
            }

        # Otherwise accept LLM decision
        return {
            "decision": decision,
            "reason": str(llm_result.get("reason") or "").strip() or "LLM classification",
            "confidence": conf,
            "match": {"type": "llm", "value": None}
        }

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        if "```json" in response:
            response = response.split("```json")[1].split("```")[0]
        elif "```" in response:
            response = response.split("```")[1].split("```")[0]

        data = json.loads(response.strip())
        decision = str(data.get("decision") or "").strip().lower()
        if decision not in ["dismiss", "enrich", "escalate"]:
            raise ValueError(f"Invalid decision: {decision}")

        conf = data.get("confidence", 0.5)
        try:
            conf = float(conf)
        except Exception:
            conf = 0.5
        conf = max(0.0, min(conf, 1.0))

        return {
            "decision": decision,
            "reason": str(data.get("reason") or "").strip(),
            "confidence": conf
        }