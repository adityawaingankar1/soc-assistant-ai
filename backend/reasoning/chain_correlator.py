# backend/reasoning/chain_correlator.py
from typing import List, Dict, Optional
from backend.llm.nvidia_client import nvidia_client
from backend.llm.prompt_builder import PromptBuilder
from loguru import logger
import json


class ChainCorrelator:
    """
    Extended Thinking: Multi-Alert Attack Chain Correlation Engine
    
    Reasoning Flow:
    ──────────────────────────────────────────────────────────────
    Alert A (Port Scan)
    Alert B (Phishing Email Opened)        ←── Input
    Alert C (Lateral Movement Detected)
         │
         ▼
    [Timeline Ordering] Sort by timestamp
         │
         ▼
    [TTP Mapping] Map each alert to MITRE ATT&CK tactic
         │
         ▼
    [Sequence Analysis] Does tactic order match known kill chain?
    Recon → Initial Access → Execution → Lateral Movement?
         │
         ▼
    [LLM Deep Analysis] Multi-alert XML → LLM reasoning
         │
         ▼
    [Chain Decision] Is this one coordinated attack?
         │
         ▼
    [Unified Response] Single coordinated playbook
    ──────────────────────────────────────────────────────────────
    
    Example Pattern Recognition:
    Alert A: T1595 (Reconnaissance/Scanning)
    Alert B: T1566.001 (Phishing with Attachment)  
    Alert C: T1021 (Remote Services/Lateral Movement)
    
    → Detected Pattern: Classic APT kill chain
    → Confidence: 0.92
    → Response: Coordinated incident response
    """

    # MITRE Tactic ordering in kill chain
    TACTIC_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact"
    ]

    def __init__(self):
        self.prompt_builder = PromptBuilder()

    def correlate(self, alerts: List[Dict]) -> Dict:
        """
        Correlate multiple alerts into potential attack chains.
        """
        if len(alerts) < 2:
            return {
                "is_attack_chain": False,
                "reason": "Minimum 2 alerts required for correlation"
            }

        logger.info(f"[Correlator] Correlating {len(alerts)} alerts")

        # Step 1: Timeline ordering
        sorted_alerts = self._sort_by_time(alerts)

        # Step 2: Local heuristic analysis
        heuristic = self._heuristic_correlation(sorted_alerts)

        # Step 3: LLM deep analysis
        try:
            messages = self.prompt_builder.build_correlation_prompt(sorted_alerts)
            response = nvidia_client.chat(messages, temperature=0.05, max_tokens=2000)

            # Clean JSON from response
            if "```json" in response:
                response = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                response = response.split("```")[1].split("```")[0]

            llm_result = json.loads(response.strip())
            llm_result["heuristic_signals"] = heuristic
            llm_result["alert_count"] = len(alerts)
            return llm_result

        except Exception as e:
            logger.error(f"[Correlator] LLM analysis failed: {e}")
            return {
                "is_attack_chain": heuristic["likely_chain"],
                "chain_confidence": heuristic["confidence"],
                "heuristic_signals": heuristic,
                "note": "LLM analysis unavailable — using heuristics only"
            }

    def _sort_by_time(self, alerts: List[Dict]) -> List[Dict]:
        """Sort alerts chronologically."""
        def get_time(alert):
            return alert.get("timestamp", "")
        return sorted(alerts, key=get_time)

    def _heuristic_correlation(self, alerts: List[Dict]) -> Dict:
        """
        Fast heuristic correlation before LLM analysis.
        Detects known attack progression patterns.
        """
        mitre_techniques = []
        sources = set()
        assets = set()

        for alert in alerts:
            mitre = alert.get("mitre_mapping", "")
            if mitre:
                mitre_techniques.append(mitre)
            sources.add(alert.get("alert_source", ""))
            assets.add(alert.get("affected_asset", ""))

        # Check for multi-stage signals
        signals = {
            "multiple_sources": len(sources) > 1,
            "same_asset_targeted": len(assets) < len(alerts),
            "multiple_mitre_tactics": len(mitre_techniques) > 1,
            "high_severity_present": any(
                a.get("severity") in ["CRITICAL", "HIGH"] for a in alerts
            ),
            "time_compressed": len(alerts) > 2  # Multiple alerts in one session
        }

        signal_count = sum(signals.values())
        likely_chain = signal_count >= 3
        confidence = min(signal_count / 5 * 0.9, 0.9)

        return {
            "likely_chain": likely_chain,
            "confidence": round(confidence, 2),
            "signals": signals,
            "unique_sources": list(sources),
            "unique_assets": list(assets),
            "mitre_techniques_found": mitre_techniques
        }