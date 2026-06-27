from __future__ import annotations

from typing import Dict, Any, List, Tuple
import re


class ConfidenceScorer:
    """
    Confidence scorer (production-v4).

    Fixes the mismatch observed in your PDF:
    - Ransomware with explicit impact artifacts (mass encryption, VSS deletion, service stop)
      must NOT score ~27% purely because SIEM linkage is weak.

    Approach:
    - Keep weighted formula
    - Derive/boost artifact/exploit-context from alert narrative + MITRE + predicates
    - Corroboration reflects linkage quality; it should not collapse the whole confidence
    """

    PLAYBOOK_FLOORS = {
        "RANSOMWARE": 0.80,
        "EDGE_EXPLOIT": 0.65,
        "WEBAPP_EXPLOIT": 0.60,
        "IDENTITY_COMPROMISE": 0.55,
        "INVESTIGATE": 0.30,
    }

    DESTRUCTIVE_MITRE = {"T1486", "T1490", "T1489", "T1070.004", "T1565"}

    RANSOMWARE_ARTIFACT_PATTERNS: List[Tuple[str, float]] = [
        (r"\bmass file encryption\b", 0.95),
        (r"\bencrypt(ed|ion)\b", 0.90),
        (r"\bransom(note)?\b", 0.85),
        (r"\bshadow copies\b|\bvss\b|\bvssadmin\b", 0.85),
        (r"\bdelete(d)?\b.*\bshadow\b|\bdelete(d)?\b.*\bvss\b", 0.90),
        (r"\bservice(s)?\b.*\b(stop(ped)?|terminated|disabled)\b", 0.70),
        (r"\bextensions?\b.*\bchanged\b", 0.70),
        (r"\b\.interlock\b", 0.95),
        (r"\binhibit system recovery\b", 0.80),
        (r"\bbackup\b.*\b(stop(ped)?|disabled|killed)\b", 0.80),
        (r"\blateral movement\b", 0.60),
        (r"\bSMB\b", 0.55),
    ]

    def score(
        self,
        components: Dict[str, float],
        penalties: Dict[str, float],
        context: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        context = context or {}
        predicates = context.get("predicates", {}) or {}
        evidence = context.get("evidence_summary", {}) or {}

        incident_type = (context.get("incident_type") or "INVESTIGATE").strip().upper()
        mitre_mapping = (
            (context.get("mitre_mapping") or "")
            or (context.get("normalized_alert", {}) or {}).get("mitre_mapping", "")
            or ""
        )

        alert_text = " ".join(
            [
                str(context.get("alert_description") or ""),
                str(context.get("Alert Description") or ""),
                str(context.get("additional_context") or ""),
                str(context.get("Additional Context") or ""),
                str(context.get("normalized_alert", {}) or {}),
            ]
        ).strip()

        def clamp(x: float) -> float:
            return max(0.0, min(float(x), 1.0))

        # Defaults; allow overrides but avoid "0.0 locks it down forever"
        # by later deriving boosts from context.
        S_artifact = clamp(components.get("S_artifact", 0.55))
        S_exploit_context = clamp(components.get("S_exploit_context", 0.50))
        S_corroboration = clamp(components.get("S_corroboration", 0.35))
        S_exposure = clamp(components.get("S_exposure", 0.70))
        S_asset_criticality = clamp(components.get("S_asset_criticality", 0.80))
        S_ti = clamp(components.get("S_ti", 0.50))

        derived_reasons: List[str] = []

        # Ransomware boosts (from narrative/predicates/MITRE)
        ransomware_mode = (
            incident_type == "RANSOMWARE"
            or predicates.get("ransomware_signals") is True
            or ("T1486" in mitre_mapping)
        )
        if ransomware_mode:
            if alert_text:
                best = 0.0
                for pat, score in self.RANSOMWARE_ARTIFACT_PATTERNS:
                    if re.search(pat, alert_text, flags=re.IGNORECASE):
                        best = max(best, score)
                if best > 0:
                    S_artifact = max(S_artifact, best)
                    derived_reasons.append(f"S_artifact boosted by alert narrative patterns to {round(S_artifact, 2)}")

            if any(t in mitre_mapping for t in self.DESTRUCTIVE_MITRE):
                S_exploit_context = max(S_exploit_context, 0.90)
                derived_reasons.append("S_exploit_context boosted by destructive MITRE mapping")

            if predicates.get("ransomware_signals", False):
                S_artifact = max(S_artifact, 0.95)
                S_exploit_context = max(S_exploit_context, 0.92)
                derived_reasons.append("Boosted by predicates.ransomware_signals")

        # Corroboration: linked signals > unlinked > none
        unlinked = evidence.get("unlinked_environment_signals", []) or []
        linked = evidence.get("linked_signals", []) or []

        if linked:
            S_corroboration = max(S_corroboration, 0.75)
            derived_reasons.append("S_corroboration boosted by linked signals")
        elif unlinked:
            if len(unlinked) >= 4:
                S_corroboration = max(S_corroboration, 0.65)
                derived_reasons.append("S_corroboration boosted by multiple unlinked environment signals")
            else:
                S_corroboration = max(S_corroboration, 0.50)
                derived_reasons.append("S_corroboration boosted by some unlinked environment signals")

        # Exposure: unknown is risky
        if predicates.get("internet_facing_yes_or_unknown", True):
            S_exposure = max(S_exposure, 0.85)

        # Asset tier
        risk_tier = (context.get("asset_risk_tier") or context.get("risk_tier") or "").upper()
        if risk_tier in ("CRITICAL", "HIGH"):
            S_asset_criticality = 1.0

        # TI: compute from enriched_iocs if present
        enriched_iocs = context.get("enriched_iocs", []) or context.get("ioc_enrichment", []) or []
        if enriched_iocs:
            malicious_count = sum(1 for i in enriched_iocs if i.get("malicious") is True)
            total = max(len(enriched_iocs), 1)
            S_ti = clamp(0.35 + 0.65 * (malicious_count / total))
            derived_reasons.append(f"S_ti derived from enrichment malicious_rate={malicious_count}/{total}")

        # Penalties
        P_benign_change = clamp(penalties.get("P_benign_change", 0.0))
        P_data_quality = clamp(penalties.get("P_data_quality", 0.0))

        # Weighted formula (same structure as your PDF)
        raw = (
            0.28 * S_artifact
            + 0.22 * S_exploit_context
            + 0.18 * S_corroboration
            + 0.12 * S_exposure
            + 0.12 * S_asset_criticality
            + 0.08 * S_ti
            - 0.20 * P_benign_change
            - 0.10 * P_data_quality
        )

        final_0_1 = clamp(raw)

        floor = self.PLAYBOOK_FLOORS.get(incident_type, self.PLAYBOOK_FLOORS["INVESTIGATE"])
        final_0_1 = max(final_0_1, floor)

        confidence_percent = int(round(final_0_1 * 100))

        return {
            "confidence_final": round(final_0_1, 3),
            "confidence_percent": confidence_percent,
            "components": {
                "S_artifact": round(S_artifact, 3),
                "S_exploit_context": round(S_exploit_context, 3),
                "S_corroboration": round(S_corroboration, 3),
                "S_exposure": round(S_exposure, 3),
                "S_asset_criticality": round(S_asset_criticality, 3),
                "S_ti": round(S_ti, 3),
            },
            "penalties": {
                "P_benign_change": round(P_benign_change, 3),
                "P_data_quality": round(P_data_quality, 3),
            },
            "incident_type": incident_type,
            "mitre_mapping": mitre_mapping,
            "version": "production-v4",
            "derived_reasons": derived_reasons,
            "note": "Incident confidence derived from impact artifacts + MITRE; linkage quality is reflected via corroboration.",
        }