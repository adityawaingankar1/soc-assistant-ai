import asyncio
import re
from typing import Dict, List
from loguru import logger


class HistoryAgent:
    """Historical incident context agent."""

    INCIDENT_HISTORY = [
        {
            "incident_id": "INC-2024-001",
            "date": "2024-10-15",
            "alert_source": "EDR",
            "attack_type": "Phishing → Credential Theft",
            "mitre": "T1566.001 → T1078",
            "outcome": "Contained",
            "affected_assets": ["WS-001", "WS-002"],
            "resolution_time_hours": 4,
            "lessons_learned": "Enable MFA on all finance accounts"
        },
        {
            "incident_id": "INC-2024-002",
            "date": "2024-11-20",
            "alert_source": "SIEM",
            "attack_type": "Brute Force → Lateral Movement",
            "mitre": "T1110 → T1021",
            "outcome": "Full Incident",
            "affected_assets": ["SRV-DB-01"],
            "resolution_time_hours": 18,
            "lessons_learned": "Network segmentation between finance and DB zones needed"
        },
        {
            "incident_id": "INC-2025-003",
            "date": "2025-03-08",
            "alert_source": "SIEM",
            "attack_type": "SMB Lateral Movement → Ransomware",
            "mitre": "T1021.002 → T1486 → T1490",
            "outcome": "Full Incident",
            "affected_assets": ["SRV-DC-01", "SRV-DB-01"],
            "resolution_time_hours": 36,
            "lessons_learned": "Restrict SMB admin shares, protect backups, and monitor shadow copy deletion"
        }
    ]

    async def get_context(self, alert_data: Dict) -> Dict:
        """Retrieve historical context relevant to the current alert."""
        await asyncio.sleep(0.1)

        source = str(alert_data.get("alert_source", "") or "").lower()
        asset = str(alert_data.get("affected_asset", "") or "").lower()
        mitre_raw = str(alert_data.get("mitre_mapping", "") or "").lower()
        description = str(alert_data.get("description", "") or "").lower()
        additional_context = str(alert_data.get("additional_context", "") or "").lower()

        current_mitre = self._extract_mitre_ids(mitre_raw)
        ransomware_chain_indicators = self._detect_ransomware_chain_indicators(description, additional_context)

        relevant = []
        for incident in self.INCIDENT_HISTORY:
            score = 0
            incident_mitre = self._extract_mitre_ids(incident.get("mitre", ""))

            if source and source in incident["alert_source"].lower():
                score += 2

            if any(a.lower() in asset or asset in a.lower() for a in incident["affected_assets"]):
                score += 3

            overlap = self._calculate_mitre_overlap(incident_mitre, current_mitre)
            if overlap:
                score += min(len(overlap) * 3, 6)

            attack_type = incident.get("attack_type", "").lower()
            if "ransomware" in description and "ransomware" in attack_type:
                score += 3

            if ransomware_chain_indicators["likely_pre_ransomware_chain"] and (
                "lateral movement" in attack_type or "smb" in attack_type
            ):
                score += 2

            # If same general infra/server family keeps appearing, give recurrence boost
            if self._asset_family_match(asset, incident.get("affected_assets", [])):
                score += 1

            if score > 0:
                relevant.append({
                    **incident,
                    "relevance_score": score,
                    "mitre_overlap": overlap,
                    "chain_similarity": ransomware_chain_indicators["likely_pre_ransomware_chain"]
                })

        relevant.sort(key=lambda x: x["relevance_score"], reverse=True)
        similar_incidents = relevant[:3]

        matched = len(similar_incidents) > 0 and similar_incidents[0]["relevance_score"] >= 5
        target_resolution_hours = min(
            [inc.get("resolution_time_hours", 24) for inc in similar_incidents],
            default=24
        )

        recurring_target = (
            any(asset in str(inc.get("affected_assets", [])).lower() for inc in similar_incidents)
            or self._recurring_family_target(asset, similar_incidents)
        )

        logger.info(f"[History] Found {len(similar_incidents)} similar past incidents")

        return {
            "matched": matched,
            "similar_incidents_found": len(similar_incidents),
            "similar_incidents": similar_incidents,
            "recurring_target": recurring_target,
            "mitre_overlap_detected": any(inc.get("mitre_overlap") for inc in similar_incidents),
            "pre_ransomware_chain_detected": ransomware_chain_indicators["likely_pre_ransomware_chain"],
            "target_resolution_hours": target_resolution_hours,
            "resolution_benchmark_hours": target_resolution_hours,
            "recommendation": (
                "Historical incidents show overlapping ransomware/lateral movement patterns — prioritize containment, scope expansion, and accelerated recovery planning"
                if similar_incidents else
                "No historical precedent found"
            )
        }

    def _extract_mitre_ids(self, text: str) -> List[str]:
        return re.findall(r't\d{4}(?:\.\d{3})?', (text or "").lower())

    def _calculate_mitre_overlap(self, historical_mitre: List[str], current_mitre: List[str]) -> List[str]:
        """
        Matches MITRE techniques including parent-child relationships.
        Example: T1021 matches T1021.002
        """
        overlaps = []
        for hist in historical_mitre:
            for curr in current_mitre:
                hist_base = hist.split('.')[0].lower()
                curr_base = curr.split('.')[0].lower()
                if hist.lower() == curr.lower() or hist_base == curr_base:
                    if hist not in overlaps:
                        overlaps.append(hist)
                    break
        return overlaps

    def _detect_ransomware_chain_indicators(self, description: str, context: str) -> Dict:
        text = f"{description} {context}".lower()
        score = 0
        indicators = []

        patterns = [
            ("smb", 2),
            ("lateral movement", 2),
            ("rdp", 1),
            ("shared drive", 1),
            ("shadow copies", 2),
            ("vss", 2),
            ("backup services", 2),
            ("encryption", 3),
            ("encrypted", 3)
        ]

        for phrase, weight in patterns:
            if phrase in text:
                indicators.append(phrase)
                score += weight

        return {
            "likely_pre_ransomware_chain": score >= 5,
            "score": score,
            "signals": indicators
        }

    def _asset_family_match(self, asset: str, affected_assets: List[str]) -> bool:
        """
        Basic family-level recurrence:
        STP-CITYNET-SRV01 should still count as server-family recurrence
        against historical SRV-* style incidents.
        """
        asset_lower = (asset or "").lower()
        if not asset_lower:
            return False

        keywords = []
        if "srv" in asset_lower or "server" in asset_lower:
            keywords.append("srv")
            keywords.append("server")
        if "db" in asset_lower or "database" in asset_lower:
            keywords.append("db")
        if "dc" in asset_lower or "domain" in asset_lower:
            keywords.append("dc")

        hist_blob = " ".join([str(a).lower() for a in affected_assets])

        return any(k in hist_blob for k in keywords)

    def _recurring_family_target(self, asset: str, incidents: List[Dict]) -> bool:
        count = 0
        for inc in incidents:
            if self._asset_family_match(asset, inc.get("affected_assets", [])):
                count += 1
        return count >= 1