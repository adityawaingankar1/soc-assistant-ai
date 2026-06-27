from __future__ import annotations

from typing import Dict, Any, List
from pathlib import Path
import json

from backend.routing.router import route_incident


class IncidentRouter:
    """
    Deterministic incident router.

    Enterprise improvements:
    - APT / espionage routing
    - FRP / Volt Typhoon persistence recognition
    - ransomware separation
    - persistence tradecraft classification
    - safer overrides
    """

    # =====================================================
    # APT / ESPIONAGE INDICATORS
    # =====================================================

    APT_PATTERNS = [

        # Generic espionage
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
        "document exfiltration",
        "research theft",
        "credential compromise",
        "stealth persistence",
        "proxy tunneling",

        # Volt Typhoon / FRP
        "volt typhoon",
        "fast reverse proxy",
        "frp",
        "frpc",
        "frps",
        "brightmetricagent",
        "smsvcservice",
        "reverse proxy",
        "traffic tunneling",
        "living off the land",

        # Persistence / credential abuse
        "ntds.dit",
        "log clearing",
        "wevtutil",
        "valid accounts",
        "rdp",
        "vpn admin creds",
        "scheduled task persistence",
    ]

    # =====================================================
    # RANSOMWARE INDICATORS
    # =====================================================

    RANSOMWARE_PATTERNS = [
        "files encrypted",
        "file encryption",
        "ransom note",
        "mass rename",
        "vssadmin delete shadows",
        "shadow copy deletion",
        "encryption detected",
        ".locked",
        ".encrypted",
        "bitcoin payment",
        "decrypt files",
        "ransom demand",
        "backup deletion",
        "recovery inhibition",
        "cipher /w",
        "wbadmin delete",
    ]

    # =====================================================
    # PERSISTENCE / TUNNELING INDICATORS
    # =====================================================

    PERSISTENCE_PATTERNS = [
        "reverse proxy",
        "frp",
        "frpc",
        "frps",
        "scheduled task",
        "service creation",
        "run key",
        "startup folder",
        "log clearing",
        "wevtutil",
        "ntds.dit",
        "credential compromise",
        "valid accounts",
        "rdp",
        "traffic tunneling",
        "portproxy",
    ]

    def __init__(
        self,
        rules_path: Path | None = None
    ):

        if rules_path is None:

            rules_path = (
                Path(__file__).resolve().parents[1]
                / "routing"
                / "router_rules.json"
            )

        self.rules_path = rules_path

        self._cache: Dict[str, Any] | None = None

        self._mtime: float | None = None

    # =====================================================
    # RULE LOADING
    # =====================================================

    def _load_rules(self) -> Dict[str, Any]:

        p = self.rules_path

        mtime = p.stat().st_mtime

        if (
            self._cache is not None
            and self._mtime == mtime
        ):
            return self._cache

        self._cache = json.loads(
            p.read_text(encoding="utf-8")
        )

        self._mtime = mtime

        return self._cache

    # =====================================================
    # HELPERS
    # =====================================================

    def _build_text(
        self,
        alert_data: Dict[str, Any]
    ) -> str:

        return " ".join(
            [
                str(alert_data.get("description", "")),
                str(alert_data.get("additional_context", "")),
                str(alert_data.get("ioc_list", "")),
                str(alert_data.get("mitre_mapping", "")),
                str(alert_data.get("alert_source", "")),
                str(alert_data.get("affected_asset", "")),
            ]
        ).lower()

    def _count_matches(
        self,
        text: str,
        patterns: List[str]
    ) -> List[str]:

        return [
            p for p in patterns
            if p in text
        ]

    # =====================================================
    # MAIN ROUTER
    # =====================================================

    def route(
        self,
        alert_data: Dict[str, Any],
        enrichment: Dict[str, Any],
        predicates: Dict[str, Any]
    ) -> Dict[str, Any]:

        text = self._build_text(alert_data)

        apt_hits = self._count_matches(
            text,
            self.APT_PATTERNS
        )

        ransomware_hits = self._count_matches(
            text,
            self.RANSOMWARE_PATTERNS
        )

        persistence_hits = self._count_matches(
            text,
            self.PERSISTENCE_PATTERNS
        )

        # =================================================
        # APT / ESPIONAGE PRIORITY
        # =================================================

        # Strong Volt Typhoon / FRP persistence
        # should NEVER become generic INVESTIGATE.
        if len(apt_hits) >= 2:

            return {
                "incident_type": "APT_ESPIONAGE",

                "playbook_family": "APT_ESPIONAGE",

                "rule_id": "apt_espionage",

                "rule_priority": 120,

                "routing_reason": (
                    "Detected espionage / "
                    "nation-state tradecraft indicators"
                ),

                "matched_indicators": apt_hits[:10],
            }

        # =================================================
        # PERSISTENCE / TUNNELING
        # =================================================

        if len(persistence_hits) >= 2:

            return {
                "incident_type": "APT_PERSISTENCE",

                "playbook_family": "APT_PERSISTENCE",

                "rule_id": "apt_persistence",

                "rule_priority": 110,

                "routing_reason": (
                    "Persistence / tunneling "
                    "tradecraft detected"
                ),

                "matched_indicators": persistence_hits[:10],
            }

        # =================================================
        # RANSOMWARE
        # =================================================

        # Require stronger evidence before ransomware.
        if len(ransomware_hits) >= 2:

            return {
                "incident_type": "RANSOMWARE",

                "playbook_family": "RANSOMWARE",

                "rule_id": "ransomware",

                "rule_priority": 100,

                "routing_reason": (
                    "Confirmed ransomware "
                    "behavioral indicators"
                ),

                "matched_indicators": ransomware_hits[:10],
            }
            
        if predicates.get("apt_tradecraft"):
            return {
                "incident_type": "APT_ESPIONAGE",
                "playbook_family": "APT_ESPIONAGE",
                "rule_id": "apt_tradecraft",
                "rule_priority": 130,
                "routing_reason": (
                    "APT tradecraft predicates detected"
                ),
            }
            
        if predicates.get("has_persistence_tradecraft"):
            return {
                "incident_type": "APT_PERSISTENCE",
                "playbook_family": "APT_PERSISTENCE",
                "rule_id": "apt_persistence",
                "rule_priority": 125,
                "routing_reason": (
                    "Persistence tradecraft detected"
                ),
            }
        # =================================================
        # FALLBACK TO EXISTING RULE ENGINE
        # =================================================

        rules = self._load_rules()

        routed = route_incident(
            rules,
            predicates
        )

        # =================================================
        # SAFETY OVERRIDES
        # =================================================

        # Prevent espionage from becoming ransomware.
        if (
            routed.get("incident_type") == "RANSOMWARE"
            and len(apt_hits) >= 1
            and len(ransomware_hits) < 2
        ):

            routed["incident_type"] = "APT_ESPIONAGE"

            routed["playbook_family"] = "APT_ESPIONAGE"

            routed["routing_reason"] = (
                "Ransomware classification overridden "
                "by espionage tradecraft indicators"
            )

            routed["matched_indicators"] = apt_hits[:10]

        # Prevent persistence tooling from becoming generic investigate.
        if (
            routed.get("incident_type") == "INVESTIGATE"
            and len(persistence_hits) >= 2
        ):

            routed["incident_type"] = "APT_PERSISTENCE"

            routed["playbook_family"] = "APT_PERSISTENCE"

            routed["routing_reason"] = (
                "Generic investigation upgraded "
                "to persistence tradecraft classification"
            )

            routed["matched_indicators"] = persistence_hits[:10]

        return routed