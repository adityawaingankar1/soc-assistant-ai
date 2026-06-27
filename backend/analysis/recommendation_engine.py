from typing import Dict, Any, List

from backend.analysis.playbook_store import PlaybookStore
from backend.analysis.gating import GatingEngine


class RecommendationEngine:

    """
    Enterprise-grade recommendation engine.

    Improvements:
    - APT / persistence-specific recommendations
    - safer action gating
    - incident-aware recommendations
    - FRP / Volt Typhoon handling
    - credential abuse handling
    """

    def __init__(
        self,
        store: PlaybookStore | None = None
    ):

        self.store = store or PlaybookStore()

        self.gating = GatingEngine()

    # =====================================================
    # MAIN ENGINE
    # =====================================================

    def recommend(
        self,
        incident_type: str,
        predicates: Dict[str, Any],
        max_actions: int = 9
    ) -> Dict[str, Any]:

        max_actions = max(
            1,
            min(int(max_actions or 9), 9)
        )

        pb = (
            self.store.get(incident_type)
            or self.store.get("INVESTIGATE")
            or {
                "actions": [],
                "version": 0
            }
        )

        actions = pb.get("actions") or []

        gated = self.gating.filter_actions(
            actions,
            predicates
        )

        safe: List[Dict[str, Any]] = []

        flags: List[str] = []

        seen_ids = set()

        # =================================================
        # PLAYBOOK ACTIONS
        # =================================================

        for a in gated:

            if not isinstance(a, dict):
                continue

            aid = str(
                a.get("id") or ""
            ).strip()

            if aid and aid in seen_ids:
                continue

            if aid:
                seen_ids.add(aid)

            text = str(
                a.get("action") or ""
            )

            lower = text.lower()

            # ---------------------------------------------
            # IOC GATING
            # ---------------------------------------------

            if (
                "block" in lower
                and not predicates.get(
                    "has_any_enforceable_iocs"
                )
            ):

                flags.append(
                    "Removed non-actionable block "
                    "action: no enforceable IOCs."
                )

                continue

            # ---------------------------------------------
            # ISOLATION GATING
            # ---------------------------------------------

            if (
                "isolate" in lower
                and "edr" in lower
            ):

                if not predicates.get(
                    "asset_class_endpoint_or_server"
                ):

                    flags.append(
                        "Removed infeasible isolate "
                        "action: unsupported asset type."
                    )

                    continue

                if not predicates.get(
                    "edr_available"
                ):

                    flags.append(
                        "Removed infeasible isolate "
                        "action: EDR unavailable."
                    )

                    continue

            safe.append(a)

            if len(safe) >= max_actions:
                break

        # =================================================
        # DYNAMIC APT / PERSISTENCE RECOMMENDATIONS
        # =================================================

        dynamic_actions: List[Dict[str, Any]] = []

        # -------------------------------------------------
        # APT / ESPIONAGE
        # -------------------------------------------------

        if predicates.get("apt_tradecraft"):

            dynamic_actions.extend([

                {
                    "id": "apt_scope_expansion",

                    "action": (
                        "Expand scope across adjacent "
                        "systems, privileged accounts, "
                        "VPN activity, and authentication "
                        "telemetry for potential "
                        "nation-state lateral movement."
                    ),

                    "owner_team": "SOC",

                    "approval_level": "IR Lead",

                    "risk": "Medium",
                },

                {
                    "id": "apt_memory_acquisition",

                    "action": (
                        "Acquire volatile memory and "
                        "collect persistence artifacts "
                        "before remediation."
                    ),

                    "owner_team": "DFIR",

                    "approval_level": "IR Lead",

                    "risk": "Medium",
                },
            ])

        # -------------------------------------------------
        # PERSISTENCE TRADECRAFT
        # -------------------------------------------------

        if predicates.get(
            "has_persistence_tradecraft"
        ):

            dynamic_actions.extend([

                {
                    "id": "persist_hunt_tasks",

                    "action": (
                        "Hunt for persistence "
                        "mechanisms including "
                        "scheduled tasks, services, "
                        "startup items, Run keys, "
                        "and port proxy configuration."
                    ),

                    "owner_team": "SOC",

                    "approval_level": "SOC",

                    "risk": "Low",
                },

                {
                    "id": "persist_service_review",

                    "action": (
                        "Review newly created or "
                        "modified Windows services "
                        "and unsigned binaries."
                    ),

                    "owner_team": "SOC",

                    "approval_level": "SOC",

                    "risk": "Low",
                },
            ])

        # -------------------------------------------------
        # TUNNELING / FRP
        # -------------------------------------------------

        if predicates.get(
            "has_tunneling_behavior"
        ):

            dynamic_actions.extend([

                {
                    "id": "frp_network_hunt",

                    "action": (
                        "Investigate reverse proxy / "
                        "tunneling behavior including "
                        "FRP clients, SSH reverse "
                        "tunnels, and port proxy usage."
                    ),

                    "owner_team": "Network Security",

                    "approval_level": "SOC",

                    "risk": "Medium",
                },

                {
                    "id": "frp_egress_review",

                    "action": (
                        "Review outbound encrypted "
                        "traffic and long-lived "
                        "connections for stealth "
                        "tunneling indicators."
                    ),

                    "owner_team": "Network Security",

                    "approval_level": "SOC",

                    "risk": "Low",
                },
            ])

        # -------------------------------------------------
        # CREDENTIAL ABUSE
        # -------------------------------------------------

        if predicates.get(
            "has_credential_abuse"
        ):

            dynamic_actions.extend([

                {
                    "id": "cred_review",

                    "action": (
                        "Review privileged account "
                        "usage, RDP logons, NTDS "
                        "access attempts, and VPN "
                        "authentication anomalies."
                    ),

                    "owner_team": "IAM",

                    "approval_level": "IR Lead",

                    "risk": "Medium",
                },

                {
                    "id": "cred_rotation",

                    "action": (
                        "Prepare staged credential "
                        "rotation for impacted "
                        "administrative accounts."
                    ),

                    "owner_team": "IAM",

                    "approval_level": "IR Lead",

                    "risk": "High",
                },
            ])

        # -------------------------------------------------
        # HASH MATCHES
        # -------------------------------------------------

        if predicates.get(
            "has_advisory_hash_match"
        ):

            dynamic_actions.append({

                "id": "hash_hunt",

                "action": (
                    "Hunt for matching advisory "
                    "hashes across endpoints, "
                    "servers, EDR telemetry, "
                    "and historical logs."
                ),

                "owner_team": "Threat Hunting",

                "approval_level": "SOC",

                "risk": "Low",
            })

        # =================================================
        # MERGE DYNAMIC ACTIONS
        # =================================================

        for d in dynamic_actions:

            did = str(
                d.get("id") or ""
            ).strip()

            if did and did not in seen_ids:

                safe.append(d)

                seen_ids.add(did)

            if len(safe) >= max_actions:
                break

        # =================================================
        # FALLBACK
        # =================================================

        if not safe:

            safe = (
                self.store.get("INVESTIGATE")
                or {"actions": []}
            ).get("actions", [])[:max_actions]

        return {
            "actions": safe[:max_actions],

            "action_flags": flags,

            "playbook_version": pb.get("version"),
        }