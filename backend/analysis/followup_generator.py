from __future__ import annotations

from typing import Dict, Any, List, Tuple


def _dedupe_append(out: List[str], seen_lower: set, s: str) -> None:
    s = (s or "").strip()
    if not s:
        return
    k = s.lower()
    if k in seen_lower:
        return
    seen_lower.add(k)
    out.append(s)


def _take_n(items: List[str], n: int, out: List[str], seen_lower: set) -> None:
    for s in items:
        if len(out) >= n:
            return
        _dedupe_append(out, seen_lower, s)


def generate_followups(
    incident_type: str,
    predicates: Dict[str, Any],
    enrichment: Dict[str, Any],
    evidence_summary: Dict[str, Any],
) -> List[str]:
    """
    Deterministic, incident-aware follow-ups (no LLM).

    Requirement (per your request):
    - If incident_type == RANSOMWARE: ALWAYS include 2 ransomware-specific questions.

    Returns up to 3 questions total.
    """
    it = (incident_type or "INVESTIGATE").upper().strip()

    out: List[str] = []
    seen_lower: set = set()

    siem = enrichment.get("siem_context", {}) or {}
    linked_total = int((((siem.get("linked") or {}).get("total_events")) or 0))

    # --------------------------
    # Build prioritized global gaps (most important first)
    # --------------------------
    global_qs: List[str] = []

    if not predicates.get("has_any_enforceable_iocs"):
        global_qs.append(
            "Can we extract enforceable IOCs (source IPs, domains, URLs, hashes) from primary logs for this alert (WAF/IIS/EDR/Syslog) and add them to the case?"
        )

    if linked_total < 1:
        global_qs.append(
            "Why couldn’t SIEM events be linked to this alert scope—do we have the right join keys (hostname aliases, IPs, time window), and can we safely widen scope?"
        )

    if predicates.get("internet_facing_true_or_unknown"):
        global_qs.append(
            "Can we confirm exposure (internet/partner-facing) via VIP/NAT/WAF/DNS and identify all inbound paths to the affected service?"
        )

    # --------------------------
    # Incident-specific question banks
    # --------------------------
    ransomware_qs: List[str] = [
        "Do endpoint/process logs show ransomware prep activity (shadow copy deletion, backup deletion attempts, mass rename) tied to the affected asset?",
        "What is the earliest impacted host (patient zero), and are there lateral movement indicators connecting affected systems?",
        "Are backups intact and clean, and can we validate restore points after containment without reinfection?",
    ]

    webapp_qs: List[str] = [
        "Do we have on-host confirmation for the suspected webshell path(s) (file exists, timestamps, hash, owner) and any IIS execution traces for that path?",
        "Do WAF/IIS logs show the exploitation request sequence tied to a specific client IP or session (URI, headers, status codes)?",
        "Are there suspicious outbound transfers or unusual application transfer activity correlated to the suspected exploitation window (destinations, volume, new users)?",
    ]

    edge_qs: List[str] = [
        "Do edge device logs show admin logins or configuration commits from unusual IPs/users during the alert window?",
        "Can we confirm firmware/version and whether the suspected CVE/KEV applies to this model/version?",
        "Is the management plane exposed externally, and do we have a validated allowlist/MFA control for it?",
    ]

    identity_qs: List[str] = [
        "Which account(s) are implicated, and do sign-in logs show risky sign-ins (impossible travel, unfamiliar device/IP, legacy auth) during the window?",
        "Are there OAuth grants/app consents, mailbox rules, forwarding, or admin role changes correlating to the suspected compromise?",
        "Do we have corroboration from Entra/M365 audit logs that actions occurred from the same IP/device that triggered the alert?",
    ]

    investigate_qs: List[str] = [
        "What independent telemetry source can confirm or refute the alert (WAF/IIS vs EDR vs IAM vs firewall)?",
        "Are there related alerts/incidents affecting the same asset/user in the past 24–72 hours that change confidence?",
        "Do we have asset ownership/criticality and EDR availability to determine feasible containment actions?",
    ]

    # --------------------------
    # Assembly rules
    # --------------------------
    if it == "RANSOMWARE":
        # Always include 2 ransomware-specific questions
        _take_n(ransomware_qs, 2, out, seen_lower)

        # Fill the remaining slot (3rd) with highest-priority global gap if any,
        # else the remaining ransomware question, else a generic investigate question.
        if len(out) < 3:
            if global_qs:
                _take_n(global_qs, 3, out, seen_lower)
            else:
                # take the remaining ransomware question (3rd)
                _take_n(ransomware_qs, 3, out, seen_lower)

        if len(out) < 3:
            _take_n(investigate_qs, 3, out, seen_lower)

        return out[:3]

    # Non-ransomware behavior: keep previous spirit (global gaps first, then incident-specific)
    # Add globals
    _take_n(global_qs, 3, out, seen_lower)

    # Add incident-specific
    if it == "WEBAPP_EXPLOIT":
        _take_n(webapp_qs, 3, out, seen_lower)
    elif it == "EDGE_EXPLOIT":
        _take_n(edge_qs, 3, out, seen_lower)
    elif it == "IDENTITY_COMPROMISE":
        _take_n(identity_qs, 3, out, seen_lower)
    else:
        _take_n(investigate_qs, 3, out, seen_lower)

    return out[:3]