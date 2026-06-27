from __future__ import annotations
from typing import Dict, Any, List


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items or []:
        x = str(x or "").strip()
        if not x:
            continue
        k = x.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


SAFE_MIN_ACTIONS_BY_INCIDENT: Dict[str, List[str]] = {
    "WEBAPP_EXPLOIT": [
        "Preserve evidence: collect IIS/WAF/app logs + snapshot relevant directories/config before changes.",
        "Validate exposure: confirm if service is internet/partner-facing (VIP/NAT/WAF/DNS), and identify all ingress paths.",
        "Contain service: restrict inbound access (allowlist/maintenance mode) or take service offline to stop exploitation (business-approved).",
        "Patch/upgrade per vendor guidance and validate fixed version; confirm mitigations effective.",
        "Hunt for post-exploitation artifacts and validate integrity (webroots, configs, scheduled tasks, service accounts).",
    ],
    "EDGE_EXPLOIT": [
        "Preserve evidence: export device logs (admin auth, config changes) and current config before changes.",
        "Validate exposure: confirm if management plane is internet/partner-facing; enumerate ingress paths.",
        "Restrict management-plane access to allowlisted IPs only; enforce MFA if supported.",
        "Apply vendor mitigations/hotfix and validate version; check for persistence/config tampering.",
        "Review admin accounts and recent configuration changes for unauthorized actions.",
    ],
    "IDENTITY_COMPROMISE": [
        "Preserve evidence: export sign-in logs, risky sign-ins, audit logs, and mailbox/app consent changes.",
        "Review recent sign-ins for anomalies (impossible travel, unfamiliar IPs/devices, legacy auth).",
        "Revoke sessions/refresh tokens for suspected accounts if confidence is high enough and business-approved.",
        "Reset credentials and verify MFA/Conditional Access posture for affected identities.",
        "Hunt for persistence via OAuth app consent, mailbox rules, and privileged role changes.",
    ],
    "RANSOMWARE": [
        "Preserve evidence: memory (if feasible), host artifacts, and SIEM telemetry before remediation.",
        "Isolate affected endpoints/servers via EDR or network controls to stop spread (business-approved).",
        "Identify patient-zero and lateral movement paths; scope impacted assets/accounts.",
        "Block/contain observed IOCs where enforceable (IPs/domains/hashes) and disable suspected compromised accounts.",
        "Restore from known-good backups only after containment + eradication; verify backups are clean.",
    ],
    "INVESTIGATE": [
        "Collect additional telemetry (SIEM + host/network/IAM as applicable) to confirm or refute compromise.",
        "Validate alert scope and linkage keys (host/ip/time); expand scope safely if needed.",
        "Identify whether the asset is internet/partner-facing and its business criticality.",
        "Search for related alerts/incidents on the same asset/user in the last 24–72 hours.",
        "Extract enforceable IOCs (ip/domain/url/hash) from primary logs and add to the case.",
    ],
}


DEFAULT_FOLLOWUPS = [
    "Do we have corroborating logs from an independent source (WAF/IIS/EDR/IAM)?",
    "What’s the exposure posture of the affected service (internet/partner-facing)?",
    "Are there related alerts on the same asset/user in the last 24–72 hours?",
]


def ensure_complete_result(
    result: Dict[str, Any],
    *,
    incident_type: str,
    alert_source: str,
    affected_asset: str,
    confidence_percent: int,
    linked_signal_count: int,
    evidence_summary: Dict[str, Any],
) -> Dict[str, Any]:
    incident_type = (incident_type or "INVESTIGATE").upper().strip()

    # Explanation fallback
    explanation = str(result.get("explanation") or "").strip()
    if not explanation:
        key_evidence = (evidence_summary or {}).get("key_evidence") or []
        gaps = (evidence_summary or {}).get("gaps") or []
        bullets = "\n".join([f"- {x}" for x in key_evidence[:3]]) or "- (insufficient structured evidence captured)"
        main_gap = gaps[0] if gaps else "Insufficient corroboration in linked telemetry; validate linkage keys and logging coverage."
        result["explanation"] = (
            "## Incident Update\n\n"
            f"Assessment for `{incident_type}` affecting `{affected_asset}` from `{alert_source}`. "
            f"Confidence: `{int(confidence_percent)}%`.\n\n"
            "## Key Evidence (Scoped)\n"
            f"{bullets}\n\n"
            "## Main Uncertainty/Gap\n"
            f"{main_gap}\n"
        )

    # Recommended actions: ensure minimum safe set
    actions = result.get("recommended_actions") or []
    if not isinstance(actions, list):
        actions = [str(actions)]
    actions = _dedupe_keep_order([str(a) for a in actions])

    min_actions = SAFE_MIN_ACTIONS_BY_INCIDENT.get(incident_type, SAFE_MIN_ACTIONS_BY_INCIDENT["INVESTIGATE"])
    if len(actions) < 5:
        actions = _dedupe_keep_order(actions + min_actions)

    result["recommended_actions"] = actions[:9]

    # Follow-ups: only fill if missing/short
    fu = result.get("follow_up_questions") or []
    if not isinstance(fu, list):
        fu = [str(fu)]
    fu = _dedupe_keep_order([str(x) for x in fu])
    if len(fu) < 3:
        fu = _dedupe_keep_order(fu + DEFAULT_FOLLOWUPS)

    result["follow_up_questions"] = fu[:3]
    return result