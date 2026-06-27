from typing import Dict, Any, List


PLAYBOOKS: Dict[str, List[Dict[str, Any]]] = {
    # WEBAPP exploitation (e.g., MOVEit-style)
    "WEBAPP_EXPLOIT": [
        {
            "id": "web_preserve",
            "action": "Preserve evidence: collect IIS/WAF/app logs + snapshot relevant directories/config before changes.",
            "owner_team": "SOC",
            "approval_level": "SOC",
            "risk": "Low",
            "requires_all": [],
        },
        {
            "id": "web_contain_inbound",
            "action": "Contain service: temporarily restrict inbound access (allowlist/maintenance mode) or take service offline to stop exploitation.",
            "owner_team": "NetOps",
            "approval_level": "SOC Lead",
            "risk": "Medium/High (service disruption)",
            "requires_all": ["confidence_ge_0_8"],
        },
        {
            "id": "web_patch",
            "action": "Patch/upgrade per vendor guidance and validate fixed version; confirm mitigations effective.",
            "owner_team": "AppOps",
            "approval_level": "Change Mgmt",
            "risk": "Medium",
            "requires_all": ["has_cves"],
        },
        {
            "id": "web_artifacts",
            "action": "Hunt for post-exploitation artifacts (unexpected .aspx in webroot like `human2.aspx`, suspicious headers like `X-siLock-*`).",
            "owner_team": "SOC",
            "approval_level": "SOC",
            "risk": "Low",
            "requires_all": ["web_artifact_possible"],
        },
        {
            "id": "web_exfil_review",
            "action": "Review outbound transfers and potential data theft indicators; scope impacted users/partners.",
            "owner_team": "IR",
            "approval_level": "IR Lead",
            "risk": "Medium",
            "requires_all": ["confidence_ge_0_55"],
        },
        {
            "id": "web_rotate_secrets",
            "action": "Rotate application/service credentials and API keys if compromise is probable/confirmed.",
            "owner_team": "IAM",
            "approval_level": "IR Lead",
            "risk": "Medium",
            "requires_all": ["confidence_ge_0_8"],
        },
        {
            "id": "block_iocs",
            "action": "Block confirmed relevant IOCs at WAF/proxy/firewall/EDR after validating linkage to this incident.",
            "owner_team": "NetOps",
            "approval_level": "SOC Lead",
            "risk": "Medium (false block risk)",
            "requires_all": ["has_any_enforceable_iocs"],
        },
    ],

    "EDGE_EXPLOIT": [
        {
            "id": "edge_preserve",
            "action": "Preserve evidence: export device logs (admin auth, config changes) and current config before changes.",
            "owner_team": "NetOps",
            "approval_level": "SOC",
            "risk": "Low",
            "requires_all": [],
        },
        {
            "id": "edge_restrict_mgmt",
            "action": "Restrict management-plane access to allowlisted IPs only; enforce MFA if supported.",
            "owner_team": "NetOps",
            "approval_level": "SOC Lead",
            "risk": "Medium",
            "requires_all": ["internet_facing_yes_or_unknown"],
        },
        {
            "id": "edge_patch",
            "action": "Apply vendor mitigations/hotfix and validate version; check for persistence/config tampering.",
            "owner_team": "NetOps",
            "approval_level": "Change Mgmt",
            "risk": "Medium",
            "requires_all": ["high_risk_cve"],
        },
        {
            "id": "block_iocs",
            "action": "Block confirmed relevant IOCs at perimeter controls after validating relevance.",
            "owner_team": "NetOps",
            "approval_level": "SOC Lead",
            "risk": "Medium",
            "requires_all": ["has_any_enforceable_iocs"],
        },
    ],

    "IDENTITY_COMPROMISE": [
        {
            "id": "id_preserve",
            "action": "Preserve evidence: export sign-in logs, risky sign-ins, audit logs, and mailbox/app consent changes.",
            "owner_team": "SOC",
            "approval_level": "SOC",
            "risk": "Low",
            "requires_all": [],
        },
        {
            "id": "id_revoke",
            "action": "Revoke active sessions/refresh tokens for suspected accounts; enforce MFA/Conditional Access.",
            "owner_team": "IAM",
            "approval_level": "SOC Lead",
            "risk": "Medium (user disruption)",
            "requires_all": ["confidence_ge_0_55"],
        },
        {
            "id": "id_disable_oauth",
            "action": "Disable suspicious OAuth app consents / token grants if present.",
            "owner_team": "IAM",
            "approval_level": "SOC Lead",
            "risk": "Low/Medium",
            "requires_all": ["identity_signals"],
        },
    ],

    "RANSOMWARE": [
        {
            "id": "ran_preserve",
            "action": "Preserve evidence: memory (if feasible), host artifacts, and SIEM telemetry before remediation.",
            "owner_team": "SOC",
            "approval_level": "SOC",
            "risk": "Low",
            "requires_all": [],
        },
        {
            "id": "ran_isolate",
            "action": "Isolate affected endpoints/servers via EDR to stop spread (if available).",
            "owner_team": "SOC",
            "approval_level": "SOC Lead",
            "risk": "High (service disruption)",
            "requires_all": ["asset_class_endpoint_or_server", "edr_available"],
        },
        {
            "id": "ran_restore",
            "action": "Restore from known-good backups only after containment + eradication; verify backups are clean.",
            "owner_team": "IT Ops",
            "approval_level": "IR Lead",
            "risk": "High",
            "requires_all": ["ransomware_signals"],
        },
    ],

    "INVESTIGATE": [
        {
            "id": "inv_preserve",
            "action": "Collect additional telemetry (SIEM + host/network/IAM as applicable) to confirm or refute compromise.",
            "owner_team": "SOC",
            "approval_level": "SOC",
            "risk": "Low",
            "requires_all": [],
        },
    ],
}