from __future__ import annotations
from typing import List, Optional

DEFAULT_SENTINEL_TABLES_BY_INCIDENT = {
    "EDGE_EXPLOIT": ["Syslog", "CommonSecurityLog"],
    "WEBAPP_EXPLOIT": ["W3CIISLog", "Syslog", "CommonSecurityLog"],
    "IDENTITY_COMPROMISE": ["SigninLogs", "AuditLogs", "OfficeActivity"],
    # Expanded to include network/DNS tables when available
    "RANSOMWARE": ["DeviceProcessEvents", "DeviceFileEvents", "DeviceNetworkEvents", "DnsEvents", "SecurityEvent"],
    "INVESTIGATE": ["SecurityEvent", "Syslog", "CommonSecurityLog"],
}

def select_tables(incident_type: str, asset_class: Optional[str] = None) -> List[str]:
    it = (incident_type or "INVESTIGATE").strip().upper()
    ac = (asset_class or "unknown").strip().lower()
    tables = list(DEFAULT_SENTINEL_TABLES_BY_INCIDENT.get(it, DEFAULT_SENTINEL_TABLES_BY_INCIDENT["INVESTIGATE"]))

    # Asset-class hardening
    if ac in {"edge_appliance", "edge"}:
        prefer = ["Syslog", "CommonSecurityLog"]
        tables = [t for t in tables if t in prefer] or prefer

    return tables