from __future__ import annotations
from typing import Dict, Any, List, Optional
from datetime import datetime
import re
import json
import unicodedata
from loguru import logger

from backend.tools.sentinel_tables import select_tables
from backend.tools.kql_validator import validate_kql_queries


_INVISIBLE_OR_BAD = {
    "\u200b",  # zero width space
    "\ufeff",  # BOM
    "\ufffe",  # noncharacter
    "\uffff",  # noncharacter
    "\u00ad",  # soft hyphen (often injected by PDF/text flows)
    "\u2060",  # word joiner
}


def _clean_text(s: str) -> str:
    """
    Remove invisible/non-printable Unicode characters that can sneak into
    hostnames and break KQL matching (the '' artifact typically comes from such chars
    or from line wrap/hyphenation in exports).
    """
    s = (s or "")
    s = unicodedata.normalize("NFKC", s)

    # normalize fancy dashes to ASCII hyphen
    s = s.replace("\u2013", "-").replace("\u2014", "-").replace("\u2212", "-")

    # drop known bad chars
    for ch in _INVISIBLE_OR_BAD:
        s = s.replace(ch, "")

    # drop other "Other" categories (C*) but keep newlines/tabs if present
    cleaned = []
    for c in s:
        if c in ("\n", "\t"):
            cleaned.append(c)
            continue
        cat = unicodedata.category(c)  # e.g. 'Cf', 'Cc', 'Cn'
        if cat and cat[0] == "C":
            continue
        if not c.isprintable():
            continue
        cleaned.append(c)

    return "".join(cleaned).strip()


def _kql_escape(s: str) -> str:
    s = _clean_text(s or "")
    return s.replace("'", "''")


def _normalize_asset_host_key(s: str) -> str:
    """
    Convert 'HOST — description (OS)' -> 'HOST'
    Convert 'host.domain.local' -> 'host'
    Strip hidden unicode that can break KQL.
    Then extract a safe hostname token.
    """
    s = _clean_text(s or "")
    if not s:
        return ""
    s = s.split("—", 1)[0].strip()
    s = re.split(r"\s*\(", s, maxsplit=1)[0].strip()

    # If FQDN, take host part
    if "." in s and not s.replace(".", "").isdigit():
        s = s.split(".", 1)[0].strip()

    # If still multiple tokens, take first
    s = s.split()[0].strip()

    # Extract a safe hostname-like token (prevents garbage from passing through)
    m = re.search(r"\b[A-Za-z0-9][A-Za-z0-9-]{1,63}\b", s)
    return m.group(0) if m else s


def _union(subqueries: List[str]) -> str:
    cleaned = [q.strip() for q in (subqueries or []) if q and q.strip()]
    if not cleaned:
        return ""
    if len(cleaned) == 1:
        return cleaned[0]
    parts = []
    for q in cleaned:
        parts.append("(\n" + q + "\n)")
    return "union isfuzzy=true\n" + ",\n".join(parts)


class SentinelKQLTool:
    TOOL_NAME = "generate_sentinel_kql"

    def generate(
        self,
        incident_type: str,
        affected_asset: str,
        entities: Optional[List[Dict[str, Any]]] = None,
        time_window_hours: int = 24,
        asset_class: Optional[str] = None,
    ) -> Dict[str, Any]:
        incident_type = (incident_type or "INVESTIGATE").strip().upper()
        affected_asset = _clean_text(affected_asset or "")
        entities = entities or []
        if time_window_hours < 1 or time_window_hours > 168:
            time_window_hours = 24

        tables = select_tables(incident_type, asset_class)
        asset_host_key = _normalize_asset_host_key(affected_asset) or affected_asset

        logger.info(
            f"[KQL] Generate queries incident_type={incident_type} asset={affected_asset} "
            f"asset_host_key={asset_host_key} asset_class={asset_class} tables={tables} "
            f"window={time_window_hours}h"
        )

        ips: List[str] = []
        domains: List[str] = []
        urls: List[str] = []
        hashes: List[str] = []
        file_names: List[str] = []
        registry_keys: List[str] = []
        cves: List[str] = []

        for e in entities:
            if not isinstance(e, dict):
                continue
            t = (e.get("entity_type") or e.get("type") or "").strip().lower()
            v = _clean_text((e.get("normalized") or e.get("value") or "").strip())
            if not v:
                continue

            if t == "ip":
                ips.append(v)

            # =====================================================
            # FIX: FILTER OUT FAKE DOMAINS (.exe/.dll/.lnk/etc)
            # =====================================================
            elif t == "domain":

                # Prevent executable names from polluting
                # DNS/domain hunting logic
                if not re.search(
                    r"(?i)\.(exe|dll|lnk|bat|cmd|ps1|js|vbs|msi|scr|hta)$",
                    v,
                ):
                    domains.append(v.lower())

            elif t == "url":
                urls.append(v)
            elif t in {"hash", "sha256", "md5", "sha1"}:
                hashes.append(v.lower())
            elif t == "file_name":
                file_names.append(v)
            elif t == "registry_key":
                registry_keys.append(v)
            elif t == "cve":
                cves.append(v.upper())

        ips = sorted(set(ips))
        domains = sorted(set(domains))
        urls = sorted(set(urls))
        hashes = sorted(set(hashes))
        file_names = sorted(set(file_names))
        registry_keys = sorted(set(registry_keys))
        cves = sorted(set(cves))

        def dyn_list(values: List[str]) -> str:
            return "dynamic([" + ", ".join([f"'{_kql_escape(x)}'" for x in values]) + "])"

        # IMPORTANT: multi-line filter to avoid PDF wrapping inside hostname tokens
        asset_filter = ""
        if asset_host_key:
            a = _kql_escape(asset_host_key)
            has_fallback = f"\n or tostring(DeviceName) has '{a}'" if len(a) >= 6 else ""
            asset_filter = (
                f"| where tostring(DeviceName) =~ '{a}'\n"
                f" or tostring(Computer) =~ '{a}'\n"
                f" or tostring(HostName) =~ '{a}'"
                f"{has_fallback}"
            )

        queries: List[Dict[str, Any]] = []

        # IP sightings
        if ips:
            sub: List[str] = []

            if "CommonSecurityLog" in tables:
                sub.append(
                    f"""
CommonSecurityLog
| where TimeGenerated > ago({time_window_hours}h)
| where SrcIpAddr in (ips) or DstIpAddr in (ips)
| project TimeGenerated, Table="CommonSecurityLog", DeviceVendor, DeviceProduct, SrcIpAddr,
DstIpAddr, DestinationPort, Message
""".strip()
                )

            if "DeviceNetworkEvents" in tables:
                sub.append(
                    f"""
DeviceNetworkEvents
| where Timestamp > ago({time_window_hours}h)
{asset_filter}
| where RemoteIP in (ips) or LocalIP in (ips)
| project TimeGenerated=Timestamp, Table="DeviceNetworkEvents", DeviceName, RemoteIP,
RemotePort, LocalIP,
InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,
RemoteUrl
""".strip()
                )

            if "Syslog" in tables:
                sub.append(
                    f"""
Syslog
| where TimeGenerated > ago({time_window_hours}h)
| where SyslogMessage has_any (ips)
| project TimeGenerated, Table="Syslog", HostName, ProcessName, SyslogMessage
""".strip()
                )

            if sub:
                queries.append(
                    {
                        "name": "IP sightings (table-aware)",
                        "description": "Find events with matching IPs across selected tables for this incident type.",
                        "query": f"let ips = {dyn_list(ips)};\n{_union(sub)}\n| sort by TimeGenerated desc",
                    }
                )

        # Domain/DNS sightings
        if domains:
            sub = []

            if "DeviceNetworkEvents" in tables:
                sub.append(
                    f"""
DeviceNetworkEvents
| where Timestamp > ago({time_window_hours}h)
{asset_filter}
| where RemoteUrl has_any (domains)
| project TimeGenerated=Timestamp, Table="DeviceNetworkEvents", DeviceName, RemoteUrl,
RemoteIP,
InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
""".strip()
                )

            if "DnsEvents" in tables:
                sub.append(
                    f"""
DnsEvents
| where TimeGenerated > ago({time_window_hours}h)
| where Name has_any (domains)
| project TimeGenerated, Table="DnsEvents", Computer, ClientIP, Name, IPAddresses
""".strip()
                )

            if "Syslog" in tables:
                sub.append(
                    f"""
Syslog
| where TimeGenerated > ago({time_window_hours}h)
| where SyslogMessage has_any (domains)
| project TimeGenerated, Table="Syslog", HostName, ProcessName, SyslogMessage
""".strip()
                )

            if sub:
                queries.append(
                    {
                        "name": "Domain/DNS sightings (table-aware)",
                        "description": "Search for suspicious domains across selected tables.",
                        "query": f"let domains = {dyn_list(domains)};\n{_union(sub)}\n| sort by TimeGenerated desc",
                    }
                )

        # Hash sightings
        if hashes:
            if "DeviceFileEvents" in tables:
                queries.append(
                    {
                        "name": "File hash sightings (DeviceFileEvents)",
                        "description": "Search for known hashes (SHA256/MD5 depending on ingestion).",
                        "query": f"""
let hashes = {dyn_list(hashes)};
DeviceFileEvents
| where Timestamp > ago({time_window_hours}h)
{asset_filter}
| where SHA256 in (hashes) or MD5 in (hashes) or InitiatingProcessSHA256 in (hashes) or InitiatingProcessMD5 in (hashes)
| project TimeGenerated=Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
MD5,
InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by TimeGenerated desc
""".strip(),
                    }
                )

            # =====================================================
            # ADD: HASH HUNTING FOR PROCESS EVENTS
            # =====================================================
            if "DeviceProcessEvents" in tables:
                queries.append(
                    {
                        "name": "Process Hash Sightings",
                        "description": ("Search for malicious process hashes."),
                        "query": f"""
let hashes = {dyn_list(hashes)};

DeviceProcessEvents
| where Timestamp > ago({time_window_hours}h)

{asset_filter}

| where
    SHA256 in (hashes)
    or MD5 in (hashes)

| project
    TimeGenerated=Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    SHA256,
    MD5,
    InitiatingProcessFileName

| sort by TimeGenerated desc
""".strip(),
                    }
                )

        # File-name sightings
        if file_names and "DeviceProcessEvents" in tables:
            queries.append(
                {
                    "name": "Suspicious file/process name sightings (DeviceProcessEvents)",
                    "description": "Search for suspicious process/file names seen in the alert.",
                    "query": f"""
let names = {dyn_list(file_names[:50])};
DeviceProcessEvents
| where Timestamp > ago({time_window_hours}h)
{asset_filter}
| where FileName in (names) or ProcessCommandLine has_any (names)
| project TimeGenerated=Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated desc
""".strip(),
                }
            )

        # =====================================================
        # FRP / VOLT TYPHOON PERSISTENCE HUNTING
        # =====================================================

        if (
            incident_type in {"APT_ESPIONAGE", "APT_PERSISTENCE", "INVESTIGATE"}
            and file_names
        ):
            if "DeviceProcessEvents" in tables:
                queries.append(
                    {
                        "name": "FRP / Reverse Proxy Persistence Hunting",
                        "description": (
                            "Search for FRP tooling, "
                            "reverse proxy persistence, "
                            "and suspicious tunneling activity."
                        ),
                        "query": f"""
let names = {dyn_list(file_names[:50])};

DeviceProcessEvents
| where Timestamp > ago({time_window_hours}h)

{asset_filter}

| where
    FileName in (names)
    or ProcessCommandLine has_any (
        "frp",
        "frpc",
        "reverse proxy",
        "proxy",
        "tunnel",
        "ssh -R",
        "portproxy",
        "netsh interface portproxy"
    )

| project
    TimeGenerated=Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine

| sort by TimeGenerated desc
""".strip(),
                    }
                )

        # =====================================================
        # RDP / VALID ACCOUNT ABUSE
        # =====================================================

        if incident_type in {"APT_ESPIONAGE", "APT_PERSISTENCE", "INVESTIGATE"}:
            if "SecurityEvent" in tables:
                queries.append(
                    {
                        "name": "RDP / Valid Account Activity",
                        "description": (
                            "Hunt for suspicious RDP logons, "
                            "credential abuse, and lateral movement."
                        ),
                        "query": f"""
SecurityEvent
| where TimeGenerated > ago({time_window_hours}h)

| where EventID in (4624, 4625, 4648, 4672)

| where
    LogonType == 10
    or AuthenticationPackageName has "NTLM"

| project
    TimeGenerated,
    Computer,
    Account,
    IpAddress,
    EventID,
    Activity,
    LogonType,
    AuthenticationPackageName

| sort by TimeGenerated desc
""".strip(),
                    }
                )

        # =====================================================
        # NTDS / LOG CLEARING / DEFENSE EVASION
        # =====================================================

        if "SecurityEvent" in tables:
            queries.append(
                {
                    "name": "NTDS Access / Log Clearing Indicators",
                    "description": (
                        "Hunt for credential dumping, "
                        "NTDS access, and log tampering."
                    ),
                    "query": f"""
SecurityEvent
| where TimeGenerated > ago({time_window_hours}h)

| where
    CommandLine has_any (
        "ntds.dit",
        "esentutl",
        "vssadmin",
        "wevtutil",
        "log clear",
        "clear-eventlog",
        "ntdsutil"
    )

| project
    TimeGenerated,
    Computer,
    Account,
    EventID,
    Activity,
    CommandLine,
    Process

| sort by TimeGenerated desc
""".strip(),
                }
            )

        # Incident-specific
        if incident_type in {"APT_ESPIONAGE", "APT_PERSISTENCE"}:
            # Placeholder branch to enable future APT playbooks
            pass

        if incident_type == "RANSOMWARE":
            if "DeviceProcessEvents" in tables:
                queries.append(
                    {
                        "name": "Ransomware execution patterns (DeviceProcessEvents)",
                        "description": "Search for ransomware prep commands (vssadmin, wbadmin, bcdedit, cipher, wevtutil).",
                        "query": f"""
DeviceProcessEvents
| where Timestamp > ago({time_window_hours}h)
{asset_filter}
| where ProcessCommandLine has_any
("vssadmin","wbadmin","bcdedit","cipher","wevtutil","rundll32","wmic shadowcopy","powershell -enc")
| project TimeGenerated=Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated desc
""".strip(),
                    }
                )

            if "DeviceFileEvents" in tables:
                suspicious_ext = [
                    ".interlock",
                    ".locked",
                    ".encrypt",
                    ".encrypted",
                    ".crypted",
                    ".ransom",
                ]
                queries.append(
                    {
                        "name": "Ransomware file activity (DeviceFileEvents)",
                        "description": "Hunt for ransomware extensions and rename/write patterns (best-effort).",
                        "query": f"""
let exts = dynamic({json.dumps(suspicious_ext)});
DeviceFileEvents
| where Timestamp > ago({time_window_hours}h)
{asset_filter}
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| extend LowerName=tolower(FileName)
| where LowerName has_any (exts)
| project TimeGenerated=Timestamp, DeviceName, ActionType, FileName, FolderPath,
InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by TimeGenerated desc
""".strip(),
                    }
                )

            if "SecurityEvent" in tables:
                queries.append(
                    {
                        "name": "Shadow copy deletion hints (SecurityEvent)",
                        "description": "Hunt for vssadmin/wbadmin/bcdedit/wevtutil usage (if ingested).",
                        "query": f"""
SecurityEvent
| where TimeGenerated > ago({time_window_hours}h)
| where CommandLine has_any ("vssadmin", "wbadmin", "bcdedit", "wevtutil")
| project TimeGenerated, Computer, Account, EventID, Activity, CommandLine, Process
| sort by TimeGenerated desc
""".strip(),
                    }
                )

        # Fallback
        if not queries:
            sub = []
            if "SecurityEvent" in tables:
                sub.append(
                    f"""
SecurityEvent
| where TimeGenerated > ago({time_window_hours}h)
| project TimeGenerated, Table="SecurityEvent", Computer, EventID, Activity, Account, IpAddress
""".strip()
                )
            if "CommonSecurityLog" in tables:
                sub.append(
                    f"""
CommonSecurityLog
| where TimeGenerated > ago({time_window_hours}h)
| project TimeGenerated, Table="CommonSecurityLog", DeviceVendor, DeviceProduct, Message
""".strip()
                )
            if "Syslog" in tables:
                sub.append(
                    f"""
Syslog
| where TimeGenerated > ago({time_window_hours}h)
| project TimeGenerated, Table="Syslog", HostName, ProcessName, SyslogMessage
""".strip()
                )
            queries.append(
                {
                    "name": "Generic triage (table-aware)",
                    "description": "Baseline triage query across selected tables.",
                    "query": f"{_union(sub)}\n| sort by TimeGenerated desc",
                }
            )

        validation = validate_kql_queries(queries, tables)

        return {
            "success": True,
            "tool": self.TOOL_NAME,
            "incident_type": incident_type,
            "affected_asset": affected_asset,
            "asset_host_key": asset_host_key,
            "asset_class": asset_class,
            "tables": tables,
            "time_window_hours": time_window_hours,
            "inputs": {
                "ips": ips,
                "domains": domains,
                "urls": urls,
                "hashes": hashes,
                "cves": cves,
            },
            "queries": queries,
            "validation": validation,
            "generated_at": datetime.utcnow().isoformat(),
        }