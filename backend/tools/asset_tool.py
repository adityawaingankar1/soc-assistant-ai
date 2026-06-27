from __future__ import annotations

"""
Asset Lookup Tool
Queries the CMDB (Configuration Management Database) for asset information.

Fixes:
- Canonicalizes alert asset labels like:
  'HOST — description (OS)' -> 'HOST'
So CMDB + KQL filters match real hostnames.
"""

from typing import Dict, List, Optional
from datetime import datetime
from loguru import logger
import ipaddress
import re


class AssetTool:
    TOOL_NAME = "lookup_asset"

    MOCK_CMDB = {
        "WS-001": {
            "hostname": "WS-001",
            "ip_addresses": ["10.0.1.50"],
            "mac_address": "00:1A:2B:3C:4D:5E",
            "os": "Windows 11 Pro",
            "os_version": "22H2 (Build 22621)",
            "owner_name": "John Smith",
            "owner_email": "john.smith@company.com",
            "department": "Finance",
            "location": "Office Floor 3 - Desk 42",
            "criticality": "HIGH",
            "asset_type": "workstation",
            "data_classifications": ["PII", "Financial Records"],
            "last_patch_date": "2024-11-15",
            "last_seen": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "compliance_status": "compliant",
            "network_zone": "internal_corporate",
            "open_ports": [],
            "installed_security_tools": ["CrowdStrike Falcon", "Microsoft Defender"],
            "is_domain_joined": True,
            "vulnerabilities_high": 2,
            "vulnerabilities_critical": 0,
        },
        "WS-002": {
            "hostname": "WS-002",
            "ip_addresses": ["10.0.1.51"],
            "os": "Windows 10 Pro",
            "os_version": "21H2",
            "owner_name": "Sarah Johnson",
            "owner_email": "sarah.johnson@company.com",
            "department": "Finance",
            "location": "Office Floor 3 - Desk 43",
            "criticality": "HIGH",
            "asset_type": "workstation",
            "data_classifications": ["PII", "Financial Records"],
            "last_patch_date": "2024-09-20",
            "compliance_status": "non_compliant",
            "compliance_issues": ["Missing critical patch KB5031356", "Outdated AV signatures"],
            "network_zone": "internal_corporate",
            "is_domain_joined": True,
            "vulnerabilities_high": 8,
            "vulnerabilities_critical": 3,
        },
        "SRV-DB-01": {
            "hostname": "SRV-DB-01",
            "ip_addresses": ["10.0.2.10"],
            "os": "Ubuntu 22.04 LTS",
            "os_version": "5.15.0-91-generic",
            "owner_name": "Database Team",
            "owner_email": "db-team@company.com",
            "department": "Engineering",
            "location": "Data Center A - Rack 12",
            "criticality": "CRITICAL",
            "asset_type": "server",
            "data_classifications": ["PII", "PCI-DSS", "HIPAA"],
            "last_patch_date": "2024-12-01",
            "last_seen": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "compliance_status": "compliant",
            "network_zone": "dmz",
            "open_ports": [5432, 6379, 22],
            "running_services": ["PostgreSQL 15", "Redis 7.0", "SSH"],
            "backup_schedule": "daily",
            "last_backup": "2024-12-09T02:00:00Z",
            "is_domain_joined": False,
            "vulnerabilities_high": 1,
            "vulnerabilities_critical": 0,
            "installed_security_tools": ["Qualys Agent", "Filebeat", "fail2ban"],
        },
        "SRV-DC-01": {
            "hostname": "SRV-DC-01",
            "ip_addresses": ["10.0.0.10"],
            "os": "Windows Server 2022",
            "owner_name": "IT Infrastructure Team",
            "owner_email": "infra@company.com",
            "department": "IT Operations",
            "location": "Data Center A - Rack 1",
            "criticality": "CRITICAL",
            "asset_type": "domain_controller",
            "data_classifications": ["Confidential", "AD Credentials"],
            "last_patch_date": "2024-12-01",
            "compliance_status": "compliant",
            "network_zone": "internal_infrastructure",
            "open_ports": [53, 88, 389, 445, 636, 3268],
            "running_services": ["Active Directory", "DNS", "LDAP", "Kerberos"],
            "is_domain_joined": True,
            "vulnerabilities_high": 0,
            "vulnerabilities_critical": 0,
            "installed_security_tools": ["CrowdStrike Falcon", "Microsoft Defender ATP"],
        },
        "SRV-WEB-01": {
            "hostname": "SRV-WEB-01",
            "ip_addresses": ["10.0.3.20", "203.0.113.10"],
            "os": "Ubuntu 20.04 LTS",
            "owner_name": "Web Team",
            "owner_email": "web-ops@company.com",
            "department": "Engineering",
            "criticality": "HIGH",
            "asset_type": "web_server",
            "data_classifications": ["Public"],
            "last_patch_date": "2024-11-25",
            "network_zone": "dmz",
            "open_ports": [80, 443, 22],
            "running_services": ["Nginx 1.25", "Node.js 20"],
            "internet_facing": True,
            "waf_enabled": True,
        },
    }

    @staticmethod
    def canonicalize_identifier(ip_or_hostname: str) -> str:
        s = (ip_or_hostname or "").strip()
        if not s:
            return ""

        # embedded IP?
        m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s)
        if m:
            return m.group(0)

        s = s.split("—", 1)[0].strip()
        s = re.split(r"\s*\(", s, maxsplit=1)[0].strip()

        if "." in s and not s.replace(".", "").isdigit():
            s = s.split(".", 1)[0].strip()

        s = s.split()[0].strip()
        return s

    def lookup(self, ip_or_hostname: str) -> Dict:
        logger.info(f"[Asset] Looking up: {ip_or_hostname}")
        raw = (ip_or_hostname or "").strip()
        if not raw:
            return self._error("ip_address/hostname is required")

        key = self.canonicalize_identifier(raw)
        if not key:
            return self._error("Unable to canonicalize identifier")

        if key.upper() in self.MOCK_CMDB:
            return self._format_response(self.MOCK_CMDB[key.upper()], searched_identifier=raw, canonical_identifier=key)

        for hostname, asset in self.MOCK_CMDB.items():
            if hostname.lower() == key.lower() or str(asset.get("hostname", "")).lower() == key.lower():
                return self._format_response(asset, searched_identifier=raw, canonical_identifier=key)

        for _, asset in self.MOCK_CMDB.items():
            if key in (asset.get("ip_addresses", []) or []):
                return self._format_response(asset, searched_identifier=raw, canonical_identifier=key)

        logger.warning(f"[Asset] Not found in CMDB: raw={raw} canonical={key}")

        guessed_class = "unknown"
        if re.search(r"\bSRV\b|SERVER", raw, flags=re.IGNORECASE):
            guessed_class = "server"
        elif re.search(r"\bWS\b|WORKSTATION", raw, flags=re.IGNORECASE):
            guessed_class = "workstation"

        return {
            "success": True,
            "tool": self.TOOL_NAME,
            "found": False,
            "searched_identifier": raw,
            "canonical_identifier": key,
            "message": "Asset not found in CMDB — validate ownership and exposure",
            "recommendation": "Treat exposure as UNKNOWN (potentially internet-facing). Prioritize validation.",
            "internet_facing": None,
            "internet_facing_status": "unknown",
            "internet_facing_confidence": "LOW",
            "public_ip_addresses": [],
            "asset_class": guessed_class,
            "edr_available": False,
            "looked_up_at": datetime.utcnow().isoformat(),
        }

    def _format_response(self, asset: Dict, searched_identifier: str, canonical_identifier: str) -> Dict:
        a = dict(asset or {})
        public_ips = self._public_ips(a.get("ip_addresses", []) or [])
        edr_available = self._derive_edr_available(a)

        if a.get("internet_facing") is True:
            internet_facing: Optional[bool] = True
            status, conf = "yes", "HIGH"
        elif public_ips:
            internet_facing = True
            status, conf = "yes", "MEDIUM"
        elif a.get("network_zone") == "dmz":
            internet_facing = None
            status, conf = "unknown", "MEDIUM"
        else:
            internet_facing = False
            status, conf = "no", "MEDIUM"

        a["public_ip_addresses"] = public_ips
        a["edr_available"] = edr_available
        a["internet_facing"] = internet_facing
        a["internet_facing_status"] = status
        a["internet_facing_confidence"] = conf

        asset_type = (a.get("asset_type") or "").lower()
        if asset_type in {"server", "domain_controller", "web_server"}:
            asset_class = "server"
        elif asset_type in {"workstation", "laptop", "desktop"}:
            asset_class = "endpoint"
        else:
            asset_class = "unknown"

        return {
            "success": True,
            "tool": self.TOOL_NAME,
            "found": True,
            "searched_identifier": searched_identifier,
            "canonical_identifier": canonical_identifier,
            "asset_class": asset_class,
            **a,
            "looked_up_at": datetime.utcnow().isoformat(),
        }

    def _derive_edr_available(self, asset: Dict) -> bool:
        tools = " ".join([str(x) for x in (asset.get("installed_security_tools") or [])]).lower()
        return any(k in tools for k in ["crowdstrike", "defender", "falcon", "edr", "sentinelone", "carbon black"])

    def _public_ips(self, ips: List[str]) -> List[str]:
        out = []
        for ip in ips or []:
            try:
                obj = ipaddress.ip_address(ip)
                if not obj.is_private:
                    out.append(ip)
            except Exception:
                continue
        return out

    def _error(self, message: str) -> Dict:
        return {
            "success": False,
            "tool": self.TOOL_NAME,
            "error": message,
            "looked_up_at": datetime.utcnow().isoformat(),
        }