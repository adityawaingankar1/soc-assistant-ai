from typing import Dict, List, Any
from datetime import datetime
import re
from loguru import logger


class CVETool:
    TOOL_NAME = "enrich_cve"

    MOCK_CVES = {
        "CVE-2023-34362": {
            "cvss_base": 9.8,
            "severity": "CRITICAL",
            "kev": True,
            "title": "MOVEit Transfer SQL Injection leading to potential RCE / Webshell deployment",
            "affected_products": ["MOVEit Transfer"],
            "vendor": "Progress Software",
            "published": "2023-06-01",
            "last_modified": "2023-06-15",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            ],
            "observed_artifacts": [
                "human2.aspx (webshell / artifact reported in public incident analysis)",
                "X-siLock-* headers (observed in exploitation activity / webshell interaction patterns)"
            ],
            "mitigations": [
                "Take MOVEit Transfer out of service or restrict inbound access during containment (temporary allowlist)",
                "Apply vendor patches/hotfixes and confirm fixed version",
                "Rotate MOVEit application credentials and API keys after remediation",
                "Review IIS/MOVEit logs and database artifacts for signs of compromise"
            ],
            "detection": [
                "Search IIS logs for unusual requests, webshell indicators, and X-siLock-* header usage",
                "Inspect web root for unexpected .aspx files (e.g., human2.aspx) and validate integrity",
                "Review outbound transfers / unusual data exfil patterns"
            ]
        },
        "CVE-2024-3400": {
            "cvss_base": 10.0,
            "severity": "CRITICAL",
            "kev": True,
            "title": "Remote Code Execution in Edge/VPN Component",
            "affected_products": ["VPN Gateway", "Edge Appliance"],
            "vendor": "VendorX",
            "published": "2024-04-01",
            "last_modified": "2024-04-10",
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            ],
            "mitigations": [
                "Apply vendor hotfix / upgrade immediately",
                "Restrict management-plane access to allowlisted IPs",
                "Review device logs for suspicious admin sessions and config changes"
            ],
            "detection": [
                "Look for exploitation signatures in WAF/VPN logs",
                "Check for unexpected file writes and new admin/API keys on the device"
            ]
        }
    }

    def enrich(self, cve_id: str) -> Dict[str, Any]:
        cve = (cve_id or "").strip().upper()
        logger.info(f"[CVE] Enriching: {cve}")

        if not cve:
            return self._error("cve_id is required")

        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve):
            return self._error("Invalid CVE format", cve_id=cve)

        data = self.MOCK_CVES.get(cve)
        if not data:
            return {
                "success": True,
                "tool": self.TOOL_NAME,
                "cve_id": cve,
                "found": False,
                "note": "CVE not found in mock database (prod: query NVD/vendor + KEV).",
                "enriched_at": datetime.utcnow().isoformat()
            }

        return {
            "success": True,
            "tool": self.TOOL_NAME,
            "cve_id": cve,
            "found": True,
            **data,
            "enriched_at": datetime.utcnow().isoformat()
        }

    def bulk_enrich(self, cves: List[str]) -> List[Dict[str, Any]]:
        return [self.enrich(c) for c in (cves or [])]

    def _error(self, message: str, **kwargs) -> Dict[str, Any]:
        return {
            "success": False,
            "tool": self.TOOL_NAME,
            "error": message,
            "enriched_at": datetime.utcnow().isoformat(),
            **kwargs
        }