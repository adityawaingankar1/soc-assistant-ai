from __future__ import annotations

from typing import Dict, Any, List, Optional
from datetime import datetime

class SplunkSPLTool:
    TOOL_NAME = "generate_splunk_spl"

    def generate(
        self,
        incident_type: str,
        affected_asset: str,
        entities: Optional[List[Dict[str, Any]]] = None,
        time_window_hours: int = 24,
    ) -> Dict[str, Any]:
        incident_type = (incident_type or "INVESTIGATE").strip().upper()
        affected_asset = (affected_asset or "").strip()
        entities = entities or []
        if time_window_hours < 1 or time_window_hours > 168:
            time_window_hours = 24

        ips, domains, urls, hashes, files = [], [], [], [], []
        for e in entities:
            if not isinstance(e, dict):
                continue
            t = (e.get("entity_type") or e.get("type") or "").strip().lower()
            v = (e.get("normalized") or e.get("value") or "").strip()
            if not v:
                continue
            if t == "ip":
                ips.append(v)
            elif t == "domain":
                domains.append(v)
            elif t == "url":
                urls.append(v)
            elif t in {"hash", "sha256", "md5", "sha1"}:
                hashes.append(v)
            elif t == "file_name":
                files.append(v)

        def uniq(xs: List[str]) -> List[str]:
            return sorted(set([x for x in xs if x]))

        ips, domains, urls, hashes, files = map(uniq, (ips, domains, urls, hashes, files))

        earliest = f"-{time_window_hours}h"
        terms = [affected_asset] if affected_asset else []
        terms += (ips + domains + urls + hashes + files)
        terms = [t for t in terms if t][:25]
        or_clause = " OR ".join([f"\"{t}\"" for t in terms]) if terms else "*"

        queries: List[Dict[str, str]] = []

        queries.append({
            "name": "Generic IOC + asset sightings",
            "description": "Schema-agnostic raw string search for asset + IOCs.",
            "query": (
                f"search earliest={earliest} ({or_clause})\n"
                "| head 200\n"
                "| table _time host source sourcetype user src dest src_ip dest_ip process_name CommandLine Image FileName url domain _raw\n"
            )
        })

        if incident_type == "RANSOMWARE":
            queries.append({
                "name": "Ransomware prep command hunt",
                "description": "Hunt for vssadmin/wbadmin/bcdedit/wevtutil/powershell -enc patterns.",
                "query": (
                    f"search earliest={earliest} (vssadmin OR wbadmin OR bcdedit OR wevtutil OR \"wmic shadowcopy\" OR \"powershell -enc\")\n"
                    + (f"| search \"{affected_asset}\"" if affected_asset else "")
                    + "\n| head 200\n| table _time host user process_name CommandLine Image parent_process _raw\n"
                )
            })
            queries.append({
                "name": "Ransomware extension hunt",
                "description": "Search for ransomware extension mentions (.interlock etc.).",
                "query": (
                    f"search earliest={earliest} (\".interlock\" OR \".locked\" OR \".encrypted\" OR \".ransom\" OR \"shadow copy\" OR \"Volume Shadow\")\n"
                    + (f"| search \"{affected_asset}\"" if affected_asset else "")
                    + "\n| head 200\n| table _time host source sourcetype user _raw\n"
                )
            })

        return {
            "success": True,
            "tool": self.TOOL_NAME,
            "incident_type": incident_type,
            "affected_asset": affected_asset,
            "time_window_hours": time_window_hours,
            "inputs": {"ips": ips, "domains": domains, "urls": urls, "hashes": hashes, "files": files},
            "queries": queries,
            "generated_at": datetime.utcnow().isoformat(),
        }