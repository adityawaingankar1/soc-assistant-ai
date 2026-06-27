import asyncio
from typing import Dict, Any, List
from loguru import logger
from backend.tools.cve_tool import CVETool


class VulnIntelAgent:
    def __init__(self):
        self.cve_tool = CVETool()

    async def enrich(self, alert_data: Dict) -> Dict[str, Any]:
        await asyncio.sleep(0.05)

        entities = alert_data.get("entities") or []
        cves: List[str] = []
        for e in entities:
            if isinstance(e, dict) and (e.get("entity_type") == "cve"):
                cve = (e.get("normalized") or e.get("value") or "").strip().upper()
                if cve:
                    cves.append(cve)

        cves = sorted(list(set(cves)))
        if not cves:
            return {
                "status": "no_cves",
                "summary": {
                    "total_cves": 0,
                    "found_count": 0,
                    "kev_count": 0,
                    "max_cvss": 0.0,
                    "high_risk": False,
                    "exploit_context_score": 0.0
                },
                "cves": []
            }

        enriched = self.cve_tool.bulk_enrich(cves)
        found = [x for x in enriched if x.get("found") is True]
        kev_count = sum(1 for x in found if x.get("kev") is True)

        max_cvss = 0.0
        for x in found:
            try:
                max_cvss = max(max_cvss, float(x.get("cvss_base") or 0.0))
            except Exception:
                pass

        high_risk = bool(kev_count > 0 or max_cvss >= 9.0)

        # Exploit context score: KEV dominates (this is what defenders need)
        exploit_context_score = 0.2
        if kev_count > 0:
            exploit_context_score = 0.9
        elif max_cvss >= 9.0:
            exploit_context_score = 0.7
        elif max_cvss >= 7.0:
            exploit_context_score = 0.5

        logger.info(f"[VulnIntel] CVEs={len(cves)} found={len(found)} kev={kev_count} max_cvss={max_cvss}")

        return {
            "status": "ok",
            "summary": {
                "total_cves": len(cves),
                "found_count": len(found),
                "kev_count": kev_count,
                "max_cvss": round(max_cvss, 1),
                "high_risk": high_risk,
                "exploit_context_score": round(exploit_context_score, 3)
            },
            "cves": enriched
        }