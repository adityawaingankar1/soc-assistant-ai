from __future__ import annotations

import asyncio
import os
import uuid
import ipaddress
from typing import Dict, List, Any, Optional
from loguru import logger

from backend.tools.ioc_tool import IOCTool


class ThreatIntelAgent:
    """
    Threat Intelligence enrichment agent.

    Production hardening:
    - Prefer structured entities from alert_data['entities']
    - Enrich only TI-eligible: ip/domain/url/hash
    - Attribution is DISABLED by default (no actors in output)
      Enable with SOC_ENABLE_ATTRIBUTION=1
    - STIX output is enabled by default, but can be disabled with SOC_ENABLE_STIX=0
    """

    ENABLE_ATTRIBUTION = os.getenv("SOC_ENABLE_ATTRIBUTION", "0").strip() == "1"
    ENABLE_STIX = os.getenv("SOC_ENABLE_STIX", "1").strip() != "0"

    def __init__(self):
        self.ioc_tool = IOCTool()

    async def enrich(self, alert_data: Dict) -> Dict:
        await asyncio.sleep(0.05)

        raw_ioc_input = alert_data.get("ioc_list", "") or ""
        entities = alert_data.get("entities")

        parsed_iocs = self._build_parsed_iocs(raw_ioc_input, entities)

        results: Dict[str, Any] = {
            "raw_ioc_input": raw_ioc_input,
            "iocs_parsed": parsed_iocs,
            "iocs_analyzed": [ioc.get("value") for ioc in parsed_iocs if ioc.get("value")],
            "findings": [],
            "threat_level": "unknown",
            "campaigns": [],
            "summary": {
                "total_iocs": len(parsed_iocs),
                "enriched_successfully": 0,
                "malicious_count": 0,
                "suspicious_count": 0,
                "unknown_count": 0,
                "unsupported_count": 0,
                "errors": 0,
            },
            # STIX stays present for schema stability; can be disabled by env var
            "stix_bundle": {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": "2.1",
                "objects": [],
            },
        }

        # Attribution fields are gated
        if self.ENABLE_ATTRIBUTION:
            results["known_threat_actors"] = []
            results["attribution"] = {"most_likely_actor": None, "actor_confidence": "LOW", "basis": []}

        if not parsed_iocs:
            results["status"] = "no_iocs"
            results["match_rate"] = 0.0
            results["enrichment_coverage"] = 0.0
            results["actionable_coverage"] = 0.0
            results["unsupported_rate"] = 0.0
            if not self.ENABLE_STIX:
                results["stix_bundle"] = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1", "objects": []}
            return results

        # Only used if attribution enabled
        actor_ids: Dict[str, str] = {}

        for parsed in parsed_iocs:
            try:
                ioc_type = (parsed.get("type") or "").strip().lower()
                ioc_value = (parsed.get("value") or "").strip()

                if not ioc_value:
                    continue

                # Enrich only TI-supported
                if ioc_type in {"ip", "domain", "hash", "url"}:
                    finding = self.ioc_tool.enrich(ioc_value, ioc_type)
                else:
                    results["summary"]["unsupported_count"] += 1
                    finding = {
                        "success": True,
                        "tool": "enrich_ioc",
                        "indicator": ioc_value,
                        "indicator_type": ioc_type,
                        "verdict": "UNSUPPORTED_FOR_TI",
                        "malicious": None,
                        "confidence": "LOW",
                        "note": f"{ioc_type} entity captured but not supported by TI enrichment",
                    }

                finding["extraction_stage"] = parsed.get("extraction_stage")
                results["findings"].append(finding)

                if finding.get("success"):
                    results["summary"]["enriched_successfully"] += 1

                verdict = str(finding.get("verdict", "")).upper()
                if finding.get("malicious") is True or verdict == "MALICIOUS":
                    results["summary"]["malicious_count"] += 1
                    results["threat_level"] = "malicious"
                elif verdict == "SUSPICIOUS":
                    results["summary"]["suspicious_count"] += 1
                    if results["threat_level"] == "unknown":
                        results["threat_level"] = "suspicious"
                else:
                    results["summary"]["unknown_count"] += 1

                # campaigns are safe to include (not attribution)
                for campaign in (finding.get("campaigns") or []) or []:
                    if campaign not in results["campaigns"]:
                        results["campaigns"].append(campaign)

                # ---- STIX output (optional) ----
                if self.ENABLE_STIX:
                    stix_indicator = self._to_stix_indicator(finding)
                    if stix_indicator:
                        results["stix_bundle"]["objects"].append(stix_indicator)

                    # Threat-actor objects + relationships are gated
                    if self.ENABLE_ATTRIBUTION:
                        actor = finding.get("threat_actor")
                        if actor:
                            # Populate known_threat_actors + relationships
                            if actor not in results.get("known_threat_actors", []):
                                results["known_threat_actors"].append(actor)

                            if actor not in actor_ids:
                                actor_obj = self._to_stix_threat_actor(actor, finding)
                                actor_ids[actor] = actor_obj["id"]
                                results["stix_bundle"]["objects"].append(actor_obj)

                            if stix_indicator:
                                relationship = self._to_stix_relationship(
                                    source_ref=stix_indicator["id"],
                                    target_ref=actor_ids[actor],
                                )
                                results["stix_bundle"]["objects"].append(relationship)

            except Exception as e:
                logger.error(f"[ThreatIntel] Failed IOC enrichment for {parsed}: {e}")
                results["summary"]["errors"] += 1
                results["findings"].append(
                    {
                        "success": False,
                        "indicator": parsed.get("value"),
                        "indicator_type": parsed.get("type", "unknown"),
                        "error": str(e),
                        "verdict": "ERROR",
                        "extraction_stage": parsed.get("extraction_stage"),
                    }
                )

        total_iocs = max(int(results["summary"]["total_iocs"] or 0), 1)
        results["match_rate"] = round(results["summary"]["malicious_count"] / total_iocs, 3)
        results["enrichment_coverage"] = round(results["summary"]["enriched_successfully"] / total_iocs, 3)
        results["actionable_coverage"] = round(results["summary"]["malicious_count"] / total_iocs, 3)
        results["unsupported_rate"] = round(results["summary"]["unsupported_count"] / total_iocs, 3)

        results["iocs_analyzed"] = [f.get("indicator") for f in results["findings"] if f.get("indicator")]

        # Attribution inference is gated
        if self.ENABLE_ATTRIBUTION:
            results["attribution"] = self._infer_attribution(results)

        # If STIX disabled, drop it (keep schema stable)
        if not self.ENABLE_STIX:
            results["stix_bundle"] = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1", "objects": []}

        return results

    def _build_parsed_iocs(self, raw_ioc_text: str, entities: Any) -> List[Dict[str, Any]]:
        parsed: List[Dict[str, Any]] = []
        seen = set()

        # Prefer structured entities passed in (already normalized upstream)
        if isinstance(entities, list) and entities:
            for e in entities:
                if not isinstance(e, dict):
                    continue
                et = (e.get("entity_type") or e.get("type") or "").strip().lower()
                val = (e.get("normalized") or e.get("value") or "").strip()
                if not val:
                    continue
                key = (et, val.lower())
                if key in seen:
                    continue
                seen.add(key)
                parsed.append({"type": et, "value": val, "extraction_stage": "structured_entities"})
            return parsed

        # Fallback: parse from raw text
        raw_items = IOCTool.parse_ioc_list(raw_ioc_text)
        typed = IOCTool.classify_iocs(raw_items)

        for t in typed:
            et = (t.get("entity_type") or "unknown").strip().lower()
            val = (t.get("normalized") or "").strip()
            if not val:
                continue
            key = (et, val.lower())
            if key in seen:
                continue
            seen.add(key)
            parsed.append({"type": et, "value": val, "extraction_stage": "json_first_fallback"})

        return parsed

    def _infer_attribution(self, results: Dict) -> Dict:
        """
        Trust rule (gated feature):
        - Do NOT attribute unless there is at least one malicious TI finding and an explicit actor value.
        """
        malicious_count = int((results.get("summary") or {}).get("malicious_count") or 0)
        actors = results.get("known_threat_actors", []) or []

        if malicious_count <= 0 or not actors:
            return {
                "most_likely_actor": None,
                "actor_confidence": "LOW",
                "basis": ["No malicious TI-backed actor evidence."],
            }

        conf = "MEDIUM" if len(actors) == 1 else "LOW"
        return {
            "most_likely_actor": actors[0],
            "actor_confidence": conf,
            "basis": ["Actor extracted from TI enrichment on malicious indicators."],
        }

    # ---------------------------
    # STIX helpers (indicator always OK; actor/relationships gated)
    # ---------------------------

    def _hash_stix_pattern(self, h: str, hash_type: Optional[str]) -> str:
        """
        STIX 2.1 hash pattern keys:
          - MD5
          - 'SHA-1'
          - 'SHA-256'
          - 'SHA-512'
        """
        hv = (h or "").strip()
        ht = (hash_type or "").strip().upper()

        if not ht:
            # Best-effort detect by length
            L = len(hv)
            ht = {32: "MD5", 40: "SHA1", 64: "SHA256", 128: "SHA512"}.get(L, "")

        if ht in {"SHA1", "SHA-1"}:
            return f"[file:hashes.'SHA-1' = '{hv}']"
        if ht in {"SHA256", "SHA-256"}:
            return f"[file:hashes.'SHA-256' = '{hv}']"
        if ht in {"SHA512", "SHA-512"}:
            return f"[file:hashes.'SHA-512' = '{hv}']"
        # default MD5
        return f"[file:hashes.MD5 = '{hv}']"

    def _to_stix_indicator(self, finding: Dict) -> Dict:
        indicator = finding.get("indicator")
        indicator_type = (finding.get("indicator_type") or "").strip().lower()
        verdict = str(finding.get("verdict", "")).upper()

        if not indicator or indicator_type not in {"ip", "domain", "hash", "url"}:
            return {}

        if indicator_type == "ip":
            # IPv4/IPv6 safe
            try:
                ip_obj = ipaddress.ip_address(str(indicator))
                stix_ip_type = "ipv6-addr" if ip_obj.version == 6 else "ipv4-addr"
                pattern = f"[{stix_ip_type}:value = '{indicator}']"
            except Exception:
                pattern = f"[ipv4-addr:value = '{indicator}']"
            name = "IOC: IP"
            phase_name = "command-and-control"

        elif indicator_type == "domain":
            pattern = f"[domain-name:value = '{indicator}']"
            name = "IOC: Domain"
            phase_name = "command-and-control"

        elif indicator_type == "url":
            pattern = f"[url:value = '{indicator}']"
            name = "IOC: URL"
            phase_name = "delivery"

        else:
            # hash
            pattern = self._hash_stix_pattern(str(indicator), finding.get("hash_type"))
            name = "IOC: File Hash"
            phase_name = "execution"

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "name": name,
            "description": f"Threat intel enrichment verdict={verdict}",
            "indicator_types": ["malicious-activity"],
            "pattern_type": "stix",
            "pattern": pattern,
            "valid_from": "2025-01-01T00:00:00Z",
            "confidence": int(finding.get("reputation_score", 50) or 50),
            "labels": finding.get("tags", []) or [indicator_type, verdict.lower() if verdict else "unknown"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": phase_name}],
        }

    def _to_stix_threat_actor(self, actor_name: str, finding: Dict) -> Dict:
        # Only used when attribution enabled
        labels = ["unknown-threat-actor"]
        return {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{uuid.uuid4()}",
            "name": actor_name,
            "threat_actor_types": ["crime-syndicate"],
            "first_seen": "2024-09-01T00:00:00Z",
            "goals": ["financial-gain"],
            "sophistication": "advanced",
            "labels": labels,
        }

    def _to_stix_relationship(self, source_ref: str, target_ref: str) -> Dict:
        # Only used when attribution enabled
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid4()}",
            "relationship_type": "indicates",
            "source_ref": source_ref,
            "target_ref": target_ref,
        }