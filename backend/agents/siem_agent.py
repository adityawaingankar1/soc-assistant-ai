import asyncio
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timezone
from loguru import logger
from backend.tools.siem_tool import SIEMTool


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts or not isinstance(ts, str):
        return None
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts)
    except Exception:
        return None


class SIEMAgent:
    """
    SIEM context agent (mock).
    Trust hardening:
    - Evidence scoping / linkage enforcement
    - Unlinked events quarantined as "environment signals"
    - IOC provenance from linked SIEM events
    """

    def __init__(self):
        self.siem_tool = SIEMTool()

    async def get_context(self, alert_data: Dict) -> Dict[str, Any]:
        await asyncio.sleep(0.05)

        alert_id = str(alert_data.get("alert_id") or "").strip()
        if not alert_id:
            return {"status": "no_alert_id", "error": "alert_id missing"}

        affected_asset = str(alert_data.get("affected_asset") or "").strip()
        alert_ts = _parse_ts(alert_data.get("timestamp"))
        if alert_ts and alert_ts.tzinfo is None:
            alert_ts = alert_ts.replace(tzinfo=timezone.utc)

        asset_hostnames = {affected_asset.lower()} if affected_asset else set()
        asset_ips = set()

        try:
            res = await asyncio.to_thread(
                self.siem_tool.query,
                alert_id=alert_id,
                time_window_hours=24,
                event_categories=None
            )
        except Exception as e:
            logger.error(f"[SIEMAgent] Query failed: {e}")
            return {"status": "failed", "error": str(e)}

        events = res.get("events") or []
        if not isinstance(events, list):
            events = []

        linked, unlinked = self._scope_events(
            events=events,
            asset_hostnames=asset_hostnames,
            asset_ips=asset_ips,
            alert_ts=alert_ts
        )

        linked_signals = self._detect_risk_signals(linked)
        linked_signal_ids = self._detect_signal_ids(linked)

        linked_iocs = self._extract_iocs_from_events(linked)
        discovered_entities = self._iocs_to_entities(linked_iocs)

        unlinked_signals = self._detect_risk_signals(unlinked)
        unlinked_signal_ids = self._detect_signal_ids(unlinked)

        return {
            "status": "ok",
            "scope": {
                "affected_asset": affected_asset,
                "asset_hostnames": sorted(list(asset_hostnames)),
                "asset_ips": sorted(list(asset_ips)),
                "alert_timestamp": alert_data.get("timestamp"),
                "linkage_policy": "Require 2+ join keys (host/ip/time) to link SIEM events to this alert"
            },
            "linked": {
                "total_events": len(linked),
                "sample_events": linked[:12],
                "signals": linked_signals,            # human-readable
                "signal_ids": linked_signal_ids,      # stable IDs (for routing/scoring)
                "discovered_iocs": linked_iocs,
                "discovered_entities": discovered_entities
            },
            "environment_unlinked": {
                "total_events": len(unlinked),
                "sample_events": unlinked[:6],
                "signals": unlinked_signals,
                "signal_ids": unlinked_signal_ids,
                "note": "Events exist in the environment but cannot be reliably tied to this alert scope yet."
            }
        }

    def _scope_events(
        self,
        events: List[Dict[str, Any]],
        asset_hostnames: set,
        asset_ips: set,
        alert_ts: Optional[datetime]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Linkage requirement: 2+ join keys (host/ip/time).
        - host match: destination/hostname/device fields contain affected asset
        - ip match: any ip field matches asset_ips (if available)
        - time match: within +/- 2h of alert timestamp (if available)
        """
        linked: List[Dict[str, Any]] = []
        unlinked: List[Dict[str, Any]] = []

        for e in events or []:
            if not isinstance(e, dict):
                continue

            join_keys = 0

            host_fields = [
                str(e.get("destination") or ""),
                str(e.get("hostname") or ""),
                str(e.get("device") or ""),
                str(e.get("asset") or "")
            ]
            host_blob = " ".join([h.lower() for h in host_fields if h]).strip()
            if host_blob and any(h in host_blob for h in asset_hostnames):
                join_keys += 1

            ip_fields = [
                str(e.get("source_ip") or ""),
                str(e.get("destination_ip") or ""),
                str(e.get("resolved_ip") or "")
            ]
            if asset_ips and any(ip in asset_ips for ip in ip_fields):
                join_keys += 1

            if alert_ts is not None:
                et = _parse_ts(e.get("timestamp"))
                if et and et.tzinfo is None:
                    et = et.replace(tzinfo=timezone.utc)
                if et:
                    delta = abs((et - alert_ts).total_seconds())
                    if delta <= 2 * 3600:
                        join_keys += 1

            if join_keys >= 2:
                linked.append(e)
            else:
                unlinked.append(e)

        return linked, unlinked

    def _detect_risk_signals(self, events: List[Dict[str, Any]]) -> List[str]:
        signals = []
        event_types = [str(e.get("event_type", "")) for e in events]

        if "authentication_failure" in event_types and "authentication_success" in event_types:
            signals.append("Brute force success pattern: failures followed by successful login")
        if any("encoded" in str(e.get("command_line", "")).lower() for e in events):
            signals.append("Encoded command detected — possible obfuscation")
        if any(str(e.get("parent_process", "")).lower() == "outlook.exe" for e in events):
            signals.append("Process spawned from email client — possible phishing execution")
        if any("temp" in str(e.get("file_path", "")).lower() for e in events):
            signals.append("Executable dropped in Temp directory — suspicious")
        if any(str(e.get("event_type")) == "outbound_connection" for e in events):
            signals.append("Outbound connection to external IP detected")

        return signals

    def _detect_signal_ids(self, events: List[Dict[str, Any]]) -> List[str]:
        ids: List[str] = []

        def add(x: str):
            if x not in ids:
                ids.append(x)

        etypes = [str(e.get("event_type", "")) for e in events or []]

        if "authentication_failure" in etypes and "authentication_success" in etypes:
            add("BRUTEFORCE_SUCCESS")

        if any("encoded" in str(e.get("command_line", "")).lower() for e in events or []):
            add("ENCODED_COMMAND")

        if any(str(e.get("event_type")) == "outbound_connection" for e in events or []):
            add("OUTBOUND_CONNECTION")

        # Conservative hint (you can tighten later once you ingest real EDR telemetry)
        if any("vssadmin" in str(e.get("command_line", "")).lower() for e in events or []):
            add("VSS_DELETE")

        return ids

    def _extract_iocs_from_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        IOC provenance: enrichment (SIEM linked).
        Only returns enforceable IOC types: ip/domain/url/hash where present.
        """
        out = []
        seen = set()

        def add(t: str, v: str):
            key = (t, v.lower())
            if v and key not in seen:
                seen.add(key)
                out.append({"type": t, "value": v, "source": "siem_linked"})

        for e in events or []:
            if not isinstance(e, dict):
                continue
            if e.get("destination_ip"):
                add("ip", str(e["destination_ip"]))
            if e.get("source_ip"):
                add("ip", str(e["source_ip"]))
            if e.get("resolved_ip"):
                add("ip", str(e["resolved_ip"]))
            if e.get("domain"):
                add("domain", str(e["domain"]).lower())
            if e.get("url"):
                add("url", str(e["url"]))
            if e.get("hash_md5"):
                add("hash", str(e["hash_md5"]).lower())
            if e.get("hash_sha256"):
                add("hash", str(e["hash_sha256"]).lower())

        return out

    def _iocs_to_entities(self, linked_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for i in linked_iocs or []:
            if not isinstance(i, dict):
                continue
            t = (i.get("type") or "").strip().lower()
            v = (i.get("value") or "").strip()
            if not t or not v:
                continue
            out.append({
                "entity_type": t,
                "value": v,
                "normalized": v,
                "source": i.get("source") or "siem_linked"
            })
        return out