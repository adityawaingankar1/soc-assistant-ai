import asyncio
from typing import Dict
from loguru import logger
from backend.tools.asset_tool import AssetTool


class AssetAgent:
    """
    Asset lookup and classification agent.

    UPDATED:
    - Preserve existing keys used by the app
    - Add asset_class + edr_available hints (non-breaking additions)
    """

    def __init__(self):
        self.asset_tool = AssetTool()

    async def lookup(self, alert_data: Dict) -> Dict:
        await asyncio.sleep(0.1)

        asset_id = str(alert_data.get("affected_asset", "") or "").strip()
        severity = str(alert_data.get("severity", "MEDIUM") or "MEDIUM").upper()

        result = self.asset_tool.lookup(asset_id)

        if not isinstance(result, dict):
            logger.warning("[Asset] AssetTool returned invalid result")
            return {
                "found": False,
                "asset_id_searched": asset_id,
                "risk_multiplier": 1.0,
                "risk_tier": "MEDIUM",
                "risk_factors": ["Asset lookup returned invalid result"],
                "note": "Asset lookup failed",
                "asset_class": "unknown",
                "edr_available": True
            }

        risk_assessment = result.get("risk_assessment", {}) or {}

        normalized = {
            "found": bool(result.get("found", False)),
            "asset_id_searched": asset_id,
            "asset_details": result if result.get("found") else None,
            "risk_multiplier": float(risk_assessment.get("incident_priority_multiplier", 1.0) or 1.0),
            "risk_tier": risk_assessment.get("risk_level", "MEDIUM"),
            "risk_factors": risk_assessment.get("risk_factors", []),
            "risk_assessment": risk_assessment,
            "isolation_recommended": bool(risk_assessment.get("isolation_recommended", False)),
            "note": result.get("message") or result.get("note") or "Asset lookup completed",
            "recommendation": result.get("recommendation", ""),
        }

        # Non-breaking additions
        normalized["asset_class"] = self._infer_asset_class(asset_id, result)
        normalized["edr_available"] = bool(result.get("edr_available", True))

        # Severity-aware boost for unmanaged critical alerts
        if not normalized["found"] and severity == "CRITICAL" and normalized["risk_multiplier"] < 4.0:
            normalized["risk_multiplier"] = 4.68
            normalized["risk_tier"] = "CRITICAL"
            normalized["isolation_recommended"] = True
            normalized["risk_factors"] = list(normalized["risk_factors"]) + [
                "Severity-aware escalation override applied for unmanaged critical alert"
            ]
            normalized["risk_assessment"] = {
                **risk_assessment,
                "incident_priority_multiplier": 4.68,
                "risk_level": "CRITICAL",
                "isolation_recommended": True,
                "risk_factors": normalized["risk_factors"]
            }

        if normalized["found"]:
            logger.info(
                f"[Asset] Found asset: {result.get('hostname', asset_id)} "
                f"(multiplier={normalized['risk_multiplier']}, tier={normalized['risk_tier']})"
            )
        else:
            logger.warning(
                f"[Asset] Unmanaged/unknown asset: {asset_id} "
                f"(multiplier={normalized['risk_multiplier']}, tier={normalized['risk_tier']})"
            )

        return normalized

    def _infer_asset_class(self, asset_id: str, asset_details: Dict) -> str:
        blob = " ".join([
            str(asset_id or ""),
            str(asset_details.get("hostname", "") or ""),
            str(asset_details.get("device_type", "") or ""),
            str(asset_details.get("category", "") or ""),
            str(asset_details.get("os", "") or ""),
        ]).lower()

        if any(k in blob for k in ["firewall", "vpn", "palo", "forti", "checkpoint", "edge", "gateway", "appliance"]):
            return "edge_appliance"
        if any(k in blob for k in ["m365", "office365", "entra", "azure ad", "okta", "saas"]):
            return "saas"
        if any(k in blob for k in ["server", "srv-", "dc", "domain controller"]):
            return "server"
        if any(k in blob for k in ["workstation", "laptop", "desktop", "ws-"]):
            return "endpoint"

        return "unknown"