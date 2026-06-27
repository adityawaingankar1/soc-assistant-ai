"""
Endpoint Isolation Tool
Network-isolates compromised endpoints via EDR.
⚠️ USE WITH CAUTION — This action disrupts business operations.
"""
from typing import Dict, List
from datetime import datetime
import uuid
from loguru import logger


class IsolateTool:
    """
    Simulated endpoint isolation tool.
    """

    TOOL_NAME = "isolate_endpoint"

    _isolation_store: Dict = {}

    HIGH_IMPACT_ASSETS = {
        "SRV-DC-01",
        "SRV-DB-01",
        "SRV-WEB-01",
        "SRV-BACKUP-01"
    }

    ISOLATION_TYPES = {
        "full": "Block ALL network traffic (allow only EDR telemetry)",
        "partial": "Block inbound/outbound except IT management subnet",
        "forensic": "Block outbound only — preserve inbound for forensic access"
    }

    def isolate(
        self,
        host_id: str,
        reason: str,
        isolation_type: str = "full",
        initiated_by: str = "SOC Assistant (Automated)",
        skip_safety_check: bool = False
    ) -> Dict:
        logger.warning(f"[Isolate] Isolation requested: {host_id} | Reason: {reason}")

        host_id = (host_id or "").strip()
        reason = (reason or "").strip()
        isolation_type = (isolation_type or "full").strip().lower()

        if not host_id:
            return self._error("host_id is required", host_id=host_id)

        if not reason:
            return self._error("reason is required", host_id=host_id)

        if isolation_type not in self.ISOLATION_TYPES:
            return self._error(
                f"Invalid isolation_type '{isolation_type}'. Must be one of: {list(self.ISOLATION_TYPES.keys())}",
                host_id=host_id
            )

        if not skip_safety_check and host_id.upper() in self.HIGH_IMPACT_ASSETS:
            logger.warning(f"[Isolate] High-impact asset detected: {host_id}")
            return {
                "success": False,
                "tool": self.TOOL_NAME,
                "host_id": host_id,
                "status": "REQUIRES_APPROVAL",
                "message": f"{host_id} is a high-impact asset. Manual approval required before isolation.",
                "approval_required_from": ["Senior SOC Analyst", "CISO"],
                "impact_assessment": self._assess_isolation_impact(host_id),
                "recommendation": "Escalate to incident response team for immediate review",
                "executed_at": datetime.utcnow().isoformat()
            }

        if host_id.upper() in self._isolation_store:
            existing = self._isolation_store[host_id.upper()]
            return {
                "success": True,
                "tool": self.TOOL_NAME,
                "host_id": host_id,
                "status": "ALREADY_ISOLATED",
                "message": f"Endpoint {host_id} was already isolated",
                "existing_isolation": existing,
                "executed_at": datetime.utcnow().isoformat()
            }

        action_id = f"ISO-{uuid.uuid4().hex[:10].upper()}"
        isolated_at = datetime.utcnow()

        isolation_record = {
            "action_id": action_id,
            "host_id": host_id,
            "status": "isolated",
            "isolation_type": isolation_type,
            "reason": reason,
            "initiated_by": initiated_by,
            "isolated_at": isolated_at.isoformat(),
            "network_status": "ISOLATED",
            "traffic_rules": self._get_traffic_rules(isolation_type),
            "edr_connection": "MAINTAINED",
            "business_impact": self._assess_isolation_impact(host_id),
            "reversal_token": f"DISO-{uuid.uuid4().hex[:16].upper()}",
            "reversal_instructions": {
                "steps": [
                    f"1. Confirm investigation complete for {host_id}",
                    "2. Verify no malware persistence remains",
                    f"3. De-isolate using original action_id={action_id}",
                    "4. Monitor endpoint for 24 hours post de-isolation"
                ],
                "requires_approval": True,
                "approval_level": "Senior SOC Analyst"
            },
            "audit_log": [
                {
                    "timestamp": isolated_at.isoformat(),
                    "action": "ISOLATED",
                    "actor": initiated_by,
                    "reason": reason
                }
            ]
        }

        self._isolation_store[host_id.upper()] = isolation_record

        logger.warning(
            f"[Isolate] {host_id} isolated successfully | "
            f"Action ID: {action_id} | Type: {isolation_type}"
        )

        return {
            "success": True,
            "tool": self.TOOL_NAME,
            "host_id": host_id,
            "status": "ISOLATED",
            "action_id": action_id,
            "isolation_type": isolation_type,
            "isolated_at": isolated_at.isoformat(),
            "message": f"Endpoint {host_id} has been successfully isolated from the network.",
            "edr_connection": "Maintained — forensic collection still possible",
            "next_steps": [
                "Collect forensic artifacts while endpoint is isolated",
                "Review EDR telemetry for full attack chain",
                "Run memory dump for malware analysis",
                "Do NOT de-isolate until investigation is complete"
            ],
            "business_impact": isolation_record["business_impact"],
            "reversal_token": isolation_record["reversal_token"],
            "soc_ticket_required": True,
            "executed_at": datetime.utcnow().isoformat()
        }

    def de_isolate(
        self,
        host_id: str,
        action_id: str,
        reversal_token: str,
        approved_by: str
    ) -> Dict:
        host_key = (host_id or "").upper()

        if host_key not in self._isolation_store:
            return self._error(f"No active isolation found for {host_id}", host_id=host_id)

        isolation = self._isolation_store[host_key]

        if isolation.get("reversal_token") != reversal_token:
            logger.error(f"[Isolate] Invalid reversal token for {host_id}")
            return {
                "success": False,
                "tool": self.TOOL_NAME,
                "host_id": host_id,
                "error": "Invalid reversal token — unauthorized de-isolation attempt",
                "security_alert": True,
                "executed_at": datetime.utcnow().isoformat()
            }

        isolation["audit_log"].append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": "DE_ISOLATED",
            "actor": approved_by,
            "reason": "Investigation complete — approved for de-isolation"
        })

        del self._isolation_store[host_key]

        return {
            "success": True,
            "tool": self.TOOL_NAME,
            "host_id": host_id,
            "status": "DE_ISOLATED",
            "message": f"Endpoint {host_id} has been restored to network",
            "de_isolated_at": datetime.utcnow().isoformat(),
            "approved_by": approved_by,
            "post_isolation_checklist": [
                "Monitor for 24 hours after de-isolation",
                "Verify no re-infection indicators",
                "Confirm all patches applied",
                "Update incident ticket with outcome"
            ]
        }

    def get_isolation_status(self, host_id: str) -> Dict:
        host_key = (host_id or "").upper()
        if host_key in self._isolation_store:
            record = self._isolation_store[host_key]
            return {
                "host_id": host_id,
                "is_isolated": True,
                "isolated_at": record["isolated_at"],
                "isolation_type": record["isolation_type"],
                "reason": record["reason"],
                "action_id": record["action_id"]
            }
        return {"host_id": host_id, "is_isolated": False}

    def _get_traffic_rules(self, isolation_type: str) -> List[str]:
        rules = {
            "full": [
                "BLOCK: All inbound traffic",
                "BLOCK: All outbound traffic",
                "ALLOW: EDR telemetry port 443 to EDR cloud",
                "ALLOW: Management traffic from IT admin VLAN"
            ],
            "partial": [
                "BLOCK: All traffic to/from internet",
                "BLOCK: Lateral movement to other subnets",
                "ALLOW: Traffic within IT admin VLAN",
                "ALLOW: DNS queries to internal DNS only",
                "ALLOW: EDR telemetry"
            ],
            "forensic": [
                "BLOCK: All outbound traffic",
                "ALLOW: All inbound traffic (for forensic access)",
                "ALLOW: EDR telemetry"
            ]
        }
        return rules.get(isolation_type, rules["full"])

    def _assess_isolation_impact(self, host_id: str) -> Dict:
        impact_db = {
            "SRV-DB-01": {
                "impact_level": "CRITICAL",
                "affected_services": ["Customer Portal", "Payment Processing", "Internal Apps"],
                "data_at_risk": "Customer PII, Financial Records",
                "estimated_users_affected": 500,
                "revenue_impact": "HIGH",
                "compliance_implications": ["PCI-DSS breach notification may be required"]
            },
            "SRV-DC-01": {
                "impact_level": "CRITICAL",
                "affected_services": ["All Active Directory authentication", "Internal DNS", "Group Policies"],
                "estimated_users_affected": 350,
                "note": "Isolating DC will prevent all domain logins"
            },
            "SRV-WEB-01": {
                "impact_level": "HIGH",
                "affected_services": ["Public website", "Customer-facing APIs"],
                "estimated_users_affected": 10000,
                "revenue_impact": "HIGH"
            }
        }

        default_impact = {
            "impact_level": "MEDIUM",
            "affected_services": ["Unknown — check with asset owner"],
            "estimated_users_affected": 1,
            "revenue_impact": "LOW",
            "recommendation": "Proceed with isolation — limited blast radius expected"
        }

        return impact_db.get(host_id.upper(), default_impact)

    def _error(self, message: str, **kwargs) -> Dict:
        return {
            "success": False,
            "tool": self.TOOL_NAME,
            "error": message,
            "executed_at": datetime.utcnow().isoformat(),
            **kwargs
        }

    def get_schema(self) -> Dict:
        return {
            "name": self.TOOL_NAME,
            "description": "Network-isolate a compromised endpoint via EDR to stop threat propagation. USE ONLY FOR CONFIRMED CRITICAL THREATS.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host_id": {
                        "type": "string",
                        "description": "Hostname or host ID of the endpoint to isolate"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Specific reason for isolation"
                    },
                    "isolation_type": {
                        "type": "string",
                        "enum": ["full", "partial", "forensic"],
                        "description": "Type of isolation",
                        "default": "full"
                    }
                },
                "required": ["host_id", "reason"]
            }
        }