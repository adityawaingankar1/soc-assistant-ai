"""
Incident Ticket Tool
Creates incident tickets in the ticketing system.
"""
from typing import Dict, Optional, List
from datetime import datetime, timedelta
import uuid
from loguru import logger


class TicketTool:
    TOOL_NAME = "create_incident_ticket"

    SLA_TIMELINES = {
        "CRITICAL": {"initial_response": 15, "acknowledgment": 30, "resolution_target": 240, "escalation_threshold": 60},
        "HIGH": {"initial_response": 30, "acknowledgment": 60, "resolution_target": 480, "escalation_threshold": 120},
        "MEDIUM": {"initial_response": 60, "acknowledgment": 120, "resolution_target": 1440, "escalation_threshold": 360},
        "LOW": {"initial_response": 240, "acknowledgment": 480, "resolution_target": 4320, "escalation_threshold": 1440}
    }

    ASSIGNMENT_ROUTING = {
        "ransomware": "incident-response-team@company.com",
        "data exfiltration": "incident-response-team@company.com",
        "phishing": "soc-tier2@company.com",
        "brute force": "soc-tier1@company.com",
        "lateral movement": "incident-response-team@company.com",
        "credential theft": "soc-tier2@company.com",
        "malware": "soc-tier2@company.com",
        "default": "soc-tier1@company.com"
    }

    _ticket_store: Dict = {}

    def create(
        self,
        alert_id: str,
        severity: str,
        attack_type: str,
        summary: str,
        affected_assets: Optional[List[str]] = None,
        assigned_team: Optional[str] = None,
        additional_notes: Optional[str] = None
    ) -> Dict:
        logger.info(f"[Ticket] Creating incident ticket for alert {alert_id} - {severity}")

        alert_id = (alert_id or "").strip()
        severity_upper = (severity or "MEDIUM").upper().strip()
        attack_type = (attack_type or "Unknown").strip()
        summary = (summary or "").strip()

        if not alert_id:
            return self._error("alert_id is required")

        if severity_upper not in self.SLA_TIMELINES:
            severity_upper = "MEDIUM"

        if not summary:
            return self._error("summary is required")

        ticket_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        sla = self.SLA_TIMELINES[severity_upper]
        created_at = datetime.utcnow()

        if not assigned_team:
            attack_lower = attack_type.lower()
            assigned_team = next(
                (
                    team for keyword, team in self.ASSIGNMENT_ROUTING.items()
                    if keyword != "default" and keyword in attack_lower
                ),
                self.ASSIGNMENT_ROUTING["default"]
            )

        ticket = {
            "ticket_id": ticket_id,
            "tool": self.TOOL_NAME,
            "status": "open",
            "source_alert_id": alert_id,
            "severity": severity_upper,
            "priority": self._severity_to_priority(severity_upper),
            "attack_type": attack_type,
            "title": f"[{severity_upper}] {attack_type} - {summary[:80]}",
            "summary": summary[:500],
            "affected_assets": affected_assets or [],
            "assigned_to": assigned_team,
            "created_by": "SOC Assistant (Automated)",
            "created_at": created_at.isoformat(),
            "updated_at": created_at.isoformat(),
            "sla": {
                "initial_response_by": self._add_minutes(created_at, sla["initial_response"]),
                "acknowledgment_by": self._add_minutes(created_at, sla["acknowledgment"]),
                "resolution_target": self._add_minutes(created_at, sla["resolution_target"]),
                "escalation_at": self._add_minutes(created_at, sla["escalation_threshold"])
            },
            "url": f"https://tickets.company.com/incidents/{ticket_id}",
            "escalation_path": self._get_escalation_path(severity_upper),
            "checklist": self._get_response_checklist(attack_type),
            "additional_notes": additional_notes or "",
            "tags": [attack_type.lower().replace(" ", "-"), severity_upper.lower()],
            "playbook_url": f"https://wiki.company.com/runbooks/{attack_type.lower().replace(' ', '-')}",
            "success": True
        }

        self._ticket_store[ticket_id] = ticket
        logger.info(f"[Ticket] Created {ticket_id} - Assigned to {assigned_team}")
        return ticket

    def get_ticket(self, ticket_id: str) -> Optional[Dict]:
        return self._ticket_store.get(ticket_id)

    def update_ticket(self, ticket_id: str, status: str, notes: str = "") -> Dict:
        if ticket_id not in self._ticket_store:
            return self._error(f"Ticket {ticket_id} not found")

        self._ticket_store[ticket_id]["status"] = status
        self._ticket_store[ticket_id]["updated_at"] = datetime.utcnow().isoformat()

        if notes:
            self._ticket_store[ticket_id]["additional_notes"] += (
                f"\n[{datetime.utcnow().isoformat()}] {notes}"
            )

        return self._ticket_store[ticket_id]

    def _severity_to_priority(self, severity: str) -> int:
        return {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}.get(severity, 3)

    def _add_minutes(self, base_time: datetime, minutes: int) -> str:
        return (base_time + timedelta(minutes=minutes)).isoformat()

    def _get_escalation_path(self, severity: str) -> List[str]:
        paths = {
            "CRITICAL": [
                "soc-tier1@company.com",
                "soc-tier2@company.com",
                "incident-response-team@company.com",
                "ciso@company.com"
            ],
            "HIGH": [
                "soc-tier1@company.com",
                "soc-tier2@company.com",
                "incident-response-team@company.com"
            ],
            "MEDIUM": [
                "soc-tier1@company.com",
                "soc-tier2@company.com"
            ],
            "LOW": [
                "soc-tier1@company.com"
            ]
        }
        return paths.get(severity, paths["MEDIUM"])

    def _get_response_checklist(self, attack_type: str) -> List[Dict]:
        base_checklist = [
            {"step": 1, "action": "Acknowledge alert and assign to analyst", "completed": False},
            {"step": 2, "action": "Confirm alert is not a false positive", "completed": False},
            {"step": 3, "action": "Determine blast radius (affected systems)", "completed": False},
            {"step": 4, "action": "Notify stakeholders per communication plan", "completed": False}
        ]

        attack_specific = {
            "ransomware": [
                {"step": 5, "action": "IMMEDIATELY isolate all affected endpoints", "completed": False},
                {"step": 6, "action": "Identify patient zero (initial infection vector)", "completed": False},
                {"step": 7, "action": "Check backup integrity before recovery", "completed": False}
            ],
            "phishing": [
                {"step": 5, "action": "Quarantine phishing email across all mailboxes", "completed": False},
                {"step": 6, "action": "Identify all users who received/clicked", "completed": False},
                {"step": 7, "action": "Block sender domain and embedded URLs", "completed": False}
            ],
            "lateral movement": [
                {"step": 5, "action": "Map the lateral movement path", "completed": False},
                {"step": 6, "action": "Identify compromised credentials", "completed": False},
                {"step": 7, "action": "Reset compromised credentials immediately", "completed": False}
            ]
        }

        attack_lower = attack_type.lower()
        for keyword, extra_steps in attack_specific.items():
            if keyword in attack_lower:
                return base_checklist + extra_steps

        return base_checklist

    def _error(self, message: str) -> Dict:
        return {
            "success": False,
            "tool": self.TOOL_NAME,
            "error": message,
            "executed_at": datetime.utcnow().isoformat()
        }

    def get_schema(self) -> Dict:
        return {
            "name": self.TOOL_NAME,
            "description": "Create a formal incident ticket in the ticketing system. Automatically assigns to appropriate team, sets SLA deadlines, and generates response checklist.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_id": {"type": "string", "description": "The source alert ID this ticket is created for"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"], "description": "Incident severity level"},
                    "attack_type": {"type": "string", "description": "Type of security incident"},
                    "summary": {"type": "string", "description": "Brief incident description (max 500 characters)"},
                    "affected_assets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of affected hostnames or IP addresses"
                    }
                },
                "required": ["alert_id", "severity", "attack_type", "summary"]
            }
        }