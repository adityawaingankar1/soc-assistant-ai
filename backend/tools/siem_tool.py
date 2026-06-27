"""
SIEM Tool
Queries the SIEM for events related to a given alert ID or time window.
"""
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import uuid
from loguru import logger


class SIEMTool:
    TOOL_NAME = "query_siem"

    MOCK_EVENTS = {
        "authentication": [
            {
                "event_type": "authentication_failure",
                "source_ip": "10.0.1.50",
                "destination": "SRV-DC-01",
                "user": "john.smith",
                "failure_reason": "InvalidPassword",
                "count": 47
            },
            {
                "event_type": "authentication_success",
                "source_ip": "10.0.1.50",
                "destination": "SRV-DC-01",
                "user": "john.smith",
                "note": "Success after 47 failures — possible brute force"
            }
        ],
        "process": [
            {
                "event_type": "process_creation",
                "process": "cmd.exe",
                "parent_process": "outlook.exe",
                "command_line": "cmd.exe /c whoami && net user",
                "user": "john.smith",
                "pid": 4821
            },
            {
                "event_type": "process_creation",
                "process": "powershell.exe",
                "parent_process": "cmd.exe",
                "command_line": "powershell -enc JABjAGwAaQBlAG4AdAAgAD0A...",
                "note": "Encoded PowerShell — possible download cradle"
            }
        ],
        "network": [
            {
                "event_type": "dns_query",
                "domain": "evil-domain.ru",
                "query_type": "A",
                "source_ip": "10.0.1.50",
                "resolved_ip": "91.234.199.10"
            },
            {
                "event_type": "outbound_connection",
                "destination_ip": "91.234.199.10",
                "destination_port": 443,
                "bytes_sent": 4096,
                "bytes_received": 128000,
                "protocol": "HTTPS",
                "note": "Unusual data volume to unknown external IP"
            }
        ],
        "file": [
            {
                "event_type": "file_modification",
                "file_path": "C:\\Users\\john.smith\\Documents\\invoice.docm",
                "operation": "write",
                "process": "WINWORD.EXE"
            },
            {
                "event_type": "file_creation",
                "file_path": "C:\\Windows\\Temp\\svchost32.exe",
                "hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
                "note": "Suspicious executable dropped in Temp directory"
            }
        ]
    }

    def query(
        self,
        alert_id: str,
        time_window_hours: int = 24,
        event_categories: Optional[List[str]] = None
    ) -> Dict:
        logger.info(f"[SIEM] Querying alert_id={alert_id}, window={time_window_hours}h")

        alert_id = (alert_id or "").strip()
        if not alert_id:
            return self._error("alert_id is required")

        if time_window_hours < 1 or time_window_hours > 168:
            time_window_hours = 24

        if event_categories:
            categories = [c for c in event_categories if c in self.MOCK_EVENTS]
        else:
            categories = list(self.MOCK_EVENTS.keys())

        events = []
        base_time = datetime.utcnow() - timedelta(hours=time_window_hours)

        for i, category in enumerate(categories):
            for j, event in enumerate(self.MOCK_EVENTS[category]):
                event_time = base_time + timedelta(minutes=(i * 10 + j * 3))
                events.append({
                    "event_id": f"EVT-{uuid.uuid4().hex[:8].upper()}",
                    "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "category": category,
                    **event
                })

        events.sort(key=lambda x: x["timestamp"])

        result = {
            "success": True,
            "tool": self.TOOL_NAME,
            "alert_id": alert_id,
            "query_time_utc": datetime.utcnow().isoformat(),
            "time_window_hours": time_window_hours,
            "total_events_found": len(events),
            "events": events,
            "summary": self._generate_summary(events),
            "risk_signals": self._detect_risk_signals(events)
        }

        logger.info(f"[SIEM] Found {len(events)} events for alert {alert_id}")
        return result

    def _generate_summary(self, events: List[Dict]) -> str:
        type_counts = {}
        for event in events:
            etype = event.get("event_type", "unknown")
            type_counts[etype] = type_counts.get(etype, 0) + 1
        summary_parts = [f"{count} {etype}" for etype, count in type_counts.items()]
        return f"Found: {', '.join(summary_parts)}"

    def _detect_risk_signals(self, events: List[Dict]) -> List[str]:
        signals = []
        event_types = [e.get("event_type", "") for e in events]

        if "authentication_failure" in event_types and "authentication_success" in event_types:
            signals.append("Brute force success pattern: failures followed by successful login")

        if any("encoded" in str(e.get("command_line", "")).lower() for e in events):
            signals.append("Encoded command detected — possible obfuscation")

        if any(e.get("parent_process", "") == "outlook.exe" for e in events):
            signals.append("Process spawned from email client — possible phishing execution")

        if any("Temp" in str(e.get("file_path", "")) for e in events):
            signals.append("Executable dropped in Temp directory — suspicious")

        if any(e.get("event_type") == "outbound_connection" for e in events):
            signals.append("Outbound connection to external IP detected")

        return signals

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
            "description": "Query the SIEM for additional events related to an alert ID. Returns related authentication, process, network, and file events.",
            "parameters": {
                "type": "object",
                "properties": {
                    "alert_id": {
                        "type": "string",
                        "description": "The SIEM alert or event ID to query"
                    },
                    "time_window_hours": {
                        "type": "integer",
                        "description": "How many hours back to search for related events",
                        "default": 24
                    },
                    "event_categories": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["authentication", "process", "network", "file"]},
                        "description": "Filter results by event category"
                    }
                },
                "required": ["alert_id"]
            }
        }