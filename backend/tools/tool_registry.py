from __future__ import annotations

from typing import Dict, Any, Optional
from datetime import datetime
import uuid
import os
from loguru import logger

from backend.tools.kql_tool import SentinelKQLTool
from backend.tools.spl_tool import SplunkSPLTool
from backend.tools.ioc_tool import IOCTool
from backend.tools.asset_tool import AssetTool

from backend.connectors.splunk_connector import SplunkConnector

SENTINEL_ENABLED = os.getenv("SENTINEL_ENABLED", "false").lower() == "true"
if SENTINEL_ENABLED:
    from backend.connectors.sentinel_connector import SentinelConnector  # type: ignore


TOOL_SCHEMAS = [
    {
        "name": "enrich_ioc",
        "description": "Enrich an IOC with threat intel (ip/domain/hash/url).",
        "parameters": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string"},
                "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "url"]},
            },
            "required": ["indicator", "indicator_type"],
        },
    },
    {
        "name": "lookup_asset",
        "description": "Look up asset information by IP or hostname from CMDB.",
        "parameters": {
            "type": "object",
            "properties": {"ip_address": {"type": "string"}},
            "required": ["ip_address"],
        },
    },
    {
        "name": "generate_sentinel_kql",
        "description": "Generate Microsoft Sentinel KQL (read-only).",
        "parameters": {
            "type": "object",
            "properties": {
                "incident_type": {"type": "string"},
                "affected_asset": {"type": "string"},
                "entities": {"type": "array", "items": {"type": "object"}},
                "time_window_hours": {"type": "integer", "default": 24},
                "asset_class": {"type": "string"},
            },
            "required": ["incident_type", "affected_asset"],
        },
    },
    {
        "name": "generate_splunk_spl",
        "description": "Generate Splunk SPL investigation queries (read-only).",
        "parameters": {
            "type": "object",
            "properties": {
                "incident_type": {"type": "string"},
                "affected_asset": {"type": "string"},
                "entities": {"type": "array", "items": {"type": "object"}},
                "time_window_hours": {"type": "integer", "default": 24},
            },
            "required": ["incident_type", "affected_asset"],
        },
    },
    {
        "name": "execute_splunk_spl",
        "description": "Execute a Splunk SPL query via REST API (read-only).",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "earliest_time": {"type": "string", "default": "-24h"},
                "latest_time": {"type": "string", "default": "now"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "execute_sentinel_kql",
        "description": "Execute a Sentinel/Log Analytics KQL query (dev-only via Azure CLI auth).",
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string"}, "time_window_hours": {"type": "integer", "default": 24}},
            "required": ["query"],
        },
    },
]

TOOL_POLICIES = {
    "enrich_ioc": {"mode": "read", "requires_approval": False},
    "lookup_asset": {"mode": "read", "requires_approval": False},
    "generate_sentinel_kql": {"mode": "read", "requires_approval": False},
    "generate_splunk_spl": {"mode": "read", "requires_approval": False},
    "execute_splunk_spl": {"mode": "read", "requires_approval": False},
    "execute_sentinel_kql": {"mode": "read", "requires_approval": False},
}


class ToolRegistry:
    """Tool execution engine with standardized response envelopes."""

    def __init__(self):
        self.schemas = TOOL_SCHEMAS
        self.schema_map = {s["name"]: s for s in TOOL_SCHEMAS}
        self.policy_map = TOOL_POLICIES

        self.kql_tool = SentinelKQLTool()
        self.spl_tool = SplunkSPLTool()
        self.ioc_tool = IOCTool()
        self.asset_tool = AssetTool()

        try:
            self.splunk = SplunkConnector()
        except Exception:
            self.splunk = None

        self.sentinel = None
        if SENTINEL_ENABLED:
            try:
                self.sentinel = SentinelConnector()
            except Exception:
                self.sentinel = None

    def execute_tool(self, tool_name: str, parameters: Dict) -> Dict:
        tool_map = {
            "enrich_ioc": self._enrich_ioc,
            "lookup_asset": self._lookup_asset,
            "generate_sentinel_kql": self._generate_sentinel_kql,
            "generate_splunk_spl": self._generate_splunk_spl,
            "execute_splunk_spl": self._execute_splunk_spl,
            "execute_sentinel_kql": self._execute_sentinel_kql,
        }

        execution_id = f"TOOL-{uuid.uuid4().hex[:10].upper()}"
        logger.info(f"[Tools] Executing {tool_name} | execution_id={execution_id}")

        if tool_name not in tool_map:
            return self._envelope(False, execution_id, tool_name, f"Unknown tool: {tool_name}", None)

        validation_error = self._validate_required_parameters(tool_name, parameters)
        if validation_error:
            return self._envelope(False, execution_id, tool_name, validation_error, None)

        try:
            result = tool_map[tool_name](parameters)
            return self._envelope(True, execution_id, tool_name, None, result)
        except Exception as e:
            return self._envelope(False, execution_id, tool_name, str(e), None)

    def _validate_required_parameters(self, tool_name: str, parameters: Dict) -> Optional[str]:
        schema = self.schema_map.get(tool_name)
        if not schema:
            return f"No schema found for tool: {tool_name}"
        required = schema.get("parameters", {}).get("required", [])
        missing = []
        for field in required:
            if field not in parameters or parameters.get(field) in (None, "", [], {}):
                missing.append(field)
        if missing:
            return f"Missing required parameter(s) for {tool_name}: {missing}"
        return None

    def _envelope(self, success: bool, execution_id: str, tool: str, error: Optional[str], result: Any) -> Dict:
        return {
            "success": success,
            "execution_id": execution_id,
            "tool": tool,
            "error": error,
            "result": result,
            "executed_at": datetime.utcnow().isoformat(),
        }

    # ---- Tools ----

    def _enrich_ioc(self, params: Dict) -> Dict:
        return self.ioc_tool.enrich(params["indicator"], params["indicator_type"])

    def _lookup_asset(self, params: Dict) -> Dict:
        return self.asset_tool.lookup(params["ip_address"])

    def _generate_sentinel_kql(self, params: Dict) -> Dict:
        return self.kql_tool.generate(
            incident_type=params.get("incident_type"),
            affected_asset=params.get("affected_asset"),
            entities=params.get("entities") or [],
            time_window_hours=int(params.get("time_window_hours") or 24),
            asset_class=params.get("asset_class"),
        )

    def _generate_splunk_spl(self, params: Dict) -> Dict:
        return self.spl_tool.generate(
            incident_type=params.get("incident_type"),
            affected_asset=params.get("affected_asset"),
            entities=params.get("entities") or [],
            time_window_hours=int(params.get("time_window_hours") or 24),
        )

    def _execute_splunk_spl(self, params: Dict) -> Dict:
        q = params["query"]
        earliest = params.get("earliest_time") or "-24h"
        latest = params.get("latest_time") or "now"
        return self.splunk.execute_search(q, earliest_time=earliest, latest_time=latest)

    def _execute_sentinel_kql(self, params: Dict) -> Dict:
        if not self.sentinel:
            raise RuntimeError("Sentinel execution is disabled/unavailable. Set SENTINEL_ENABLED=true and ensure az login works.")
        q = params["query"]
        tw = int(params.get("time_window_hours") or 24)
        return self.sentinel.execute_kql(q, time_window_hours=tw)