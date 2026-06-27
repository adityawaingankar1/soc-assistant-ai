"""
Tools Package
Simulated SOC tool integrations.

Tools:
- SIEMTool        → Query SIEM for related events
- IOCTool         → Enrich indicators of compromise
- AssetTool       → Lookup asset by IP or hostname
- TicketTool      → Create incident tickets
- IsolateTool     → Isolate compromised endpoints
- ToolRegistry    → Central dispatcher for all tools
"""

from backend.tools.tool_registry import ToolRegistry, TOOL_SCHEMAS
from backend.tools.siem_tool import SIEMTool
from backend.tools.ioc_tool import IOCTool
from backend.tools.asset_tool import AssetTool
from backend.tools.ticket_tool import TicketTool
from backend.tools.isolate_tool import IsolateTool

__all__ = [
    "ToolRegistry",
    "TOOL_SCHEMAS",
    "SIEMTool",
    "IOCTool",
    "AssetTool",
    "TicketTool",
    "IsolateTool",
]