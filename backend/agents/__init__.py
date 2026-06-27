"""
Agent Package
Multi-agent workflow system for SOC alert triage.

Agents:
- RouterAgent       → Classify alert: dismiss | enrich | escalate
- ThreatIntelAgent  → IOC enrichment & threat intelligence
- AssetAgent        → CMDB asset lookup & criticality
- HistoryAgent      → Past incident context retrieval
- AgentOrchestrator → Coordinator for parallel agent execution
"""

from backend.agents.router_agent import RouterAgent
from backend.agents.threat_intel_agent import ThreatIntelAgent
from backend.agents.asset_agent import AssetAgent
from backend.agents.history_agent import HistoryAgent
from backend.agents.orchestrator import AgentOrchestrator

__all__ = [
    "RouterAgent",
    "ThreatIntelAgent",
    "AssetAgent",
    "HistoryAgent",
    "AgentOrchestrator",
]