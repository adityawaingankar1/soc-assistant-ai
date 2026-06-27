from __future__ import annotations

import os
from datetime import timedelta
from typing import Dict, Any
import asyncio

class SentinelConnector:
    """
    Optional DEV connector using Azure CLI auth.
    Enabled only when SENTINEL_ENABLED=true.
    """

    def __init__(self):
        self.enabled = os.getenv("SENTINEL_ENABLED", "false").lower() == "true"
        self.workspace_id = os.getenv("LOG_ANALYTICS_WORKSPACE_ID", "").strip()
        self.auth_mode = os.getenv("SENTINEL_AUTH_MODE", "azure_cli").strip().lower()

        if not self.enabled:
            self.disabled = True
            return
        self.disabled = False
        if not self.workspace_id:
            raise RuntimeError("Missing LOG_ANALYTICS_WORKSPACE_ID")
        if self.auth_mode != "azure_cli":
            raise RuntimeError("Only azure_cli auth supported in this mode")

        from azure.identity import AzureCliCredential
        from azure.monitor.query import LogsQueryClient
        self.cred = AzureCliCredential()
        self.client = LogsQueryClient(self.cred)

    async def execute_kql(self,query: str,time_window_hours: int = 24) -> Dict[str, Any]:
        def _run_query():
            resp = self.client.query_workspace(
                workspace_id=self.workspace_id,
                query=query,
                timespan=timedelta(
                    hours=int(time_window_hours)
                ),
            )
            out: Dict[str, Any] = {
                "status": str(resp.status),
                "tables": []
            }
            
            if resp.tables:
                
                for t in resp.tables:
                    
                    out["tables"].append({
                        "name": t.name,
                        "columns": [
                            c.name for c in t.columns
                        ],
                        
                        "rows": t.rows[:5000],
                        "row_count": len(t.rows),
                    })
            return out
        return await asyncio.to_thread(_run_query)