from __future__ import annotations
from typing import Dict, Any, List
from backend.graph.neo4j_client import Neo4jClient

class GraphBuilder:
    def __init__(self, client: Neo4jClient):
        self.client = client

    def upsert_alert(self, alert_id: str, asset: str, source: str, severity: str):
        self.client.run(
            """
            MERGE (a:Alert {id: $id})
            SET a.asset=$asset, a.source=$source, a.severity=$severity
            """,
            {"id": alert_id, "asset": asset, "source": source, "severity": severity},
        )

    def add_entities(self, alert_id: str, entities: List[Dict[str, Any]]):
        for e in entities or []:
            if not isinstance(e, dict):
                continue
            t = (e.get("entity_type") or e.get("type") or "unknown").strip().lower()
            v = (e.get("normalized") or e.get("value") or "").strip()
            if not v:
                continue

            label = {
                "ip": "IP",
                "domain": "Domain",
                "hash": "Hash",
                "url": "URL",
                "file_name": "File",
                "registry_key": "RegistryKey",
            }.get(t, "Entity")

            self.client.run(
                f"""
                MERGE (n:{label} {{value: $value}})
                WITH n
                MATCH (a:Alert {{id: $alert_id}})
                MERGE (a)-[:MENTIONS {{type: $type}}]->(n)
                """,
                {"alert_id": alert_id, "value": v, "type": t},
            )