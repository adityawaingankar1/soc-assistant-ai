from __future__ import annotations

from typing import Dict, Any

from loguru import logger

from backend.graph.neo4j_client import (
    Neo4jClient
)


class AttackGraphService:

    def __init__(self):

        self.neo4j = Neo4jClient()

    # =====================================================
    # INGEST ALERT
    # =====================================================

    def ingest_alert(
        self,
        alert_data: Dict[str, Any],
        analysis: Dict[str, Any]
    ):

        alert_id = alert_data.get("alert_id")

        asset = alert_data.get(
            "affected_asset"
        )

        severity = alert_data.get(
            "severity"
        )

        tx = self.neo4j.session()

        try:

            # ALERT NODE
            tx.run(
                """
                MERGE (a:Alert {id: $id})

                SET
                    a.severity = $severity,
                    a.asset = $asset
                """,
                id=alert_id,
                severity=severity,
                asset=asset,
            )

            # IOC ENTITIES
            entities = (
                analysis.get("enrichment_data", {})
                .get("entities", [])
            )

            for e in entities:

                etype = e.get("entity_type")

                value = e.get("normalized")

                if not etype or not value:
                    continue

                tx.run(
                    f"""
                    MERGE (i:{etype.upper()} {{
                        value: $value
                    }})

                    MERGE (a:Alert {{
                        id: $alert_id
                    }})

                    MERGE (a)-[:OBSERVED]->(i)
                    """,
                    value=value,
                    alert_id=alert_id,
                )

            # ATTACK TYPE
            attack_type = analysis.get(
                "attack_type"
            )

            if attack_type:

                tx.run(
                    """
                    MERGE (t:IncidentType {
                        name: $name
                    })

                    MERGE (a:Alert {
                        id: $alert_id
                    })

                    MERGE (a)-[:CLASSIFIED_AS]->(t)
                    """,
                    name=attack_type,
                    alert_id=alert_id,
                )

            logger.info(
                f"[Graph] Ingested alert "
                f"{alert_id}"
            )

        finally:

            tx.close()