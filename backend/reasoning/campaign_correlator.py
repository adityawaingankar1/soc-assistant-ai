from __future__ import annotations

from typing import Dict, Any, List

from backend.graph.neo4j_client import (
    Neo4jClient
)


class CampaignCorrelator:

    def __init__(self):

        self.neo4j = Neo4jClient()

    def related_alerts(
        self,
        alert_id: str
    ) -> List[Dict[str, Any]]:

        q = """
        MATCH (a:Alert {id: $id})
              -[:OBSERVED]->
              (i)
              <-[:OBSERVED]-
              (related:Alert)

        WHERE related.id <> $id

        RETURN
            related.id as alert_id,
            count(i) as shared_iocs

        ORDER BY shared_iocs DESC
        LIMIT 10
        """

        with self.neo4j.session() as s:

            res = s.run(
                q,
                id=alert_id
            )

            return [
                dict(r)
                for r in res
            ]