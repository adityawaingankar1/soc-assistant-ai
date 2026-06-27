from __future__ import annotations

import os
from neo4j import GraphDatabase
from loguru import logger


class Neo4jClient:
    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "").strip()
        self.user = os.getenv("NEO4J_USER", "").strip()
        self.password = os.getenv("NEO4J_PASSWORD", "").strip()
        self.database = os.getenv("NEO4J_DATABASE", "neo4j").strip()

        if not all([self.uri, self.user, self.password]):
            logger.warning("[Neo4j] disabled — missing credentials")
            self.disabled = True
            self.driver = None
            return

        self.disabled = False
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))

    def close(self):
        if getattr(self, "disabled", False):
            return
        if self.driver:
            self.driver.close()

    def run(self, cypher: str, params: dict | None = None):
        if getattr(self, "disabled", False):
            return None
        with self.driver.session(database=self.database) as session:
            return list(session.run(cypher, params or {}))