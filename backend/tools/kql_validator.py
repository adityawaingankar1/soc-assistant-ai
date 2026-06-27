from __future__ import annotations

from typing import Dict, Any, List, Set
import re

TABLE_RX = re.compile(r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\n\s*\|")

# Operators/patterns that are commonly blocked in enterprise KQL execution contexts
# (or are risky because they can pull external content / run advanced execution).
FORBIDDEN_PATTERNS = [
    "externaldata",
    "invoke",
    "evaluate",
    "search *",
    "union *",
]


def extract_tables_from_kql(kql: str) -> Set[str]:
    if not kql:
        return set()
    return set(TABLE_RX.findall(kql))


def validate_kql_queries(queries: List[Dict[str, Any]], allowed_tables: List[str]) -> Dict[str, Any]:
    """
    Validates the generated KQL for sanity:
    - time filter presence (warn)
    - table usage matches selected table set (warn)
    - forbidden/dangerous operators (warn)
    """
    allowed = set(allowed_tables or [])
    warnings: List[str] = []
    all_tables: Set[str] = set()

    if not queries:
        return {"ok": False, "warnings": ["No queries were generated."], "tables": []}

    for q in queries:
        name = q.get("name") or "Unnamed"
        body = str(q.get("query") or "")

        tables = extract_tables_from_kql(body)
        all_tables |= tables

        # Time filter sanity check
        if ("ago(" not in body) and ("TimeGenerated >" not in body) and ("Timestamp >" not in body):
            warnings.append(f"Query '{name}' may be missing a time filter.")

        # Table allowlist check
        if allowed:
            unexpected = sorted([t for t in tables if t not in allowed])
            if unexpected:
                warnings.append(f"Query '{name}' references tables outside selected set: {unexpected}")

        # Forbidden operator/pattern check
        body_l = body.lower()
        for pattern in FORBIDDEN_PATTERNS:
            if pattern.lower() in body_l:
                warnings.append(
                    f"Query '{name}' contains potentially dangerous operator: {pattern}"
                )

    return {
        "ok": True,
        "warnings": warnings[:8],
        "tables": sorted(list(all_tables)),
    }