from __future__ import annotations

import os
import json
import hashlib
from typing import Any, Dict, List, Tuple

MAX_ROWS = int(os.getenv("EVIDENCE_MAX_ROWS", "5000"))
MAX_BYTES = int(os.getenv("EVIDENCE_MAX_BYTES", "5000000"))

def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def cap_rows(rows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    warnings: List[str] = []
    capped = rows[:MAX_ROWS]
    if len(rows) > MAX_ROWS:
        warnings.append(f"Truncated rows to {MAX_ROWS} (from {len(rows)})")
    return capped, warnings

def cap_bytes(rows: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
    warnings: List[str] = []
    out: List[Dict[str, Any]] = []
    total = 0
    for r in rows:
        b = _canonical_json(r)
        if total + len(b) > MAX_BYTES:
            warnings.append(f"Truncated payload to {MAX_BYTES} bytes")
            break
        out.append(r)
        total += len(b)
    return out, warnings

def hash_rows(rows: List[Dict[str, Any]]) -> str:
    h = hashlib.sha256()
    h.update(_canonical_json(rows))
    return h.hexdigest()