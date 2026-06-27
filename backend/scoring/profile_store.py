from __future__ import annotations
from typing import Dict, Any
from pathlib import Path
import json

class ScoringProfileStore:
    def __init__(self, path: Path | None = None):
        if path is None:
            path = Path(__file__).resolve().parent / "scoring_profiles.json"
        self.path = path
        self._cache: Dict[str, Any] | None = None
        self._mtime: float | None = None

    def _load(self) -> Dict[str, Any]:
        mtime = self.path.stat().st_mtime
        if self._cache is not None and self._mtime == mtime:
            return self._cache
        self._cache = json.loads(self.path.read_text(encoding="utf-8"))
        self._mtime = mtime
        return self._cache

    def get_profile(self, incident_type: str) -> Dict[str, Any]:
        data = self._load()
        it = (incident_type or "INVESTIGATE").strip().upper()
        base = dict(data.get("default") or {})
        specific = dict(data.get(it) or {})
        # Merge: specific overrides base keys; lists are replaced intentionally
        base.update(specific)
        return base