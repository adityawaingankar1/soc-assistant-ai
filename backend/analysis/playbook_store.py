from __future__ import annotations
from typing import Dict, Any, List, Optional
from pathlib import Path
import json
import os
from loguru import logger


class PlaybookStore:
    """
    Playbook loader that supports BOTH:
    1) Flat layout: backend/playbooks/*.json   (your current setup)
    2) Profile layout: backend/playbooks/profiles/{profile}/*.json (optional)

    If profiles exist, it loads default then overlays active profile.
    Otherwise it loads flat playbooks.
    """

    def __init__(self, playbooks_dir: Optional[Path] = None):
        if playbooks_dir is None:
            playbooks_dir = Path(__file__).resolve().parents[1] / "playbooks"
        self.playbooks_dir = playbooks_dir
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._mtimes: Dict[str, float] = {}

    def active_profile(self) -> str:
        return (os.getenv("SOC_PROFILE", "default") or "default").strip().lower()

    def _profiles_root(self) -> Path:
        return self.playbooks_dir / "profiles"

    def _profile_dir(self, profile: str) -> Path:
        return self._profiles_root() / profile

    def load_all(self, force: bool = False) -> Dict[str, Dict[str, Any]]:
        profiles_root = self._profiles_root()

        if profiles_root.exists():
            # Profile mode: load default first then overlay profile
            default_dir = self._profile_dir("default")
            active = self.active_profile()
            active_dir = self._profile_dir(active)

            if not default_dir.exists():
                logger.warning(f"[Playbooks] profiles/default not found: {default_dir}")
                return self._cache

            self._load_dir(default_dir, force=force, overlay=False)
            if active != "default" and active_dir.exists():
                self._load_dir(active_dir, force=force, overlay=True)

            return self._cache

        # Flat mode: load backend/playbooks/*.json
        if not self.playbooks_dir.exists():
            logger.warning(f"[Playbooks] Directory not found: {self.playbooks_dir}")
            return self._cache

        self._load_dir(self.playbooks_dir, force=force, overlay=True)
        return self._cache

    def _load_dir(self, directory: Path, force: bool, overlay: bool):
        for p in directory.glob("*.json"):
            try:
                mtime = p.stat().st_mtime
                key = str(p.resolve())
                if not force and self._mtimes.get(key) == mtime:
                    continue

                data = json.loads(p.read_text(encoding="utf-8"))
                incident_type = str(data.get("incident_type") or "").strip().upper()
                if not incident_type:
                    logger.warning(f"[Playbooks] Missing incident_type in {p.name}")
                    continue

                if overlay or incident_type not in self._cache:
                    self._cache[incident_type] = data

                self._mtimes[key] = mtime
                logger.info(f"[Playbooks] Loaded {incident_type} v{data.get('version')} from {p.name}")
            except Exception as e:
                logger.error(f"[Playbooks] Failed to load {p}: {e}")

    def get(self, incident_type: str) -> Optional[Dict[str, Any]]:
        self.load_all(force=False)
        return self._cache.get(str(incident_type or "").strip().upper())

    def list_incident_types(self) -> List[str]:
        self.load_all(force=False)
        return sorted(list(self._cache.keys()))

    def reload(self) -> Dict[str, Dict[str, Any]]:
        return self.load_all(force=True)