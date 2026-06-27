# backend/__init__.py

import os
from dotenv import load_dotenv

# ── Load .env first ───────────────────────────────────────────────────────────
load_dotenv()

# ── Disable ChromaDB telemetry ────────────────────────────────────────────────
os.environ["ANONYMIZED_TELEMETRY"]        = "False"
os.environ["CHROMA_ANONYMIZED_TELEMETRY"] = "False"

# ── Silence the posthog capture() signature bug in ChromaDB ──────────────────
# ChromaDB calls posthog.capture(event, data) but installed posthog
# expects capture(distinct_id, event, properties).
# We patch it to a no-op so it never errors.
try:
    import posthog
    posthog.capture = lambda *args, **kwargs: None   # no-op patch
    posthog.disabled = True
except Exception:
    pass  # posthog not installed — already safe

__version__ = "1.0.0"