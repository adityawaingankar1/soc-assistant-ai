"""
Rate Limiting Middleware using slowapi

Current strategy:
- Shared limiter instance across app
- IP-based limiting using client remote address
- Safe default limits for development and moderate usage

Production note:
- If deployed behind a reverse proxy/load balancer,
  configure trusted proxy handling so client IPs are correct.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address
from backend.config import get_settings

settings = get_settings()

DEFAULT_LIMITS = (
    ["500/minute"] if settings.is_development
    else ["200/minute"]
)

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=DEFAULT_LIMITS
)