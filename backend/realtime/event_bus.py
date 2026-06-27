# backend/realtime/event_bus.py
from __future__ import annotations

import asyncio
from typing import Any, Dict, Set, Optional
from datetime import datetime
from loguru import logger

_MAIN_LOOP: Optional[asyncio.AbstractEventLoop] = None
_PUBLISH_QUEUE: Optional[asyncio.Queue] = None
_PUBLISH_TASK: Optional[asyncio.Task] = None


def set_main_loop(loop: asyncio.AbstractEventLoop):
    global _MAIN_LOOP
    _MAIN_LOOP = loop


def get_main_loop() -> Optional[asyncio.AbstractEventLoop]:
    return _MAIN_LOOP


class EventBus:
    def __init__(self):
        self._subscribers: Set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue):
        async with self._lock:
            self._subscribers.discard(q)

    async def publish(self, event: Dict[str, Any]):
        payload = dict(event or {})
        payload.setdefault("ts", datetime.utcnow().isoformat() + "Z")

        async with self._lock:
            subs = list(self._subscribers)

        for q in subs:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass


event_bus = EventBus()


async def _publisher_loop():
    """Runs on the main event loop and publishes queued events to subscribers."""
    assert _PUBLISH_QUEUE is not None
    while True:
        payload = await _PUBLISH_QUEUE.get()
        try:
            await event_bus.publish(payload)
        except Exception as e:
            logger.warning(f"[EventBus] publish failed: {e}")


def start_publisher(loop: asyncio.AbstractEventLoop):
    """
    Call once at startup (lifespan).
    Creates the publish queue and starts the publisher task.
    """
    global _PUBLISH_QUEUE, _PUBLISH_TASK
    if _PUBLISH_QUEUE is None:
        _PUBLISH_QUEUE = asyncio.Queue(maxsize=2000)
    if _PUBLISH_TASK is None or _PUBLISH_TASK.done():
        _PUBLISH_TASK = loop.create_task(_publisher_loop())
        logger.info("[EventBus] Publisher loop started")


def publish_threadsafe(payload: Dict[str, Any]) -> None:
    """
    Thread-safe entry point for sync routes.
    It enqueues payload into the main-loop publisher queue.
    """
    loop = get_main_loop()
    if loop is None or _PUBLISH_QUEUE is None:
        return

    try:
        loop.call_soon_threadsafe(_PUBLISH_QUEUE.put_nowait, payload)
    except Exception:
        return