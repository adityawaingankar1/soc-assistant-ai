from __future__ import annotations

import os
import asyncio
from typing import Dict, Any, Optional

import httpx
from loguru import logger

class SplunkConnector:

    def __init__(self):

        self.enabled = (
            os.getenv("SPLUNK_ENABLED", "true").lower()
            == "true"
        )

        self.base_url = os.getenv(
            "SPLUNK_BASE_URL",
            ""
        ).rstrip("/")

        self.token = os.getenv(
            "SPLUNK_TOKEN",
            ""
        ).strip()

        self.verify_tls = (
            os.getenv(
                "SPLUNK_VERIFY_TLS",
                "true"
            ).lower() == "true"
        )

        self.timeout_seconds = int(
            os.getenv(
                "SPLUNK_SEARCH_TIMEOUT_SECONDS",
                "60"
            )
        )

        self.poll_interval = float(
            os.getenv(
                "SPLUNK_SEARCH_POLL_INTERVAL_SECONDS",
                "0.7"
            )
        )

        self.max_rows = int(
            os.getenv(
                "SPLUNK_MAX_RESULT_ROWS",
                "5000"
            )
        )

        if not self.enabled:
            logger.warning(
                "[Splunk] connector disabled"
            )
            self.disabled = True
            return
        self.disabled = False

        if not self.base_url or not self.token:
            raise RuntimeError(
                "Missing SPLUNK_BASE_URL or SPLUNK_TOKEN"
            )

    def _headers(self) -> Dict[str, str]:

        return {
            "Authorization": f"Bearer {self.token}"
        }

    async def execute_search(
        self,
        search: str,
        *,
        earliest_time: Optional[str] = None,
        latest_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        
        if getattr(self, "disabled", False):
            return {
                "success": False,
                "disabled": True,
                "error": "Splunk connector disabled"
            }

        if not search or not isinstance(search, str):
            raise ValueError("search is required")

        if not search.lstrip().lower().startswith("search "):
            search = "search " + search.strip()

        timeout = httpx.Timeout(60.0)

        async with httpx.AsyncClient(
            verify=self.verify_tls,
            timeout=timeout
        ) as client:

            # CREATE JOB
            data = {
                "search": search,
                "output_mode": "json"
            }

            if earliest_time:
                data["earliest_time"] = earliest_time

            if latest_time:
                data["latest_time"] = latest_time

            r = await client.post(
                f"{self.base_url}/services/search/jobs",
                headers={
                    **self._headers(),
                    "Content-Type":
                    "application/x-www-form-urlencoded"
                },
                data=data,
            )

            r.raise_for_status()

            sid = (r.json() or {}).get("sid")

            if not sid:
                raise RuntimeError(
                    f"Splunk returned no sid: {r.text}"
                )

            # POLL
            start = asyncio.get_event_loop().time()

            while True:

                elapsed = (
                    asyncio.get_event_loop().time()
                    - start
                )

                if elapsed > self.timeout_seconds:
                    raise TimeoutError(
                        f"Splunk search timed out "
                        f"after {self.timeout_seconds}s"
                    )

                j = await client.get(
                    f"{self.base_url}/services/search/jobs/{sid}",
                    headers=self._headers(),
                    params={"output_mode": "json"},
                )

                j.raise_for_status()

                entry = (
                    j.json().get("entry") or [{}]
                )[0]

                content = entry.get("content") or {}

                if (
                    content.get("isDone")
                    or str(
                        content.get("dispatchState") or ""
                    ).upper() == "DONE"
                ):
                    break

                # NON-BLOCKING SLEEP
                await asyncio.sleep(self.poll_interval)

            # FETCH RESULTS
            res = await client.get(
                f"{self.base_url}/services/search/jobs/{sid}/results",
                headers=self._headers(),
                params={
                    "output_mode": "json",
                    "count": self.max_rows
                },
            )

            res.raise_for_status()

            rows = (
                res.json() or {}
            ).get("results") or []

            return {
                "sid": sid,
                "row_count": len(rows),
                "rows": rows
            }