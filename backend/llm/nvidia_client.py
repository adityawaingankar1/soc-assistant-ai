# backend/llm/nvidia_client.py

from __future__ import annotations

import json
import time
from typing import List, Dict, Any, Optional, Iterator

import requests
from requests.adapters import HTTPAdapter
from loguru import logger

from backend.config import get_settings

settings = get_settings()


class NVIDIAClient:
    """
    NVIDIA Integrate / NIM OpenAI-compatible chat client.

    Production optimizations:
    - Lower latency defaults
    - Faster failover
    - Reduced retry amplification
    - Automatic token shrinking
    - Better timeout handling
    - Graceful degradation
    """

    def __init__(self):

        self.base_url = (
            settings.nvidia_base_url or ""
        ).rstrip("/")

        self.api_key = settings.nvidia_api_key

        # DEFAULT TO SMALLER / FASTER MODEL
        self.model = (
            settings.nvidia_model
            or "meta/llama-3.1-8b-instruct"
        )

        self.session = requests.Session()

        adapter = HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=1,
        )

        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    # ---------------------------------------------------------
    # Headers
    # ---------------------------------------------------------

    def _headers(self) -> Dict[str, str]:

        if not self.api_key:
            raise PermissionError(
                "NVIDIA API key not configured."
            )

        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    # ---------------------------------------------------------
    # Blocking Chat
    # ---------------------------------------------------------

    def chat(
        self,
        messages: List[Dict[str, Any]],
        temperature: float = 0.2,

        # REDUCED DEFAULT TOKENS
        max_tokens: int = 320,

        timeout_seconds: Optional[int] = None,
        retries: Optional[int] = None,
        model: Optional[str] = None,
    ) -> str:

        """
        Blocking chat completion.

        Production hardened:
        - Fast timeout handling
        - Reduced retries
        - Automatic token shrinking
        - Better logging
        """

        if not isinstance(messages, list) or not messages:
            raise RuntimeError(
                "Invalid 'messages' payload."
            )

        # MUCH LOWER DEFAULT TIMEOUT
        read_timeout = int(
            timeout_seconds
            or getattr(
                settings,
                "nvidia_read_timeout_seconds",
                60
            )
        )

        connect_timeout = int(
            getattr(
                settings,
                "nvidia_connect_timeout_seconds",
                10
            )
        )

        # DEFAULT TO SINGLE RETRY ONLY
        max_retries = int(
            retries
            if retries is not None
            else getattr(
                settings,
                "nvidia_retries",
                1
            )
        )

        backoff = float(
            getattr(
                settings,
                "nvidia_retry_backoff_seconds",
                1.5
            )
        )

        token_multiplier = float(
            getattr(
                settings,
                "nvidia_retry_max_tokens_multiplier",
                0.75
            )
        )

        url = f"{self.base_url}/chat/completions"

        attempt = 0

        last_error: Optional[Exception] = None

        selected_model = model or self.model

        while attempt <= max_retries:

            # SHRINK TOKENS ON RETRY
            attempt_max_tokens = max(
                96,
                int(max_tokens * (token_multiplier ** attempt))
            )

            payload = {
                "model": selected_model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": attempt_max_tokens,
            }

            t0 = time.perf_counter()

            try:

                if attempt == 0:

                    logger.info(
                        f"[NVIDIA] request "
                        f"model={selected_model} "
                        f"messages={len(messages)} "
                        f"max_tokens={attempt_max_tokens} "
                        f"timeouts=("
                        f"connect={connect_timeout}s, "
                        f"read={read_timeout}s)"
                    )

                else:

                    logger.warning(
                        f"[NVIDIA] retry "
                        f"{attempt + 1}/{max_retries + 1} "
                        f"max_tokens={attempt_max_tokens}"
                    )

                resp = self.session.post(
                    url,
                    headers=self._headers(),
                    json=payload,
                    timeout=(
                        connect_timeout,
                        read_timeout
                    ),
                )

                elapsed = (
                    time.perf_counter() - t0
                )

                # -------------------------------------------------
                # AUTH
                # -------------------------------------------------

                if resp.status_code in (401, 403):

                    logger.error(
                        f"[NVIDIA] auth failed "
                        f"status={resp.status_code}"
                    )

                    raise PermissionError(
                        "NVIDIA authentication failed."
                    )

                # -------------------------------------------------
                # RATE LIMIT
                # -------------------------------------------------

                if resp.status_code == 429:

                    logger.error(
                        "[NVIDIA] rate limited"
                    )

                    raise RuntimeError(
                        "NVIDIA rate limit reached."
                    )

                # -------------------------------------------------
                # TRANSIENT PROVIDER ERRORS
                # -------------------------------------------------

                if resp.status_code in (
                    500,
                    502,
                    503,
                    504
                ):

                    raise RuntimeError(
                        f"NVIDIA service error "
                        f"{resp.status_code}"
                    )

                # -------------------------------------------------
                # OTHER ERRORS
                # -------------------------------------------------

                if resp.status_code >= 400:

                    raise RuntimeError(
                        f"NVIDIA request failed "
                        f"{resp.status_code}: "
                        f"{resp.text[:200]}"
                    )

                # -------------------------------------------------
                # RESPONSE
                # -------------------------------------------------

                data = resp.json()

                choices = (
                    data.get("choices") or []
                )

                if not choices:

                    raise RuntimeError(
                        "NVIDIA response missing choices."
                    )

                message = (
                    choices[0].get("message") or {}
                )

                content = message.get("content")

                if not content:

                    raise RuntimeError(
                        "NVIDIA response missing content."
                    )

                logger.info(
                    f"[NVIDIA] ok "
                    f"elapsed={elapsed:.2f}s "
                    f"chars={len(content)}"
                )

                return content

            # -----------------------------------------------------
            # TIMEOUTS
            # -----------------------------------------------------

            except requests.exceptions.ReadTimeout as e:

                last_error = e

                logger.error(
                    f"[NVIDIA] read timeout "
                    f"after {read_timeout}s "
                    f"attempt="
                    f"{attempt + 1}/{max_retries + 1}"
                )

            except requests.exceptions.ConnectTimeout as e:

                last_error = e

                logger.error(
                    f"[NVIDIA] connect timeout "
                    f"after {connect_timeout}s"
                )

            except requests.exceptions.RequestException as e:

                last_error = e

                logger.error(
                    f"[NVIDIA] network error: {e}"
                )

            except PermissionError:
                raise

            except RuntimeError as e:

                last_error = e

                err = str(e).lower()

                transient = any(
                    s in err
                    for s in [
                        "502",
                        "503",
                        "504",
                        "500",
                        "service error"
                    ]
                )

                if (
                    not transient
                    or attempt >= max_retries
                ):
                    raise

                logger.warning(
                    f"[NVIDIA] transient retry: {e}"
                )

            attempt += 1

            if attempt <= max_retries:

                # NON-EXPLOSIVE BACKOFF
                time.sleep(
                    backoff * attempt
                )

        raise TimeoutError(
            f"NVIDIA API timed out "
            f"after {read_timeout}s."
        ) from last_error

    # ---------------------------------------------------------
    # Streaming Chat
    # ---------------------------------------------------------

    def stream_chat(
        self,
        messages: List[Dict[str, Any]],
        temperature: float = 0.2,

        # REDUCED TOKENS
        max_tokens: int = 320,

        timeout_seconds: Optional[int] = None,
        model: Optional[str] = None,
    ) -> Iterator[str]:

        if not isinstance(messages, list) or not messages:
            raise RuntimeError(
                "Invalid 'messages' payload."
            )

        read_timeout = int(
            timeout_seconds
            or getattr(
                settings,
                "nvidia_read_timeout_seconds",
                60
            )
        )

        connect_timeout = int(
            getattr(
                settings,
                "nvidia_connect_timeout_seconds",
                10
            )
        )

        selected_model = (
            model
            or getattr(
                settings,
                "nvidia_chat_model",
                None
            )
            or self.model
        )

        url = f"{self.base_url}/chat/completions"

        payload = {
            "model": selected_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }

        logger.info(
            f"[NVIDIA:stream] request "
            f"model={selected_model} "
            f"messages={len(messages)} "
            f"max_tokens={max_tokens}"
        )

        t0 = time.perf_counter()

        try:

            with self.session.post(
                url,
                headers=self._headers(),
                json=payload,
                timeout=(
                    connect_timeout,
                    read_timeout
                ),
                stream=True,
            ) as resp:

                if resp.status_code in (401, 403):

                    raise PermissionError(
                        "NVIDIA auth failed."
                    )

                if resp.status_code == 429:

                    raise RuntimeError(
                        "NVIDIA rate limited."
                    )

                if resp.status_code >= 400:

                    raise RuntimeError(
                        f"NVIDIA stream failed "
                        f"{resp.status_code}"
                    )

                for raw_line in resp.iter_lines(
                    decode_unicode=True
                ):

                    if not raw_line:
                        continue

                    line = raw_line.strip()

                    if not line:
                        continue

                    if line.startswith("data:"):

                        line = line[
                            len("data:")
                        :].strip()

                    if line == "[DONE]":
                        break

                    try:
                        data = json.loads(line)

                    except Exception:
                        continue

                    choices = (
                        data.get("choices") or []
                    )

                    if not choices:
                        continue

                    delta = (
                        choices[0].get("delta")
                        or {}
                    )

                    content = delta.get("content")

                    if content:
                        yield content

            elapsed = (
                time.perf_counter() - t0
            )

            logger.info(
                f"[NVIDIA:stream] complete "
                f"elapsed={elapsed:.2f}s"
            )

        except requests.exceptions.ReadTimeout as e:

            logger.error(
                f"[NVIDIA:stream] read timeout "
                f"{read_timeout}s"
            )

            raise TimeoutError(
                f"NVIDIA stream timed out "
                f"after {read_timeout}s."
            ) from e

        except requests.exceptions.ConnectTimeout as e:

            logger.error(
                f"[NVIDIA:stream] connect timeout"
            )

            raise TimeoutError(
                f"NVIDIA connection timeout "
                f"after {connect_timeout}s."
            ) from e

        except requests.exceptions.RequestException as e:

            logger.error(
                f"[NVIDIA:stream] network error: {e}"
            )

            raise RuntimeError(
                f"NVIDIA network error: {e}"
            ) from e


nvidia_client = NVIDIAClient()