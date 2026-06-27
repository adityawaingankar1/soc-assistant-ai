# backend/config.py
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables and optional .env.

    Environment variables are case-insensitive by default.

    Examples:
    - NVIDIA_API_KEY maps to nvidia_api_key
    - APP_PORT maps to app_port
    - NVIDIA_CHAT_MODEL maps to nvidia_chat_model
    """

    # ── Environment / App ────────────────────────────────────────────────
    environment: Literal["development", "staging", "production"] = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    debug: bool = False
    secret_key: str = "change-me-in-production"

    # ── NVIDIA ───────────────────────────────────────────────────────────
    nvidia_api_key: str = ""
    nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"

    # Default/deep model.
    nvidia_model: str = "meta/llama-3.1-70b-instruct"

    # Fast model for chat streaming.
    # If this model is unavailable in your NVIDIA account, set it equal to nvidia_model in .env.
    nvidia_chat_model: str = "meta/llama-3.1-8b-instruct"

    # Deep model for alert triage, correlation, and report generation.
    nvidia_deep_model: str = "meta/llama-3.1-70b-instruct"

    # ── NVIDIA Reliability / Timeouts ────────────────────────────────────
    nvidia_connect_timeout_seconds: int = 10
    nvidia_read_timeout_seconds: int = 300
    nvidia_retries: int = 2
    nvidia_retry_backoff_seconds: float = 1.5
    nvidia_retry_max_tokens_multiplier: float = 0.6

    # ── Chat UX / Streaming ──────────────────────────────────────────────
    chat_stream_timeout_seconds: int = 120
    chat_general_max_tokens: int = 450
    chat_deep_max_tokens: int = 700
    chat_history_limit: int = 10

    # If False, simple questions like "What is phishing?" skip RAG for speed.
    chat_rag_general_enabled: bool = False

    # ── Database ─────────────────────────────────────────────────────────
    database_url: str = "sqlite:///./soc_assistant.db"

    # ── RAG ──────────────────────────────────────────────────────────────
    chroma_persist_dir: str = "./chroma_store"
    embedding_model: str = "all-MiniLM-L6-v2"
    chunk_size: int = 500
    chunk_overlap: int = 100
    top_k_results: int = 5

    # ── CORS ─────────────────────────────────────────────────────────────
    frontend_url: str = "http://localhost:3000"

    # ── Enterprise Retention / Privacy ───────────────────────────────────
    user_chat_purge_days: int = 90
    user_purge_batch_size: int = 200
    audit_strip_pii_keys: bool = True
    audit_pii_placeholder: str = "[redacted]"

    # ── Evidence storage caps ────────────────────────────────────────────
    evidence_max_rows: int = 5000
    evidence_max_bytes: int = 5_000_000

    # ── Splunk Integration ───────────────────────────────────────────────
    splunk_enabled: bool = False
    splunk_base_url: str = ""
    splunk_token: str = ""
    splunk_verify_tls: bool = True
    splunk_search_timeout_seconds: int = 60
    splunk_search_poll_interval_seconds: float = 0.7
    splunk_max_result_rows: int = 5000

    # ── Sentinel / Log Analytics Integration ─────────────────────────────
    sentinel_enabled: bool = False
    sentinel_auth_mode: str = "azure_cli"
    azure_tenant_id: str = ""
    log_analytics_workspace_id: str = ""

    # ── Neo4j ────────────────────────────────────────────────────────────
    neo4j_uri: str = ""
    neo4j_user: str = ""
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"

    # ── SOC Policy Toggles ───────────────────────────────────────────────
    soc_enable_attribution: bool = False
    soc_enable_stix: bool = False
    soc_include_hash_type: bool = True
    soc_allow_auto_destructive: bool = False

    # ── Pydantic Settings config ─────────────────────────────────────────
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Validators ───────────────────────────────────────────────────────

    @field_validator("environment", mode="before")
    @classmethod
    def normalize_environment(cls, v: str) -> str:
        v = (v or "development").strip().lower()
        allowed = {"development", "staging", "production"}

        if v not in allowed:
            raise ValueError(f"environment must be one of: {sorted(allowed)}")

        return v

    @field_validator("app_port")
    @classmethod
    def validate_app_port(cls, v: int) -> int:
        if v < 1 or v > 65535:
            raise ValueError("app_port must be between 1 and 65535")

        return v

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        v = (v or "").strip()

        if not v:
            raise ValueError("secret_key must not be empty")

        return v

    @field_validator("frontend_url")
    @classmethod
    def normalize_frontend_url(cls, v: str) -> str:
        v = (v or "").strip()

        if not v:
            return "http://localhost:3000"

        return v.rstrip("/")

    @field_validator("nvidia_base_url")
    @classmethod
    def normalize_nvidia_base_url(cls, v: str) -> str:
        v = (v or "").strip()

        if not v:
            return "https://integrate.api.nvidia.com/v1"

        return v.rstrip("/")

    @field_validator("nvidia_model", "nvidia_chat_model", "nvidia_deep_model")
    @classmethod
    def validate_model_name(cls, v: str) -> str:
        v = (v or "").strip()

        if not v:
            raise ValueError("NVIDIA model name must not be empty")

        return v

    @field_validator("chunk_size")
    @classmethod
    def validate_chunk_size(cls, v: int) -> int:
        if v < 100 or v > 5000:
            raise ValueError("chunk_size must be between 100 and 5000")

        return v

    @field_validator("chunk_overlap")
    @classmethod
    def validate_chunk_overlap(cls, v: int) -> int:
        if v < 0 or v > 1000:
            raise ValueError("chunk_overlap must be between 0 and 1000")

        return v

    @field_validator("top_k_results")
    @classmethod
    def validate_top_k(cls, v: int) -> int:
        if v < 1 or v > 20:
            raise ValueError("top_k_results must be between 1 and 20")

        return v

    @field_validator("user_chat_purge_days")
    @classmethod
    def validate_user_chat_purge_days(cls, v: int) -> int:
        if v < 1 or v > 3650:
            raise ValueError("user_chat_purge_days must be between 1 and 3650")

        return v

    @field_validator("user_purge_batch_size")
    @classmethod
    def validate_user_purge_batch_size(cls, v: int) -> int:
        if v < 1 or v > 5000:
            raise ValueError("user_purge_batch_size must be between 1 and 5000")

        return v

    @field_validator("audit_pii_placeholder")
    @classmethod
    def validate_audit_placeholder(cls, v: str) -> str:
        v = (v or "").strip()

        if not v:
            raise ValueError("audit_pii_placeholder must not be empty")

        if len(v) > 100:
            raise ValueError("audit_pii_placeholder too long")

        return v

    @field_validator("nvidia_connect_timeout_seconds")
    @classmethod
    def validate_nvidia_connect_timeout(cls, v: int) -> int:
        if v < 1 or v > 60:
            raise ValueError(
                "nvidia_connect_timeout_seconds must be between 1 and 60"
            )

        return v

    @field_validator("nvidia_read_timeout_seconds")
    @classmethod
    def validate_nvidia_read_timeout(cls, v: int) -> int:
        if v < 10 or v > 1800:
            raise ValueError(
                "nvidia_read_timeout_seconds must be between 10 and 1800"
            )

        return v

    @field_validator("chat_stream_timeout_seconds")
    @classmethod
    def validate_chat_stream_timeout(cls, v: int) -> int:
        if v < 10 or v > 600:
            raise ValueError("chat_stream_timeout_seconds must be between 10 and 600")

        return v

    @field_validator("chat_general_max_tokens")
    @classmethod
    def validate_chat_general_max_tokens(cls, v: int) -> int:
        if v < 64 or v > 2000:
            raise ValueError("chat_general_max_tokens must be between 64 and 2000")

        return v

    @field_validator("chat_deep_max_tokens")
    @classmethod
    def validate_chat_deep_max_tokens(cls, v: int) -> int:
        if v < 64 or v > 4000:
            raise ValueError("chat_deep_max_tokens must be between 64 and 4000")

        return v

    @field_validator("chat_history_limit")
    @classmethod
    def validate_chat_history_limit(cls, v: int) -> int:
        if v < 2 or v > 50:
            raise ValueError("chat_history_limit must be between 2 and 50")

        return v

    @field_validator("nvidia_retries")
    @classmethod
    def validate_nvidia_retries(cls, v: int) -> int:
        if v < 0 or v > 5:
            raise ValueError("nvidia_retries must be between 0 and 5")

        return v

    @field_validator("nvidia_retry_backoff_seconds")
    @classmethod
    def validate_nvidia_backoff(cls, v: float) -> float:
        if v < 0 or v > 60:
            raise ValueError("nvidia_retry_backoff_seconds must be between 0 and 60")

        return v

    @field_validator("nvidia_retry_max_tokens_multiplier")
    @classmethod
    def validate_nvidia_retry_multiplier(cls, v: float) -> float:
        if v <= 0 or v > 1:
            raise ValueError("nvidia_retry_max_tokens_multiplier must be > 0 and <= 1")

        return v

    @field_validator("evidence_max_rows")
    @classmethod
    def validate_evidence_max_rows(cls, v: int) -> int:
        if v < 100 or v > 500000:
            raise ValueError("evidence_max_rows must be between 100 and 500000")

        return v

    @field_validator("evidence_max_bytes")
    @classmethod
    def validate_evidence_max_bytes(cls, v: int) -> int:
        if v < 100000 or v > 200000000:
            raise ValueError("evidence_max_bytes must be between 100000 and 200000000")

        return v

    @field_validator("splunk_base_url")
    @classmethod
    def normalize_splunk_base_url(cls, v: str) -> str:
        return (v or "").strip().rstrip("/")

    @field_validator("neo4j_uri")
    @classmethod
    def normalize_neo4j_uri(cls, v: str) -> str:
        return (v or "").strip()

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"


@lru_cache()
def get_settings() -> Settings:
    settings = Settings()

    # Production safety checks.
    if settings.is_production and settings.secret_key == "change-me-in-production":
        raise ValueError(
            "Unsafe production configuration: secret_key must be changed in production."
        )

    # NVIDIA should be mandatory outside development.
    if not settings.is_development and not settings.nvidia_api_key.strip():
        raise ValueError("nvidia_api_key must be set for non-development environments.")

    # Splunk validation.
    if settings.splunk_enabled:
        if not settings.splunk_base_url:
            raise ValueError("splunk_base_url must be set when splunk_enabled=true")

        if not settings.splunk_token:
            raise ValueError("splunk_token must be set when splunk_enabled=true")

    # Sentinel validation.
    if settings.sentinel_enabled:
        if not settings.log_analytics_workspace_id:
            raise ValueError(
                "log_analytics_workspace_id must be set when sentinel_enabled=true"
            )

    return settings
