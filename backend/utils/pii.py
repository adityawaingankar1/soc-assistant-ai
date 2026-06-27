# backend/utils/pii.py
from typing import Any, Dict, Iterable, Set

DEFAULT_PII_KEYS: Set[str] = {
    # common identity keys
    "username", "email",

    # common "actor" keys used across your event_data payloads
    "uploaded_by", "deleted_by", "cleared_by", "listed_by",
    "performed_by", "analyzed_by", "reset_by", "reloaded_by",

    # sometimes present in other systems
    "name", "full_name", "phone", "phone_number"
}


def redact_pii_keys(obj: Any, keys: Iterable[str] = DEFAULT_PII_KEYS, placeholder: str = "[redacted]") -> Any:
    """
    Redacts values for specific keys inside nested dict/list structures.
    Keeps the keys but replaces values with placeholder to preserve schema.
    """
    keyset = set(keys)

    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if k in keyset:
                out[k] = placeholder
            else:
                out[k] = redact_pii_keys(v, keyset, placeholder)
        return out

    if isinstance(obj, list):
        return [redact_pii_keys(x, keyset, placeholder) for x in obj]

    return obj


def redact_pii_strings(obj: Any, pii_values: Set[str], placeholder: str = "[deleted]") -> Any:
    """
    Redacts occurrences of any string in pii_values across nested dict/list.
    Useful for cleaning old logs that embedded username/email into free-text.
    """
    if not pii_values:
        return obj

    if isinstance(obj, dict):
        return {k: redact_pii_strings(v, pii_values, placeholder) for k, v in obj.items()}

    if isinstance(obj, list):
        return [redact_pii_strings(x, pii_values, placeholder) for x in obj]

    if isinstance(obj, str):
        out = obj
        for p in pii_values:
            if p and p in out:
                out = out.replace(p, placeholder)
        return out

    return obj