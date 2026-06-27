# backend/utils/api_response.py
from typing import Any, Dict, Optional


def success_response(
    data: Any = None,
    message: str = "Success",
    request_id: Optional[str] = None,
    meta: Optional[Dict] = None
) -> Dict:
    payload = {
        "success": True,
        "message": message,
        "data": data
    }
    if request_id:
        payload["request_id"] = request_id
    if meta:
        payload["meta"] = meta
    return payload


def error_response(
    message: str = "An error occurred",
    code: str = "API_ERROR",
    request_id: Optional[str] = None,
    details: Optional[Any] = None
) -> Dict:
    payload = {
        "success": False,
        "error": {
            "code": code,
            "message": message
        }
    }
    if request_id:
        payload["request_id"] = request_id
    if details is not None:
        payload["error"]["details"] = details
    return payload