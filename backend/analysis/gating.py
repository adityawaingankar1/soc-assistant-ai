from typing import Dict, Any, List


def action_enabled(action: dict, predicates: dict) -> bool:
    req_all = action.get("requires_all", []) or []
    req_any = action.get("requires_any", []) or []
    not_if = action.get("not_if", []) or []

    if any(predicates.get(k, False) for k in not_if):
        return False
    if req_all and not all(predicates.get(k, False) for k in req_all):
        return False
    if req_any and not any(predicates.get(k, False) for k in req_any):
        return False
    return True


class GatingEngine:
    def filter_actions(self, actions: List[Dict[str, Any]], predicates: Dict[str, Any]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for a in actions or []:
            if not isinstance(a, dict):
                continue
            if action_enabled(a, predicates):
                out.append(a)
        return out