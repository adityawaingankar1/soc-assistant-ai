from typing import Dict, Any

def _matches(rule: Dict[str, Any], predicates: Dict[str, bool]) -> bool:
    when_all = rule.get("when_all", []) or []
    when_any = rule.get("when_any", []) or []
    not_if_any = rule.get("not_if_any", []) or []

    if any(predicates.get(k, False) for k in not_if_any):
        return False
    if when_all and not all(predicates.get(k, False) for k in when_all):
        return False
    if when_any and not any(predicates.get(k, False) for k in when_any):
        return False
    return True

def route_incident(router_rules: Dict[str, Any], predicates: Dict[str, bool]) -> Dict[str, Any]:
    rules = sorted(router_rules.get("rules", []), key=lambda r: r.get("priority", 0), reverse=True)

    for r in rules:
        if _matches(r, predicates):
            out = dict(r.get("set", {}))
            out["rule_id"] = r.get("id")
            out["rule_priority"] = r.get("priority", 0)
            return out

    default = dict(router_rules.get("default", {"incident_type": "INVESTIGATE", "playbook_family": "GENERIC"}))
    default["rule_id"] = "default"
    default["rule_priority"] = -1
    return default