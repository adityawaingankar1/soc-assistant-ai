from __future__ import annotations

from typing import Any, Dict, List


def _as_list(x: Any) -> List[str]:
    """
    Normalize unknown input to list[str].
    - None -> []
    - str  -> [str] (if non-empty)
    - list -> [str(item) ...]
    - other -> [str(x)]
    """
    if x is None:
        return []
    if isinstance(x, list):
        return [str(i) for i in x if str(i).strip()]
    if isinstance(x, str):
        s = x.strip()
        return [s] if s else []
    s = str(x).strip()
    return [s] if s else []


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for it in items or []:
        s = str(it or "").strip()
        if not s:
            continue
        k = s.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def _bullets(items: List[str], empty: str = "- (none)") -> str:
    items = [str(i).strip() for i in (items or []) if str(i).strip()]
    if not items:
        return empty
    return "\n".join([f"- {i}" for i in items])


class TicketPackRenderer:
    """
    Backward-compatible renderer.

    Your current code path (per traceback) does:
        return summary + "\\n\\n" + self._old_detailed_render(doc)

    So we keep:
      - render_markdown()
      - _old_detailed_render()  (compat shim)

    Input doc keys expected (best-effort):
      summary, decision, risk, incident_type, confidence_percent,
      key_evidence, linked_signals, gaps, actions, unlinked_environment_signals
    """

    def render_markdown(self, doc: Dict[str, Any]) -> str:
        doc = doc or {}

        incident_type = str(doc.get("incident_type") or "INVESTIGATE").strip().upper()
        decision = str(doc.get("decision") or "enrich").strip().lower()
        risk = str(doc.get("risk") or "MEDIUM").strip().upper()

        conf = doc.get("confidence_percent", None)
        try:
            conf_str = f"{int(conf)}%"
        except Exception:
            conf_str = "Unknown"

        # "summary" coming from your orchestrator is the LLM explanation markdown.
        llm_summary = str(doc.get("summary") or "").strip()
        if not llm_summary:
            llm_summary = "## Incident Update\n\nNo narrative summary was generated."

        executive = (
            "# EXECUTIVE SUMMARY\n"
            f"**Incident Type**: {incident_type}\n"
            f"**AI Confidence**: {conf_str}\n"
            f"**Triage Decision**: {decision}\n"
            f"**Risk**: {risk}\n"
        )

        # Keep old behavior: exec summary + detailed ticket pack
        return executive + "\n\n" + llm_summary + "\n\n" + self._old_detailed_render(doc)

    # ---------------------------------------------------------------------
    # Backward compatibility shim (fixes your AttributeError)
    # ---------------------------------------------------------------------
    def _old_detailed_render(self, doc: Dict[str, Any]) -> str:
        """
        This method existed in an older version of your renderer.
        Some code paths still call it. Keep it as an alias to the new renderer.
        """
        return self._render_ticket_pack(doc)

    # ---------------------------------------------------------------------
    # New implementation
    # ---------------------------------------------------------------------
    def _render_ticket_pack(self, doc: Dict[str, Any]) -> str:
        doc = doc or {}

        key_evidence = _dedupe_keep_order(_as_list(doc.get("key_evidence")))
        linked_signals = _dedupe_keep_order(_as_list(doc.get("linked_signals")))
        gaps = _dedupe_keep_order(_as_list(doc.get("gaps")))
        actions = _dedupe_keep_order(_as_list(doc.get("actions")))
        unlinked_env = _dedupe_keep_order(_as_list(doc.get("unlinked_environment_signals")))

        incident_type = str(doc.get("incident_type") or "INVESTIGATE").strip().upper()
        decision = str(doc.get("decision") or "enrich").strip().lower()
        risk = str(doc.get("risk") or "MEDIUM").strip().upper()

        conf = doc.get("confidence_percent", None)
        try:
            conf_str = f"{int(conf)}%"
        except Exception:
            conf_str = "Unknown"

        # Render
        out = []
        out.append("# SOC Ticket Pack")
        out.append("")
        out.append("## Summary")
        out.append(f"- **Incident Type**: {incident_type}")
        out.append(f"- **Decision**: {decision}")
        out.append(f"- **Risk**: {risk}")
        out.append(f"- **Confidence**: {conf_str}")
        out.append("")
        out.append("## Key Evidence (Scoped)")
        out.append(_bullets(key_evidence))
        out.append("")
        out.append("## Observed Signals (Linked)")
        out.append(_bullets(linked_signals))
        out.append("")
        out.append("## Investigation Gaps")
        out.append(_bullets(gaps))
        out.append("")
        out.append("## Immediate Actions (Gated + Safe)")
        out.append(_bullets(actions))
        out.append("")
        out.append("## Environment Signals (Unlinked / Quarantined)")
        out.append(_bullets(unlinked_env))
        out.append("")

        return "\n".join(out).strip() + "\n"