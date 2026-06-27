from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional

from loguru import logger

from backend.agents.router_agent import RouterAgent
from backend.agents.threat_intel_agent import ThreatIntelAgent
from backend.agents.asset_agent import AssetAgent
from backend.agents.history_agent import HistoryAgent
from backend.agents.vuln_intel_agent import VulnIntelAgent
from backend.agents.siem_agent import SIEMAgent

from backend.analysis.incident_router import IncidentRouter
from backend.analysis.confidence_scorer import ConfidenceScorer
from backend.analysis.recommendation_engine import RecommendationEngine
from backend.analysis.renderer import TicketPackRenderer
from backend.analysis.result_guard import ensure_complete_result
from backend.analysis.followup_generator import generate_followups

from backend.rag.retriever import RAGRetriever
from backend.llm.nvidia_client import nvidia_client
from backend.llm.prompt_builder import PromptBuilder

from backend.routing.predicates import compute_predicates
from backend.scoring.profile_store import ScoringProfileStore

from backend.tools.ioc_tool import IOCTool


# ============================================================
# Prometheus Metrics (persist pipeline latencies)
# ============================================================
try:
    from prometheus_client import Histogram, Counter  # type: ignore
except Exception:  # pragma: no cover
    Histogram = None  # type: ignore
    Counter = None  # type: ignore


def _metric_observe(metric: Any, value: float, **labels: Any) -> None:
    if metric is None:
        return
    try:
        if labels:
            metric.labels(**labels).observe(value)
        else:
            metric.observe(value)
    except Exception:
        # never break SOC pipeline due to metrics
        return


def _metric_inc(metric: Any, amount: float = 1.0, **labels: Any) -> None:
    if metric is None:
        return
    try:
        if labels:
            metric.labels(**labels).inc(amount)
        else:
            metric.inc(amount)
    except Exception:
        return


# Track required latencies:
# ✅ SIEM latency
# ✅ RAG latency
# ✅ LLM latency
# ✅ total pipeline latency
ORCH_STEP_LATENCY_SECONDS = (
    Histogram(
        "soc_orchestrator_step_latency_seconds",
        "Latency (seconds) for orchestrator steps",
        labelnames=("step",),
        buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 40, 80, 160),
    )
    if Histogram
    else None
)

ORCH_STEP_FAILURES_TOTAL = (
    Counter(
        "soc_orchestrator_step_failures_total",
        "Count of orchestrator step failures",
        labelnames=("step",),
    )
    if Counter
    else None
)


# ============================================================
# STEP 6 — Analyst Case Management (DB table model)
# NOTE: This model is typically placed in backend/database models.
# Included here exactly per instructions; migrate it to your models module.
# ============================================================
try:
    from sqlalchemy import Column, String, DateTime, Text, JSON  # type: ignore
    from backend.database import Base  # type: ignore

    class InvestigationCase(Base):  # type: ignore
        __tablename__ = "investigation_cases"

        case_id = Column(String(64), primary_key=True, index=True)
        owner = Column(String(128), index=True, nullable=False)
        status = Column(String(32), index=True, nullable=False, default="open")
        priority = Column(String(16), index=True, nullable=False, default="medium")

        # Store alert ids / evidence refs as JSON lists for flexibility
        linked_alerts = Column(JSON, nullable=False, default=list)
        notes = Column(Text, nullable=True)
        evidence_refs = Column(JSON, nullable=False, default=list)

        created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

except Exception:
    # If SQLAlchemy/Base aren't available in this runtime context, skip model definition.
    InvestigationCase = None  # type: ignore


# ============================================================
# STEP 7 — SOAR Execution Layer (guarded execution + approvals)
# (Skeleton for enterprise SOC realism; integrate with your API/workflows)
# ============================================================
@dataclass
class SOARActionRequest:
    action_type: str  # e.g. "host_isolate", "ioc_block", "account_disable"
    requested_by: str
    reason: str = ""
    target: Dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = True
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class SOARActionResult:
    success: bool
    status: str  # "pending_approval" | "executed" | "rejected" | "failed"
    action_id: str
    message: str = ""
    audit: Dict[str, Any] = field(default_factory=dict)


class SOARExecutionLayer:
    """
    Minimal enterprise-style scaffold:
    - guarded execution
    - human approval
    - audit trail (hook into your write_audit_log / DB)
    """

    def request_action(self, req: SOARActionRequest) -> SOARActionResult:
        action_id = f"soar_{int(time.time() * 1000)}"
        if req.requires_approval:
            return SOARActionResult(
                success=True,
                status="pending_approval",
                action_id=action_id,
                message="Action queued pending human approval.",
                audit={
                    "requested_by": req.requested_by,
                    "action_type": req.action_type,
                    "target": req.target,
                    "reason": req.reason,
                    "created_at": req.created_at,
                },
            )

        # If you later enable auto-execution, implement guarded execution here.
        return SOARActionResult(
            success=False,
            status="failed",
            action_id=action_id,
            message="Auto-execution disabled. Approval required.",
            audit={
                "requested_by": req.requested_by,
                "action_type": req.action_type,
                "target": req.target,
                "reason": req.reason,
                "created_at": req.created_at,
            },
        )


class AgentOrchestrator:
    def __init__(self):
        self.router_agent = RouterAgent()
        self.ti_agent = ThreatIntelAgent()
        self.asset_agent = AssetAgent()
        self.history_agent = HistoryAgent()
        self.vuln_agent = VulnIntelAgent()
        self.siem_agent = SIEMAgent()

        self.incident_router = IncidentRouter()
        self.profile_store = ScoringProfileStore()
        self.conf_scorer = ConfidenceScorer()
        self.reco_engine = RecommendationEngine()
        self.renderer = TicketPackRenderer()

        self.retriever = RAGRetriever()
        self.prompt_builder = PromptBuilder()

        # deterministic local parsing fallback
        self._ioc_tool = IOCTool()

        # SOAR execution scaffold (approval-based by default)
        self.soar = SOARExecutionLayer()

    async def process_alert(self, alert_data: Dict) -> Dict:
        overall_start = time.perf_counter()
        alert_id = alert_data.get("alert_id", "N/A")
        logger.info(f"[Orchestrator] Processing alert_id={alert_id}")

        # STEP 0: router hint only
        try:
            routing = await asyncio.to_thread(self.router_agent.route, alert_data) or {}
        except Exception as e:
            logger.warning(f"[Orchestrator] Router failed, defaulting enrich: {e}")
            routing = {"decision": "enrich", "reason": "router_failed", "confidence": 0.5}

        router_decision = str(routing.get("decision") or "enrich").strip().lower()
        router_reason = str(routing.get("reason") or "").strip()
        try:
            router_confidence = float(routing.get("confidence") or 0.0)
        except Exception:
            router_confidence = 0.0

        # STEP 1: enrichment (also track SIEM latency inside)
        step_start = time.perf_counter()
        enrichment = await self._parallel_enrich(alert_data)
        enrichment_latency = time.perf_counter() - step_start
        _metric_observe(ORCH_STEP_LATENCY_SECONDS, enrichment_latency, step="enrichment")
        logger.info(f"[Timing] enrichment={enrichment_latency:.2f}s")

        # Pull out per-agent latency metrics (if present)
        agent_lat = enrichment.pop("_agent_latencies", {}) if isinstance(enrichment, dict) else {}
        if isinstance(agent_lat, dict):
            siem_lat = agent_lat.get("siem_context")
            if isinstance(siem_lat, (int, float)):
                _metric_observe(ORCH_STEP_LATENCY_SECONDS, float(siem_lat), step="siem")

        # Build normalized entities deterministically (prevents "http_header blob" failure)
        normalized_entities = self._build_normalized_entities(alert_data, enrichment)
        enrichment["normalized_entities"] = normalized_entities

        # Keep any existing enrichment IOC outputs
        enrichment.setdefault("normalized_ioc_enrichment", alert_data.get("ioc_enrichment") or [])

        asset = enrichment.get("asset_info", {}) or {}
        # Support both shapes: {asset_details:{...}} or flat
        details = asset.get("asset_details") if isinstance(asset.get("asset_details"), dict) else asset

        normalized_alert = {
            "alert_id": alert_data.get("alert_id"),
            "alert_source": alert_data.get("alert_source"),
            "severity": alert_data.get("severity"),
            "affected_asset": alert_data.get("affected_asset"),
            "timestamp": alert_data.get("timestamp"),
            "mitre_mapping": alert_data.get("mitre_mapping"),
            "description": alert_data.get("description"),
            "additional_context": alert_data.get("additional_context"),
            "ioc_list": alert_data.get("ioc_list"),
            "entities": normalized_entities,
            "asset": {
                "asset_class": (details.get("asset_class") or asset.get("asset_class") or "unknown"),
                "internet_facing_status": (
                    details.get("internet_facing_status")
                    or details.get("internet_facing")
                    or asset.get("internet_facing_status")
                    or "unknown"
                ),
                "edr_available": bool(details.get("edr_available", asset.get("edr_available", False))),
            },
        }

        siem = enrichment.get("siem_context", {}) or {}
        linked = (siem.get("linked") or {})
        linked_signal_ids = linked.get("signal_ids") or []
        linked_discovered_entities = linked.get("discovered_entities") or []

        evidence_bundle = {
            "linked_evidence": {
                "signals": linked_signal_ids,
                "discovered_entities": linked_discovered_entities,
            }
        }
        vuln_intel = enrichment.get("vuln_intel", {}) or {}

        # STEP 2: predicates (pre-confidence)
        predicates = compute_predicates(
            normalized_alert=normalized_alert,
            evidence_bundle=evidence_bundle,
            vuln_intel=vuln_intel,
            confidence_percent=None,
        )

        # STEP 3: incident routing
        route = self.incident_router.route(alert_data, enrichment, predicates)
        incident_type = route.get("incident_type") or "INVESTIGATE"

        # STEP 4: confidence inputs
        components, penalties = self._build_confidence_inputs(
            alert_data=alert_data,
            enrichment=enrichment,
            p=predicates,
            incident_type=incident_type,
            normalized_alert=normalized_alert,
            evidence_bundle=evidence_bundle,
        )

        # Provide full context to scorer
        asset_risk_tier = str(asset.get("risk_tier") or details.get("risk_tier") or "").upper() or None
        enriched_iocs = self._extract_enriched_iocs(enrichment)

        conf = self.conf_scorer.score(
            components,
            penalties,
            context={
                "incident_type": incident_type,
                "predicates": predicates,
                "evidence_summary": {},  # will fill after evidence build (step 8)
                "mitre_mapping": str(alert_data.get("mitre_mapping") or ""),
                "alert_description": str(alert_data.get("description") or ""),
                "additional_context": str(alert_data.get("additional_context") or ""),
                "normalized_alert": normalized_alert,
                "asset_risk_tier": asset_risk_tier,
                "enriched_iocs": enriched_iocs,
            },
        )

        # STEP 5: recompute predicates with confidence
        predicates = compute_predicates(
            normalized_alert=normalized_alert,
            evidence_bundle=evidence_bundle,
            vuln_intel=vuln_intel,
            confidence_percent=conf["confidence_percent"],
        )

        # STEP 6: outcome + triage
        outcome = self._outcome_from_conf(conf["confidence_percent"])
        triage_decision = self._final_triage_decision(
            router_decision=router_decision,
            router_confidence=router_confidence,
            confidence_percent=int(conf["confidence_percent"]),
            outcome=outcome,
            predicates=predicates,
            severity=str(alert_data.get("severity") or ""),
        )

        # STEP 7: recommendations
        rec = self.reco_engine.recommend(incident_type=incident_type, predicates=predicates, max_actions=9)
        action_objs = rec.get("actions") or []
        action_flags = rec.get("action_flags") or []
        recommended_actions = [a.get("action") for a in action_objs if isinstance(a, dict) and a.get("action")]

        # STEP 8: evidence summary + followups + quality checks
        evidence = self._build_evidence_summary(alert_data, enrichment, predicates)
        followups = generate_followups(incident_type, predicates, enrichment, evidence)
        quality_checks = self._quality_checks(incident_type, predicates, enrichment)

        # STEP 9: LLM explanation (also tracks RAG + LLM latency metrics)
        soc_artifacts_for_llm = {
            "incident_type": incident_type,
            "playbook_family": route.get("playbook_family"),
            "router_rule_id": route.get("rule_id"),
            "router_rule_priority": route.get("rule_priority"),
            "router_hint": {"decision": router_decision, "confidence": router_confidence, "reason": router_reason},
            "predicates": predicates,
            "confidence": conf,
            "confidence_inputs": {"components": components, "penalties": penalties},
            "evidence_bundle": evidence_bundle,
            "evidence_summary": evidence,
            "quality_checks": quality_checks,
        }

        step_start = time.perf_counter()
        explanation, attack_type = await self._llm_explanation_optional(alert_data, soc_artifacts_for_llm, incident_type)
        llm_block_latency = time.perf_counter() - step_start
        _metric_observe(ORCH_STEP_LATENCY_SECONDS, llm_block_latency, step="llm_total_block")
        logger.info(f"[Timing] llm={llm_block_latency:.2f}s")

        risk_level = self._risk_from_conf_and_severity(
            conf["confidence_percent"], str(alert_data.get("severity") or "MEDIUM")
        )

        result = {
            "triage_decision": triage_decision,
            "outcome": outcome,
            "risk_level": risk_level,
            "attack_type": attack_type or incident_type,
            "explanation": explanation,
            "recommended_actions": recommended_actions,
            "confidence_score": conf["confidence_final"],
            "source_citations": [],
            "follow_up_questions": followups,
            "playbook": self.renderer.render_markdown(
                {
                    "summary": explanation,
                    "decision": triage_decision,
                    "risk": risk_level,
                    "incident_type": incident_type,
                    "confidence_percent": conf["confidence_percent"],
                    "key_evidence": evidence.get("key_evidence") or [],
                    "linked_signals": evidence.get("linked_signals") or [],
                    "gaps": evidence.get("gaps") or [],
                    "actions": recommended_actions,
                    "unlinked_environment_signals": evidence.get("unlinked_environment_signals") or [],
                }
            ),
            "enrichment_data": {
                **enrichment,
                "soc_artifacts": {
                    "incident_type": incident_type,
                    "playbook_family": route.get("playbook_family"),
                    "router_rule_id": route.get("rule_id"),
                    "router_rule_priority": route.get("rule_priority"),
                    "router_hint": {"decision": router_decision, "confidence": router_confidence, "reason": router_reason},
                    "predicates": predicates,
                    "confidence": conf,
                    "confidence_inputs": {"components": components, "penalties": penalties},
                    "action_flags": action_flags,
                    "recommended_action_objects": action_objs,
                    "playbook_version": rec.get("playbook_version"),
                    "evidence_summary": evidence,
                    "evidence_bundle": evidence_bundle,
                    "quality_checks": quality_checks,
                },
            },
        }

        linked_signal_count = len(linked_signal_ids) if isinstance(linked_signal_ids, list) else 0
        result = ensure_complete_result(
            result,
            incident_type=incident_type,
            alert_source=str(alert_data.get("alert_source") or ""),
            affected_asset=str(alert_data.get("affected_asset") or ""),
            confidence_percent=int(conf["confidence_percent"]),
            linked_signal_count=linked_signal_count,
            evidence_summary=evidence,
        )

        total_latency = time.perf_counter() - overall_start
        _metric_observe(ORCH_STEP_LATENCY_SECONDS, total_latency, step="total_pipeline")
        logger.info(f"[Timing] total_alert_processing={total_latency:.2f}s")
        return result

    def _build_normalized_entities(self, alert_data: Dict, enrichment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Guarantees entity extraction even if an upstream agent fails/mis-parses.
        This fixes the 'http_header blob' issue from your earlier run.
        """
        raw_iocs = (
            alert_data.get("ioc_list")
            or alert_data.get("IOC List")
            or (enrichment.get("threat_intel", {}) or {}).get("raw_ioc_input")
            or ""
        )
        parsed = self._ioc_tool.parse_ioc_list(raw_iocs)
        entities = self._ioc_tool.classify_iocs(parsed)

        # If the alert already provided entities, include them too (dedupe happens in classifier)
        extra = alert_data.get("entities") or []
        if extra and isinstance(extra, list):
            entities.extend(self._ioc_tool.classify_iocs(extra))

        # Deduplicate by (entity_type, normalized)
        dedup: Dict[Tuple[Any, Any], Dict[str, Any]] = {}
        for e in entities:
            if not isinstance(e, dict):
                continue
            k = (e.get("entity_type"), e.get("normalized"))
            if k not in dedup:
                dedup[k] = e
        return list(dedup.values())

    def _extract_enriched_iocs(self, enrichment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Pulls TI enrichments into a uniform list so ConfidenceScorer can use them.
        """
        ti = enrichment.get("threat_intel", {}) or {}
        findings = ti.get("findings") or []
        out: List[Dict[str, Any]] = []
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, dict):
                    out.append(f)
        return out

    def _quality_checks(self, incident_type: str, predicates: Dict[str, Any], enrichment: Dict[str, Any]) -> List[str]:
        checks: List[str] = []
        it = (incident_type or "INVESTIGATE").upper().strip()
        asset = enrichment.get("asset_info", {}) or {}

        if asset.get("found") is False:
            checks.append("Asset not found in CMDB: validate ownership, exposure, and telemetry availability.")
        if predicates.get("internet_facing_true_or_unknown"):
            checks.append("Exposure is true/unknown: treat as high risk until VIP/NAT/WAF/DNS confirms otherwise.")

        siem = enrichment.get("siem_context", {}) or {}
        linked_total = int((((siem.get("linked") or {}).get("total_events")) or 0))
        unlinked_total = int((((siem.get("environment_unlinked") or {}).get("total_events")) or 0))

        if linked_total < 1 and unlinked_total > 0:
            checks.append(
                "SIEM has environment signals but none are linked: verify join keys (host aliases, IPs, time window) to prevent mis-scoping."
            )
        if not predicates.get("has_any_enforceable_iocs"):
            checks.append("No enforceable IOCs (ip/domain/url/hash) captured yet: limits blocking actions and TI scoring.")
        if it == "WEBAPP_EXPLOIT" and not predicates.get("web_artifact_possible"):
            checks.append("Web exploit type selected but web artifacts are weak: confirm with IIS/WAF evidence before disruptive containment.")
        return checks[:8]

    def _final_triage_decision(
        self,
        router_decision: str,
        router_confidence: float,
        confidence_percent: int,
        outcome: str,
        predicates: Dict[str, Any],
        severity: str,
    ) -> str:
        sev = (severity or "").upper().strip()
        danger = any(
            [
                bool(predicates.get("web_artifact_strong")),
                bool(predicates.get("ransomware_signals")),
                bool(predicates.get("identity_telemetry_signals")),
                bool(predicates.get("high_risk_cve")),
                bool(predicates.get("internet_facing_true_or_unknown")),
            ]
        )
        if outcome == "escalate_incident":
            return "escalate"
        if outcome in {"investigate", "monitor"}:
            return "enrich"
        if router_decision == "dismiss" and router_confidence >= 0.92 and not danger:
            return "dismiss"
        if sev in {"CRITICAL", "HIGH"}:
            return "enrich"
        if confidence_percent < 35 and not danger:
            return "dismiss"
        return "enrich"

    async def _parallel_enrich(self, alert_data: Dict) -> Dict[str, Any]:
        """
        Performs enrichment in parallel and records per-agent latencies.
        Adds `_agent_latencies` to the output for downstream metrics.
        """

        async def _timed(name: str, coro) -> Tuple[str, Any, float]:
            t0 = time.perf_counter()
            try:
                res = await coro
                return name, res, (time.perf_counter() - t0)
            except Exception as e:
                return name, e, (time.perf_counter() - t0)

        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    _timed("threat_intel", self.ti_agent.enrich(alert_data)),
                    _timed("asset_info", self.asset_agent.lookup(alert_data)),
                    _timed("historical_context", self.history_agent.get_context(alert_data)),
                    _timed("vuln_intel", self.vuln_agent.enrich(alert_data)),
                    _timed("siem_context", self.siem_agent.get_context(alert_data)),
                    return_exceptions=False,
                ),
                timeout=20,
            )
        except asyncio.TimeoutError:
            logger.error("[Enrichment] Timeout after 20 seconds")
            _metric_inc(ORCH_STEP_FAILURES_TOTAL, step="enrichment_timeout")
            return {
                "threat_intel": {"status": "timeout"},
                "asset_info": {"status": "timeout"},
                "historical_context": {"status": "timeout"},
                "vuln_intel": {"status": "timeout"},
                "siem_context": {"status": "timeout"},
                "_agent_latencies": {},
            }

        out: Dict[str, Any] = {}
        lat: Dict[str, float] = {}

        for name, res, seconds in results:
            lat[name] = float(seconds)

            # Prometheus per-agent step timing (optional)
            # (This includes SIEM latency which you requested.)
            _metric_observe(ORCH_STEP_LATENCY_SECONDS, float(seconds), step=f"agent_{name}")

            if isinstance(res, Exception):
                logger.warning(f"[Enrichment] {name} failed: {res}")
                _metric_inc(ORCH_STEP_FAILURES_TOTAL, step=f"agent_{name}")
                out[name] = {"status": "failed", "error": str(res)}
            elif not isinstance(res, dict):
                out[name] = {"status": "failed", "error": f"invalid type {type(res).__name__}"}
            else:
                out[name] = res

        out["_agent_latencies"] = lat
        return out

    def _build_confidence_inputs(
        self,
        alert_data: Dict,
        enrichment: Dict[str, Any],
        p: Dict[str, Any],
        incident_type: str,
        normalized_alert: Dict[str, Any],
        evidence_bundle: Dict[str, Any],
    ) -> Tuple[Dict[str, float], Dict[str, float]]:
        # Artifact base (set sane baseline; do not default to 0.0)
        S_artifact = 0.55
        if p.get("web_artifact_strong"):
            S_artifact = 0.95
        elif p.get("web_artifact_possible"):
            S_artifact = 0.70
        elif p.get("ransomware_signals"):
            S_artifact = 0.90

        profile = self.profile_store.get_profile(incident_type)
        artifact_rules = profile.get("artifact_rules") or []
        entities = normalized_alert.get("entities") or []
        entity_types_present = {
            str(e.get("entity_type") or e.get("type") or "").strip().lower()
            for e in entities
            if isinstance(e, dict)
        }
        linked_signals = set((evidence_bundle.get("linked_evidence") or {}).get("signals") or [])

        artifact_boost = 0.0
        for r in artifact_rules:
            match = (r or {}).get("match") or {}
            score = float((r or {}).get("score") or 0.0)
            if not match or score <= 0:
                continue
            if "entity_type" in match and str(match["entity_type"]).strip().lower() in entity_types_present:
                artifact_boost += score
            if "signal" in match and str(match["signal"]).strip() in linked_signals:
                artifact_boost += score

        artifact_boost = min(1.0, artifact_boost)
        S_artifact = min(1.0, S_artifact + artifact_boost)

        # Exploit context
        vuln = enrichment.get("vuln_intel", {}) or {}
        S_exploit_context = float((vuln.get("summary") or {}).get("exploit_context_score") or 0.0)
        if S_exploit_context <= 0.0 and p.get("high_risk_cve"):
            S_exploit_context = 0.75
        if p.get("web_artifact_strong") and S_exploit_context < 0.70:
            S_exploit_context = 0.85
        if p.get("ransomware_signals") and S_exploit_context < 0.85:
            S_exploit_context = 0.90

        # Corroboration: include unlinked as partial (scorer will also handle with context)
        siem = enrichment.get("siem_context", {}) or {}
        linked_total = int((((siem.get("linked") or {}).get("total_events")) or 0))
        unlinked_total = int((((siem.get("environment_unlinked") or {}).get("total_events")) or 0))
        if linked_total >= 5:
            S_corroboration = 0.9
        elif linked_total >= 2:
            S_corroboration = 0.6
        elif linked_total >= 1:
            S_corroboration = 0.35
        elif unlinked_total >= 4:
            S_corroboration = 0.55
        else:
            S_corroboration = 0.25

        # Exposure
        S_exposure = 0.75 if p.get("internet_facing_true_or_unknown") else 0.2

        # Asset criticality
        asset = enrichment.get("asset_info") or {}
        tier = str(asset.get("risk_tier") or "unknown").upper()
        S_asset_criticality = {"CRITICAL": 1.0, "HIGH": 0.85, "MEDIUM": 0.65, "LOW": 0.4}.get(tier, 0.6)

        # TI score
        if not p.get("has_any_enforceable_iocs"):
            S_ti = 0.5
        else:
            ti = enrichment.get("threat_intel") or {}
            summ = ti.get("summary") or {}
            mal = float(summ.get("malicious_count", 0) or 0)
            total = float(summ.get("total_iocs", 1) or 1)
            cov = float(ti.get("enrichment_coverage", 0.0) or 0.0)
            S_ti = min(1.0, (mal / max(total, 1.0)) * 0.7 + cov * 0.3)

        blob = " ".join([str(alert_data.get("description", "")), str(alert_data.get("additional_context", ""))]).lower()
        if any(
            x in blob
            for x in [
                "volt typhoon",
                "frp",
                "fast reverse proxy",
                "published in public advisory",
                "credential compromise",
                "ntds.dit",
            ]
        ):
            S_artifact = min(1.0, S_artifact + 0.25)

        P_benign_change = (
            0.6 if any(k in blob for k in ["change ticket", "maintenance window", "approved change", "scheduled upgrade"]) else 0.0
        )
        P_data_quality = 0.5 if not alert_data.get("timestamp") else 0.0

        return (
            {
                "S_artifact": float(S_artifact),
                "S_exploit_context": float(S_exploit_context),
                "S_corroboration": float(S_corroboration),
                "S_exposure": float(S_exposure),
                "S_asset_criticality": float(S_asset_criticality),
                "S_ti": float(S_ti),
            },
            {
                "P_benign_change": float(P_benign_change),
                "P_data_quality": float(P_data_quality),
            },
        )

    def _outcome_from_conf(self, confidence_percent: int) -> str:
        if confidence_percent >= 80:
            return "escalate_incident"
        if 55 <= confidence_percent <= 79:
            return "investigate"
        if 35 <= confidence_percent <= 54:
            return "monitor"
        return "close_or_benign"

    def _risk_from_conf_and_severity(self, confidence_percent: int, severity: str) -> str:
        sev = (severity or "MEDIUM").upper().strip()
        base = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 0, "LOW": -10, "INFO": -20}.get(sev, 0)
        score = confidence_percent + base
        if score >= 85:
            return "CRITICAL"
        if score >= 65:
            return "HIGH"
        if score >= 45:
            return "MEDIUM"
        if score >= 25:
            return "LOW"
        return "INFO"

    def _build_evidence_summary(self, alert_data: Dict, enrichment: Dict[str, Any], p: Dict[str, Any]) -> Dict[str, Any]:
        key_evidence: List[str] = []
        gaps: List[str] = []

        key_evidence.append(
            f"Alert source `{alert_data.get('alert_source')}` severity `{alert_data.get('severity')}` asset `{alert_data.get('affected_asset')}`"
        )
        if p.get("has_cves"):
            key_evidence.append("CVE context present (see vuln_intel).")
        if p.get("web_artifact_strong"):
            key_evidence.append("Strong web exploitation artifact combo detected (alert artifacts and/or linked evidence).")
        elif p.get("web_artifact_possible"):
            key_evidence.append("Web exploitation artifact indicators present (verify on-box artifacts/logs).")
        if p.get("ransomware_signals"):
            key_evidence.append("Ransomware-impact signals present (encryption/recovery inhibition/lateral movement patterns).")

        siem = enrichment.get("siem_context", {}) or {}
        linked = (siem.get("linked") or {})
        env_unlinked = (siem.get("environment_unlinked") or {})
        linked_total = int(linked.get("total_events") or 0)

        if not p.get("has_any_enforceable_iocs"):
            gaps.append("No enforceable IOCs available (ip/domain/url/hash) from alert or linked enrichment yet.")
        if linked_total < 1:
            gaps.append("No SIEM events could be linked to this alert scope (host/ip/time). Validate join keys or expand scope safely.")
        if p.get("internet_facing_true_or_unknown"):
            gaps.append("Validate exposure (VIP/NAT/WAF/DNS). Treat as high risk until proven not internet/partner-facing.")

        linked_signal_ids = (linked.get("signal_ids") or [])[:10]
        linked_signals_human = (linked.get("signals") or [])[:10]
        linked_signals = [f"[{x}]" for x in linked_signal_ids] + list(linked_signals_human)

        unlinked_ids = (env_unlinked.get("signal_ids") or [])[:10]
        unlinked_human = (env_unlinked.get("signals") or [])[:10]
        unlinked_env = [f"[{x}]" for x in unlinked_ids] + list(unlinked_human)

        return {
            "key_evidence": key_evidence[:10],
            "linked_signals": linked_signals[:10],
            "gaps": gaps[:10],
            "unlinked_environment_signals": unlinked_env[:10],
        }

    async def _llm_explanation_optional(
        self, alert_data: Dict, soc_artifacts: Dict[str, Any], incident_type: str
    ) -> Tuple[str, str]:
        base_summary = (
            f"## Incident Update\n\n"
            f"Assessment for `{incident_type}` affecting "
            f"`{alert_data.get('affected_asset')}` "
            f"from `{alert_data.get('alert_source')}`. "
            f"Evidence is scoped.\n"
        )

        try:
            conf_obj = (soc_artifacts or {}).get("confidence", {}) or {}
            confidence_percent = conf_obj.get("confidence_percent", None)

            evidence_bundle = (soc_artifacts or {}).get("evidence_bundle", {}) or {}
            linked = (evidence_bundle.get("linked_evidence", {}) or {})
            linked_signals = linked.get("signals") or []
            linked_signal_count = len(linked_signals) if isinstance(linked_signals, list) else 0

            evidence_mode = (
                "CONFIRMED"
                if (isinstance(confidence_percent, int) and confidence_percent >= 80 and linked_signal_count > 0)
                else "PROBABLE"
            )

            query = " ".join(
                [
                    str(alert_data.get("description", "")),
                    str(alert_data.get("ioc_list", "")),
                    str(alert_data.get("additional_context", "")),
                ]
            ).strip()

            # ✅ RAG latency tracking (Prometheus + logs)
            rag_start = time.perf_counter()
            results = await asyncio.to_thread(self.retriever.retrieve, query, 2) if query else []
            ctx = self.retriever.format_context(results)[:3500] if results else ""
            rag_latency = time.perf_counter() - rag_start
            _metric_observe(ORCH_STEP_LATENCY_SECONDS, rag_latency, step="rag")
            logger.info(f"[Timing] rag={rag_latency:.2f}s")

            system = (
                "You are a SOC analyst. "
                "Produce a polished, scannable incident update in Markdown.\n"
                "Rules:\n"
                "1) Use ONLY the scoped evidence.\n"
                "2) Ignore unlinked environment signals unless explicitly linked.\n"
                "3) Do NOT add recommended actions.\n"
                "4) No threat actor attribution.\n"
                "5) No speculation about sophistication/motivation.\n"
                "6) If EVIDENCE_MODE is PROBABLE:\n"
                " - Use probabilistic wording.\n"
                " - Do NOT say data theft occurred.\n"
                " - Do NOT state exploitation as fact.\n"
                "7) If LINKED_SIGNAL_COUNT == 0, Main Uncertainty MUST mention lack of linked corroboration.\n"
                "Required structure:\n"
                "## Incident Update\n"
                "## Assessment\n"
                "## Key Evidence (Scoped)\n"
                "## Gaps / Required Telemetry\n"
                "## Confidence Rationale\n"
            )

            compact_evidence = {
                "incident_type": soc_artifacts.get("incident_type"),
                "confidence": (soc_artifacts.get("confidence") or {}).get("confidence_percent"),
                "predicates": soc_artifacts.get("predicates"),
                "quality_checks": soc_artifacts.get("quality_checks"),
                "evidence_summary": soc_artifacts.get("evidence_summary"),
            }

            prompt = (
                f"EVIDENCE_MODE: {evidence_mode}\n"
                f"CONFIDENCE_PERCENT: {confidence_percent}\n"
                f"LINKED_SIGNAL_COUNT: {linked_signal_count}\n\n"
                f"<alert>\n"
                f"{self.prompt_builder.build_alert_xml(alert_data)}\n"
                f"</alert>\n\n"
                f"<scoped_evidence>\n"
                f"{json.dumps(compact_evidence)}\n"
                f"</scoped_evidence>\n\n"
                f"<knowledge>\n"
                f"{ctx}\n"
                f"</knowledge>\n"
            )

            messages = [{"role": "system", "content": system}, {"role": "user", "content": prompt}]

            # ✅ LLM latency tracking (Prometheus + logs)
            llm_start = time.perf_counter()
            text = await asyncio.wait_for(
                asyncio.to_thread(nvidia_client.chat, messages, temperature=0.2, max_tokens=320),
                timeout=70,
            )
            llm_latency = time.perf_counter() - llm_start
            _metric_observe(ORCH_STEP_LATENCY_SECONDS, llm_latency, step="llm")
            logger.info(f"[Timing] llm_call={llm_latency:.2f}s")

            text = (text or "").strip()
            if not text:
                return base_summary, incident_type
            return text, incident_type

        except Exception as e:
            _metric_inc(ORCH_STEP_FAILURES_TOTAL, step="llm_explanation")
            logger.warning(f"[LLM] explanation generation failed: {e}")
            fallback = (
                f"## Incident Update\n\n"
                f"Deterministic SOC analysis completed.\n\n"
                f"Incident Type: {incident_type}\n"
                f"Risk Level: Derived from rule-based scoring.\n\n"
                f"LLM narrative generation was unavailable, "
                f"but evidence correlation and enrichment completed successfully."
            )
            return fallback, incident_type