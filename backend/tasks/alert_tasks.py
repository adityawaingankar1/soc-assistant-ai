from __future__ import annotations

import asyncio
import time

from loguru import logger

from backend.celery_app import celery_app

from backend.database import (
    SessionLocal,
    AlertResponse
)

from backend.realtime.event_bus import (
    publish_threadsafe
)


@celery_app.task(bind=True)
def process_alert_task(
    self,
    alert_data: dict,
    user_id: str
):

    # =================================================
    # TRACK PROCESSING TIME
    # =================================================

    started = time.perf_counter()

    # =================================================
    # LAZY IMPORTS
    # Prevent startup crashes / memory spikes
    # =================================================

    from backend.agents.orchestrator import (
        AgentOrchestrator
    )

    from backend.graph.attack_graph_service import (
        AttackGraphService
    )

    alert_id = alert_data.get("alert_id")

    db = SessionLocal()

    try:

        logger.info(
            f"[Celery] Processing alert "
            f"{alert_id}"
        )

        # =================================================
        # LAZY INITIALIZATION
        # =================================================

        orchestrator = AgentOrchestrator()

        graph_service = AttackGraphService()

        # =================================================
        # RUN ANALYSIS
        # =================================================

        result = asyncio.run(
            orchestrator.process_alert(
                alert_data
            )
        )

        # =================================================
        # ADD PROCESSING TIME
        # =================================================

        processing_time = round(
            time.perf_counter() - started,
            2
        )

        result["processing_time_seconds"] = (
            processing_time
        )

        # =================================================
        # STORE RESPONSE
        # =================================================

        response = AlertResponse(

            alert_id=alert_id,

            triage_decision=result.get(
                "triage_decision"
            ),

            risk_level=result.get(
                "risk_level"
            ),

            attack_type=result.get(
                "attack_type"
            ),

            explanation=result.get(
                "explanation"
            ),

            recommended_actions=result.get(
                "recommended_actions",
                []
            ),

            confidence_score=result.get(
                "confidence_score",
                0.0
            ),

            source_citations=result.get(
                "source_citations",
                []
            ),

            follow_up_questions=result.get(
                "follow_up_questions",
                []
            ),

            enrichment_data=result.get(
                "enrichment_data",
                {}
            ),

            playbook=result.get(
                "playbook",
                ""
            )
        )

        db.add(response)

        db.commit()

        logger.info(
            f"[Celery] Stored analysis "
            f"{alert_id} "
            f"in {processing_time}s"
        )

        # =================================================
        # GRAPH INGESTION
        # =================================================

        try:

            graph_service.ingest_alert(
                alert_data,
                result
            )

        except Exception as e:

            logger.warning(
                f"[Graph] ingestion failed: {e}"
            )

        # =================================================
        # SSE EVENT
        # =================================================

        publish_threadsafe({

            "event_type":
            "alert_analysis_completed",

            "user_id": user_id,

            "data": {
                "alert_id": alert_id,
                "result": result,
                "processing_time_seconds": processing_time
            }
        })

        return result

    except Exception as e:

        logger.exception(
            f"[Celery] Alert failed: {e}"
        )

        publish_threadsafe({

            "event_type":
            "alert_analysis_failed",

            "user_id": user_id,

            "data": {
                "alert_id": alert_id,
                "error": str(e)
            }
        })

        raise

    finally:

        db.close()