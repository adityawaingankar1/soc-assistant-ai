from fastapi import APIRouter

from celery.result import AsyncResult

from backend.celery_app import celery_app

router = APIRouter(
    prefix="/api/tasks",
    tags=["Tasks"]
)


@router.get("/{task_id}")
def task_status(task_id: str):

    task = AsyncResult(
        task_id,
        app=celery_app
    )

    return {
        "task_id": task_id,
        "status": task.status,
        "result": (
            task.result
            if task.ready()
            else None
        )
    }