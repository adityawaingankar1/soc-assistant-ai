from celery import Celery

celery_app = Celery(
    "soc_assistant",

    broker="redis://redis:6379/0",

    backend="redis://redis:6379/1",

    include=[
        "backend.tasks.alert_tasks"
    ]
)

celery_app.conf.update(

    task_serializer="json",

    accept_content=["json"],

    result_serializer="json",

    timezone="UTC",

    enable_utc=True,

    task_track_started=True,

    task_time_limit=600,

    worker_prefetch_multiplier=1,
)