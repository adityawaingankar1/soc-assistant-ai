from celery import shared_task

from backend.utils.email_service import (
    send_welcome_email
)


@shared_task(
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3}
)
def send_welcome_email_task(
    self,
    recipient_email,
    username,
    role
):
    return send_welcome_email(
        recipient_email=recipient_email,
        username=username,
        role=role
    )