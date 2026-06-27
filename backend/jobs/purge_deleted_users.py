# backend/jobs/purge_deleted_users.py
from datetime import datetime, timedelta
import argparse

from loguru import logger
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.database import SessionLocal, User, ChatSession, SystemLog


def purge_user_chat_and_mark_purged(db: Session, user: User, dry_run: bool = False) -> dict:
    """
    Privacy-first purge after retention window:
    - delete chat_sessions for the user
    - redact message_preview in chat audit logs
    - mark user purged_at
    - clear original_username/email so reuse is allowed after grace period
    """
    # For dry-run visibility
    msg_count = db.query(ChatSession).filter(ChatSession.user_id == user.id).count()
    logs_count = db.query(SystemLog).filter(
        SystemLog.user_id == user.id,
        SystemLog.event_type.in_(["chat_message_processed"])
    ).count()

    if dry_run:
        return {
            "dry_run": True,
            "would_delete_chat_messages": int(msg_count),
            "would_redact_chat_logs": int(logs_count),
        }

    deleted_msgs = (
        db.query(ChatSession)
        .filter(ChatSession.user_id == user.id)
        .delete(synchronize_session=False)
    )

    # Redact chat previews in audit logs
    chat_logs = (
        db.query(SystemLog)
        .filter(
            SystemLog.user_id == user.id,
            SystemLog.event_type.in_(["chat_message_processed"])
        )
        .all()
    )

    redacted = 0
    for log in chat_logs:
        if isinstance(log.event_data, dict) and "message_preview" in log.event_data:
            log.event_data["message_preview"] = "[purged]"
            redacted += 1

    user.purged_at = datetime.utcnow()

    # End grace window: allow username/email reuse
    user.original_username = None
    user.original_email = None

    db.commit()

    return {
        "dry_run": False,
        "deleted_chat_messages": int(deleted_msgs or 0),
        "chat_logs_redacted": int(redacted),
    }


def run_purge(retention_days: int, batch_size: int, dry_run: bool = False) -> dict:
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=retention_days)

        users = (
            db.query(User)
            .filter(User.deleted_at.isnot(None))
            .filter(User.deleted_at <= cutoff)
            .filter(User.purged_at.is_(None))
            .limit(batch_size)
            .all()
        )

        results = []
        for u in users:
            try:
                r = purge_user_chat_and_mark_purged(db, u, dry_run=dry_run)
                results.append({"user_id": u.id, **r})
                logger.info(f"[Purge] user_id={u.id} result={r}")
            except Exception as e:
                db.rollback()
                logger.error(f"[Purge] Failed for user_id={u.id}: {e}")

        return {
            "retention_days": retention_days,
            "batch_size": batch_size,
            "dry_run": dry_run,
            "purged_users": len(results),
            "details": results
        }
    finally:
        db.close()


def main():
    settings = get_settings()

    parser = argparse.ArgumentParser(description="Purge chat content for soft-deleted users after retention window.")
    parser.add_argument("--dry-run", action="store_true", help="Preview what would be purged without writing changes.")
    parser.add_argument("--retention-days", type=int, default=settings.user_chat_purge_days)
    parser.add_argument("--batch-size", type=int, default=settings.user_purge_batch_size)
    args = parser.parse_args()

    out = run_purge(
        retention_days=args.retention_days,
        batch_size=args.batch_size,
        dry_run=args.dry_run
    )
    print(out)


if __name__ == "__main__":
    main()